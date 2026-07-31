package bolt

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	storm "github.com/asdine/storm/v3"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	bbolt "go.etcd.io/bbolt"
)

const (
	auditEventKeyBytes     = 16
	auditRecoveryBatchSize = 100
	maxAuditListLimit      = 1000
)

var errAuditSchemaUnavailable = errors.New("audit storage schema is unavailable")

type auditBoltStore struct {
	db  *storm.DB
	now func() time.Time
}

func newAuditStore(db *storm.DB) *auditBoltStore {
	return &auditBoltStore{
		db:  db,
		now: time.Now,
	}
}

func (store *auditBoltStore) CreatePending(event auditdb.Event) error {
	if err := event.ValidatePending(); err != nil {
		return err
	}
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("serialize pending audit event: %w", err)
	}
	err = store.db.Bolt.Update(func(tx *bbolt.Tx) error {
		pending, bucketErr := requiredAuditBucket(tx, auditPendingBucket)
		if bucketErr != nil {
			return bucketErr
		}
		requestIDs, bucketErr := requiredAuditBucket(tx, auditRequestIDsBucket)
		if bucketErr != nil {
			return bucketErr
		}
		requestKey := []byte(event.RequestID)
		if pending.Get(requestKey) != nil || requestIDs.Get(requestKey) != nil {
			return auditdb.ErrRequestIDExists
		}
		return pending.Put(requestKey, data)
	})
	if err != nil {
		return fmt.Errorf("create pending audit event: %w", err)
	}
	return nil
}

func (store *auditBoltStore) Finalize(requestID string, finalization auditdb.Finalization) (*auditdb.Event, error) {
	if err := auditdb.ValidateRequestID(requestID); err != nil {
		return nil, err
	}
	var terminal *auditdb.Event
	err := store.db.Bolt.Update(func(tx *bbolt.Tx) error {
		pending, bucketErr := requiredAuditBucket(tx, auditPendingBucket)
		if bucketErr != nil {
			return bucketErr
		}
		requestIDs, bucketErr := requiredAuditBucket(tx, auditRequestIDsBucket)
		if bucketErr != nil {
			return bucketErr
		}
		requestKey := []byte(requestID)
		pendingData := pending.Get(requestKey)
		if pendingData == nil {
			eventKey := requestIDs.Get(requestKey)
			if eventKey == nil {
				return auditdb.ErrPendingNotFound
			}
			existing, loadErr := loadTerminalEventForRequest(tx, requestID, eventKey)
			if loadErr != nil {
				return loadErr
			}
			terminal = existing
			return nil
		}

		event, decodeErr := decodePendingEvent(requestID, pendingData)
		if decodeErr != nil {
			return decodeErr
		}
		timestamp := finalization.TimestampUTC
		if timestamp.IsZero() {
			timestamp = store.now()
		}
		event.TimestampUTC = timestamp.UTC()
		event.Result = finalization.Result
		event.HTTPStatus = finalization.HTTPStatus
		event.ErrorCode = finalization.ErrorCode
		event.Metadata = auditdb.MergeMetadataV1(event.Metadata, finalization.Metadata)
		if putErr := putTerminalEvent(tx, event, true); putErr != nil {
			return putErr
		}
		if deleteErr := pending.Delete(requestKey); deleteErr != nil {
			return fmt.Errorf("delete finalized pending audit event: %w", deleteErr)
		}
		terminal = event
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("finalize audit event: %w", err)
	}
	return terminal, nil
}

func (store *auditBoltStore) AppendTerminal(event auditdb.Event) (*auditdb.Event, error) {
	if event.ID != "" {
		return nil, fmt.Errorf("%w: terminal event ID must be assigned by storage", auditdb.ErrInvalidEvent)
	}
	if event.TimestampUTC.IsZero() {
		event.TimestampUTC = store.now().UTC()
	} else {
		event.TimestampUTC = event.TimestampUTC.UTC()
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}
	err := store.db.Bolt.Update(func(tx *bbolt.Tx) error {
		return putTerminalEvent(tx, &event, false)
	})
	if err != nil {
		return nil, fmt.Errorf("append terminal audit event: %w", err)
	}
	return &event, nil
}

func (store *auditBoltStore) GetByID(id string) (*auditdb.Event, error) {
	if err := auditdb.ValidateEventID(id); err != nil {
		return nil, err
	}
	eventKey, err := hex.DecodeString(id)
	if err != nil || len(eventKey) != auditEventKeyBytes {
		return nil, fmt.Errorf("%w: invalid id", auditdb.ErrInvalidEvent)
	}
	var event *auditdb.Event
	err = store.db.Bolt.View(func(tx *bbolt.Tx) error {
		loaded, loadErr := loadTerminalEvent(tx, eventKey)
		if loadErr != nil {
			return loadErr
		}
		event = loaded
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("get audit event by ID: %w", err)
	}
	return event, nil
}

func (store *auditBoltStore) GetByRequestID(requestID string) (*auditdb.Event, error) {
	if err := auditdb.ValidateRequestID(requestID); err != nil {
		return nil, err
	}
	var event *auditdb.Event
	err := store.db.Bolt.View(func(tx *bbolt.Tx) error {
		requestIDs, bucketErr := requiredAuditBucket(tx, auditRequestIDsBucket)
		if bucketErr != nil {
			return bucketErr
		}
		eventKey := requestIDs.Get([]byte(requestID))
		if eventKey == nil {
			return auditdb.ErrEventNotFound
		}
		loaded, loadErr := loadTerminalEventForRequest(tx, requestID, eventKey)
		if loadErr != nil {
			return loadErr
		}
		event = loaded
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("get audit event by request ID: %w", err)
	}
	return event, nil
}

func (store *auditBoltStore) ListTerminal(limit int) ([]auditdb.Event, error) {
	if limit < 1 || limit > maxAuditListLimit {
		return nil, auditdb.ErrInvalidLimit
	}
	events := make([]auditdb.Event, 0, limit)
	err := store.db.Bolt.View(func(tx *bbolt.Tx) error {
		bucket, bucketErr := requiredAuditBucket(tx, auditEventsBucket)
		if bucketErr != nil {
			return bucketErr
		}
		cursor := bucket.Cursor()
		for key, value := cursor.First(); key != nil && len(events) < limit; key, value = cursor.Next() {
			event, decodeErr := decodeTerminalEvent(key, value)
			if decodeErr != nil {
				return decodeErr
			}
			events = append(events, *event)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list terminal audit events: %w", err)
	}
	return events, nil
}

func (store *auditBoltStore) RecoverPending() (int, error) {
	total := 0
	for {
		recovered, err := store.recoverPendingBatch()
		if err != nil {
			return total, fmt.Errorf("recover pending audit events: %w", err)
		}
		total += recovered
		if recovered < auditRecoveryBatchSize {
			return total, nil
		}
	}
}

type pendingRecord struct {
	requestID string
	data      []byte
}

func (store *auditBoltStore) recoverPendingBatch() (int, error) {
	recovered := 0
	err := store.db.Bolt.Update(func(tx *bbolt.Tx) error {
		pending, bucketErr := requiredAuditBucket(tx, auditPendingBucket)
		if bucketErr != nil {
			return bucketErr
		}
		records := make([]pendingRecord, 0, auditRecoveryBatchSize)
		cursor := pending.Cursor()
		for key, value := cursor.First(); key != nil && len(records) < auditRecoveryBatchSize; key, value = cursor.Next() {
			records = append(records, pendingRecord{
				requestID: string(append([]byte(nil), key...)),
				data:      append([]byte(nil), value...),
			})
		}
		for _, record := range records {
			event, decodeErr := decodePendingEvent(record.requestID, record.data)
			if decodeErr != nil {
				return decodeErr
			}
			event.TimestampUTC = store.now().UTC()
			event.Result = auditdb.ResultUnknown
			event.HTTPStatus = nil
			event.ErrorCode = auditdb.ProcessInterruptedErrorCode
			if putErr := putTerminalEvent(tx, event, true); putErr != nil {
				return putErr
			}
			if deleteErr := pending.Delete([]byte(record.requestID)); deleteErr != nil {
				return fmt.Errorf("delete recovered pending audit event: %w", deleteErr)
			}
			recovered++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return recovered, nil
}

func putTerminalEvent(tx *bbolt.Tx, event *auditdb.Event, allowPending bool) error {
	requestIDs, err := requiredAuditBucket(tx, auditRequestIDsBucket)
	if err != nil {
		return err
	}
	pending, err := requiredAuditBucket(tx, auditPendingBucket)
	if err != nil {
		return err
	}
	requestKey := []byte(event.RequestID)
	if requestIDs.Get(requestKey) != nil || (!allowPending && pending.Get(requestKey) != nil) {
		return auditdb.ErrRequestIDExists
	}
	events, err := requiredAuditBucket(tx, auditEventsBucket)
	if err != nil {
		return err
	}
	sequence, err := events.NextSequence()
	if err != nil {
		return fmt.Errorf("allocate audit event sequence: %w", err)
	}
	if sequence == 0 {
		return errors.New("audit event sequence exhausted")
	}
	eventKey := makeAuditEventKey(event.TimestampUTC, sequence)
	if events.Get(eventKey) != nil {
		return errors.New("audit event key collision")
	}
	event.ID = hex.EncodeToString(eventKey)
	if err := event.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("serialize terminal audit event: %w", err)
	}
	if err := events.Put(eventKey, data); err != nil {
		return fmt.Errorf("persist terminal audit event: %w", err)
	}
	if err := requestIDs.Put(requestKey, eventKey); err != nil {
		return fmt.Errorf("persist audit request ID index: %w", err)
	}
	indexes := []struct {
		bucket []byte
		value  string
	}{
		{bucket: auditIndexActorBucket, value: auditActorIndexValue(*event)},
		{bucket: auditIndexActionBucket, value: string(event.Action)},
		{bucket: auditIndexTokenRefBucket, value: event.TokenRef},
		{bucket: auditIndexShareRefBucket, value: event.ShareRef},
		{bucket: auditIndexSourceBucket, value: event.Source},
		{bucket: auditIndexResultBucket, value: string(event.Result)},
	}
	for _, index := range indexes {
		if index.value == "" {
			continue
		}
		bucket, bucketErr := requiredAuditBucket(tx, index.bucket)
		if bucketErr != nil {
			return bucketErr
		}
		if putErr := bucket.Put(auditSecondaryIndexKey(index.value, eventKey), eventKey); putErr != nil {
			return fmt.Errorf("persist audit secondary index: %w", putErr)
		}
	}
	return nil
}

func loadTerminalEvent(tx *bbolt.Tx, eventKey []byte) (*auditdb.Event, error) {
	events, err := requiredAuditBucket(tx, auditEventsBucket)
	if err != nil {
		return nil, err
	}
	data := events.Get(eventKey)
	if data == nil {
		return nil, auditdb.ErrEventNotFound
	}
	return decodeTerminalEvent(eventKey, data)
}

func loadTerminalEventForRequest(tx *bbolt.Tx, requestID string, eventKey []byte) (*auditdb.Event, error) {
	event, err := loadTerminalEvent(tx, eventKey)
	if err != nil {
		return nil, err
	}
	if event.RequestID != requestID {
		return nil, errors.New("audit request ID index does not match its event")
	}
	return event, nil
}

func decodeTerminalEvent(eventKey, data []byte) (*auditdb.Event, error) {
	if len(eventKey) != auditEventKeyBytes {
		return nil, errors.New("invalid persisted audit event key")
	}
	var event auditdb.Event
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, errors.New("invalid persisted audit event encoding")
	}
	if event.ID != hex.EncodeToString(eventKey) {
		return nil, errors.New("persisted audit event ID does not match its key")
	}
	if err := event.Validate(); err != nil {
		return nil, fmt.Errorf("validate persisted audit event: %w", err)
	}
	if binary.BigEndian.Uint64(eventKey[:8]) != uint64(event.TimestampUTC.UnixNano()) {
		return nil, errors.New("persisted audit event timestamp does not match its key")
	}
	return &event, nil
}

func decodePendingEvent(requestID string, data []byte) (*auditdb.Event, error) {
	var event auditdb.Event
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, errors.New("invalid persisted pending audit event encoding")
	}
	if event.RequestID != requestID {
		return nil, errors.New("persisted pending audit request ID does not match its key")
	}
	if err := event.ValidatePending(); err != nil {
		return nil, fmt.Errorf("validate persisted pending audit event: %w", err)
	}
	return &event, nil
}

func requiredAuditBucket(tx *bbolt.Tx, name []byte) (*bbolt.Bucket, error) {
	bucket := tx.Bucket(name)
	if bucket == nil {
		return nil, fmt.Errorf("%w: required bucket is missing", errAuditSchemaUnavailable)
	}
	return bucket, nil
}

func makeAuditEventKey(timestamp time.Time, sequence uint64) []byte {
	key := make([]byte, auditEventKeyBytes)
	binary.BigEndian.PutUint64(key[:8], uint64(timestamp.UnixNano()))
	binary.BigEndian.PutUint64(key[8:], sequence)
	return key
}

func auditSecondaryIndexKey(value string, eventKey []byte) []byte {
	key := make([]byte, len(value)+1+len(eventKey))
	copy(key, value)
	key[len(value)] = 0
	copy(key[len(value)+1:], eventKey)
	return key
}

func auditActorIndexValue(event auditdb.Event) string {
	if event.UserID != nil {
		return "user:" + strconv.FormatUint(uint64(*event.UserID), 10)
	}
	if event.Username != "" {
		return "username:" + event.Username
	}
	return "anonymous"
}
