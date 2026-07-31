package bolt

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	storm "github.com/asdine/storm/v3"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	bbolt "go.etcd.io/bbolt"
)

func auditIntPointer(value int) *int {
	return &value
}

func auditInt64Pointer(value int64) *int64 {
	return &value
}

func auditBoolPointer(value bool) *bool {
	return &value
}

func openAuditTestDB(t *testing.T, path string) (*storm.DB, *auditBoltStore) {
	t.Helper()
	db, err := storm.Open(path)
	if err != nil {
		t.Fatalf("open audit database: %v", err)
	}
	if err := MigrateDatabase(db); err != nil {
		_ = db.Close()
		t.Fatalf("migrate audit database: %v", err)
	}
	return db, newAuditStore(db)
}

func closeAuditTestDB(t *testing.T, db *storm.DB) {
	t.Helper()
	if err := db.Close(); err != nil {
		t.Fatalf("close audit database: %v", err)
	}
}

func terminalAuditEvent(requestID string, timestamp time.Time) auditdb.Event {
	return auditdb.Event{
		SchemaVersion: auditdb.CurrentSchemaVersion,
		TimestampUTC:  timestamp,
		RequestID:     requestID,
		UserID:        func() *uint { value := uint(42); return &value }(),
		Username:      "audit-user",
		AuthMethod:    auditdb.AuthMethodToken,
		TokenRef:      auditdb.DeriveTokenRef("token-hash-for-audit-test"),
		ShareRef:      auditdb.DeriveShareRef("share-hash-for-audit-test"),
		ClientIP:      "2001:db8::42",
		Action:        auditdb.ActionFileDownload,
		Origin:        auditdb.OriginHTTP,
		Source:        "primary",
		Path:          "/reports/audit.pdf",
		CanonicalPath: "/reports/audit.pdf",
		EffectivePermissions: &auditdb.Permissions{
			Browse:   true,
			Preview:  true,
			Download: true,
		},
		Result:     auditdb.ResultSuccess,
		HTTPStatus: auditIntPointer(200),
		Metadata: &auditdb.MetadataV1{
			SchemaVersion: auditdb.CurrentMetadataSchemaVersion,
			DurationMs:    auditInt64Pointer(12),
			Bytes:         auditInt64Pointer(1024),
			Method:        auditdb.MethodGET,
		},
	}
}

func pendingAuditEvent(requestID string) auditdb.Event {
	event := terminalAuditEvent(requestID, time.Time{})
	event.Result = ""
	event.HTTPStatus = nil
	event.Metadata = &auditdb.MetadataV1{
		SchemaVersion: auditdb.CurrentMetadataSchemaVersion,
		Overwrite:     auditBoolPointer(false),
		Method:        auditdb.MethodPUT,
	}
	return event
}

func TestAuditAppendTerminalPersistsAndIndexes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, store := openAuditTestDB(t, path)
	event := terminalAuditEvent("request-terminal-persist", time.Date(2026, 7, 31, 11, 0, 0, 1, time.UTC))

	stored, err := store.AppendTerminal(event)
	if err != nil {
		t.Fatalf("append terminal event: %v", err)
	}
	if stored.ID == "" {
		t.Fatal("stored event ID is empty")
	}
	if stored.TimestampUTC.Location() != time.UTC {
		t.Fatalf("stored timestamp location: got %v", stored.TimestampUTC.Location())
	}

	byID, err := store.GetByID(stored.ID)
	if err != nil {
		t.Fatalf("get event by ID: %v", err)
	}
	byRequestID, err := store.GetByRequestID(stored.RequestID)
	if err != nil {
		t.Fatalf("get event by request ID: %v", err)
	}
	if byID.ID != stored.ID || byRequestID.ID != stored.ID {
		t.Fatal("event lookup returned inconsistent IDs")
	}

	eventKey, err := hex.DecodeString(stored.ID)
	if err != nil {
		t.Fatalf("decode stored event ID: %v", err)
	}
	indexes := []struct {
		bucket []byte
		value  string
	}{
		{bucket: auditIndexActorBucket, value: auditActorIndexValue(*stored)},
		{bucket: auditIndexActionBucket, value: string(stored.Action)},
		{bucket: auditIndexTokenRefBucket, value: stored.TokenRef},
		{bucket: auditIndexShareRefBucket, value: stored.ShareRef},
		{bucket: auditIndexSourceBucket, value: stored.Source},
		{bucket: auditIndexResultBucket, value: string(stored.Result)},
	}
	if err := db.Bolt.View(func(tx *bbolt.Tx) error {
		for _, index := range indexes {
			bucket := tx.Bucket(index.bucket)
			if bucket == nil {
				return fmt.Errorf("missing index bucket %s", index.bucket)
			}
			value := bucket.Get(auditSecondaryIndexKey(index.value, eventKey))
			if !bytes.Equal(value, eventKey) {
				return fmt.Errorf("index %s does not reference event", index.bucket)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("verify event indexes: %v", err)
	}

	closeAuditTestDB(t, db)
	db, store = openAuditTestDB(t, path)
	defer closeAuditTestDB(t, db)
	reopened, err := store.GetByID(stored.ID)
	if err != nil {
		t.Fatalf("get event after reopening database: %v", err)
	}
	if reopened.RequestID != stored.RequestID || reopened.TokenRef != stored.TokenRef {
		t.Fatal("reopened event differs from persisted event")
	}
}

func TestAuditRequestIDUniquenessAndStableTimeOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, store := openAuditTestDB(t, path)
	timestamp := time.Date(2026, 7, 31, 12, 0, 0, 100, time.UTC)

	first, err := store.AppendTerminal(terminalAuditEvent("request-time-first", timestamp))
	if err != nil {
		t.Fatalf("append first event: %v", err)
	}
	closeAuditTestDB(t, db)

	db, store = openAuditTestDB(t, path)
	defer closeAuditTestDB(t, db)
	second, err := store.AppendTerminal(terminalAuditEvent("request-time-second", timestamp))
	if err != nil {
		t.Fatalf("append second event after reopen: %v", err)
	}
	if first.ID == second.ID {
		t.Fatal("same-nanosecond events collided across database reopen")
	}

	events, err := store.ListTerminal(10)
	if err != nil {
		t.Fatalf("list terminal events: %v", err)
	}
	if len(events) != 2 || events[0].ID != first.ID || events[1].ID != second.ID {
		t.Fatalf("unexpected stable order: %+v", events)
	}

	duplicate := terminalAuditEvent(first.RequestID, timestamp.Add(time.Second))
	if _, err := store.AppendTerminal(duplicate); !errors.Is(err, auditdb.ErrRequestIDExists) {
		t.Fatalf("duplicate terminal request ID: got %v", err)
	}
	if err := store.CreatePending(pendingAuditEvent(first.RequestID)); !errors.Is(err, auditdb.ErrRequestIDExists) {
		t.Fatalf("terminal request ID reused by pending event: got %v", err)
	}
}

func TestAuditPendingPersistsAndFinalizesAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, store := openAuditTestDB(t, path)
	pending := pendingAuditEvent("request-pending-finalize")
	if err := store.CreatePending(pending); err != nil {
		t.Fatalf("create pending event: %v", err)
	}
	if err := store.CreatePending(pending); !errors.Is(err, auditdb.ErrRequestIDExists) {
		t.Fatalf("duplicate pending request ID: got %v", err)
	}
	closeAuditTestDB(t, db)

	db, store = openAuditTestDB(t, path)
	defer closeAuditTestDB(t, db)
	if err := db.Bolt.View(func(tx *bbolt.Tx) error {
		if value := tx.Bucket(auditPendingBucket).Get([]byte(pending.RequestID)); value == nil {
			return errors.New("pending event did not survive database reopen")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	finalized, err := store.Finalize(pending.RequestID, auditdb.Finalization{
		TimestampUTC: time.Date(2026, 7, 31, 12, 30, 0, 0, time.UTC),
		Result:       auditdb.ResultFailed,
		HTTPStatus:   auditIntPointer(500),
		ErrorCode:    "write_failed",
		Metadata: &auditdb.MetadataV1{
			SchemaVersion: auditdb.CurrentMetadataSchemaVersion,
			DurationMs:    auditInt64Pointer(50),
			Bytes:         auditInt64Pointer(0),
		},
	})
	if err != nil {
		t.Fatalf("finalize pending event: %v", err)
	}
	if finalized.Result != auditdb.ResultFailed || finalized.ErrorCode != "write_failed" {
		t.Fatalf("unexpected final result: %+v", finalized)
	}
	if finalized.Metadata == nil || finalized.Metadata.Overwrite == nil || *finalized.Metadata.Overwrite {
		t.Fatal("finalization did not preserve safe pending metadata")
	}
	if finalized.Metadata.DurationMs == nil || *finalized.Metadata.DurationMs != 50 {
		t.Fatal("finalization did not merge final metadata")
	}
	if err := db.Bolt.View(func(tx *bbolt.Tx) error {
		if value := tx.Bucket(auditPendingBucket).Get([]byte(pending.RequestID)); value != nil {
			return errors.New("pending event remains after finalization")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	repeated, err := store.Finalize(pending.RequestID, auditdb.Finalization{Result: auditdb.ResultSuccess})
	if err != nil {
		t.Fatalf("repeat finalization must be idempotent: %v", err)
	}
	if repeated.ID != finalized.ID {
		t.Fatal("repeat finalization created a second event")
	}
	if _, err := store.Finalize("request-pending-missing", auditdb.Finalization{Result: auditdb.ResultSuccess}); !errors.Is(err, auditdb.ErrPendingNotFound) {
		t.Fatalf("missing pending event: got %v", err)
	}
}

func TestAuditFinalizeFailureDoesNotLosePending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, store := openAuditTestDB(t, path)
	defer closeAuditTestDB(t, db)
	pending := pendingAuditEvent("request-finalize-rollback")
	if err := store.CreatePending(pending); err != nil {
		t.Fatalf("create pending event: %v", err)
	}
	if err := db.Bolt.Update(func(tx *bbolt.Tx) error {
		return tx.DeleteBucket(auditIndexResultBucket)
	}); err != nil {
		t.Fatalf("remove result index bucket: %v", err)
	}

	if _, err := store.Finalize(pending.RequestID, auditdb.Finalization{
		Result:     auditdb.ResultFailed,
		HTTPStatus: auditIntPointer(500),
		ErrorCode:  "write_failed",
	}); err == nil {
		t.Fatal("finalization unexpectedly succeeded with a missing index bucket")
	}
	if _, err := store.GetByRequestID(pending.RequestID); !errors.Is(err, auditdb.ErrEventNotFound) {
		t.Fatalf("rolled-back terminal event is visible: %v", err)
	}
	if err := db.Bolt.View(func(tx *bbolt.Tx) error {
		if value := tx.Bucket(auditPendingBucket).Get([]byte(pending.RequestID)); value == nil {
			return errors.New("pending event was lost on finalization failure")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := MigrateDatabase(db); err != nil {
		t.Fatalf("repair missing V3 bucket idempotently: %v", err)
	}
	if _, err := store.Finalize(pending.RequestID, auditdb.Finalization{Result: auditdb.ResultSuccess}); err != nil {
		t.Fatalf("finalize preserved pending event after bucket repair: %v", err)
	}
}

func TestAuditCorruptPendingKeyFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, store := openAuditTestDB(t, path)
	defer closeAuditTestDB(t, db)
	pending := pendingAuditEvent("request-pending-original")
	if err := store.CreatePending(pending); err != nil {
		t.Fatalf("create pending event: %v", err)
	}
	const mismatchedKey = "request-pending-mismatched"
	if err := db.Bolt.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(auditPendingBucket)
		data := append([]byte(nil), bucket.Get([]byte(pending.RequestID))...)
		if err := bucket.Delete([]byte(pending.RequestID)); err != nil {
			return err
		}
		return bucket.Put([]byte(mismatchedKey), data)
	}); err != nil {
		t.Fatalf("corrupt pending key: %v", err)
	}

	if _, err := store.RecoverPending(); err == nil {
		t.Fatal("recovery accepted a pending key and request ID mismatch")
	}
	if _, err := store.GetByRequestID(pending.RequestID); !errors.Is(err, auditdb.ErrEventNotFound) {
		t.Fatalf("corrupt pending event produced a terminal event: %v", err)
	}
	if err := db.Bolt.View(func(tx *bbolt.Tx) error {
		if tx.Bucket(auditPendingBucket).Get([]byte(mismatchedKey)) == nil {
			return errors.New("corrupt pending event was deleted after failed recovery")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAuditEventKeyCollisionDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, store := openAuditTestDB(t, path)
	defer closeAuditTestDB(t, db)
	timestamp := time.Date(2026, 7, 31, 13, 0, 0, 0, time.UTC)
	first, err := store.AppendTerminal(terminalAuditEvent("request-collision-first", timestamp))
	if err != nil {
		t.Fatalf("append first event: %v", err)
	}
	if err := db.Bolt.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(auditEventsBucket).SetSequence(0)
	}); err != nil {
		t.Fatalf("reset event sequence: %v", err)
	}

	if _, err := store.AppendTerminal(terminalAuditEvent("request-collision-second", timestamp)); err == nil {
		t.Fatal("event key collision overwrote an existing event")
	}
	preserved, err := store.GetByID(first.ID)
	if err != nil {
		t.Fatalf("get first event after collision: %v", err)
	}
	if preserved.RequestID != first.RequestID {
		t.Fatalf("event key collision changed first event to %q", preserved.RequestID)
	}
	if _, err := store.GetByRequestID("request-collision-second"); !errors.Is(err, auditdb.ErrEventNotFound) {
		t.Fatalf("colliding request ID index was committed: %v", err)
	}
}

func TestAuditLookupFailsClosedOnCorruptPrimaryIndexes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, store := openAuditTestDB(t, path)
	defer closeAuditTestDB(t, db)
	first, err := store.AppendTerminal(terminalAuditEvent(
		"request-index-integrity-first",
		time.Date(2026, 7, 31, 13, 30, 0, 0, time.UTC),
	))
	if err != nil {
		t.Fatalf("append first event: %v", err)
	}
	second, err := store.AppendTerminal(terminalAuditEvent(
		"request-index-integrity-second",
		time.Date(2026, 7, 31, 13, 31, 0, 0, time.UTC),
	))
	if err != nil {
		t.Fatalf("append second event: %v", err)
	}
	secondKey, err := hex.DecodeString(second.ID)
	if err != nil {
		t.Fatalf("decode second event ID: %v", err)
	}
	if err := db.Bolt.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(auditRequestIDsBucket).Put([]byte(first.RequestID), secondKey)
	}); err != nil {
		t.Fatalf("corrupt request ID index: %v", err)
	}
	if _, err := store.GetByRequestID(first.RequestID); err == nil {
		t.Fatal("lookup accepted a request ID index pointing to another event")
	}

	firstKey, err := hex.DecodeString(first.ID)
	if err != nil {
		t.Fatalf("decode first event ID: %v", err)
	}
	if err := db.Bolt.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(auditEventsBucket)
		var corrupted auditdb.Event
		if err := json.Unmarshal(bucket.Get(firstKey), &corrupted); err != nil {
			return err
		}
		corrupted.TimestampUTC = corrupted.TimestampUTC.Add(time.Second)
		data, err := json.Marshal(corrupted)
		if err != nil {
			return err
		}
		return bucket.Put(firstKey, data)
	}); err != nil {
		t.Fatalf("corrupt event timestamp: %v", err)
	}
	if _, err := store.GetByID(first.ID); err == nil {
		t.Fatal("lookup accepted an event timestamp inconsistent with its primary key")
	}
}

func TestAuditStartupRecoversPendingExactlyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, store := openAuditTestDB(t, path)
	pending := pendingAuditEvent("request-recover-pending")
	if err := store.CreatePending(pending); err != nil {
		t.Fatalf("create pending event: %v", err)
	}
	closeAuditTestDB(t, db)

	db, err := storm.Open(path)
	if err != nil {
		t.Fatalf("reopen database for startup: %v", err)
	}
	defer closeAuditTestDB(t, db)
	boltStore, err := NewStorage(db)
	if err != nil {
		t.Fatalf("initialize storage with pending recovery: %v", err)
	}
	recovered, err := boltStore.Audit.GetByRequestID(pending.RequestID)
	if err != nil {
		t.Fatalf("get recovered event: %v", err)
	}
	if recovered.Result != auditdb.ResultUnknown || recovered.ErrorCode != auditdb.ProcessInterruptedErrorCode {
		t.Fatalf("unexpected recovered result: %+v", recovered)
	}
	if recovered.Metadata == nil || recovered.Metadata.Overwrite == nil {
		t.Fatal("recovery did not preserve safe pending metadata")
	}
	recoveredCount, err := boltStore.Audit.RecoverPending()
	if err != nil {
		t.Fatalf("repeat pending recovery: %v", err)
	}
	if recoveredCount != 0 {
		t.Fatalf("repeat recovery created %d events", recoveredCount)
	}
	events, err := boltStore.Audit.ListTerminal(10)
	if err != nil {
		t.Fatalf("list recovered events: %v", err)
	}
	if len(events) != 1 || events[0].ID != recovered.ID {
		t.Fatalf("recovery did not create exactly one terminal event: %+v", events)
	}
}

func TestAuditStorageDoesNotPersistOrReturnSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, store := openAuditTestDB(t, path)
	defer closeAuditTestDB(t, db)

	secrets := []string{
		"bearer-token-obvious-secret",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdea",
		"password-obvious-secret",
		"Authorization: Bearer obvious-secret",
		"Cookie: session=obvious-secret",
		"share-secret-obvious-value",
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		"onlyoffice-secret-obvious-value",
	}
	pending := pendingAuditEvent("request-secret-leakage")
	pending.TokenRef = auditdb.DeriveTokenRef(secrets[1])
	pending.ShareRef = auditdb.DeriveShareRef(secrets[6])
	if err := store.CreatePending(pending); err != nil {
		t.Fatalf("create pending event: %v", err)
	}
	assertAuditBytesDoNotContainSecrets(t, auditDatabaseBytes(t, db), secrets)

	stored, err := store.Finalize(pending.RequestID, auditdb.Finalization{
		Result:     auditdb.ResultDenied,
		HTTPStatus: auditIntPointer(403),
		ErrorCode:  "permission_denied",
	})
	if err != nil {
		t.Fatalf("finalize pending event: %v", err)
	}
	databaseData := auditDatabaseBytes(t, db)
	assertAuditBytesDoNotContainSecrets(t, databaseData, secrets)
	if !bytes.Contains(databaseData, []byte(pending.TokenRef)) || !bytes.Contains(databaseData, []byte(pending.ShareRef)) {
		t.Fatal("safe derived references are missing from persistence")
	}

	byID, err := store.GetByID(stored.ID)
	if err != nil {
		t.Fatalf("get secret test event by ID: %v", err)
	}
	byRequestID, err := store.GetByRequestID(stored.RequestID)
	if err != nil {
		t.Fatalf("get secret test event by request ID: %v", err)
	}
	for _, returned := range []*auditdb.Event{stored, byID, byRequestID} {
		data, marshalErr := json.Marshal(returned)
		if marshalErr != nil {
			t.Fatalf("marshal returned event: %v", marshalErr)
		}
		assertAuditBytesDoNotContainSecrets(t, data, secrets)
	}

	invalid := terminalAuditEvent("request-invalid-secret", time.Now().UTC())
	invalid.Metadata.Method = auditdb.Method(secrets[0])
	validationErr := invalid.Validate()
	if validationErr == nil {
		t.Fatal("secret-shaped method unexpectedly passed validation")
	}
	assertAuditBytesDoNotContainSecrets(t, []byte(validationErr.Error()), secrets)
}

func auditDatabaseBytes(t *testing.T, db *storm.DB) []byte {
	t.Helper()
	var data bytes.Buffer
	if err := db.Bolt.View(func(tx *bbolt.Tx) error {
		return tx.ForEach(func(name []byte, bucket *bbolt.Bucket) error {
			data.Write(name)
			return appendAuditBucketBytes(&data, bucket)
		})
	}); err != nil {
		t.Fatalf("scan audit database: %v", err)
	}
	return data.Bytes()
}

func appendAuditBucketBytes(destination *bytes.Buffer, bucket *bbolt.Bucket) error {
	return bucket.ForEach(func(key, value []byte) error {
		destination.Write(key)
		if value != nil {
			destination.Write(value)
			return nil
		}
		child := bucket.Bucket(key)
		if child == nil {
			return errors.New("nested bucket disappeared during scan")
		}
		return appendAuditBucketBytes(destination, child)
	})
}

func assertAuditBytesDoNotContainSecrets(t *testing.T, data []byte, secrets []string) {
	t.Helper()
	for _, secret := range secrets {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("audit data contains forbidden secret category %q", secretCategory(secret))
		}
	}
}

func secretCategory(secret string) string {
	switch {
	case strings.HasPrefix(secret, "bearer"):
		return "bearer"
	case strings.HasPrefix(secret, "password"):
		return "password"
	case strings.HasPrefix(secret, "Authorization"):
		return "authorization"
	case strings.HasPrefix(secret, "Cookie"):
		return "cookie"
	case strings.HasPrefix(secret, "share"):
		return "share secret"
	case strings.HasPrefix(secret, "onlyoffice"):
		return "onlyoffice secret"
	default:
		return "credential hash"
	}
}
