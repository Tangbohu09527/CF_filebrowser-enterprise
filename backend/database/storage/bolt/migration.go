package bolt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	storm "github.com/asdine/storm/v3"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	bbolt "go.etcd.io/bbolt"
)

const (
	LegacyDatabaseVersion  = 2
	CurrentDatabaseVersion = 3
)

var (
	auditEventsBucket        = []byte("audit_events")
	auditPendingBucket       = []byte("audit_pending")
	auditRequestIDsBucket    = []byte("audit_request_ids")
	auditIndexActorBucket    = []byte("audit_index_actor")
	auditIndexActionBucket   = []byte("audit_index_action")
	auditIndexTokenRefBucket = []byte("audit_index_token_ref")
	auditIndexShareRefBucket = []byte("audit_index_share_ref")
	auditIndexSourceBucket   = []byte("audit_index_source")
	auditIndexResultBucket   = []byte("audit_index_result")
	auditMetadataBucket      = []byte("audit_metadata")
	auditSchemaVersionKey    = []byte("schema_version")

	auditBucketNames = [][]byte{
		auditEventsBucket,
		auditPendingBucket,
		auditRequestIDsBucket,
		auditIndexActorBucket,
		auditIndexActionBucket,
		auditIndexTokenRefBucket,
		auditIndexShareRefBucket,
		auditIndexSourceBucket,
		auditIndexResultBucket,
		auditMetadataBucket,
	}
)

func MigrateDatabase(db *storm.DB) error {
	if db == nil || db.Bolt == nil {
		return errors.New("database migration requires an open Storm database")
	}
	version, err := readDatabaseVersion(db)
	if err != nil {
		return fmt.Errorf("read database version: %w", err)
	}
	if version != LegacyDatabaseVersion && version != CurrentDatabaseVersion {
		return errors.New("unsupported database version")
	}

	err = db.Bolt.Update(func(tx *bbolt.Tx) error {
		for _, name := range auditBucketNames {
			if _, createErr := tx.CreateBucketIfNotExists(name); createErr != nil {
				return fmt.Errorf("create required audit bucket: %w", createErr)
			}
		}
		if metadataErr := initializeAuditSchemaMetadata(tx); metadataErr != nil {
			return metadataErr
		}
		if version == CurrentDatabaseVersion {
			return nil
		}
		if setErr := db.WithTransaction(tx).Set("config", "version", CurrentDatabaseVersion); setErr != nil {
			return fmt.Errorf("persist database version: %w", setErr)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("migrate database to V3: %w", err)
	}
	return nil
}

func readDatabaseVersion(db *storm.DB) (int, error) {
	var version int
	err := db.Get("config", "version", &version)
	if errors.Is(err, storm.ErrNotFound) {
		return LegacyDatabaseVersion, nil
	}
	return version, err
}

func initializeAuditSchemaMetadata(tx *bbolt.Tx) error {
	metadata := tx.Bucket(auditMetadataBucket)
	if metadata == nil {
		return errors.New("required audit metadata bucket is missing")
	}
	expected := make([]byte, 8)
	binary.BigEndian.PutUint64(expected, uint64(auditdb.CurrentSchemaVersion))
	stored := metadata.Get(auditSchemaVersionKey)
	if stored != nil && !bytes.Equal(stored, expected) {
		return errors.New("incompatible audit schema metadata")
	}
	if stored == nil {
		if err := metadata.Put(auditSchemaVersionKey, expected); err != nil {
			return fmt.Errorf("initialize audit schema metadata: %w", err)
		}
	}
	return nil
}
