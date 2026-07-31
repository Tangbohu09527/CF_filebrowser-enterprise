package bolt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"path/filepath"
	"testing"

	storm "github.com/asdine/storm/v3"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	bbolt "go.etcd.io/bbolt"
)

func openMigrationTestDB(t *testing.T) *storm.DB {
	t.Helper()
	db, err := storm.Open(filepath.Join(t.TempDir(), "migration.db"))
	if err != nil {
		t.Fatalf("open migration database: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close migration database: %v", err)
		}
	})
	return db
}

func setMigrationTestVersion(t *testing.T, db *storm.DB, version int) {
	t.Helper()
	if err := db.Set("config", "version", version); err != nil {
		t.Fatalf("seed database version: %v", err)
	}
}

func migrationTestVersion(t *testing.T, db *storm.DB) int {
	t.Helper()
	var version int
	if err := db.Get("config", "version", &version); err != nil {
		t.Fatalf("read database version: %v", err)
	}
	return version
}

func TestMigrateDatabaseV2ToV3(t *testing.T) {
	db := openMigrationTestDB(t)
	setMigrationTestVersion(t, db, LegacyDatabaseVersion)

	if err := MigrateDatabase(db); err != nil {
		t.Fatalf("migrate V2 to V3: %v", err)
	}
	if got := migrationTestVersion(t, db); got != CurrentDatabaseVersion {
		t.Fatalf("database version: got %d want %d", got, CurrentDatabaseVersion)
	}
	if err := db.Bolt.View(func(tx *bbolt.Tx) error {
		for _, name := range auditBucketNames {
			if tx.Bucket(name) == nil {
				return errors.New("missing audit bucket: " + string(name))
			}
		}
		metadata := tx.Bucket(auditMetadataBucket)
		if metadata == nil {
			return errors.New("missing audit metadata bucket")
		}
		value := metadata.Get(auditSchemaVersionKey)
		if len(value) != 8 || binary.BigEndian.Uint64(value) != uint64(auditdb.CurrentSchemaVersion) {
			return errors.New("unexpected audit schema version metadata")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateDatabaseV3IsIdempotent(t *testing.T) {
	db := openMigrationTestDB(t)
	setMigrationTestVersion(t, db, LegacyDatabaseVersion)
	if err := MigrateDatabase(db); err != nil {
		t.Fatalf("first migration: %v", err)
	}
	markerKey := []byte("existing-event-marker")
	markerValue := []byte("preserve-me")
	if err := db.Bolt.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(auditEventsBucket).Put(markerKey, markerValue)
	}); err != nil {
		t.Fatalf("seed existing V3 data: %v", err)
	}

	if err := MigrateDatabase(db); err != nil {
		t.Fatalf("repeat V3 migration: %v", err)
	}
	if got := migrationTestVersion(t, db); got != CurrentDatabaseVersion {
		t.Fatalf("database version after repeat migration: got %d", got)
	}
	if err := db.Bolt.View(func(tx *bbolt.Tx) error {
		if got := tx.Bucket(auditEventsBucket).Get(markerKey); !bytes.Equal(got, markerValue) {
			return errors.New("idempotent migration changed existing audit data")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateDatabaseFailureDoesNotAdvanceVersion(t *testing.T) {
	db := openMigrationTestDB(t)
	setMigrationTestVersion(t, db, LegacyDatabaseVersion)
	if err := db.Bolt.Update(func(tx *bbolt.Tx) error {
		metadata, err := tx.CreateBucketIfNotExists(auditMetadataBucket)
		if err != nil {
			return err
		}
		return metadata.Put(auditSchemaVersionKey, []byte("invalid-schema"))
	}); err != nil {
		t.Fatalf("seed incompatible audit metadata: %v", err)
	}

	if err := MigrateDatabase(db); err == nil {
		t.Fatal("migration unexpectedly accepted incompatible audit metadata")
	}
	if got := migrationTestVersion(t, db); got != LegacyDatabaseVersion {
		t.Fatalf("failed migration advanced version to %d", got)
	}
	if err := db.Bolt.View(func(tx *bbolt.Tx) error {
		for _, name := range auditBucketNames {
			if bytes.Equal(name, auditMetadataBucket) {
				continue
			}
			if tx.Bucket(name) != nil {
				return errors.New("failed migration committed bucket: " + string(name))
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateDatabaseRepairsMissingV3BucketWithoutChangingData(t *testing.T) {
	db := openMigrationTestDB(t)
	setMigrationTestVersion(t, db, LegacyDatabaseVersion)
	if err := MigrateDatabase(db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}
	if err := db.Bolt.Update(func(tx *bbolt.Tx) error {
		return tx.DeleteBucket(auditIndexResultBucket)
	}); err != nil {
		t.Fatalf("remove V3 bucket: %v", err)
	}
	if err := MigrateDatabase(db); err != nil {
		t.Fatalf("repair missing V3 bucket: %v", err)
	}
	if err := db.Bolt.View(func(tx *bbolt.Tx) error {
		if tx.Bucket(auditIndexResultBucket) == nil {
			return errors.New("missing V3 bucket was not recreated")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
