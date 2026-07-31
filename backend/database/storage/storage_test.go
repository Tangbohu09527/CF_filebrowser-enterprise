package storage

import (
	"errors"
	"path/filepath"
	"testing"

	storm "github.com/asdine/storm/v3"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/database/storage/bolt"
	bbolt "go.etcd.io/bbolt"
)

func TestQuickSetupAdminHasExplicitReadPermissions(t *testing.T) {
	previousConfig := settings.Config
	previousEnv := settings.Env
	t.Cleanup(func() {
		settings.Config = previousConfig
		settings.Env = previousEnv
		settings.InitializeUserResolvers()
	})

	settings.Config = settings.SetDefaults(false)
	settings.Config.Auth.AdminUsername = "quick-setup-admin"
	settings.Config.Auth.AdminPassword = "admin-password"
	settings.Config.Auth.Methods.PasswordAuth.Enabled = true
	settings.Env.IsFirstLoad = true
	disabled := false
	settings.Config.UserDefaults.Account.Permissions.Browse = &disabled
	settings.Config.UserDefaults.Account.Permissions.Preview = &disabled
	settings.Config.UserDefaults.Account.Permissions.Download = &disabled
	settings.InitializeUserResolvers()

	db, err := storm.Open(filepath.Join(t.TempDir(), "quick-setup.db"))
	if err != nil {
		t.Fatalf("open quick setup database: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("close quick setup database: %v", closeErr)
		}
	})
	store, err := bolt.NewStorage(db)
	if err != nil {
		t.Fatalf("create quick setup storage: %v", err)
	}

	quickSetup(store)
	admin, err := store.Users.Get("quick-setup-admin")
	if err != nil {
		t.Fatalf("load quick setup admin: %v", err)
	}
	if !admin.Permissions.Browse || !admin.Permissions.Preview || !admin.Permissions.Download {
		t.Fatalf("quick setup admin read permissions: got %+v, want Browse/Preview/Download true", admin.Permissions)
	}
}

func TestInitializeDbFailsClosedWhenV3MigrationFails(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "migration-failure.db")
	db, err := storm.Open(dbPath)
	if err != nil {
		t.Fatalf("open migration seed database: %v", err)
	}
	if err := db.Set("config", "version", bolt.LegacyDatabaseVersion); err != nil {
		_ = db.Close()
		t.Fatalf("seed V2 database version: %v", err)
	}
	if err := db.Bolt.Update(func(tx *bbolt.Tx) error {
		metadata, err := tx.CreateBucketIfNotExists([]byte("audit_metadata"))
		if err != nil {
			return err
		}
		return metadata.Put([]byte("schema_version"), []byte("invalid-schema"))
	}); err != nil {
		_ = db.Close()
		t.Fatalf("seed incompatible audit metadata: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close migration seed database: %v", err)
	}

	store, existed, err := InitializeDb(dbPath)
	if err == nil {
		t.Fatal("InitializeDb unexpectedly ignored mandatory migration failure")
	}
	if store != nil {
		t.Fatal("InitializeDb returned a usable store after migration failure")
	}
	if !existed {
		t.Fatal("InitializeDb did not recognize the seeded database")
	}

	db, err = storm.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen database after failed initialization: %v", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("close reopened database: %v", closeErr)
		}
	}()
	var version int
	if err := db.Get("config", "version", &version); err != nil {
		t.Fatalf("read version after failed initialization: %v", err)
	}
	if version != bolt.LegacyDatabaseVersion {
		t.Fatalf("failed initialization advanced database version to %d", version)
	}
	if err := db.Bolt.View(func(tx *bbolt.Tx) error {
		if tx.Bucket([]byte("audit_events")) != nil {
			return errors.New("failed migration committed audit events bucket")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
