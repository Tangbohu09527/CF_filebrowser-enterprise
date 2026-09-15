package storage

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	storm "github.com/asdine/storm/v3"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/storage/bolt"
	logpkg "github.com/gtsteffaniak/go-logger/logger"
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

// bootstrapDebugCapture embeds the logger interface to keep this regression
// scoped to Debugf, the initialization path that previously exposed passwords.
type bootstrapDebugCapture struct {
	logpkg.Logger
	output strings.Builder
}

func (capture *bootstrapDebugCapture) Debugf(format string, args ...any) {
	_, _ = fmt.Fprintf(&capture.output, format, args...)
	_ = capture.output.WriteByte('\n')
}

func TestQuickSetupDoesNotLogBootstrapPassword(t *testing.T) {
	previousConfig := settings.Config
	previousEnv := settings.Env
	t.Cleanup(func() {
		settings.Config = previousConfig
		settings.Env = previousEnv
		settings.InitializeUserResolvers()
	})
	settings.Config = settings.SetDefaults(false)
	settings.Config.Auth.AdminUsername = "bootstrap-log-admin"
	const password = "bootstrap-P4ssword-should-never-be-logged"
	settings.Config.Auth.AdminPassword = password
	settings.Config.Auth.Methods.PasswordAuth.Enabled = true
	settings.Env.IsFirstLoad = true
	settings.InitializeUserResolvers()

	db, err := storm.Open(filepath.Join(t.TempDir(), "bootstrap-log.db"))
	if err != nil {
		t.Fatalf("open bootstrap database: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("close bootstrap database: %v", closeErr)
		}
	})
	store, err := bolt.NewStorage(db)
	if err != nil {
		t.Fatalf("create bootstrap storage: %v", err)
	}
	capture := &bootstrapDebugCapture{}
	logpkg.SetGlobalLogger(capture)
	t.Cleanup(func() { logpkg.SetGlobalLogger(nil) })

	quickSetup(store)
	admin, err := store.Users.Get("bootstrap-log-admin")
	if err != nil {
		t.Fatalf("load initialized administrator: %v", err)
	}
	if !admin.Permissions.Admin {
		t.Fatal("bootstrap must still create an administrator")
	}
	if admin.Password == password || utils.CheckPwd(password, admin.Password) != nil {
		t.Fatal("bootstrap password must be stored as a working password hash")
	}
	if utils.CheckPwd("incorrect-password", admin.Password) == nil {
		t.Fatal("bootstrap administrator accepted an incorrect password")
	}
	output := capture.output.String()
	if !strings.Contains(output, admin.Username) {
		t.Fatal("initialization debug logging was not captured")
	}
	if strings.Contains(output, password) || strings.Contains(output, admin.Password) {
		t.Fatal("initialization log exposed bootstrap password material")
	}
}

// signingKeyTestConfig models a new process loading current configuration,
// while each test keeps its synthetic Bolt database across process boundaries.
func signingKeyTestConfig(t *testing.T) string {
	t.Helper()
	previousConfig, previousEnv, previousUserStore := settings.Config, settings.Env, userStore
	t.Cleanup(func() {
		settings.Config, settings.Env, userStore = previousConfig, previousEnv, previousUserStore
		settings.InitializeUserResolvers()
	})
	settings.Config = settings.SetDefaults(false)
	settings.Config.Auth.AdminUsername = "restart-admin"
	settings.Config.Auth.AdminPassword = "restart-admin-password"
	settings.Env.IsPlaywright = true
	settings.InitializeUserResolvers()
	return filepath.Join(t.TempDir(), "signing-key.db")
}

func closeSigningKeyTestDatabase(t *testing.T, database *storm.DB) {
	t.Helper()
	if closeErr := database.Close(); closeErr != nil {
		t.Fatalf("close signing key test database: %v", closeErr)
	}
}

func TestInitializeDbPreservesSigningKeyAcrossRestart(t *testing.T) {
	for _, initialKey := range []string{"", "explicit-initial-signing-key"} {
		name := "generated"
		if initialKey != "" {
			name = "explicit"
		}
		t.Run(name, func(t *testing.T) {
			databasePath := signingKeyTestConfig(t)
			settings.Config.Auth.Key = initialKey
			first, existed, err := InitializeDb(databasePath)
			if err != nil || existed {
				t.Fatalf("initialize fresh signing key database: existed=%v, err=%v", existed, err)
			}
			key := settings.Config.Auth.Key
			if key == "" || initialKey != "" && key != initialKey {
				closeSigningKeyTestDatabase(t, first.Access.DB)
				t.Fatal("first initialization lost the explicit key or failed to generate a key")
			}
			stored, err := first.Settings.Get()
			if err != nil || stored.Auth.Key != key {
				closeSigningKeyTestDatabase(t, first.Access.DB)
				t.Fatal("first initialization did not persist its signing key")
			}
			admin, err := first.Users.Get("restart-admin")
			if err != nil {
				closeSigningKeyTestDatabase(t, first.Access.DB)
				t.Fatalf("read initialized administrator: %v", err)
			}
			closeSigningKeyTestDatabase(t, first.Access.DB)

			// No explicit key on restart. Other current configuration must survive.
			settings.Config.Auth.Key = ""
			settings.Config.Frontend.Name = "current configuration after restart"
			reopened, existed, err := InitializeDb(databasePath)
			if err != nil || !existed {
				t.Fatalf("reopen signing key database: existed=%v, err=%v", existed, err)
			}
			t.Cleanup(func() { closeSigningKeyTestDatabase(t, reopened.Access.DB) })
			if settings.Config.Auth.Key != key {
				t.Fatal("restart did not restore the original signing key")
			}
			if settings.Config.Frontend.Name != "current configuration after restart" {
				t.Fatal("restoring the signing key replaced current configuration")
			}
			restoredAdmin, err := reopened.Users.Get("restart-admin")
			if err != nil || restoredAdmin.Password != admin.Password || restoredAdmin.Permissions != admin.Permissions {
				t.Fatal("signing key restoration changed administrator credentials or permissions")
			}
		})
	}
}

func TestInitializeDbExplicitKeyOverridesPersistedKeyWithoutRewritingIt(t *testing.T) {
	databasePath := signingKeyTestConfig(t)
	first, _, err := InitializeDb(databasePath)
	if err != nil {
		t.Fatalf("initialize signing key database: %v", err)
	}
	persistedKey := settings.Config.Auth.Key
	closeSigningKeyTestDatabase(t, first.Access.DB)
	const explicitKey = "explicit-restart-signing-key"
	settings.Config.Auth.Key = explicitKey
	reopened, existed, err := InitializeDb(databasePath)
	if err != nil || !existed {
		t.Fatalf("reopen with explicit signing key: existed=%v, err=%v", existed, err)
	}
	t.Cleanup(func() { closeSigningKeyTestDatabase(t, reopened.Access.DB) })
	if settings.Config.Auth.Key != explicitKey {
		t.Fatal("persisted key overrode the explicit runtime key")
	}
	stored, err := reopened.Settings.Get()
	if err != nil || stored.Auth.Key != persistedKey {
		t.Fatal("runtime key override unexpectedly rewrote the persisted signing key")
	}
}

func TestInitializeDbMissingOrUnreadableSigningKeyFailsClosed(t *testing.T) {
	for _, failure := range []string{"missing-settings", "empty-key", "corrupt-settings"} {
		t.Run(failure, func(t *testing.T) {
			databasePath := signingKeyTestConfig(t)
			first, _, err := InitializeDb(databasePath)
			if err != nil {
				t.Fatalf("initialize signing key database: %v", err)
			}
			if failure == "empty-key" {
				if seedErr := first.Access.DB.Set("config", "settings", &settings.Settings{}); seedErr != nil {
					t.Fatalf("seed empty persisted signing key: %v", seedErr)
				}
			}
			var original []byte
			if updateErr := first.Access.DB.Bolt.Update(func(tx *bbolt.Tx) error {
				bucket := tx.Bucket([]byte("config"))
				switch failure {
				case "missing-settings":
					if deleteErr := bucket.Delete([]byte("settings")); deleteErr != nil {
						return deleteErr
					}
				case "corrupt-settings":
					if putErr := bucket.Put([]byte("settings"), []byte("PRIVATE-INVALID-SETTINGS")); putErr != nil {
						return putErr
					}
				}
				original = bytes.Clone(bucket.Get([]byte("settings")))
				return nil
			}); updateErr != nil {
				t.Fatalf("seed invalid persisted settings: %v", updateErr)
			}
			closeSigningKeyTestDatabase(t, first.Access.DB)
			settings.Config.Auth.Key = ""
			result, existed, err := InitializeDb(databasePath)
			if result != nil {
				closeSigningKeyTestDatabase(t, result.Access.DB)
			}
			if err == nil || result != nil || !existed {
				t.Fatal("invalid persisted signing key did not reject the existing database")
			}
			if settings.Config.Auth.Key != "" || strings.Contains(err.Error(), "PRIVATE-INVALID-SETTINGS") {
				t.Fatal("failed key recovery generated a replacement or exposed persisted content")
			}
			// A bounded reopen also proves failed initialization released its handle.
			database, err := storm.Open(databasePath, storm.BoltOptions(0o600, &bbolt.Options{Timeout: time.Second}))
			if err != nil {
				t.Fatalf("failed initialization retained the database lock: %v", err)
			}
			t.Cleanup(func() { closeSigningKeyTestDatabase(t, database) })
			if viewErr := database.Bolt.View(func(tx *bbolt.Tx) error {
				if !bytes.Equal(original, tx.Bucket([]byte("config")).Get([]byte("settings"))) {
					return errors.New("failed initialization rewrote the settings record")
				}
				return nil
			}); viewErr != nil {
				t.Fatal(viewErr)
			}
		})
	}
}
