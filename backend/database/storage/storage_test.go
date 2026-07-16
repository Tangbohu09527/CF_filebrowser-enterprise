package storage

import (
	"path/filepath"
	"testing"

	storm "github.com/asdine/storm/v3"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/database/storage/bolt"
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
