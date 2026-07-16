package settings

import (
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func TestAdminPermsIncludesReadPermissions(t *testing.T) {
	permissions := AdminPerms()

	if !permissions.Browse {
		t.Error("AdminPerms Browse: got false want true")
	}
	if !permissions.Preview {
		t.Error("AdminPerms Preview: got false want true")
	}
	if !permissions.Download {
		t.Error("AdminPerms Download: got false want true")
	}
}

func TestConvertPermissionsToUsersDefaultsReadPermissions(t *testing.T) {
	permissions := ConvertPermissionsToUsers(UserDefaultsAccountPermissions{})

	assertDefaultReadPermissions(t, permissions)
}

func TestApplyUserDefaultsDefaultsReadPermissions(t *testing.T) {
	saved := Config
	t.Cleanup(func() { Config = saved })

	Config = Settings{}
	user := &users.User{Username: "new-user"}
	ApplyUserDefaults(user)

	assertDefaultReadPermissions(t, user.Permissions)
}

func assertDefaultReadPermissions(t *testing.T, permissions users.Permissions) {
	t.Helper()

	if !permissions.Browse {
		t.Error("default Browse: got false want true")
	}
	if !permissions.Preview {
		t.Error("default Preview: got false want true")
	}
	if !permissions.Download {
		t.Error("default Download: got false want true")
	}
}
