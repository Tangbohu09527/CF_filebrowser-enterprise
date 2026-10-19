package bolt

import (
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func TestServiceReaderScopeLockNotAPIEditable(t *testing.T) {
	backend := createTestUsersBackend(t)
	original := &users.User{Username: "service-reader", ServiceScopeLocked: true, NonAdminEditable: users.NonAdminEditable{Password: "valid-password", Locale: "en"}, Permissions: users.Permissions{Browse: true, Download: true}}
	if err := backend.Save(original, true, false); err != nil {
		t.Fatal(err)
	}
	for _, admin := range []bool{false, true} {
		changed := &users.User{ID: original.ID, Username: original.Username, ServiceScopeLocked: false, NonAdminEditable: users.NonAdminEditable{Locale: "zh"}}
		if err := backend.Update(changed, admin, "ServiceScopeLocked", "Locale"); err != nil {
			t.Fatal(err)
		}
		saved, err := backend.GetBy(original.ID)
		if err != nil || !saved.ServiceScopeLocked {
			t.Fatal("scope lock cleared by API update")
		}
	}
	fields, err := parseFields(&users.User{}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range fields {
		if field == "ServiceScopeLocked" {
			t.Fatal("implicit all can modify lock")
		}
	}
}
