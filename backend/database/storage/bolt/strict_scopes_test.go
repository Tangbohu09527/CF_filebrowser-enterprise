package bolt

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	storm "github.com/asdine/storm/v3"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

// Construct the new contract through JSON so this regression compiles against
// versions that silently discard strictScopes before persisting the user.
func strictScopesJSONUser(t *testing.T, payload string) *users.User {
	t.Helper()
	var user users.User
	if err := json.Unmarshal([]byte(payload), &user); err != nil {
		t.Fatalf("decode synthetic strict-scopes user: %v", err)
	}
	return &user
}

func assertStoredStrictScopes(t *testing.T, backend users.StorageBackend, id uint, want bool) *users.User {
	t.Helper()
	user, err := backend.GetBy(id)
	if err != nil {
		t.Fatalf("reload synthetic strict-scopes user: %v", err)
	}
	data, err := json.Marshal(user)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	var actual bool
	field, ok := payload["strictScopes"]
	if !ok || json.Unmarshal(field, &actual) != nil || actual != want {
		t.Fatalf("persisted strictScopes: present=%v value=%v, want %v", ok, actual, want)
	}
	return user
}

func TestStrictScopesPersistenceAndUpdateGuards(t *testing.T) {
	tests := []struct {
		name       string
		initial    bool
		actorAdmin bool
		fields     []string
		want       bool
		wantError  bool
	}{
		{"administrator enables explicitly", false, true, []string{"StrictScopes"}, true, false},
		{"administrator disables explicitly", true, true, []string{"strictScopes"}, false, false},
		{"administrator all preserves guard", true, true, []string{"all"}, true, false},
		{"administrator omitted which preserves guard", true, true, nil, true, false},
		{"administrator profile update preserves guard", true, true, []string{"Locale"}, true, false},
		{"ordinary user explicit guard rejected", true, false, []string{"StrictScopes"}, true, true},
		{"ordinary user mixed update preserves guard", true, false, []string{"StrictScopes", "Locale"}, true, false},
		{"ordinary user all preserves guard", true, false, []string{"all"}, true, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, err := storm.Open(filepath.Join(t.TempDir(), "strict-scopes.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			backend := NewUsersBackend(db)
			initial := `{"username":"synthetic-scoped-user","loginMethod":"proxy","password":"synthetic-existing-password-hash","strictScopes":false,"tokens":{"synthetic":{"token":"synthetic-existing-token"}}}`
			if test.initial {
				initial = `{"username":"synthetic-scoped-user","loginMethod":"proxy","password":"synthetic-existing-password-hash","strictScopes":true,"tokens":{"synthetic":{"token":"synthetic-existing-token"}}}`
			}
			user := strictScopesJSONUser(t, initial)
			if err = backend.Save(user, false, false); err != nil {
				t.Fatal(err)
			}
			before := assertStoredStrictScopes(t, backend, user.ID, test.initial)
			requested := !test.initial
			update := strictScopesJSONUser(t, `{"strictScopes":false,"locale":"fr"}`)
			if requested {
				update = strictScopesJSONUser(t, `{"strictScopes":true,"locale":"fr"}`)
			}
			update.ID = user.ID
			update.Username = user.Username
			err = backend.Update(update, test.actorAdmin, test.fields...)
			if (err != nil) != test.wantError {
				t.Fatalf("update error: got %v, want error=%v", err, test.wantError)
			}
			after := assertStoredStrictScopes(t, backend, user.ID, test.want)
			if after.Password != before.Password || !reflect.DeepEqual(after.Tokens, before.Tokens) {
				t.Fatal("scope guard update changed the existing password or tokens")
			}
		})
	}
}

func TestStrictScopesCanBeCorrectedWithExplicitScopes(t *testing.T) {
	previous := settings.Config
	t.Cleanup(func() {
		settings.Config = previous
		settings.InitializeUserResolvers()
	})
	root := t.TempDir()
	source := &settings.Source{Name: "strict-allowed", Path: root, Config: settings.SourceConfig{DefaultUserScope: "/"}}
	settings.Config.Server.Sources = []*settings.Source{source}
	settings.Config.Server.SourceMap = map[string]*settings.Source{root: source}
	settings.Config.Server.NameToSource = map[string]*settings.Source{source.Name: source}
	settings.InitializeUserResolvers()
	db, err := storm.Open(filepath.Join(t.TempDir(), "strict-scopes-correction.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	backend := NewUsersBackend(db)
	user := strictScopesJSONUser(t, `{"username":"synthetic-correction-user","loginMethod":"proxy","strictScopes":false,"password":"synthetic-existing-password-hash","tokens":{"synthetic":{"token":"synthetic-existing-token"}}}`)
	if err = backend.Save(user, false, false); err != nil {
		t.Fatal(err)
	}
	before, err := backend.GetBy(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	update := strictScopesJSONUser(t, `{"strictScopes":true,"scopes":[{"name":"strict-allowed","scope":"/"}]}`)
	update.ID, update.Username = user.ID, user.Username
	if err := backend.Update(update, true, "StrictScopes", "Scopes"); err != nil {
		t.Fatalf("correct source allowlist and guard together: %v", err)
	}
	after := assertStoredStrictScopes(t, backend, user.ID, true)
	if len(after.Scopes) != 1 || after.Scopes[0].Name != root || after.Scopes[0].Scope != "/" {
		t.Fatal("explicit source correction was not persisted canonically")
	}
	if after.Password != before.Password || !reflect.DeepEqual(after.Tokens, before.Tokens) {
		t.Fatal("explicit scope correction changed the existing password or tokens")
	}
}
