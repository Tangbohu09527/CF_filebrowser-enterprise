package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

// JSON construction intentionally keeps these regressions compilable before
// the persisted User.StrictScopes field is introduced.
func saveStrictScopesContractUser(t *testing.T, username string, strict bool) *users.User {
	t.Helper()
	payload := map[string]any{
		"username": username, "loginMethod": "proxy", "strictScopes": strict,
		"password": "synthetic-existing-password-hash",
		"tokens":   map[string]any{"synthetic": map[string]string{"token": "synthetic-existing-token"}},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var user users.User
	if err := json.Unmarshal(data, &user); err != nil {
		t.Fatal(err)
	}
	if err := store.Users.Save(&user, false, false); err != nil {
		t.Fatalf("save synthetic scope contract user: %v", err)
	}
	return &user
}

func assertStrictScopesContractUser(t *testing.T, id uint, want bool) *users.User {
	t.Helper()
	user, err := store.Users.Get(id)
	if err != nil {
		t.Fatal(err)
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

func TestUserPutStrictScopesContract(t *testing.T) {
	setupPermissionContractHTTPTest(t)
	settings.InitializeUserResolvers()
	tests := []struct {
		name       string
		initial    bool
		admin      bool
		body       string
		status     int
		wantStrict bool
	}{
		{"administrator explicitly enables", false, true, `{"which":["StrictScopes"],"data":{"strictScopes":true}}`, http.StatusNoContent, true},
		{"administrator explicitly disables", true, true, `{"which":["strictScopes"],"data":{"strictScopes":false}}`, http.StatusNoContent, false},
		{"explicit field omitted", true, true, `{"which":["StrictScopes"],"data":{}}`, http.StatusBadRequest, true},
		{"explicit field null", true, true, `{"which":["StrictScopes"],"data":{"strictScopes":null}}`, http.StatusBadRequest, true},
		{"legacy all omits guard", true, true, `{"which":["all"],"data":{"locale":"fr"}}`, http.StatusNoContent, true},
		{"legacy empty which omits guard", true, true, `{"data":{"locale":"fr"}}`, http.StatusNoContent, true},
		{"all cannot silently disable guard", true, true, `{"which":["all"],"data":{"strictScopes":false,"locale":"fr"}}`, http.StatusNoContent, true},
		{"profile update ignores unselected guard", true, true, `{"which":["Locale"],"data":{"strictScopes":false,"locale":"fr"}}`, http.StatusNoContent, true},
		{"ordinary user cannot disable guard", true, false, `{"which":["StrictScopes"],"data":{"strictScopes":false}}`, http.StatusBadRequest, true},
		{"ordinary mixed update cannot disable guard", true, false, `{"which":["StrictScopes","Locale"],"data":{"strictScopes":false,"locale":"fr"}}`, http.StatusNoContent, true},
		{"ordinary mixed update cannot enable guard", false, false, `{"which":["StrictScopes","Locale"],"data":{"strictScopes":true,"locale":"fr"}}`, http.StatusNoContent, false},
	}
	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			user := saveStrictScopesContractUser(t, "synthetic-scope-contract-"+strconv.Itoa(i), test.initial)
			before := assertStrictScopesContractUser(t, user.ID, test.initial)
			actor := &users.User{ID: user.ID, LoginMethod: users.LoginMethodProxy, Permissions: users.Permissions{Admin: test.admin}}
			request := httptest.NewRequest(http.MethodPut, "/api/users?id="+strconv.FormatUint(uint64(user.ID), 10), strings.NewReader(test.body))
			status, err := userPutHandler(httptest.NewRecorder(), request, &requestContext{user: actor})
			if status != test.status {
				t.Fatalf("update strict scopes status: got %d, want %d, error=%v", status, test.status, err)
			}
			after := assertStrictScopesContractUser(t, user.ID, test.wantStrict)
			if after.Password != before.Password || !reflect.DeepEqual(after.Tokens, before.Tokens) {
				t.Fatal("scope guard update changed the existing password or tokens")
			}
		})
	}
}

func TestUserPutStrictScopesCanCorrectAllowlist(t *testing.T) {
	setupPermissionContractHTTPTest(t)
	previous := settings.Config.Server
	t.Cleanup(func() {
		settings.Config.Server = previous
		settings.InitializeUserResolvers()
	})
	root := t.TempDir()
	source := &settings.Source{Name: "strict-allowed", Path: root, Config: settings.SourceConfig{DefaultUserScope: "/"}}
	settings.Config.Server.Sources = []*settings.Source{source}
	settings.Config.Server.SourceMap = map[string]*settings.Source{root: source}
	settings.Config.Server.NameToSource = map[string]*settings.Source{source.Name: source}
	settings.InitializeUserResolvers()
	user := saveStrictScopesContractUser(t, "synthetic-scope-correction", false)
	before := assertStrictScopesContractUser(t, user.ID, false)
	actor := &users.User{ID: 9999, LoginMethod: users.LoginMethodProxy, Permissions: users.Permissions{Admin: true}}
	request := httptest.NewRequest(http.MethodPut, "/api/users?id="+strconv.FormatUint(uint64(user.ID), 10), strings.NewReader(
		`{"which":["StrictScopes","Scopes"],"data":{"strictScopes":true,"scopes":[{"name":"strict-allowed","scope":"/"}]}}`,
	))
	status, err := userPutHandler(httptest.NewRecorder(), request, &requestContext{user: actor})
	if status != http.StatusNoContent || err != nil {
		t.Fatalf("correct allowlist and guard in one request: status=%d error=%v", status, err)
	}
	after := assertStrictScopesContractUser(t, user.ID, true)
	if len(after.Scopes) != 1 || after.Scopes[0].Name != root || after.Scopes[0].Scope != "/" {
		t.Fatal("explicit source correction was not persisted canonically")
	}
	if after.Password != before.Password || !reflect.DeepEqual(after.Tokens, before.Tokens) {
		t.Fatal("explicit source correction changed the existing password or tokens")
	}
}
