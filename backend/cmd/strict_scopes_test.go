package cmd

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func strictScopeSources(t *testing.T) (enterprise, originals *settings.Source) {
	t.Helper()
	previous := settings.Config
	t.Cleanup(func() {
		settings.Config = previous
		settings.InitializeUserResolvers()
	})
	enterprise = &settings.Source{Path: "/synthetic-enterprise", Name: "enterprise-source", Config: settings.SourceConfig{DefaultEnabled: true, DefaultUserScope: "/"}}
	originals = &settings.Source{Path: "/synthetic-originals", Name: "originals-source", Config: settings.SourceConfig{Private: true, DefaultEnabled: false, DefaultUserScope: "/"}}
	settings.Config.Server.Sources = []*settings.Source{enterprise, originals}
	settings.Config.Server.SourceMap = map[string]*settings.Source{enterprise.Path: enterprise, originals.Path: originals}
	settings.Config.Server.NameToSource = map[string]*settings.Source{enterprise.Name: enterprise, originals.Name: originals}
	settings.InitializeUserResolvers()
	return enterprise, originals
}

func TestStrictScopesStartupDoesNotAppendDefaultSources(t *testing.T) {
	enterprise, originals := strictScopeSources(t)
	for _, test := range []struct {
		name   string
		json   string
		strict bool
		want   []users.SourceScope
	}{
		{"strict explicit path", `{"strictScopes":true,"scopes":[{"name":"/synthetic-originals","scope":"/"}]}`, true, []users.SourceScope{{Name: originals.Path, Scope: "/"}}},
		{"strict explicit display name", `{"strictScopes":true,"scopes":[{"name":"originals-source","scope":"/"}]}`, true, []users.SourceScope{{Name: originals.Path, Scope: "/"}}},
		{"strict empty allowlist", `{"strictScopes":true,"scopes":[]}`, true, []users.SourceScope{}},
		{"legacy default behavior", `{"scopes":[{"name":"/synthetic-originals","scope":"/"}]}`, false, []users.SourceScope{{Name: enterprise.Path, Scope: "/"}, {Name: originals.Path, Scope: "/"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var user users.User
			if err := json.Unmarshal([]byte(test.json), &user); err != nil {
				t.Fatal("decode synthetic user")
			}
			updateUserScopes(&user)
			if !reflect.DeepEqual(user.Scopes, test.want) {
				t.Fatalf("startup changed explicit authorization: got %v, want %v", user.Scopes, test.want)
			}
			if updateUserScopes(&user) {
				t.Fatal("scope normalization was not idempotent")
			}
			if test.strict {
				if _, err := user.GetScopeForSourcePath(enterprise.Path); err == nil {
					t.Fatal("default Source became authorized")
				}
			}
		})
	}
}
