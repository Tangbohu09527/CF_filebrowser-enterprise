package settings

import (
	"encoding/json"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func TestStrictScopesUserDefaultsDoNotGrantDefaultSource(t *testing.T) {
	before := Config
	t.Cleanup(func() { Config = before })
	Config = SetDefaults(false)
	Config.Server.Sources = []*Source{{Name: "enterprise-source", Path: "/synthetic-enterprise", Config: SourceConfig{DefaultEnabled: true, DefaultUserScope: "/"}}}
	for _, input := range []string{
		`{"username":"synthetic-service","strictScopes":true,"scopes":[]}`,
		`{"username":"synthetic-service","strictScopes":true,"scopes":null}`,
	} {
		var user users.User
		if err := json.Unmarshal([]byte(input), &user); err != nil {
			t.Fatal("decode synthetic strict user")
		}
		ApplyUserDefaults(&user)
		if len(user.Scopes) != 0 {
			t.Fatal("empty strict allowlist acquired a default Source")
		}
		if len(user.SidebarLinks) != 0 {
			t.Fatal("empty strict allowlist acquired a default Source sidebar link")
		}
	}
	legacy := &users.User{Username: "synthetic-legacy"}
	ApplyUserDefaults(legacy)
	if len(legacy.Scopes) != 1 || legacy.Scopes[0].Name != "/synthetic-enterprise" {
		t.Fatal("legacy default Source behavior changed")
	}
}
