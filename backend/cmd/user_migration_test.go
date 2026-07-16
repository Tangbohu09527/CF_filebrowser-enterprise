package cmd

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func TestCurrentUserMigrationVersionIsFour(t *testing.T) {
	if got := users.CurrentUserMigrationVersion; got != 4 {
		t.Fatalf("CurrentUserMigrationVersion = %d, want 4", got)
	}
}

func TestMigrateUserUpgradesEveryLegacyVersionToV4(t *testing.T) {
	for version := 0; version < 4; version++ {
		for _, download := range []bool{false, true} {
			t.Run(fmt.Sprintf("v%d_download_%t", version, download), func(t *testing.T) {
				permissions := users.Permissions{Share: true}
				legacyPermissions := users.Permissions{}
				if version == 0 {
					legacyPermissions.Api = true
					legacyPermissions.Download = download
				} else {
					permissions.Download = download
				}

				u := &users.User{
					Version:     version,
					Permissions: permissions,
					Perm:        legacyPermissions,
				}

				legacySnapshot := users.Permissions{
					Api:      true,
					Modify:   true,
					Delete:   true,
					Download: false,
				}
				existingSnapshot := users.Permissions{
					Admin:    true,
					Share:    true,
					Realtime: true,
					Create:   true,
					Download: true,
				}
				legacyAPIKey := users.AuthToken{
					Key:         "legacy-secret",
					Name:        "legacy",
					BelongsTo:   42,
					IssuedAt:    100,
					ExpiresAt:   200,
					Permissions: legacySnapshot,
				}
				existingToken := users.AuthToken{
					Token:       "existing-secret",
					Name:        "existing",
					BelongsTo:   42,
					IssuedAt:    300,
					ExpiresAt:   400,
					Permissions: existingSnapshot,
				}
				if version <= 1 {
					u.ApiKeys = map[string]users.AuthToken{"legacy": legacyAPIKey}
					u.Tokens = map[string]users.AuthToken{"existing": existingToken}
				}

				if !migrateUser(u) {
					t.Fatal("migrateUser returned false for a legacy user")
				}
				if u.Version != 4 {
					t.Fatalf("Version = %d, want 4", u.Version)
				}
				if !u.Permissions.Browse || !u.Permissions.Preview {
					t.Fatalf("legacy read permissions = {Browse:%t Preview:%t}, want both true", u.Permissions.Browse, u.Permissions.Preview)
				}
				if u.Permissions.Download != download {
					t.Fatalf("Download = %t, want legacy value %t", u.Permissions.Download, download)
				}
				if !u.Permissions.Share {
					t.Fatal("pre-existing Permissions.Share was lost")
				}
				if version == 0 && !u.Permissions.Api {
					t.Fatal("v0 Perm.Api was not migrated")
				}
				if got, want := u.ShowToolsInSidebar, version <= 2; got != want {
					t.Fatalf("ShowToolsInSidebar = %t, want %t for v%d user", got, want, version)
				}

				if version <= 1 {
					if len(u.ApiKeys) != 1 || !reflect.DeepEqual(u.ApiKeys["legacy"], legacyAPIKey) {
						t.Fatalf("ApiKeys changed during migration: %#v", u.ApiKeys)
					}
					if len(u.Tokens) != 2 {
						t.Fatalf("Tokens length = %d, want 2 after ApiKeys merge", len(u.Tokens))
					}
					if got := u.Tokens["existing"]; !reflect.DeepEqual(got, existingToken) {
						t.Fatalf("existing Token changed: got %#v want %#v", got, existingToken)
					}
					migratedToken, ok := u.Tokens["legacy"]
					if !ok {
						t.Fatal("legacy ApiKey was not merged into Tokens")
					}
					if migratedToken.Token != legacyAPIKey.Key {
						t.Fatalf("migrated Token = %q, want legacy Key %q", migratedToken.Token, legacyAPIKey.Key)
					}
					if !reflect.DeepEqual(migratedToken.Permissions, legacySnapshot) {
						t.Fatalf("migrated permission snapshot changed: got %#v want %#v", migratedToken.Permissions, legacySnapshot)
					}
				}
			})
		}
	}
}

func TestMigrateUserV0MergesEveryLegacyPermission(t *testing.T) {
	tests := []struct {
		name string
		set  func(*users.Permissions)
		has  func(users.Permissions) bool
	}{
		{name: "api", set: func(p *users.Permissions) { p.Api = true }, has: func(p users.Permissions) bool { return p.Api }},
		{name: "admin", set: func(p *users.Permissions) { p.Admin = true }, has: func(p users.Permissions) bool { return p.Admin }},
		{name: "modify", set: func(p *users.Permissions) { p.Modify = true }, has: func(p users.Permissions) bool { return p.Modify }},
		{name: "share", set: func(p *users.Permissions) { p.Share = true }, has: func(p users.Permissions) bool { return p.Share }},
		{name: "realtime", set: func(p *users.Permissions) { p.Realtime = true }, has: func(p users.Permissions) bool { return p.Realtime }},
		{name: "delete", set: func(p *users.Permissions) { p.Delete = true }, has: func(p users.Permissions) bool { return p.Delete }},
		{name: "create", set: func(p *users.Permissions) { p.Create = true }, has: func(p users.Permissions) bool { return p.Create }},
		{name: "download", set: func(p *users.Permissions) { p.Download = true }, has: func(p users.Permissions) bool { return p.Download }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			legacy := users.Permissions{}
			tc.set(&legacy)
			u := &users.User{
				Version:     0,
				Perm:        legacy,
				Permissions: users.Permissions{Share: true},
			}

			if !migrateUser(u) {
				t.Fatal("migrateUser returned false for a v0 user")
			}
			if !tc.has(u.Permissions) {
				t.Fatalf("legacy Perm.%s was not merged into Permissions", tc.name)
			}
			if !u.Permissions.Share {
				t.Fatal("an existing permission was lost while merging Perm")
			}
		})
	}
}

func TestMigrateUserMergesApiKeysWithoutReplacingTokens(t *testing.T) {
	legacySnapshot := users.Permissions{Api: true, Delete: true, Download: false}
	existingSnapshot := users.Permissions{Admin: true, Share: true, Download: true}
	legacyOnly := users.AuthToken{
		Key:         "legacy-only-secret",
		Name:        "legacy-only",
		BelongsTo:   7,
		IssuedAt:    10,
		ExpiresAt:   20,
		Permissions: legacySnapshot,
	}
	legacyCollision := users.AuthToken{
		Key:         "legacy-collision-secret",
		Name:        "collision",
		Permissions: legacySnapshot,
	}
	existingCollision := users.AuthToken{
		Token:       "current-collision-secret",
		Name:        "collision",
		BelongsTo:   7,
		IssuedAt:    30,
		ExpiresAt:   40,
		Permissions: existingSnapshot,
	}
	u := &users.User{
		Version: 1,
		ApiKeys: map[string]users.AuthToken{
			"legacy-only": legacyOnly,
			"collision":   legacyCollision,
		},
		Tokens: map[string]users.AuthToken{
			"collision": existingCollision,
		},
	}

	if !migrateUser(u) {
		t.Fatal("migrateUser returned false for a v1 user")
	}
	if len(u.ApiKeys) != 2 || !reflect.DeepEqual(u.ApiKeys["legacy-only"], legacyOnly) || !reflect.DeepEqual(u.ApiKeys["collision"], legacyCollision) {
		t.Fatalf("ApiKeys changed during migration: %#v", u.ApiKeys)
	}
	if len(u.Tokens) != 2 {
		t.Fatalf("Tokens length = %d, want 2", len(u.Tokens))
	}
	if got := u.Tokens["collision"]; !reflect.DeepEqual(got, existingCollision) {
		t.Fatalf("existing Token was replaced by an ApiKey: got %#v want %#v", got, existingCollision)
	}
	migrated := u.Tokens["legacy-only"]
	if migrated.Token != legacyOnly.Key {
		t.Fatalf("migrated Token = %q, want %q", migrated.Token, legacyOnly.Key)
	}
	if !reflect.DeepEqual(migrated.Permissions, legacyOnly.Permissions) {
		t.Fatalf("migrated permission snapshot changed: got %#v want %#v", migrated.Permissions, legacyOnly.Permissions)
	}
}

func TestMigrateUserIsIdempotent(t *testing.T) {
	u := &users.User{
		Version: 0,
		Perm: users.Permissions{
			Realtime: true,
			Delete:   true,
		},
		ApiKeys: map[string]users.AuthToken{
			"legacy": {
				Key:         "legacy-secret",
				Permissions: users.Permissions{Api: true, Download: false},
			},
		},
		Tokens: map[string]users.AuthToken{
			"existing": {
				Token:       "existing-secret",
				Permissions: users.Permissions{Share: true, Download: true},
			},
		},
	}

	if !migrateUser(u) {
		t.Fatal("first migrateUser call returned false")
	}
	afterFirst := migrationTestUserJSON(t, u)
	if migrateUser(u) {
		t.Fatal("second migrateUser call returned true")
	}
	afterSecond := migrationTestUserJSON(t, u)
	if afterSecond != afterFirst {
		t.Fatalf("second migration changed the user:\nfirst:  %s\nsecond: %s", afterFirst, afterSecond)
	}

	current := &users.User{
		Version: 4,
		Permissions: users.Permissions{
			Browse:   false,
			Preview:  false,
			Download: false,
		},
	}
	before := migrationTestUserJSON(t, current)
	if migrateUser(current) {
		t.Fatal("migrateUser returned true for a current user")
	}
	if after := migrationTestUserJSON(t, current); after != before {
		t.Fatalf("current user's explicit permission revocations changed:\nbefore: %s\nafter:  %s", before, after)
	}
}

func migrationTestUserJSON(t *testing.T, u *users.User) string {
	t.Helper()
	b, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("marshal user: %v", err)
	}
	return string(b)
}
