package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/storage/bolt"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func TestMigrateUserV4HashesLegacyTokens(t *testing.T) {
	tokenPermissions := users.Permissions{Api: true, Browse: true}
	keyPermissions := users.Permissions{Api: true, Download: true}
	alreadyHashed := users.AuthToken{
		TokenHash:   utils.HashSHA256("already-hashed-secret"),
		TokenPrefix: "already-",
		IssuedAt:    500,
		ExpiresAt:   600,
		Permissions: users.Permissions{Api: true, Preview: true},
	}
	u := &users.User{
		Version: 4,
		Tokens: map[string]users.AuthToken{
			"token-field": {
				Token:              "legacy-token-secret",
				Name:               "legacy-token-name",
				BelongsTo:          42,
				IssuedAt:           100,
				ExpiresAt:          200,
				PermissionsVersion: users.CurrentPermissionsVersion,
				Permissions:        tokenPermissions,
			},
		},
		ApiKeys: map[string]users.AuthToken{
			"key-field": {
				Key:         "legacy-key-secret",
				IssuedAt:    300,
				ExpiresAt:   400,
				Permissions: keyPermissions,
			},
			"already-hashed": alreadyHashed,
		},
	}

	if !migrateUser(u) {
		t.Fatal("migrateUser returned false for a V4 user with legacy tokens")
	}
	if u.Version != 5 {
		t.Fatalf("Version = %d, want 5", u.Version)
	}
	assertMigratedTokenHashOnly(t, u.Tokens["token-field"], "legacy-token-secret", 100, 200, tokenPermissions)
	assertMigratedTokenHashOnly(t, u.ApiKeys["key-field"], "legacy-key-secret", 300, 400, keyPermissions)
	if got := u.ApiKeys["already-hashed"]; !reflect.DeepEqual(got, alreadyHashed) {
		t.Fatalf("already hash-only token changed: got %#v want %#v", got, alreadyHashed)
	}

	afterFirst := migrationTestUserJSON(t, u)
	if migrateUser(u) {
		t.Fatal("second migrateUser call returned true")
	}
	if afterSecond := migrationTestUserJSON(t, u); afterSecond != afterFirst {
		t.Fatalf("second migration changed the user:\nfirst:  %s\nsecond: %s", afterFirst, afterSecond)
	}
}

func assertMigratedTokenHashOnly(t *testing.T, got users.AuthToken, secret string, issuedAt, expiresAt int64, permissions users.Permissions) {
	t.Helper()
	wantPrefix := secret
	if len(wantPrefix) > 8 {
		wantPrefix = wantPrefix[:8]
	}
	if got.TokenHash != utils.HashSHA256(secret) || got.TokenPrefix != wantPrefix {
		t.Errorf("migrated token identity: hash=%q prefix=%q", got.TokenHash, got.TokenPrefix)
	}
	if got.Token != "" || got.Key != "" {
		t.Errorf("migrated token retained plaintext: Token=%q Key=%q", got.Token, got.Key)
	}
	if got.IssuedAt != issuedAt || got.ExpiresAt != expiresAt || got.Permissions != permissions {
		t.Errorf("migrated token metadata = %+v", got)
	}
	if got.Name != "" || got.BelongsTo != 0 || got.PermissionsVersion != 0 {
		t.Errorf("migrated token retained non-hash metadata: %+v", got)
	}
}

func TestCurrentUserMigrationVersionIsFive(t *testing.T) {
	if got := users.CurrentUserMigrationVersion; got != 5 {
		t.Fatalf("CurrentUserMigrationVersion = %d, want 5", got)
	}
}

func TestMigrateUserUpgradesEveryLegacyVersionToV5(t *testing.T) {
	for version := 0; version < 5; version++ {
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
				if u.Version != 5 {
					t.Fatalf("Version = %d, want 5", u.Version)
				}
				wantLegacyReadDefaults := version < 4
				if u.Permissions.Browse != wantLegacyReadDefaults || u.Permissions.Preview != wantLegacyReadDefaults {
					t.Fatalf("read permissions = {Browse:%t Preview:%t}, want both %t for v%d user", u.Permissions.Browse, u.Permissions.Preview, wantLegacyReadDefaults, version)
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
					if len(u.ApiKeys) != 1 {
						t.Fatalf("ApiKeys length = %d, want 1", len(u.ApiKeys))
					}
					assertMigratedTokenHashOnly(t, u.ApiKeys["legacy"], legacyAPIKey.Key, 100, 200, legacySnapshot)
					if len(u.Tokens) != 2 {
						t.Fatalf("Tokens length = %d, want 2 after ApiKeys merge", len(u.Tokens))
					}
					assertMigratedTokenHashOnly(t, u.Tokens["existing"], existingToken.Token, 300, 400, existingSnapshot)
					migratedToken, ok := u.Tokens["legacy"]
					if !ok {
						t.Fatal("legacy ApiKey was not merged into Tokens")
					}
					assertMigratedTokenHashOnly(t, migratedToken, legacyAPIKey.Key, 100, 200, legacySnapshot)
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
	if len(u.ApiKeys) != 2 {
		t.Fatalf("ApiKeys length = %d, want 2", len(u.ApiKeys))
	}
	assertMigratedTokenHashOnly(t, u.ApiKeys["legacy-only"], legacyOnly.Key, 10, 20, legacySnapshot)
	assertMigratedTokenHashOnly(t, u.ApiKeys["collision"], legacyCollision.Key, 0, 0, legacySnapshot)
	if len(u.Tokens) != 2 {
		t.Fatalf("Tokens length = %d, want 2", len(u.Tokens))
	}
	assertMigratedTokenHashOnly(t, u.Tokens["collision"], existingCollision.Token, 30, 40, existingSnapshot)
	migrated := u.Tokens["legacy-only"]
	assertMigratedTokenHashOnly(t, migrated, legacyOnly.Key, 10, 20, legacyOnly.Permissions)
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
		Version: 5,
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

func TestValidateUserInfoPersistsV5TokenMigration(t *testing.T) {
	const (
		tokenSecret = "legacy-token-secret-for-validation"
		keySecret   = "legacy-key-secret-for-validation"
	)
	backend := newMigrationUserBackend(migrationValidationUser(1, "legacy-user", tokenSecret, keySecret))
	useMigrationUserBackend(t, backend)

	if err := validateUserInfo(false); err != nil {
		t.Fatalf("validateUserInfo returned an error: %v", err)
	}

	persisted := backend.persistedUser(1)
	if persisted.Version != users.CurrentUserMigrationVersion {
		t.Fatalf("Version = %d, want %d", persisted.Version, users.CurrentUserMigrationVersion)
	}
	assertMigratedTokenHashOnly(t, persisted.Tokens["legacy-token"], tokenSecret, 100, 200, users.Permissions{Api: true, Download: true})
	assertMigratedTokenHashOnly(t, persisted.ApiKeys["legacy-key"], keySecret, 300, 400, users.Permissions{Api: true, Preview: true})
	if got := backend.updateCalls[1]; got != 1 {
		t.Fatalf("user update calls = %d, want 1", got)
	}
}

func TestValidateUserInfoReturnsMigrationPersistenceError(t *testing.T) {
	const (
		tokenSecret = "token-secret-must-not-leak"
		keySecret   = "key-secret-must-not-leak"
	)
	persistErr := errors.New("forced user update failure")
	backend := newMigrationUserBackend(migrationValidationUser(1, "failing-user", tokenSecret, keySecret))
	backend.updateErrors[1] = persistErr
	useMigrationUserBackend(t, backend)

	err := validateUserInfo(false)
	if err == nil {
		t.Fatal("validateUserInfo returned nil for a failed mandatory migration update")
	}
	if !errors.Is(err, persistErr) {
		t.Fatalf("validateUserInfo error = %v, want wrapped persistence error", err)
	}
	if !strings.Contains(err.Error(), "failing-user") {
		t.Fatalf("validateUserInfo error does not identify the affected user: %v", err)
	}
	for _, secret := range []string{tokenSecret, keySecret} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("validateUserInfo error leaked a legacy secret")
		}
	}
	if got := backend.persistedUser(1).Version; got != 4 {
		t.Fatalf("failed update persisted Version = %d, want 4", got)
	}
}

func TestValidateUserInfoMigrationRetryIsIdempotent(t *testing.T) {
	first := migrationValidationUser(1, "first-user", "first-token-secret", "")
	second := migrationValidationUser(2, "second-user", "second-token-secret", "second-key-secret")
	persistErr := errors.New("forced second user update failure")
	backend := newMigrationUserBackend(first, second)
	backend.updateErrors[2] = persistErr
	useMigrationUserBackend(t, backend)

	if err := validateUserInfo(false); !errors.Is(err, persistErr) {
		t.Fatalf("first validateUserInfo error = %v, want persistence error", err)
	}
	if got := backend.persistedUser(1).Version; got != users.CurrentUserMigrationVersion {
		t.Fatalf("first user Version = %d, want %d", got, users.CurrentUserMigrationVersion)
	}
	if got := backend.persistedUser(2).Version; got != 4 {
		t.Fatalf("second user Version = %d after failed update, want 4", got)
	}

	if err := validateUserInfo(false); !errors.Is(err, persistErr) {
		t.Fatalf("retry validateUserInfo error = %v, want persistence error", err)
	}
	if got := backend.updateCalls[1]; got != 1 {
		t.Fatalf("already migrated first user update calls = %d, want 1", got)
	}

	delete(backend.updateErrors, 2)
	if err := validateUserInfo(false); err != nil {
		t.Fatalf("validateUserInfo after repairing storage returned an error: %v", err)
	}
	if got := backend.updateCalls[1]; got != 1 {
		t.Fatalf("first user was rewritten after retry: update calls = %d, want 1", got)
	}
	persistedSecond := backend.persistedUser(2)
	if persistedSecond.Version != users.CurrentUserMigrationVersion {
		t.Fatalf("second user Version = %d, want %d", persistedSecond.Version, users.CurrentUserMigrationVersion)
	}
	assertMigratedTokenHashOnly(t, persistedSecond.Tokens["legacy-token"], "second-token-secret", 100, 200, users.Permissions{Api: true, Download: true})
	assertMigratedTokenHashOnly(t, persistedSecond.ApiKeys["legacy-key"], "second-key-secret", 300, 400, users.Permissions{Api: true, Preview: true})
}

func TestValidateUserInfoDoesNotRewriteV5User(t *testing.T) {
	current := migrationValidationUser(1, "current-user", "", "")
	current.Version = users.CurrentUserMigrationVersion
	backend := newMigrationUserBackend(current)
	useMigrationUserBackend(t, backend)

	if err := validateUserInfo(false); err != nil {
		t.Fatalf("validateUserInfo returned an error: %v", err)
	}
	if got := backend.updateCalls[1]; got != 0 {
		t.Fatalf("current user update calls = %d, want 0", got)
	}
}

func TestValidateUserInfoReturnsUserLoadError(t *testing.T) {
	loadErr := errors.New("forced user load failure")
	backend := newMigrationUserBackend()
	backend.getsErr = loadErr
	useMigrationUserBackend(t, backend)

	err := validateUserInfo(false)
	if !errors.Is(err, loadErr) {
		t.Fatalf("validateUserInfo error = %v, want wrapped load error", err)
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

type migrationUserBackend struct {
	usersByID    map[uint]*users.User
	order        []uint
	updateErrors map[uint]error
	updateCalls  map[uint]int
	getsErr      error
}

func newMigrationUserBackend(initial ...*users.User) *migrationUserBackend {
	backend := &migrationUserBackend{
		usersByID:    make(map[uint]*users.User, len(initial)),
		updateErrors: make(map[uint]error),
		updateCalls:  make(map[uint]int),
	}
	for _, user := range initial {
		backend.order = append(backend.order, user.ID)
		backend.usersByID[user.ID] = cloneMigrationUser(user)
	}
	return backend
}

func (b *migrationUserBackend) GetBy(id interface{}) (*users.User, error) {
	switch value := id.(type) {
	case uint:
		if user, ok := b.usersByID[value]; ok {
			return cloneMigrationUser(user), nil
		}
	case string:
		for _, user := range b.usersByID {
			if user.Username == value {
				return cloneMigrationUser(user), nil
			}
		}
	}
	return nil, fmt.Errorf("migration test user not found")
}

func (b *migrationUserBackend) Gets() ([]*users.User, error) {
	if b.getsErr != nil {
		return nil, b.getsErr
	}
	result := make([]*users.User, 0, len(b.order))
	for _, id := range b.order {
		result = append(result, cloneMigrationUser(b.usersByID[id]))
	}
	return result, nil
}

func (b *migrationUserBackend) Save(user *users.User, _ bool, _ bool) error {
	b.usersByID[user.ID] = cloneMigrationUser(user)
	return nil
}

func (b *migrationUserBackend) Update(user *users.User, _ bool, _ ...string) error {
	b.updateCalls[user.ID]++
	if err := b.updateErrors[user.ID]; err != nil {
		return err
	}
	b.usersByID[user.ID] = cloneMigrationUser(user)
	return nil
}

func (b *migrationUserBackend) DeleteByID(id uint) error {
	delete(b.usersByID, id)
	return nil
}

func (b *migrationUserBackend) DeleteByUsername(username string) error {
	for id, user := range b.usersByID {
		if user.Username == username {
			delete(b.usersByID, id)
			return nil
		}
	}
	return nil
}

func (b *migrationUserBackend) persistedUser(id uint) *users.User {
	return cloneMigrationUser(b.usersByID[id])
}

func migrationValidationUser(id uint, username, tokenSecret, keySecret string) *users.User {
	user := &users.User{
		ID:          id,
		Username:    username,
		Version:     4,
		LoginMethod: users.LoginMethodPassword,
		Permissions: users.Permissions{Api: true},
		Tokens:      make(map[string]users.AuthToken),
		ApiKeys:     make(map[string]users.AuthToken),
		Scopes:      []users.SourceScope{},
	}
	if tokenSecret != "" {
		user.Tokens["legacy-token"] = users.AuthToken{
			Token:       tokenSecret,
			IssuedAt:    100,
			ExpiresAt:   200,
			Permissions: users.Permissions{Api: true, Download: true},
		}
	}
	if keySecret != "" {
		user.ApiKeys["legacy-key"] = users.AuthToken{
			Key:         keySecret,
			IssuedAt:    300,
			ExpiresAt:   400,
			Permissions: users.Permissions{Api: true, Preview: true},
		}
	}
	return user
}

func cloneMigrationUser(user *users.User) *users.User {
	if user == nil {
		return nil
	}
	cloned := *user
	cloned.Tokens = make(map[string]users.AuthToken, len(user.Tokens))
	for name, token := range user.Tokens {
		cloned.Tokens[name] = token
	}
	cloned.ApiKeys = make(map[string]users.AuthToken, len(user.ApiKeys))
	for name, token := range user.ApiKeys {
		cloned.ApiKeys[name] = token
	}
	if user.Scopes != nil {
		cloned.Scopes = append(make([]users.SourceScope, 0, len(user.Scopes)), user.Scopes...)
	}
	if user.SidebarLinks != nil {
		cloned.SidebarLinks = append(make([]users.SidebarLink, 0, len(user.SidebarLinks)), user.SidebarLinks...)
	}
	return &cloned
}

func useMigrationUserBackend(t *testing.T, backend *migrationUserBackend) {
	t.Helper()
	previousStore := store
	previousConfig := settings.Config
	previousCreateBackup := createBackup
	t.Setenv("FILEBROWSER_DISABLE_AUTOMATIC_BACKUP", "true")
	settings.Config = settings.Settings{}
	settings.InitializeUserResolvers()
	createBackup = false
	store = &bolt.BoltStore{Users: users.NewStorage(backend)}
	t.Cleanup(func() {
		store = previousStore
		settings.Config = previousConfig
		settings.InitializeUserResolvers()
		createBackup = previousCreateBackup
	})
}
