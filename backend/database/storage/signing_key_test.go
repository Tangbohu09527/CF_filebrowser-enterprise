package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	storm "github.com/asdine/storm/v3"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/storage/bolt"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/go-logger/logger"
	bbolt "go.etcd.io/bbolt"
)

// All credentials in these temporary databases are public synthetic test data.
const syntheticSigningKey = "public-synthetic-signing-key-not-a-real-secret"
const syntheticBootstrapPassword = "public-synthetic-bootstrap-password-not-real"
const syntheticDifferentKey = "public-synthetic-different-signing-key-not-real"

type signingFixture struct {
	WebToken   string
	APIToken   string
	UserDigest string
	DBDigest   string
}

func TestSigningKeyFreshInitialization(t *testing.T) {
	for _, key := range []string{"", syntheticSigningKey, "public-unicode-\ufffd-key-not-real"} {
		name := "generated"
		if key != "" {
			name = "explicit"
			if key != syntheticSigningKey {
				name = "explicit valid unicode"
			}
		}
		t.Run(name, func(t *testing.T) {
			runSigningHelper(t, t.TempDir(), "fresh", key, "")
		})
	}
}

func TestSigningKeyFreshNonPersistableInputFailsBeforeDatabaseCreation(t *testing.T) {
	runSigningHelper(t, t.TempDir(), "fresh-invalid", "", "")
}

func TestSigningKeyRestartKeepsOriginalCredentialsAndCurrentConfig(t *testing.T) {
	for _, configured := range []string{"", syntheticSigningKey} {
		t.Run(map[bool]string{true: "restored", false: "matching explicit"}[configured == ""], func(t *testing.T) {
			dir := t.TempDir()
			runSigningHelper(t, dir, "seed", syntheticSigningKey, "")
			runSigningHelper(t, dir, "restart", configured, "")
		})
	}
	generated := t.TempDir()
	runSigningHelper(t, generated, "fresh", "", "")
	runSigningHelper(t, generated, "restart", "", "")
}

func TestSigningKeyStartupRejectsConflictOrMissingRecoveryWithoutWrites(t *testing.T) {
	for _, test := range []struct{ name, stored, configured string }{
		{"conflicting explicit key", "present", syntheticDifferentKey},
		{"missing persisted key", "empty", ""},
		{"missing settings record", "absent", ""},
		{"invalid settings record", "corrupt", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			runSigningHelper(t, dir, "seed", syntheticSigningKey, test.stored)
			runSigningHelper(t, dir, "reject", test.configured, "")
		})
	}
}

func TestSigningKeyExplicitRecoveryDoesNotRewriteEmptyStoredKey(t *testing.T) {
	dir := t.TempDir()
	runSigningHelper(t, dir, "seed", syntheticSigningKey, "empty")
	runSigningHelper(t, dir, "restart", syntheticSigningKey, "empty")
	db, err := storm.Open(filepath.Join(dir, "synthetic.db"))
	if err != nil {
		t.Fatal("open synthetic recovery snapshot")
	}
	fixturePath := filepath.Join(dir, "synthetic-fixture.json")
	fixture := readSigningFixture(t, fixturePath)
	fixture.DBDigest = digestDatabase(t, db)
	data, err := json.Marshal(fixture)
	if err != nil || os.WriteFile(fixturePath, data, 0600) != nil {
		t.Fatal("save synthetic recovery snapshot")
	}
	if err := db.Close(); err != nil {
		t.Fatal("close synthetic recovery snapshot")
	}
	// Removing the explicit recovery configuration must not silently invent a key.
	runSigningHelper(t, dir, "reject", "", "")
}

func TestSigningKeyLegacyLossyJSONCannotRecoverOriginalTokens(t *testing.T) {
	dir := t.TempDir()
	runSigningHelper(t, dir, "seed", "", "legacy-binary")
	runSigningHelper(t, dir, "legacy-restart", "", "")
}

func runSigningHelper(t *testing.T, dir, phase, key, variant string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSigningKeyBootstrapProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(), "CF_KEY_RECOVERY_TEST_DIR="+dir,
		"CF_KEY_RECOVERY_TEST_PHASE="+phase, "CF_KEY_RECOVERY_TEST_KEY="+key,
		"CF_KEY_RECOVERY_TEST_VARIANT="+variant)
	output, err := cmd.CombinedOutput()
	for _, secret := range []string{syntheticSigningKey, syntheticBootstrapPassword, syntheticDifferentKey, "public-unicode-\ufffd-key-not-real"} {
		if strings.Contains(string(output), secret) {
			t.Error("bootstrap output exposed a public synthetic secret marker")
		}
	}
	if err != nil {
		// Child diagnostics can contain a pre-fix password log; never echo them.
		t.Fatalf("bootstrap %s helper failed; sensitive child output suppressed", phase)
	}
	if phase == "fresh" {
		db, openErr := storm.Open(filepath.Join(dir, "synthetic.db"))
		if openErr != nil {
			t.Fatal("open generated-key output audit")
		}
		var persisted settings.Settings
		readErr := db.Get("config", "settings", &persisted)
		closeErr := db.Close()
		if readErr != nil || closeErr != nil || persisted.Auth.Key == "" {
			t.Fatal("read generated-key output audit")
		}
		if strings.Contains(string(output), persisted.Auth.Key) {
			t.Error("bootstrap output exposed its generated or configured synthetic key")
		}
	}
}

// TestSigningKeyBootstrapProcess runs in a separate test process so a genuine
// DB close/reopen is exercised without adding a production storage-close API.
func TestSigningKeyBootstrapProcess(t *testing.T) {
	dir := os.Getenv("CF_KEY_RECOVERY_TEST_DIR")
	if dir == "" {
		return
	}
	phase := os.Getenv("CF_KEY_RECOVERY_TEST_PHASE")
	variant := os.Getenv("CF_KEY_RECOVERY_TEST_VARIANT")
	settings.Config = settings.SetDefaults(false)
	settings.Config.Auth.Key = os.Getenv("CF_KEY_RECOVERY_TEST_KEY")
	settings.Config.Auth.AdminUsername = "synthetic-bootstrap-admin"
	settings.Config.Auth.AdminPassword = syntheticBootstrapPassword
	settings.Config.Auth.Methods.PasswordAuth.Enabled = phase == "fresh"
	settings.Config.Auth.Methods.NoAuth = false
	settings.Config.Server.Port = 18091
	settings.Config.Server.Sources = []*settings.Source{{Name: "synthetic-current-source", Path: filepath.Join(dir, "source"), Config: settings.SourceConfig{UseLogicalSize: true}}}
	if phase == "seed" {
		settings.Config.Server.Port = 8123
		settings.Config.Server.Sources[0].Name = "synthetic-old-source"
		settings.Config.Server.Sources[0].Config.UseLogicalSize = false
	}
	settings.InitializeUserResolvers()
	utils.BcryptCost = 4 // Only this subprocess and its disposable synthetic users.
	if err := logger.EnableCompatibilityMode(logger.JsonConfig{Levels: "debug|info|warning|error", Output: "stdout", NoColors: true}); err != nil {
		t.Fatal("configure synthetic debug logging")
	}
	path := filepath.Join(dir, "synthetic.db")
	fixturePath := filepath.Join(dir, "synthetic-fixture.json")
	if phase == "fresh-invalid" {
		settings.Config.Auth.Key = "public-invalid-text-" + string([]byte{0xff, 0xfe})
		store, exists, err := InitializeDb(path)
		if err == nil || store != nil || exists {
			t.Fatal("fresh non-persistable signing input was accepted")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("rejected fresh signing input created a partial database")
		}
		return
	}
	if phase == "seed" {
		seedSigningFixture(t, path, fixturePath, variant)
		return
	}
	before := settings.Config
	store, exists, err := InitializeDb(path)
	if phase == "reject" {
		if err == nil || store != nil || !exists {
			t.Fatal("unrecoverable or conflicting signing key was accepted")
		}
		for _, marker := range []string{syntheticSigningKey, syntheticDifferentKey} {
			if strings.Contains(err.Error(), marker) {
				t.Fatal("startup error exposed a synthetic key")
			}
		}
		probe, openErr := storm.Open(path, storm.BoltOptions(0600, &bbolt.Options{Timeout: time.Second}))
		if openErr != nil {
			t.Fatal("failed startup retained the database lock")
		}
		defer probe.Close()
		fixture := readSigningFixture(t, fixturePath)
		if digestDatabase(t, probe) != fixture.DBDigest {
			t.Fatal("rejected startup changed stored configuration or credentials")
		}
		return
	}
	if err != nil || store == nil {
		t.Fatal("initialize synthetic database")
	}
	stored, err := store.Settings.Get()
	if err != nil {
		t.Fatal("read synthetic stored settings")
	}
	if phase == "fresh" {
		if exists || settings.Config.Auth.Key == "" {
			t.Fatal("fresh signing key was not established")
		}
		if before.Auth.Key != "" && settings.Config.Auth.Key != before.Auth.Key {
			t.Error("fresh setup replaced the explicit signing key")
		}
		if before.Auth.Key == "" {
			decoded, decodeErr := hex.DecodeString(settings.Config.Auth.Key)
			if decodeErr != nil || len(decoded) != 64 {
				t.Error("generated key is not a lossless 512-bit text representation")
			}
		}
		if stored.Auth.Key != settings.Config.Auth.Key {
			t.Error("fresh signing key changed through the real JSON codec")
		}
		writeSigningFixture(t, store, fixturePath)
		return
	}
	if !exists {
		t.Fatal("restart did not load an existing database")
	}
	before.Auth.Key = settings.Config.Auth.Key
	if !reflect.DeepEqual(before, settings.Config) {
		t.Fatal("stored settings replaced current file/environment configuration")
	}
	if variant == "empty" && stored.Auth.Key != "" {
		t.Fatal("explicit recovery rewrote the old empty stored key")
	}
	fixture := readSigningFixture(t, fixturePath)
	user, err := store.Users.Get("synthetic-signing-reader")
	if err != nil || digestUser(t, user) != fixture.UserDigest {
		t.Fatal("restart changed the existing user or API token record")
	}
	for _, token := range []string{fixture.WebToken, fixture.APIToken} {
		_, verifyErr := jwt.ParseWithClaims(token, &users.AuthToken{}, func(*jwt.Token) (interface{}, error) {
			return []byte(settings.Config.Auth.Key), nil
		}, jwt.WithValidMethods([]string{"HS256"}))
		if phase == "legacy-restart" {
			if !errors.Is(verifyErr, jwt.ErrTokenSignatureInvalid) || !strings.Contains(stored.Auth.Key, "\ufffd") {
				t.Fatal("lossy legacy JSON unexpectedly recovered the original raw signing bytes")
			}
		} else if verifyErr != nil {
			t.Error("original synthetic login or API token lost its signature after restart")
		}
	}
	if settings.Config.Auth.Key != stored.Auth.Key && variant != "empty" {
		t.Fatal("runtime did not restore the existing persisted key verbatim")
	}
}

func seedSigningFixture(t *testing.T, path, fixturePath, variant string) {
	t.Helper()
	db, err := storm.Open(path)
	if err != nil {
		t.Fatal("open synthetic seed database")
	}
	defer db.Close()
	store, err := bolt.NewStorage(db)
	if err != nil {
		t.Fatal("create synthetic seed storage")
	}
	if variant == "legacy-binary" {
		settings.Config.Auth.Key = "public-synthetic-legacy-" + string([]byte{0xff, 0xfe, 0x80})
	}
	if saveErr := store.Settings.Save(&settings.Config); saveErr != nil {
		t.Fatal("save synthetic settings")
	}
	if variant == "legacy-binary" {
		persisted, readErr := store.Settings.Get()
		if readErr != nil || persisted.Auth.Key == settings.Config.Auth.Key || !strings.Contains(persisted.Auth.Key, "\ufffd") {
			t.Fatal("public raw binary key did not reproduce loss through the real JSON codec")
		}
	}
	writeSigningFixture(t, store, fixturePath)
	if variant == "empty" {
		persisted := settings.Config
		persisted.Auth.Key = ""
		if clearErr := bolt.Save(db, "settings", &persisted); clearErr != nil {
			t.Fatal("seed legacy empty-key settings")
		}
	} else if variant == "absent" {
		if deleteErr := db.Delete("config", "settings"); deleteErr != nil {
			t.Fatal("seed absent settings record")
		}
	} else if variant == "corrupt" {
		if corruptErr := bolt.Save(db, "settings", "public-synthetic-invalid-settings-record"); corruptErr != nil {
			t.Fatal("seed invalid settings record")
		}
	}
	if versionErr := bolt.Save(db, "version", 71); versionErr != nil {
		t.Fatal("seed untouched version marker")
	}
	fixture := readSigningFixture(t, fixturePath)
	fixture.DBDigest = digestDatabase(t, db)
	data, err := json.Marshal(fixture)
	if err != nil || os.WriteFile(fixturePath, data, 0600) != nil {
		t.Fatal("save synthetic fixture digest")
	}
}

func writeSigningFixture(t *testing.T, store *bolt.BoltStore, path string) {
	t.Helper()
	user := &users.User{Username: "synthetic-signing-reader", LoginMethod: users.LoginMethodPassword,
		NonAdminEditable: users.NonAdminEditable{Password: "public-synthetic-reader-password-not-real"},
		Permissions:      users.Permissions{Api: true, Browse: true, Download: true}}
	if err := store.Users.Save(user, true, true); err != nil {
		t.Fatal("save synthetic reader")
	}
	web, _, err := auth.MakeSignedTokenAPI(user, "WEB_TOKEN_synthetic", time.Hour, user.Permissions, false)
	if err != nil {
		t.Fatal("create public synthetic web token")
	}
	api, metadata, err := auth.MakeSignedTokenAPI(user, "synthetic-recovery", time.Hour,
		users.Permissions{Browse: true, Download: true}, false)
	if err != nil {
		t.Fatal("create public synthetic API token")
	}
	if tokenErr := store.Users.AddApiToken(user.ID, "synthetic-recovery", api, metadata); tokenErr != nil {
		t.Fatal("persist public synthetic API token")
	}
	saved, err := store.Users.Get(user.ID)
	if err != nil {
		t.Fatal("read synthetic user")
	}
	fixture := signingFixture{WebToken: web, APIToken: api, UserDigest: digestUser(t, saved)}
	data, err := json.Marshal(fixture)
	if err != nil || os.WriteFile(path, data, 0600) != nil {
		t.Fatal("save public synthetic token fixture")
	}
}

func readSigningFixture(t *testing.T, path string) signingFixture {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read synthetic token fixture")
	}
	var fixture signingFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal("decode synthetic token fixture")
	}
	return fixture
}

func digestUser(t *testing.T, user *users.User) string {
	t.Helper()
	data, err := json.Marshal(user)
	if err != nil {
		t.Fatal("encode synthetic user snapshot")
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func digestDatabase(t *testing.T, db *storm.DB) string {
	t.Helper()
	digest := sha256.New()
	if err := db.Bolt.View(func(tx *bbolt.Tx) error {
		return tx.ForEach(func(name []byte, bucket *bbolt.Bucket) error {
			_, _ = fmt.Fprintf(digest, "bucket:%x;", name)
			return digestBucket(digest, bucket)
		})
	}); err != nil {
		t.Fatal("snapshot synthetic logical database")
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func digestBucket(digest hash.Hash, bucket *bbolt.Bucket) error {
	_, _ = fmt.Fprintf(digest, "sequence:%d;", bucket.Sequence())
	return bucket.ForEach(func(key, value []byte) error {
		_, _ = fmt.Fprintf(digest, "%x:%x;", key, value)
		if value == nil {
			return digestBucket(digest, bucket.Bucket(key))
		}
		return nil
	})
}
