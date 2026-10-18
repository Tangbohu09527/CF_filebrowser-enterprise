package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/asdine/storm/v3"
	"github.com/gtsteffaniak/filebrowser/backend/database/storage/bolt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	commonerrors "github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func TestServiceReaderRotationPreservesEverythingExceptPassword(t *testing.T) {
	secret := []byte(strings.Repeat("S", 48))
	before := users.User{ID: 7, Username: "cf-export-reader", ServiceScopeLocked: true, LoginMethod: users.LoginMethodPassword, Scopes: []users.SourceScope{{Name: "/source", Scope: "/existing/narrow"}}, Permissions: users.Permissions{Api: true, Browse: true, Download: true}, TOTPSecret: "synthetic-existing-totp", TOTPNonce: "synthetic-nonce", OtpEnabled: true, Version: 3, NonAdminEditable: users.NonAdminEditable{Password: "old-hash", Locale: "zh-cn", ThemeColor: "existing"}}
	stored := before
	saves := 0
	expected := users.User{Username: before.Username, Scopes: before.Scopes, Permissions: before.Permissions, ServiceScopeLocked: true, LoginMethod: users.LoginMethodPassword}
	get := func(any) (*users.User, error) { value := stored; return &value, nil }
	save := func(value *users.User, changePass, disableScopeChange bool) error {
		if !changePass || !disableScopeChange {
			t.Fatal("unexpected storage flags")
		}
		saves++
		hash, err := utils.HashPwd(value.Password)
		if err != nil {
			return err
		}
		value.Password = hash
		stored = *value
		return nil
	}
	id, err := rotateServiceReaderPassword(expected, secret, get, save)
	if err != nil || id != before.ID || saves != 1 || utils.CheckPwd(string(secret), stored.Password) != nil {
		t.Fatalf("rotation failed: %v", err)
	}
	stored.Password = before.Password
	if !reflect.DeepEqual(stored, before) {
		t.Fatal("rotation modified unrelated account state")
	}
}

func TestServiceReaderRotationRejectsUnknownOrDifferentAccount(t *testing.T) {
	expected := users.User{Username: "cf-export-reader", Scopes: []users.SourceScope{{Name: "/source", Scope: "/existing/narrow"}}, Permissions: users.Permissions{Api: true, Browse: true, Download: true}, ServiceScopeLocked: true, LoginMethod: users.LoginMethodPassword}
	original := expected
	original.ID = 7
	original.Password = "unchanged"
	cases := map[string]func(*users.User){"id": func(u *users.User) { u.ID = 0 }, "username": func(u *users.User) { u.Username = "other" }, "scope": func(u *users.User) { u.Scopes = []users.SourceScope{{Name: "/source", Scope: "/"}} }, "source": func(u *users.User) { u.Scopes = []users.SourceScope{{Name: "other", Scope: "/existing/narrow"}} }, "permissions": func(u *users.User) { u.Permissions.Admin = true }, "revoked": func(u *users.User) { u.Permissions.Download = false }, "unlocked": func(u *users.User) { u.ServiceScopeLocked = false }, "login": func(u *users.User) { u.LoginMethod = "oidc" }, "password_locked": func(u *users.User) { u.LockPassword = true }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			value := original
			mutate(&value)
			saved := false
			_, err := rotateServiceReaderPassword(expected, []byte(strings.Repeat("s", 48)), func(any) (*users.User, error) { return &value, nil }, func(*users.User, bool, bool) error { saved = true; return nil })
			if err == nil || saved {
				t.Fatal("invalid reader modified")
			}
		})
	}
	for _, errGet := range []error{commonerrors.ErrNotExist, errors.New("storage unavailable")} {
		saved := false
		_, err := rotateServiceReaderPassword(expected, []byte(strings.Repeat("s", 48)), func(any) (*users.User, error) { return nil, errGet }, func(*users.User, bool, bool) error { saved = true; return nil })
		if err == nil || saved {
			t.Fatal("unknown reader modified")
		}
	}
}

func TestServiceReaderRotationKeepsFirstFailureAndRedactsSecret(t *testing.T) {
	expected := users.User{Username: "cf-export-reader", Scopes: []users.SourceScope{{Name: "/source", Scope: "/narrow"}}, Permissions: users.Permissions{Api: true, Browse: true, Download: true}, ServiceScopeLocked: true, LoginMethod: users.LoginMethodPassword}
	stored := expected
	stored.ID = 7
	secret := strings.Repeat("s", 48)
	_, err := rotateServiceReaderPassword(expected, []byte(secret), func(any) (*users.User, error) { v := stored; return &v, nil }, func(*users.User, bool, bool) error { return errors.New(secret) })
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("storage failure not safely retained")
	}
}

func TestServiceReaderRotationCLIProcess(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "files")
	scope := filepath.Join(source, "商品资料", "品牌")
	if err := os.MkdirAll(scope, 0700); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(root, "existing.db")
	db, err := storm.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Set("fixture", "sentinel", "keep"); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{"server": map[string]any{"database": database, "cacheDir": filepath.Join(root, "cache"), "sources": []any{map[string]any{"path": source, "name": "enterprise"}}, "logging": []any{map[string]any{"levels": "error"}}}, "auth": map[string]any{"key": strings.Repeat("synthetic", 8), "methods": map[string]any{"password": map[string]any{"enabled": true, "minLength": 12}}}}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config.yaml")
	if err = os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	oldSecret := strings.Repeat("OldSynthetic", 4)
	newSecret := strings.Repeat("NewSynthetic", 4)
	run := func(action, secret string) ([]byte, error) {
		c := exec.Command(os.Args[0], "-test.run=^TestServiceReaderCLIProcess$")
		c.Env = append(os.Environ(), "CF_SERVICE_READER_TEST_HELPER=1", "CF_SERVICE_READER_TEST_CONFIG="+configPath, "CF_SERVICE_READER_TEST_ACTION="+action)
		c.Stdin = strings.NewReader(secret + "\n")
		return c.CombinedOutput()
	}
	output, err := run("service-reader-rotate", newSecret)
	if err == nil || bytes.Contains(output, []byte(newSecret)) {
		t.Fatal("missing reader was created or secret logged")
	}
	output, err = run("service-reader", oldSecret)
	if err != nil {
		t.Fatalf("setup failed %v: %s", err, output)
	}
	db, err = storm.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	before, err := bolt.NewUsersBackend(db).GetBy("cf-export-reader")
	if err != nil {
		t.Fatal(err)
	}
	// Test-only fixture state ensures rotation does not reset existing OTP or UI data.
	before.TOTPSecret = "synthetic-existing-totp"
	before.TOTPNonce = "synthetic-existing-nonce"
	before.OtpEnabled = true
	before.Locale = "zh-cn"
	before.ThemeColor = "keep-theme"
	if err = db.Save(before); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	// Save normally calls MakeUserDirs, which can change a scope before saving.
	// The CLI must reject that configuration before any DB or filesystem write.
	storedBytes, err := os.ReadFile(database)
	if err != nil {
		t.Fatal(err)
	}
	sourceConfig := config["server"].(map[string]any)["sources"].([]any)[0].(map[string]any)
	sourceConfig["config"] = map[string]any{"createUserDir": true}
	unsafeConfig, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(configPath, unsafeConfig, 0600); err != nil {
		t.Fatal(err)
	}
	output, err = run("service-reader-rotate", newSecret)
	if err == nil || !bytes.Contains(output, []byte("without automatic user directories")) || bytes.Contains(output, []byte(newSecret)) {
		t.Fatal("automatic directory source was not rejected safely")
	}
	afterRejected, err := os.ReadFile(database)
	if err != nil || !bytes.Equal(storedBytes, afterRejected) {
		t.Fatal("refused rotation mutated database")
	}
	if _, err = os.Stat(filepath.Join(scope, "cf-export-reader")); !os.IsNotExist(err) {
		t.Fatal("refused rotation created a user directory")
	}
	if err = os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	output, err = run("service-reader-rotate", newSecret)
	if err != nil {
		t.Fatalf("rotation failed: %v %s", err, output)
	}
	if bytes.Contains(output, []byte(newSecret)) || !bytes.Contains(output, []byte(`"rotated":true`)) || !bytes.Contains(output, []byte(`"created":false`)) {
		t.Fatal("invalid redacted rotation receipt")
	}
	db, err = storm.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	after, err := bolt.NewUsersBackend(db).GetBy("cf-export-reader")
	if err != nil {
		t.Fatal(err)
	}
	if utils.CheckPwd(newSecret, after.Password) != nil || utils.CheckPwd(oldSecret, after.Password) == nil {
		t.Fatal("password transition incorrect")
	}
	after.Password = before.Password
	if !reflect.DeepEqual(before, after) {
		t.Fatal("existing account metadata changed")
	}
	var sentinel string
	if err = db.Get("fixture", "sentinel", &sentinel); err != nil || sentinel != "keep" {
		t.Fatal("unrelated store changed")
	}
}
