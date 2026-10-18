package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asdine/storm/v3"
	commonerrors "github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/storage/bolt"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func TestServiceReaderPasswordInput(t *testing.T) {
	secret := strings.Repeat("x", 32)
	for _, bad := range []string{"", " ", "short", secret + "\nextra", strings.Repeat("x", 4097)} {
		data, err := readServiceReaderPassword(strings.NewReader(bad))
		if err == nil || len(data) != 0 {
			t.Fatal("invalid input accepted")
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatal("secret in error")
		}
	}
	for _, ending := range []string{"", "\n", "\r\n"} {
		data, err := readServiceReaderPassword(strings.NewReader(secret + ending))
		if err != nil || string(data) != secret {
			t.Fatal("valid input rejected")
		}
		clear(data)
	}
}
func TestServiceReaderDefinitionAndCreateOnly(t *testing.T) {
	old := settings.Config
	defer func() { settings.Config = old; settings.InitializeUserResolvers() }()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "商品资料", "品牌"), 0700); err != nil {
		t.Fatal(err)
	}
	source := &settings.Source{Path: root, Name: "enterprise"}
	settings.Config.Server.NameToSource = map[string]*settings.Source{"enterprise": source}
	options := serviceReaderOptions{Username: "cf-export-reader", Source: "enterprise", Scope: "/商品资料/品牌", PasswordStdin: true}
	user, err := serviceReaderDefinition(options, []byte(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatal(err)
	}
	if !user.ServiceScopeLocked || user.Permissions != (users.Permissions{Api: true, Browse: true, Download: true}) || len(user.Scopes) != 1 {
		t.Fatal("permissions expanded")
	}
	var saved *users.User
	creates := 0
	get := func(any) (*users.User, error) {
		if saved == nil {
			return nil, commonerrors.ErrNotExist
		}
		return saved, nil
	}
	create := func(u users.User, perms users.Permissions) error { creates++; saved = &u; return nil }
	if err = persistNewServiceReader(user, get, create); err != nil || creates != 1 {
		t.Fatal(err)
	}
	if err = persistNewServiceReader(user, get, create); err == nil || creates != 1 {
		t.Fatal("existing account mutated")
	}
	if err = persistNewServiceReader(user, func(any) (*users.User, error) { return nil, errors.New("storage unavailable") }, create); err == nil || creates != 1 {
		t.Fatal("unknown state treated as missing")
	}
	for _, scope := range []string{"/", "/../escape", "/missing", "relative", "/商品资料//品牌", "/商品资料/品牌\n"} {
		bad := options
		bad.Scope = scope
		if _, err = serviceReaderDefinition(bad, []byte("never logged")); err == nil {
			t.Fatalf("bad scope %q accepted", scope)
		}
	}
}
func TestServiceReaderLockedScopeSurvivesDefaults(t *testing.T) {
	old := settings.Config
	defer func() { settings.Config = old; settings.InitializeUserResolvers() }()
	a := &settings.Source{Path: "/source-a", Name: "a", Config: settings.SourceConfig{DefaultEnabled: true, DefaultUserScope: "/"}}
	b := &settings.Source{Path: "/source-b", Name: "b", Config: settings.SourceConfig{DefaultEnabled: true, DefaultUserScope: "/"}}
	settings.Config.Server.Sources = []*settings.Source{a, b}
	settings.Config.Server.SourceMap = map[string]*settings.Source{a.Path: a, b.Path: b}
	settings.Config.Server.NameToSource = map[string]*settings.Source{"a": a, "b": b}
	settings.InitializeUserResolvers()
	user := &users.User{Username: "cf-reader", ServiceScopeLocked: true, Scopes: []users.SourceScope{{Name: a.Path, Scope: "/narrow"}}}
	if updateUserScopes(user) || len(user.Scopes) != 1 || user.Scopes[0].Scope != "/narrow" {
		t.Fatal("default source widened service scope")
	}
	user.Permissions = users.Permissions{}
	updateUserScopes(user)
	if user.Permissions != (users.Permissions{}) {
		t.Fatal("scope refresh resurrected permissions")
	}
}
func TestServiceReaderCLIProcess(t *testing.T) {
	if os.Getenv("CF_SERVICE_READER_TEST_HELPER") == "1" {
		flag.CommandLine = flag.NewFlagSet("filebrowser", flag.ExitOnError)
		os.Args = []string{"filebrowser", "set", "service-reader", "--username", "cf-export-reader", "--source", "enterprise", "--scope", "/商品资料/品牌", "--password-stdin", "-c", os.Getenv("CF_SERVICE_READER_TEST_CONFIG")}
		keepGoing, _ := runCLI()
		if keepGoing {
			os.Exit(90)
		}
		os.Exit(0)
	}
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
	cfg := map[string]any{"server": map[string]any{"database": database, "cacheDir": filepath.Join(root, "cache"), "sources": []any{map[string]any{"path": source, "name": "enterprise"}}, "logging": []any{map[string]any{"levels": "error"}}}, "auth": map[string]any{"key": strings.Repeat("synthetic", 8), "methods": map[string]any{"password": map[string]any{"enabled": true, "minLength": 12}}}}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(root, "config.yaml")
	if err = os.WriteFile(configFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	secret := "Synthetic-Only-Test-Password-1234567890"
	run := func() ([]byte, error) {
		c := exec.Command(os.Args[0], "-test.run=^TestServiceReaderCLIProcess$")
		c.Env = append(os.Environ(), "CF_SERVICE_READER_TEST_HELPER=1", "CF_SERVICE_READER_TEST_CONFIG="+configFile)
		c.Stdin = strings.NewReader(secret + "\n")
		return c.CombinedOutput()
	}
	output, err := run()
	if err != nil {
		t.Fatalf("CLI failed: %v %s", err, output)
	}
	if bytes.Contains(output, []byte(secret)) || !bytes.Contains(output, []byte(`"created":true`)) {
		t.Fatal("invalid redacted receipt")
	}
	verify := func() string {
		db, e := storm.Open(database)
		if e != nil {
			t.Fatal(e)
		}
		defer db.Close()
		u, e := bolt.NewUsersBackend(db).GetBy("cf-export-reader")
		if e != nil {
			t.Fatal(e)
		}
		if !u.ServiceScopeLocked || u.Permissions != (users.Permissions{Api: true, Browse: true, Download: true}) || len(u.Scopes) != 1 || u.Scopes[0].Scope != "/商品资料/品牌" || utils.CheckPwd(secret, u.Password) != nil {
			t.Fatal("persisted account differs")
		}
		var sentinel string
		if e = db.Get("fixture", "sentinel", &sentinel); e != nil || sentinel != "keep" {
			t.Fatal("existing database changed")
		}
		return u.Password
	}
	before := verify()
	output, err = run()
	if err == nil || bytes.Contains(output, []byte(secret)) || !bytes.Contains(output, []byte("already exists")) {
		t.Fatal("repeat was not refused")
	}
	if verify() != before {
		t.Fatal("repeat changed password")
	}
}
