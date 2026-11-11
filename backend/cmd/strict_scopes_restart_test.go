package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/fileutils"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/storage"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	fbhttp "github.com/gtsteffaniak/filebrowser/backend/http"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/filebrowser/backend/trash"
	"github.com/gtsteffaniak/go-logger/logger"
)

// These values are exclusively public synthetic credentials for disposable
// test databases. They must still never appear in test-process output.
const strictRestartKey = "public-synthetic-strict-scope-restart-signing-key"
const strictRestartPassword = "public-synthetic-strict-scope-restart-password"
const strictRestartAdmin = "synthetic-scope-admin"
const strictRestartService = "synthetic-scope-service"
const strictRestartEmpty = "synthetic-scope-empty"
const strictRestartLegacy = "synthetic-scope-legacy"
const strictRestartEnterprise = "enterprise-source"
const strictRestartOriginals = "originals-source"
const strictRestartEnterpriseFile = "enterprise-sentinel.txt"
const strictRestartEnterpriseBytes = "public synthetic enterprise sentinel bytes"
const strictRestartOriginalFile = "original-sentinel.txt"
const strictRestartOriginalBytes = "public synthetic original sentinel bytes"
const strictRestartUploadBytes = "public synthetic bytes uploaded with the first full token"
const strictRestartPendingTrash = "synthetic-seed-trash-operation-0001"
const strictRestartFailureMarker = "STRICT_SCOPE_RESTART_CHECK_FAILED "
const strictRestartCompletionMarker = "STRICT_SCOPE_RESTART_CHILD_COMPLETED "

type strictRestartFixture struct {
	SeedPID       int
	Tokens        map[string]string
	Credentials   map[string]string
	KeyDigest     string
	SourcesDigest string
}

type strictRestartClient struct {
	client  *http.Client
	baseURL string
}

func strictRestartFail(t *testing.T, code string) {
	t.Helper()
	// Only caller-controlled, non-secret check labels may be passed here. The
	// parent reports these labels instead of forwarding raw child diagnostics.
	t.Fatalf("%s%s", strictRestartFailureMarker, code)
}

func strictRestartDigest(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		strictRestartFail(t, "digest_encode")
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func strictRestartReadFixture(t *testing.T, dir string) strictRestartFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "synthetic-private-fixture.json"))
	if err != nil {
		strictRestartFail(t, "fixture_read")
	}
	var fixture strictRestartFixture
	if json.Unmarshal(data, &fixture) != nil {
		strictRestartFail(t, "fixture_decode")
	}
	return fixture
}

func TestStrictScopesFirstFullTokenSurvivesRealStartupRestart(t *testing.T) {
	dir := t.TempDir()
	for _, phase := range []string{"seed", "restart"} {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStrictScopesRestartProcess$", "-test.count=1")
		command.Env = append(os.Environ(),
			"CF_STRICT_SCOPE_RESTART_DIR="+dir,
			"CF_STRICT_SCOPE_RESTART_PHASE="+phase,
			"LISTEN_PID=", "LISTEN_FDS=0")
		output, err := command.CombinedOutput()
		cancel()
		secrets := []string{strictRestartKey, strictRestartPassword}
		if _, statErr := os.Stat(filepath.Join(dir, "synthetic-private-fixture.json")); statErr == nil {
			for _, token := range strictRestartReadFixture(t, dir).Tokens {
				secrets = append(secrets, token)
			}
		}
		for _, secret := range secrets {
			if secret != "" && bytes.Contains(output, []byte(secret)) {
				t.Fatalf("synthetic %s child exposed a credential marker; output suppressed", phase)
			}
		}
		if err != nil {
			for _, line := range strings.Split(string(output), "\n") {
				if index := strings.Index(line, strictRestartFailureMarker); index >= 0 {
					// The marker is emitted only by strictRestartFail, using public
					// assertion labels. Do not echo arbitrary child logs or panics.
					t.Errorf("synthetic %s child: %s", phase, strings.TrimSpace(line[index:]))
				}
			}
			t.Fatalf("synthetic %s child failed; raw output suppressed", phase)
		}
		if !bytes.Contains(output, []byte(strictRestartCompletionMarker+phase)) {
			t.Fatalf("synthetic %s child did not complete its assertions; raw output suppressed", phase)
		}
	}
}

// This helper is invoked in two distinct test processes. A real process exit
// closes the first process's Bolt database before restart opens the same file.
// The startup sequence deliberately includes validateUserInfo: InitializeDb
// alone cannot reproduce the accidental default-Source authorization.
func TestStrictScopesRestartProcess(t *testing.T) {
	dir := os.Getenv("CF_STRICT_SCOPE_RESTART_DIR")
	if dir == "" {
		return
	}
	phase := os.Getenv("CF_STRICT_SCOPE_RESTART_PHASE")
	if phase != "seed" && phase != "restart" {
		strictRestartFail(t, "invalid_phase")
	}
	if err := logger.EnableCompatibilityMode(logger.JsonConfig{Levels: "error", Output: "stdout", NoColors: true}); err != nil {
		strictRestartFail(t, "logger_setup")
	}
	utils.BcryptCost = 4 // This subprocess and its disposable synthetic users only.
	settings.Env = settings.Environment{EmbeddedFs: true}
	settings.Config = settings.SetDefaults(false)
	settings.Config.Server.Database = filepath.Join(dir, "synthetic-users.db")
	settings.Config.Server.CacheDir = filepath.Join(dir, "cache")
	settings.Config.Server.ListenAddress = "127.0.0.1"
	settings.Config.Server.BaseURL = "/"
	settings.Config.Server.DisableUpdateCheck = true
	settings.Config.Server.DisablePreviews = true
	settings.Config.Server.DisableWebDAV = true
	settings.Config.Auth.AdminUsername = strictRestartAdmin
	settings.Config.Auth.AdminPassword = ""
	settings.Config.Http.TrustedHeaders = map[string]bool{}
	if phase == "seed" {
		settings.Config.Auth.Key = strictRestartKey
		settings.Config.Auth.AdminPassword = strictRestartPassword
	}
	for _, name := range []string{"enterprise", "originals", "cache"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0700); err != nil {
			strictRestartFail(t, "synthetic_directory_create")
		}
	}
	if phase == "seed" {
		for relative, content := range map[string]string{
			filepath.Join("enterprise", strictRestartEnterpriseFile): strictRestartEnterpriseBytes,
			filepath.Join("originals", strictRestartOriginalFile):    strictRestartOriginalBytes,
		} {
			if err := os.WriteFile(filepath.Join(dir, relative), []byte(content), 0600); err != nil {
				strictRestartFail(t, "synthetic_sentinel_create")
			}
		}
	}
	enterprise := &settings.Source{Path: filepath.Join(dir, "enterprise"), Name: strictRestartEnterprise, Config: settings.SourceConfig{
		DefaultEnabled: true, DefaultUserScope: "/", ResolvedRules: settings.ResolvedRulesConfig{IndexingDisabled: true, NoRules: true},
	}}
	originals := &settings.Source{Path: filepath.Join(dir, "originals"), Name: strictRestartOriginals, Config: settings.SourceConfig{
		Private: true, DefaultEnabled: false, DefaultUserScope: "/", ResolvedRules: settings.ResolvedRulesConfig{IndexingDisabled: true, NoRules: true},
	}}
	settings.Config.Server.Sources = []*settings.Source{enterprise, originals}
	settings.Config.Server.SourceMap = map[string]*settings.Source{enterprise.Path: enterprise, originals.Path: originals}
	settings.Config.Server.NameToSource = map[string]*settings.Source{enterprise.Name: enterprise, originals.Name: originals}
	settings.InitializeUserResolvers()
	fileutils.SetFsPermissions(0600, 0700)
	var err error
	var exists bool
	store, exists, err = storage.InitializeDb(settings.Config.Server.Database)
	if err != nil || store == nil || exists != (phase == "restart") {
		strictRestartFail(t, "database_initialization")
	}
	// Avoid the existing explicit bootstrap-password reset behavior. Both startup
	// validation phases leave the persisted admin password hash authoritative.
	settings.Config.Auth.AdminPassword = ""
	isNewIndex, err := indexing.InitializeIndexDB()
	if err != nil {
		strictRestartFail(t, "index_database_initialization")
	}
	indexing.SetIndexingStorage(store.Indexing)
	for _, source := range settings.Config.Server.Sources {
		indexing.Initialize(source, false, isNewIndex)
	}
	validateUserInfo(!exists)
	t.Cleanup(func() {
		indexing.StopAllScanners()
		if err := indexing.GetIndexDB().Close(); err != nil {
			strictRestartFail(t, "index_database_close")
		}
	})

	// The synthetic template only permits production API router initialization;
	// no browser/UI behavior or UI acceptance is asserted by this test.
	fileutils.InitAssetFS(fstest.MapFS{"public/index.html": &fstest.MapFile{Data: []byte("<!doctype html><title>Synthetic API test harness</title>")}}, true)
	client := strictRestartStartHTTP(t)
	if phase == "seed" {
		strictRestartSeed(t, dir, client)
		fmt.Println(strictRestartCompletionMarker + phase)
		return
	}
	fixture := strictRestartReadFixture(t, dir)
	if fixture.SeedPID == os.Getpid() || fixture.SeedPID == 0 {
		strictRestartFail(t, "restart_requires_new_process")
	}
	strictRestartCheckCredentials(t, fixture)
	strictRestartAssertAuthenticated(t, client, fixture.Tokens[strictRestartService], strictRestartService)
	strictRestartAssertAuthenticated(t, client, fixture.Tokens[strictRestartEmpty], strictRestartEmpty)
	strictRestartAssertAuthenticated(t, client, fixture.Tokens[strictRestartLegacy], strictRestartLegacy)
	strictRestartAssertDeniedSource(t, client, fixture.Tokens[strictRestartService], "service", enterprise)
	for _, source := range settings.Config.Server.Sources {
		strictRestartAssertDeniedSource(t, client, fixture.Tokens[strictRestartEmpty], "empty", source)
	}
	strictRestartAssertStoredAllowlists(t)
	strictRestartAssertSelf(t, client, fixture.Tokens[strictRestartService], strictRestartService, true, []string{strictRestartOriginals})
	strictRestartAssertSelf(t, client, fixture.Tokens[strictRestartEmpty], strictRestartEmpty, true, nil)
	strictRestartAssertSelf(t, client, fixture.Tokens[strictRestartLegacy], strictRestartLegacy, false, []string{strictRestartEnterprise, strictRestartOriginals})
	strictRestartAssertDownload(t, client, fixture.Tokens[strictRestartLegacy], strictRestartEnterprise, "/"+strictRestartEnterpriseFile, strictRestartEnterpriseBytes)
	strictRestartRestoreSeed(t, client, fixture.Tokens[strictRestartService])
	strictRestartOriginalLifecycle(t, client, fixture.Tokens[strictRestartService])
	strictRestartCheckCredentials(t, fixture)
	fmt.Println(strictRestartCompletionMarker + phase)
}

func strictRestartStartHTTP(t *testing.T) strictRestartClient {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		strictRestartFail(t, "loopback_port_allocate")
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		strictRestartFail(t, "loopback_listener_address_type")
	}
	port := address.Port
	if err := listener.Close(); err != nil {
		strictRestartFail(t, "loopback_port_release")
	}
	settings.Config.Server.Port = port
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}
	client := strictRestartClient{
		client:  &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		baseURL: "http://127.0.0.1:" + strconv.Itoa(port),
	}
	ctx, cancel := context.WithCancel(context.Background())
	shutdown := make(chan struct{})
	go fbhttp.StartHttp(ctx, store, shutdown)
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		cancel()
		select {
		case <-shutdown:
		case <-time.After(5 * time.Second):
			strictRestartFail(t, "http_shutdown_timeout")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.client.Get(client.baseURL + "/health")
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return client
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	strictRestartFail(t, "http_startup_timeout")
	return client
}

func (client strictRestartClient) request(t *testing.T, label, method, path, token, password string, body []byte, want int) []byte {
	t.Helper()
	request, err := http.NewRequest(method, client.baseURL+path, bytes.NewReader(body))
	if err != nil {
		strictRestartFail(t, label+"_request_build")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if password != "" {
		request.Header.Set("X-Password", url.QueryEscape(password))
	}
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.client.Do(request)
	if err != nil {
		strictRestartFail(t, label+"_transport")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		strictRestartFail(t, label+"_response_read")
	}
	if response.StatusCode != want {
		strictRestartFail(t, fmt.Sprintf("%s_status_got_%d_want_%d", label, response.StatusCode, want))
	}
	return data
}

func strictRestartJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		strictRestartFail(t, "request_json_encode")
	}
	return data
}

func strictRestartLogin(t *testing.T, client strictRestartClient, username string) string {
	t.Helper()
	data := client.request(t, "password_login", http.MethodPost, "/api/auth/login?username="+url.QueryEscape(username), "", strictRestartPassword, nil, http.StatusOK)
	token := strings.TrimSpace(string(data))
	if strings.Count(token, ".") != 2 {
		strictRestartFail(t, "password_login_token_shape")
	}
	return token
}

func strictRestartSeed(t *testing.T, dir string, client strictRestartClient) {
	t.Helper()
	adminToken := strictRestartLogin(t, client, strictRestartAdmin)
	fixture := strictRestartFixture{SeedPID: os.Getpid(), Tokens: map[string]string{}, Credentials: map[string]string{}}
	for _, account := range []struct {
		name   string
		strict bool
		empty  bool
	}{
		{strictRestartService, true, false},
		{strictRestartEmpty, true, true},
		{strictRestartLegacy, false, false},
	} {
		scopes := []users.SourceScope{}
		if !account.empty {
			scopes = append(scopes, users.SourceScope{Name: strictRestartOriginals, Scope: "/"})
		}
		body := map[string]any{"data": map[string]any{
			"username": account.name, "password": strictRestartPassword, "loginMethod": "password", "strictScopes": account.strict, "scopes": scopes,
			"permissions": users.Permissions{Api: true, Browse: true, Download: true, Create: true, Delete: true},
		}}
		client.request(t, "admin_create_account", http.MethodPost, "/api/users", adminToken, strictRestartPassword, strictRestartJSON(t, body), http.StatusCreated)
		webToken := strictRestartLogin(t, client, account.name)
		query := url.Values{"name": {"synthetic-first-full-token"}, "days": {"1"}, "minimal": {"false"}, "permissions": {"browse,download,create,delete"}}
		data := client.request(t, "issue_first_full_token", http.MethodPost, "/api/auth/token?"+query.Encode(), webToken, "", nil, http.StatusOK)
		var payload struct{ Token string }
		if json.Unmarshal(data, &payload) != nil || payload.Token == "" {
			strictRestartFail(t, "first_full_token_decode")
		}
		var claim users.AuthToken
		parsed, err := jwt.ParseWithClaims(payload.Token, &claim, func(*jwt.Token) (interface{}, error) { return []byte(settings.Config.Auth.Key), nil }, jwt.WithValidMethods([]string{"HS256"}))
		owner, getErr := store.Users.Get(account.name)
		wantPermissions := users.Permissions{Browse: true, Download: true, Create: true, Delete: true}
		if err != nil || parsed == nil || !parsed.Valid || getErr != nil || claim.BelongsTo != owner.ID || claim.Name != "synthetic-first-full-token" || claim.PermissionsVersion != users.CurrentPermissionsVersion || claim.Permissions != wantPermissions {
			strictRestartFail(t, "first_token_not_restricted_full_token")
		}
		if len(owner.Tokens) != 1 || owner.Tokens[claim.Name].Token != payload.Token || owner.Tokens[claim.Name].Permissions != wantPermissions {
			strictRestartFail(t, "first_full_token_not_persisted_once")
		}
		fixture.Tokens[account.name] = payload.Token
	}
	strictRestartAssertSelf(t, client, fixture.Tokens[strictRestartService], strictRestartService, true, []string{strictRestartOriginals})
	strictRestartAssertSelf(t, client, fixture.Tokens[strictRestartEmpty], strictRestartEmpty, true, nil)
	strictRestartAssertSelf(t, client, fixture.Tokens[strictRestartLegacy], strictRestartLegacy, false, []string{strictRestartOriginals})
	strictRestartAssertDeniedSource(t, client, fixture.Tokens[strictRestartService], "service", settings.Config.Server.Sources[0])
	strictRestartAssertDownload(t, client, fixture.Tokens[strictRestartService], strictRestartOriginals, "/"+strictRestartOriginalFile, strictRestartOriginalBytes)
	path := strictRestartResourcePath(strictRestartOriginals, "/seed-upload.txt")
	client.request(t, "seed_create_original", http.MethodPost, path, fixture.Tokens[strictRestartService], "", []byte(strictRestartUploadBytes), http.StatusOK)
	strictRestartAssertDownload(t, client, fixture.Tokens[strictRestartService], strictRestartOriginals, "/seed-upload.txt", strictRestartUploadBytes)
	data := client.request(t, "seed_trash_original", http.MethodPost, "/api/trash", fixture.Tokens[strictRestartService], "", strictRestartJSON(t, map[string]string{
		"source": strictRestartOriginals, "path": "/seed-upload.txt", "operation_id": strictRestartPendingTrash,
	}), http.StatusOK)
	var item trash.Item
	if json.Unmarshal(data, &item) != nil || item.State != "trashed" {
		strictRestartFail(t, "seed_trash_state")
	}
	allUsers, err := store.Users.Gets()
	if err != nil || len(allUsers) != 4 {
		strictRestartFail(t, "seed_existing_users_count")
	}
	for _, user := range allUsers {
		fixture.Credentials[user.Username] = strictRestartCredentialDigest(t, user)
	}
	fixture.KeyDigest = strictRestartDigest(t, settings.Config.Auth.Key)
	fixture.SourcesDigest = strictRestartDigest(t, settings.Config.Server.Sources)
	if err := os.WriteFile(filepath.Join(dir, "synthetic-private-fixture.json"), strictRestartJSON(t, fixture), 0600); err != nil {
		strictRestartFail(t, "fixture_write")
	}
}

func strictRestartCredentialDigest(t *testing.T, user *users.User) string {
	t.Helper()
	return strictRestartDigest(t, struct {
		ID       uint
		Password string
		Tokens   map[string]users.AuthToken
	}{user.ID, user.Password, user.Tokens})
}

func strictRestartCheckCredentials(t *testing.T, fixture strictRestartFixture) {
	t.Helper()
	storedSettings, err := store.Settings.Get()
	if err != nil || strictRestartDigest(t, settings.Config.Auth.Key) != fixture.KeyDigest || strictRestartDigest(t, storedSettings.Auth.Key) != fixture.KeyDigest {
		strictRestartFail(t, "restart_changed_runtime_or_stored_key")
	}
	if strictRestartDigest(t, settings.Config.Server.Sources) != fixture.SourcesDigest || strictRestartDigest(t, storedSettings.Server.Sources) != fixture.SourcesDigest {
		strictRestartFail(t, "restart_changed_source_configuration")
	}
	allUsers, err := store.Users.Gets()
	if err != nil || len(allUsers) != len(fixture.Credentials) {
		strictRestartFail(t, "restart_changed_existing_users")
	}
	for _, user := range allUsers {
		if strictRestartCredentialDigest(t, user) != fixture.Credentials[user.Username] {
			strictRestartFail(t, "restart_changed_existing_password_or_tokens")
		}
	}
}

func strictRestartAssertStoredAllowlists(t *testing.T) {
	t.Helper()
	service, err := store.Users.Get(strictRestartService)
	if err != nil || !service.StrictScopes || !reflect.DeepEqual(service.Scopes, []users.SourceScope{{Name: settings.Config.Server.Sources[1].Path, Scope: "/"}}) {
		strictRestartFail(t, "restart_expanded_persisted_service_allowlist")
	}
	empty, err := store.Users.Get(strictRestartEmpty)
	if err != nil || !empty.StrictScopes || len(empty.Scopes) != 0 {
		strictRestartFail(t, "restart_expanded_persisted_empty_allowlist")
	}
}

func strictRestartAssertAuthenticated(t *testing.T, client strictRestartClient, token, username string) {
	t.Helper()
	data := client.request(t, "first_full_token_self", http.MethodGet, "/api/users?id=self", token, "", nil, http.StatusOK)
	var user users.User
	if json.Unmarshal(data, &user) != nil || user.Username != username {
		strictRestartFail(t, "first_full_token_self_identity")
	}
}

func strictRestartAssertSelf(t *testing.T, client strictRestartClient, token, username string, strict bool, sources []string) {
	t.Helper()
	data := client.request(t, "first_full_token_self", http.MethodGet, "/api/users?id=self", token, "", nil, http.StatusOK)
	var user users.User
	if json.Unmarshal(data, &user) != nil || user.Username != username || user.StrictScopes != strict || len(user.Scopes) != len(sources) {
		strictRestartFail(t, "first_full_token_self_authorization")
	}
	for index, source := range sources {
		if user.Scopes[index].Name != source || user.Scopes[index].Scope != "/" {
			strictRestartFail(t, "first_full_token_self_sources")
		}
	}
}

func strictRestartResourcePath(source, path string) string {
	return "/api/resources?" + url.Values{"source": {source}, "path": {path}, "skipExtendedAttrs": {"true"}}.Encode()
}

func strictRestartAssertDeniedSource(t *testing.T, client strictRestartClient, token, identity string, source *settings.Source) {
	t.Helper()
	filename := strictRestartOriginalFile
	content := strictRestartOriginalBytes
	if source.Name == strictRestartEnterprise {
		filename, content = strictRestartEnterpriseFile, strictRestartEnterpriseBytes
	}
	id := "synthetic-denied-trash-operation-0001"
	for _, request := range []struct {
		label, method, path string
		body                []byte
	}{
		{"metadata", http.MethodGet, strictRestartResourcePath(source.Name, "/"+filename), nil},
		{"listing", http.MethodGet, strictRestartResourcePath(source.Name, "/"), nil},
		{"content", http.MethodGet, strictRestartResourcePath(source.Name, "/"+filename) + "&content=true", nil},
		{"download", http.MethodGet, "/api/resources/download?" + url.Values{"source": {source.Name}, "file": {"/" + filename}}.Encode(), nil},
		{"post_create", http.MethodPost, strictRestartResourcePath(source.Name, "/blocked-"+identity+".txt"), []byte("public synthetic blocked write")},
		{"put_create", http.MethodPut, strictRestartResourcePath(source.Name, "/blocked-put-"+identity+".txt"), []byte("public synthetic blocked write")},
		{"trash", http.MethodPost, "/api/trash", strictRestartJSON(t, map[string]string{"source": source.Name, "path": "/" + filename, "operation_id": id})},
		{"trash_list", http.MethodGet, "/api/trash?source=" + url.QueryEscape(source.Name), nil},
		{"trash_get", http.MethodGet, "/api/trash/" + id + "?source=" + url.QueryEscape(source.Name), nil},
		{"restore", http.MethodPost, "/api/trash/" + id + "/restore", strictRestartJSON(t, map[string]string{"source": source.Name, "path": "/blocked-restored.txt", "restore_operation_id": "synthetic-denied-restore-0001"})},
	} {
		data := client.request(t, identity+"_denied_"+request.label, request.method, request.path, token, "", request.body, http.StatusForbidden)
		for _, marker := range []string{source.Path, filename, content} {
			if bytes.Contains(data, []byte(marker)) {
				strictRestartFail(t, "denied_response_leaked_source_data")
			}
		}
	}
	for _, name := range []string{"blocked-" + identity + ".txt", "blocked-put-" + identity + ".txt", "blocked-restored.txt"} {
		if _, err := os.Stat(filepath.Join(source.Path, name)); !os.IsNotExist(err) {
			strictRestartFail(t, "denied_source_wrote_file")
		}
	}
	data, err := os.ReadFile(filepath.Join(source.Path, filename))
	if err != nil || string(data) != content {
		strictRestartFail(t, "denied_source_changed_sentinel")
	}
}

func strictRestartAssertDownload(t *testing.T, client strictRestartClient, token, source, path, want string) {
	t.Helper()
	data := client.request(t, "authorized_download", http.MethodGet, "/api/resources/download?"+url.Values{"source": {source}, "file": {path}}.Encode(), token, "", nil, http.StatusOK)
	if string(data) != want {
		strictRestartFail(t, "authorized_download_bytes")
	}
}

func strictRestartRestoreSeed(t *testing.T, client strictRestartClient, token string) {
	t.Helper()
	data := client.request(t, "durable_seed_trash_get", http.MethodGet, "/api/trash/"+strictRestartPendingTrash+"?source="+url.QueryEscape(strictRestartOriginals), token, "", nil, http.StatusOK)
	var item trash.Item
	if json.Unmarshal(data, &item) != nil || item.State != "trashed" || item.OriginalPath != "/seed-upload.txt" {
		strictRestartFail(t, "durable_seed_trash_state")
	}
	data = client.request(t, "durable_seed_trash_list", http.MethodGet, "/api/trash?source="+url.QueryEscape(strictRestartOriginals), token, "", nil, http.StatusOK)
	if !bytes.Contains(data, []byte(strictRestartPendingTrash)) {
		strictRestartFail(t, "durable_seed_trash_listing")
	}
	client.request(t, "durable_seed_restore", http.MethodPost, "/api/trash/"+strictRestartPendingTrash+"/restore", token, "", strictRestartJSON(t, map[string]string{
		"source": strictRestartOriginals, "path": "/restored-seed.txt", "restore_operation_id": "synthetic-seed-restore-operation-0001",
	}), http.StatusOK)
	strictRestartAssertDownload(t, client, token, strictRestartOriginals, "/restored-seed.txt", strictRestartUploadBytes)
}

func strictRestartOriginalLifecycle(t *testing.T, client strictRestartClient, token string) {
	t.Helper()
	path := strictRestartResourcePath(strictRestartOriginals, "/restart-upload.txt")
	client.request(t, "restart_create_original", http.MethodPost, path, token, "", []byte(strictRestartUploadBytes), http.StatusOK)
	client.request(t, "restart_put_overwrite_denied", http.MethodPut, path, token, "", []byte("blocked overwrite"), http.StatusForbidden)
	client.request(t, "restart_post_overwrite_denied", http.MethodPost, path+"&override=true", token, "", []byte("blocked overwrite"), http.StatusForbidden)
	data := client.request(t, "restart_original_metadata", http.MethodGet, path, token, "", nil, http.StatusOK)
	if !bytes.Contains(data, []byte("restart-upload.txt")) {
		strictRestartFail(t, "restart_original_metadata_name")
	}
	data = client.request(t, "restart_original_listing", http.MethodGet, strictRestartResourcePath(strictRestartOriginals, "/"), token, "", nil, http.StatusOK)
	if !bytes.Contains(data, []byte("restart-upload.txt")) {
		strictRestartFail(t, "restart_original_listing_name")
	}
	contentPath := "/api/resources?" + url.Values{"source": {strictRestartOriginals}, "path": {"/restart-upload.txt"}, "content": {"true"}}.Encode()
	data = client.request(t, "restart_original_content", http.MethodGet, contentPath, token, "", nil, http.StatusOK)
	if !bytes.Contains(data, []byte(strictRestartUploadBytes)) {
		strictRestartFail(t, "restart_original_content_bytes")
	}
	strictRestartAssertDownload(t, client, token, strictRestartOriginals, "/restart-upload.txt", strictRestartUploadBytes)
	id := "synthetic-restart-trash-operation-0001"
	client.request(t, "restart_original_trash", http.MethodPost, "/api/trash", token, "", strictRestartJSON(t, map[string]string{
		"source": strictRestartOriginals, "path": "/restart-upload.txt", "operation_id": id,
	}), http.StatusOK)
	client.request(t, "restart_restore_no_overwrite", http.MethodPost, "/api/trash/"+id+"/restore", token, "", strictRestartJSON(t, map[string]string{
		"source": strictRestartOriginals, "path": "/" + strictRestartOriginalFile, "restore_operation_id": "synthetic-conflict-restore-operation-0001",
	}), http.StatusConflict)
	client.request(t, "restart_original_restore", http.MethodPost, "/api/trash/"+id+"/restore", token, "", strictRestartJSON(t, map[string]string{
		"source": strictRestartOriginals, "path": "/restart-restored.txt", "restore_operation_id": "synthetic-restart-restore-operation-0002",
	}), http.StatusOK)
	strictRestartAssertDownload(t, client, token, strictRestartOriginals, "/restart-restored.txt", strictRestartUploadBytes)
	strictRestartAssertDownload(t, client, token, strictRestartOriginals, "/"+strictRestartOriginalFile, strictRestartOriginalBytes)
}
