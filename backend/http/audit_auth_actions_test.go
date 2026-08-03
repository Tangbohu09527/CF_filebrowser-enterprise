package http

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	storm "github.com/asdine/storm/v3"
	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	"github.com/gtsteffaniak/filebrowser/backend/database/storage/bolt"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func TestAuditAuthenticationActions(t *testing.T) {
	t.Run("password login success records the resolved actor", func(t *testing.T) {
		fixture := newAuditAuthHTTPFixture(t, true)
		const (
			username            = "audit-login-success"
			password            = "AUDIT-AUTH-PASSWORD-SECRET"
			totpSecret          = "AUDIT-AUTH-TOTP-SECRET"
			authorizationSecret = "AUDIT-AUTH-AUTHORIZATION-SECRET"
			cookieSecret        = "AUDIT-AUTH-COOKIE-SECRET"
			bodySecret          = "AUDIT-AUTH-RAW-BODY-SECRET"
		)
		user := fixture.savePasswordUser(t, username, password)

		response := fixture.request(t, stdhttp.MethodPost, auditAuthLoginPath(username), []byte(bodySecret), map[string]string{
			"X-Password":    url.QueryEscape(password),
			"X-Secret":      totpSecret,
			"Authorization": "Bearer " + authorizationSecret,
			"Cookie":        "unrelated_session=" + cookieSecret,
		})
		if response.status != stdhttp.StatusOK {
			t.Fatalf("password login status: got %d, want 200; body=%q", response.status, response.body)
		}
		if len(response.body) == 0 {
			t.Fatal("password login returned no session token")
		}

		event := fixture.singleEvent(t)
		assertAuditAuthTerminal(t, event, auditdb.ActionAuthLogin, auditdb.ResultSuccess, stdhttp.StatusOK)
		if event.UserID == nil || *event.UserID != user.ID || event.Username != username {
			t.Errorf("login actor: got userID=%v username=%q, want %d/%q", event.UserID, event.Username, user.ID, username)
		}
		if event.AuthMethod != auditdb.AuthMethodSession {
			t.Errorf("login auth method: got %q, want %q", event.AuthMethod, auditdb.AuthMethodSession)
		}
		assertAuditAuthRequestFacts(t, event, response.requestID)

		serialized, err := json.Marshal(event)
		if err != nil {
			t.Fatal("marshal login audit event")
		}
		assertAuditAuthSecretsAbsent(t, serialized, map[string]string{
			"password":             password,
			"TOTP":                 totpSecret,
			"Authorization":        authorizationSecret,
			"Cookie":               cookieSecret,
			"raw request body":     bodySecret,
			"issued session token": string(response.body),
		})
	})

	t.Run("wrong password is a denied login failure", func(t *testing.T) {
		fixture := newAuditAuthHTTPFixture(t, true)
		const username = "audit-login-wrong-password"
		fixture.savePasswordUser(t, username, "correct-password")

		response := fixture.request(t, stdhttp.MethodPost, auditAuthLoginPath(username), nil, map[string]string{
			"X-Password": url.QueryEscape("wrong-password"),
		})
		if response.status != stdhttp.StatusUnauthorized {
			t.Fatalf("wrong-password status: got %d, want 401", response.status)
		}

		event := fixture.singleEvent(t)
		assertAuditAuthFailure(t, event, username, stdhttp.StatusUnauthorized)
		assertAuditAuthRequestFacts(t, event, response.requestID)
	})

	t.Run("unknown user is a denied login failure without a user id", func(t *testing.T) {
		fixture := newAuditAuthHTTPFixture(t, true)
		const username = "audit-login-unknown-user"
		response := fixture.request(t, stdhttp.MethodPost, auditAuthLoginPath(username), nil, map[string]string{
			"X-Password": url.QueryEscape("unknown-user-password"),
		})
		if response.status != stdhttp.StatusUnauthorized {
			t.Fatalf("unknown-user status: got %d, want 401", response.status)
		}

		event := fixture.singleEvent(t)
		assertAuditAuthFailure(t, event, username, stdhttp.StatusUnauthorized)
		assertAuditAuthRequestFacts(t, event, response.requestID)
	})

	t.Run("attempted username is retained within the audit bound", func(t *testing.T) {
		fixture := newAuditAuthHTTPFixture(t, true)
		attempted := strings.Repeat("audit-login-attempt-", 20)
		response := fixture.request(t, stdhttp.MethodPost, auditAuthLoginPath(attempted), nil, map[string]string{
			"X-Password": url.QueryEscape("unknown-user-password"),
		})
		if response.status != stdhttp.StatusUnauthorized {
			t.Fatalf("bounded-username status: got %d, want 401", response.status)
		}

		event := fixture.singleEvent(t)
		assertAuditAuthTerminal(t, event, auditdb.ActionAuthLoginFailed, auditdb.ResultDenied, stdhttp.StatusUnauthorized)
		if event.UserID != nil {
			t.Errorf("bounded attempted username retained user id %v", event.UserID)
		}
		if event.Username == "" || len(event.Username) > auditdb.MaxUsernameBytes || !utf8.ValidString(event.Username) {
			t.Errorf("bounded attempted username: got %q (%d bytes)", event.Username, len(event.Username))
		}
		if !strings.HasPrefix(attempted, event.Username) {
			t.Errorf("bounded attempted username is not a prefix of the supplied value: %q", event.Username)
		}
		assertAuditAuthRequestFacts(t, event, response.requestID)
	})

	t.Run("API token is not recorded as a login action", func(t *testing.T) {
		fixture := newAuditAuthHTTPFixture(t, false)
		user := fixture.savePasswordUser(t, "audit-login-api-token", "password-for-token-owner")
		permissions := users.Permissions{Api: true, Browse: true}
		token, metadata, err := auth.MakeSignedTokenAPI(user, "audit-login-api-token", time.Hour, permissions, false)
		if err != nil {
			t.Fatal("create API token for login isolation test")
		}
		if err := store.Users.AddApiToken(user.ID, "audit-login-api-token", token, metadata); err != nil {
			t.Fatal("persist API token metadata for login isolation test")
		}
		if err := store.Access.AddApiToken(token, user.ID); err != nil {
			t.Fatal("persist API token mapping for login isolation test")
		}

		response := fixture.request(t, stdhttp.MethodPost, "/api/auth/login", nil, map[string]string{
			"Authorization": "Bearer " + token,
		})
		if response.status != stdhttp.StatusOK {
			t.Fatalf("valid API-token login-route status: got %d, want 200", response.status)
		}
		for _, event := range fixture.events() {
			if event.Action == auditdb.ActionAuthLogin || event.Action == auditdb.ActionAuthLoginFailed {
				t.Errorf("API token request was recorded as login action %q", event.Action)
			}
		}
	})
}

type auditAuthHTTPFixture struct {
	server     *httptest.Server
	service    *AuditService
	auditStore *auditStoreStub
	client     *stdhttp.Client
}

type auditAuthHTTPResponse struct {
	status    int
	requestID string
	body      []byte
}

func newAuditAuthHTTPFixture(t *testing.T, passwordEnabled bool) *auditAuthHTTPFixture {
	t.Helper()
	if utils.InvalidPasswordHash == "" {
		if err := utils.SetInvalidPasswordHash(); err != nil {
			t.Fatal("initialize invalid password hash")
		}
	}

	db, err := storm.Open(filepath.Join(t.TempDir(), "audit-auth.db"))
	if err != nil {
		t.Fatal("open audit auth database")
	}
	testStore, err := bolt.NewStorage(db)
	if err != nil {
		_ = db.Close()
		t.Fatal("create audit auth storage")
	}
	if err := testStore.Auth.Save(&auth.JSONAuth{}); err != nil {
		_ = db.Close()
		t.Fatal("save password authenticator")
	}

	auditStore := newAuditStoreStub()
	service := NewAuditService(auditStore)
	testAuth := settings.Auth{
		Key:                  "audit-auth-test-signing-key",
		TokenExpirationHours: 2,
		Methods: settings.LoginMethods{
			PasswordAuth: settings.PasswordAuthConfig{Enabled: passwordEnabled, MinLength: 5},
		},
	}

	previousStore := store
	previousAuditRuntime := auditRuntime
	previousConfig := config
	previousAuth := settings.Config.Auth
	store = testStore
	auditRuntime = service
	config = &settings.Settings{Auth: testAuth, Http: settings.Http{DisableRateLimit: true}}
	settings.Config.Auth = testAuth

	api := stdhttp.NewServeMux()
	api.HandleFunc("POST /auth/login", withAuditDefaultAction(
		auditdb.ActionAuthLoginFailed,
		withRateLimitChain(AuthRateLimitCredentialLockout, loginHelper(loginHandler)),
	))
	root := stdhttp.NewServeMux()
	root.Handle("/api/", stdhttp.StripPrefix("/api", api))
	httpServer := httptest.NewServer(AuditMiddleware(LoggingMiddleware(root), service))
	fixture := &auditAuthHTTPFixture{
		server:     httpServer,
		service:    service,
		auditStore: auditStore,
		client:     httpServer.Client(),
	}
	t.Cleanup(func() {
		httpServer.Close()
		store = previousStore
		auditRuntime = previousAuditRuntime
		config = previousConfig
		settings.Config.Auth = previousAuth
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("close audit auth database")
		}
	})
	return fixture
}

func (fixture *auditAuthHTTPFixture) savePasswordUser(t *testing.T, username, password string) *users.User {
	t.Helper()
	user := &users.User{
		Username: username,
		NonAdminEditable: users.NonAdminEditable{
			Password: password,
		},
		LoginMethod: users.LoginMethodPassword,
		Permissions: users.Permissions{Api: true, Browse: true},
	}
	if err := store.Users.Save(user, true, false); err != nil {
		t.Fatal("save audit auth password user")
	}
	return user
}

func (fixture *auditAuthHTTPFixture) request(t *testing.T, method, path string, body []byte, headers map[string]string) auditAuthHTTPResponse {
	t.Helper()
	request, err := stdhttp.NewRequest(method, fixture.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal("build audit auth request")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := fixture.client.Do(request)
	if err != nil {
		t.Fatal("execute audit auth request")
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal("read audit auth response")
	}
	return auditAuthHTTPResponse{
		status:    response.StatusCode,
		requestID: response.Header.Get(auditRequestIDHeader),
		body:      responseBody,
	}
}

func (fixture *auditAuthHTTPFixture) events() []auditdb.Event {
	fixture.auditStore.mu.Lock()
	defer fixture.auditStore.mu.Unlock()
	events := make([]auditdb.Event, len(fixture.auditStore.appended))
	for index := range fixture.auditStore.appended {
		events[index] = cloneAuditEvent(fixture.auditStore.appended[index])
	}
	return events
}

func (fixture *auditAuthHTTPFixture) singleEvent(t *testing.T) auditdb.Event {
	t.Helper()
	events := fixture.events()
	if len(events) != 1 {
		t.Fatalf("terminal audit event count: got %d, want 1", len(events))
	}
	return events[0]
}

func auditAuthLoginPath(username string) string {
	return "/api/auth/login?" + url.Values{"username": {username}}.Encode()
}

func assertAuditAuthTerminal(t *testing.T, event auditdb.Event, action auditdb.Action, result auditdb.Result, status int) {
	t.Helper()
	if event.Action != action || event.Result != result || event.HTTPStatus == nil || *event.HTTPStatus != status {
		t.Errorf("terminal audit facts: action=%q result=%q status=%v, want %q/%q/%d",
			event.Action, event.Result, event.HTTPStatus, action, result, status)
	}
}

func assertAuditAuthFailure(t *testing.T, event auditdb.Event, attemptedUsername string, status int) {
	t.Helper()
	assertAuditAuthTerminal(t, event, auditdb.ActionAuthLoginFailed, auditdb.ResultDenied, status)
	if event.UserID != nil || event.Username != attemptedUsername {
		t.Errorf("failed login actor: got userID=%v username=%q, want nil/%q", event.UserID, event.Username, attemptedUsername)
	}
	if event.AuthMethod != auditdb.AuthMethodAnonymous {
		t.Errorf("failed login auth method: got %q, want %q", event.AuthMethod, auditdb.AuthMethodAnonymous)
	}
	if event.ErrorCode != auditErrorCodeAuthenticationRequired {
		t.Errorf("failed login error code: got %q, want %q", event.ErrorCode, auditErrorCodeAuthenticationRequired)
	}
}

func assertAuditAuthRequestFacts(t *testing.T, event auditdb.Event, requestID string) {
	t.Helper()
	if requestID == "" || event.RequestID != requestID {
		t.Errorf("audit request ID: event=%q response=%q", event.RequestID, requestID)
	}
	if event.ClientIP == "" || net.ParseIP(event.ClientIP) == nil {
		t.Errorf("audit client IP is not normalized: %q", event.ClientIP)
	}
}

func assertAuditAuthSecretsAbsent(t *testing.T, data []byte, secrets map[string]string) {
	t.Helper()
	for name, secret := range secrets {
		if secret != "" && bytes.Contains(data, []byte(secret)) {
			t.Errorf("audit event contains %s", name)
		}
	}
}
