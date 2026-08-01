package http

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	storm "github.com/asdine/storm/v3"
	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	"github.com/gtsteffaniak/filebrowser/backend/database/storage/bolt"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	logpkg "github.com/gtsteffaniak/go-logger/logger"
)

func TestAuditQueryHTTPAuthorization(t *testing.T) {
	tests := []struct {
		name       string
		credential func(*testing.T, *auditQueryHTTPFixture) string
		query      string
		wantStatus int
	}{
		{
			name: "administrator session succeeds",
			credential: func(t *testing.T, fixture *auditQueryHTTPFixture) string {
				return fixture.sessionToken(t, fixture.admin)
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "administrator API token capability succeeds",
			credential: func(t *testing.T, fixture *auditQueryHTTPFixture) string {
				return fixture.apiToken(t, fixture.admin, "audit-admin-token", users.Permissions{Api: true, Admin: true})
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "ordinary user session is forbidden",
			credential: func(t *testing.T, fixture *auditQueryHTTPFixture) string {
				return fixture.sessionToken(t, fixture.user)
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "API token without administrator capability is forbidden",
			credential: func(t *testing.T, fixture *auditQueryHTTPFixture) string {
				return fixture.apiToken(t, fixture.admin, "audit-non-admin-token", users.Permissions{Api: true})
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "administrator token cannot exceed current account permissions",
			credential: func(t *testing.T, fixture *auditQueryHTTPFixture) string {
				return fixture.apiToken(t, fixture.user, "audit-ceiling-token", users.Permissions{Api: true, Admin: true})
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "share credential is rejected",
			credential: func(*testing.T, *auditQueryHTTPFixture) string { return "" },
			query:      "hash=0123456789abcdef0123456789abcdef",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "anonymous request is rejected",
			credential: func(*testing.T, *auditQueryHTTPFixture) string { return "" },
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAuditQueryHTTPFixture(t)
			fixture.appendEvent(t, "audit-authz-event", time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC), "admin")
			response := fixture.request(test.credential(t, fixture), test.query)
			if response.Code != test.wantStatus {
				t.Fatalf("status: got %d, want %d; body=%s", response.Code, test.wantStatus, response.Body.String())
			}
		})
	}
}

func TestAuditQueryCursorSecurityAndStability(t *testing.T) {
	fixture := newAuditQueryHTTPFixture(t)
	token := fixture.sessionToken(t, fixture.admin)
	timestamp := time.Date(2026, 7, 31, 11, 0, 0, 123, time.UTC)
	original := make([]auditdb.Event, 5)
	for index := range original {
		original[index] = fixture.appendEvent(t, "audit-page-"+string(rune('0'+index)), timestamp, "alice")
	}

	firstResponse := fixture.request(token, "actor=alice&limit=2")
	first := decodeAuditQueryTestPage(t, firstResponse, http.StatusOK)
	assertAuditQueryTestRequestIDs(t, first.Items, []string{"audit-page-4", "audit-page-3"})
	if !first.HasMore || first.NextCursor == "" {
		t.Fatalf("first page continuation: hasMore=%v cursor=%q", first.HasMore, first.NextCursor)
	}
	assertAuditCursorOpaque(t, first.NextCursor, []string{"alice", fixture.authKey})

	tampered := first.NextCursor[:len(first.NextCursor)-1] + cursorReplacement(first.NextCursor[len(first.NextCursor)-1])
	if response := fixture.request(token, url.Values{
		"actor":  {"alice"},
		"limit":  {"2"},
		"cursor": {tampered},
	}.Encode()); response.Code != http.StatusBadRequest {
		t.Fatalf("tampered cursor status: got %d, want %d; body=%s", response.Code, http.StatusBadRequest, response.Body.String())
	}

	if response := fixture.request(token, url.Values{
		"actor":  {"bob"},
		"limit":  {"2"},
		"cursor": {first.NextCursor},
	}.Encode()); response.Code != http.StatusBadRequest {
		t.Fatalf("changed-filter cursor status: got %d, want %d; body=%s", response.Code, http.StatusBadRequest, response.Body.String())
	}

	// Rebuild process-local settings with the same persisted signing key.
	config = &settings.Settings{Auth: settings.Auth{Key: fixture.authKey}}
	settings.Config.Auth.Key = fixture.authKey
	fixture.appendEvent(t, "audit-page-new-after-cursor", timestamp.Add(time.Hour), "alice")

	secondResponse := fixture.request(token, url.Values{
		"actor":  {"alice"},
		"limit":  {"2"},
		"cursor": {first.NextCursor},
	}.Encode())
	second := decodeAuditQueryTestPage(t, secondResponse, http.StatusOK)
	assertAuditQueryTestRequestIDs(t, second.Items, []string{"audit-page-2", "audit-page-1"})
	if !second.HasMore || second.NextCursor == "" {
		t.Fatalf("second page continuation: hasMore=%v cursor=%q", second.HasMore, second.NextCursor)
	}

	thirdResponse := fixture.request(token, url.Values{
		"actor":  {"alice"},
		"limit":  {"2"},
		"cursor": {second.NextCursor},
	}.Encode())
	third := decodeAuditQueryTestPage(t, thirdResponse, http.StatusOK)
	assertAuditQueryTestRequestIDs(t, third.Items, []string{"audit-page-0"})
	if third.HasMore || third.NextCursor != "" {
		t.Fatalf("third page continuation: hasMore=%v cursor=%q", third.HasMore, third.NextCursor)
	}

	seen := make(map[string]struct{}, len(original))
	for _, page := range [][]auditQueryTestItem{first.Items, second.Items, third.Items} {
		for _, item := range page {
			if _, duplicate := seen[item.RequestID]; duplicate {
				t.Fatalf("duplicate request ID across pages: %s", item.RequestID)
			}
			seen[item.RequestID] = struct{}{}
		}
	}
	if len(seen) != len(original) {
		t.Fatalf("paged original event count: got %d, want %d", len(seen), len(original))
	}
}

func TestAuditQueryResponseDoesNotExposeStorageKey(t *testing.T) {
	fixture := newAuditQueryHTTPFixture(t)
	token := fixture.sessionToken(t, fixture.admin)
	stored := fixture.appendEvent(t, "audit-public-request-id", time.Date(2026, 7, 31, 11, 30, 0, 0, time.UTC), "admin")

	response := fixture.request(token, url.Values{"requestID": {stored.RequestID}}.Encode())
	if response.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	var rawPage struct {
		Items []map[string]json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &rawPage); err != nil {
		t.Fatalf("decode audit query response: %v", err)
	}
	if len(rawPage.Items) != 1 {
		t.Fatalf("item count: got %d, want 1", len(rawPage.Items))
	}
	item := rawPage.Items[0]
	if _, exposed := item["id"]; exposed {
		t.Fatalf("audit DTO exposed internal event key as id: %s", response.Body.String())
	}
	var requestID string
	if err := json.Unmarshal(item["requestId"], &requestID); err != nil {
		t.Fatalf("decode public request ID: %v", err)
	}
	if requestID != stored.RequestID {
		t.Fatalf("request ID: got %q, want %q", requestID, stored.RequestID)
	}

	rawKey, err := hex.DecodeString(stored.ID)
	if err != nil {
		t.Fatalf("decode internal event key: %v", err)
	}
	serializedItem, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("encode audit query item: %v", err)
	}
	for name, forbidden := range map[string]string{
		"hex":            stored.ID,
		"base64":         base64.StdEncoding.EncodeToString(rawKey),
		"raw base64":     base64.RawStdEncoding.EncodeToString(rawKey),
		"base64 URL":     base64.URLEncoding.EncodeToString(rawKey),
		"raw base64 URL": base64.RawURLEncoding.EncodeToString(rawKey),
	} {
		if strings.Contains(string(serializedItem), forbidden) {
			t.Errorf("audit DTO exposed %s internal event key %q: %s", name, forbidden, serializedItem)
		}
	}
}

func TestAuditQueryRejectsMissingOrShortCursorKey(t *testing.T) {
	fixture := newAuditQueryHTTPFixture(t)
	fixture.appendEvent(t, "audit-key-gate-event", time.Date(2026, 7, 31, 11, 45, 0, 0, time.UTC), "admin")

	for _, test := range []struct {
		name string
		key  string
	}{
		{name: "missing", key: ""},
		{name: "short", key: "short-audit-cursor-key"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config.Auth.Key = test.key
			request := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
			response := httptest.NewRecorder()
			wrapHandler(auditQueryHandler).ServeHTTP(response, request)
			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusInternalServerError, response.Body.String())
			}
			if test.key != "" && strings.Contains(response.Body.String(), test.key) {
				t.Fatalf("error response exposed rejected signing key: %s", response.Body.String())
			}
		})
	}
}

func TestAuditQueryCursorRejectsShortSigningKey(t *testing.T) {
	shortKey := []byte("short-audit-cursor-key")
	filterDigest := strings.Repeat("a", 64)
	afterID := strings.Repeat("b", 32)

	t.Run("encode", func(t *testing.T) {
		if _, err := encodeAuditCursor(shortKey, filterDigest, afterID); !errors.Is(err, errAuditQueryUnavailable) {
			t.Fatalf("encode short signing key: got %v, want errAuditQueryUnavailable", err)
		}
	})

	t.Run("decode", func(t *testing.T) {
		payload, err := json.Marshal(auditCursorPayload{
			Version:   auditCursorVersion,
			Filter:    filterDigest,
			AfterID:   afterID,
			Direction: auditCursorDirection,
		})
		if err != nil {
			t.Fatalf("encode cursor payload: %v", err)
		}
		encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
		cursor := encodedPayload + "." + base64.RawURLEncoding.EncodeToString(signAuditCursor(shortKey, encodedPayload))
		if _, err := decodeAuditCursor(cursor, shortKey, filterDigest); !errors.Is(err, errAuditQueryInvalid) {
			t.Fatalf("decode short signing key: got %v, want errAuditQueryInvalid", err)
		}
	})
}

func TestAuditQueryInputValidation(t *testing.T) {
	fixture := newAuditQueryHTTPFixture(t)
	token := fixture.sessionToken(t, fixture.admin)
	fixture.appendEvent(t, "audit-validation-event", time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC), "admin")

	longActor := strings.Repeat("a", auditdb.MaxUsernameBytes+1)
	longSource := strings.Repeat("s", auditdb.MaxSourceBytes+1)
	longPath := "/" + strings.Repeat("p", auditdb.MaxPathBytes)
	tests := []struct {
		name  string
		query string
	}{
		{name: "invalid from", query: "from=not-a-time"},
		{name: "invalid to", query: "to=2026-07-31"},
		{name: "from after to", query: "from=2026-08-01T00%3A00%3A00Z&to=2026-07-31T00%3A00%3A00Z"},
		{name: "invalid action", query: "action=file.not_real"},
		{name: "invalid result", query: "result=maybe"},
		{name: "invalid token ref", query: "tokenRef=ABCDEF"},
		{name: "invalid share ref", query: "shareRef=0123456789ABCDEF0123456789ABCDEF"},
		{name: "invalid cursor", query: "cursor=not-a-signed-cursor"},
		{name: "zero limit", query: "limit=0"},
		{name: "limit over maximum", query: "limit=201"},
		{name: "overlong actor", query: url.Values{"actor": {longActor}}.Encode()},
		{name: "overlong source", query: url.Values{"source": {longSource}}.Encode()},
		{name: "overlong path", query: url.Values{"path": {longPath}}.Encode()},
		{name: "duplicate filter", query: "actor=admin&actor=other"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := fixture.request(token, test.query)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusBadRequest, response.Body.String())
			}
		})
	}

	page := decodeAuditQueryTestPage(t, fixture.request(token, ""), http.StatusOK)
	if len(page.Items) != 1 {
		t.Fatalf("default-limit query item count: got %d, want 1", len(page.Items))
	}
}

func TestAuditQuerySecretLeakage(t *testing.T) {
	fixture := newAuditQueryHTTPFixture(t)
	bearer := fixture.sessionToken(t, fixture.admin)
	fixture.appendEvent(t, "audit-secret-terminal-1", time.Date(2026, 7, 31, 13, 0, 0, 0, time.UTC), "admin")
	fixture.appendEvent(t, "audit-secret-terminal-2", time.Date(2026, 7, 31, 13, 1, 0, 0, time.UTC), "admin")

	secrets := []string{
		"Bearer obvious-audit-secret",
		"TokenHash=obvious-token-hash-secret",
		"ShareHash=obvious-share-hash-secret",
		"Authorization=obvious-authorization-secret",
		"Cookie=obvious-cookie-secret",
		"password=obvious-password-secret",
		"OnlyOffice=obvious-onlyoffice-secret",
		`C:\host\private\audit-secret`,
	}
	for index, secret := range secrets {
		pending := queryHTTPAuditEvent(
			"audit-secret-pending-"+string(rune('0'+index)),
			time.Time{},
			secret,
		)
		pending.Result = ""
		pending.HTTPStatus = nil
		pending.TimestampUTC = time.Time{}
		if err := store.Audit.CreatePending(pending); err != nil {
			t.Fatalf("create secret-bearing pending event %d: %v", index, err)
		}
	}

	capture := &securityCaptureLogger{}
	logpkg.SetGlobalLogger(capture)
	t.Cleanup(func() { logpkg.SetGlobalLogger(nil) })
	handler := LoggingMiddleware(withAdmin(auditQueryHandler))
	request := httptest.NewRequest(http.MethodGet, "/api/audit?limit=1", nil)
	request.Header.Set("Authorization", "Bearer "+bearer)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	page := decodeAuditQueryTestPage(t, response, http.StatusOK)
	if page.NextCursor == "" {
		t.Fatal("secret scan requires a non-empty cursor")
	}

	outputs := []string{response.Body.String(), capture.String(), page.NextCursor}
	for _, forbidden := range append(secrets, bearer, fixture.authKey) {
		for _, output := range outputs {
			if strings.Contains(output, forbidden) {
				t.Fatalf("audit query output leaked forbidden value %q: %s", forbidden, output)
			}
		}
	}
	for _, forbiddenField := range []string{
		"tokenHash", "shareHash", "authorization", "cookie", "password", "onlyOfficeSecret",
	} {
		if strings.Contains(strings.ToLower(response.Body.String()), strings.ToLower(forbiddenField)) {
			t.Fatalf("audit DTO exposed forbidden field %q: %s", forbiddenField, response.Body.String())
		}
	}
	var rawPage struct {
		Items []map[string]json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &rawPage); err != nil {
		t.Fatalf("decode audit DTO fields: %v", err)
	}
	for _, item := range rawPage.Items {
		if _, exposed := item["schemaVersion"]; exposed {
			t.Fatalf("audit DTO exposed event schemaVersion: %s", response.Body.String())
		}
	}

	const illegalInputSecret = "BEARER-ILLEGAL-AUDIT-QUERY-SECRET"
	capture.reset()
	badRequest := httptest.NewRequest(http.MethodGet,
		"/api/audit?tokenRef="+url.QueryEscape(illegalInputSecret), nil)
	badRequest.Header.Set("Authorization", "Bearer "+bearer)
	badResponse := httptest.NewRecorder()
	handler.ServeHTTP(badResponse, badRequest)
	if badResponse.Code != http.StatusBadRequest {
		t.Fatalf("invalid secret input status: got %d, want %d", badResponse.Code, http.StatusBadRequest)
	}
	if strings.Contains(badResponse.Body.String(), illegalInputSecret) || strings.Contains(capture.String(), illegalInputSecret) {
		t.Fatalf("invalid audit query leaked through response or logs: response=%s logs=%s", badResponse.Body.String(), capture.String())
	}
}

type auditQueryHTTPFixture struct {
	db      *storm.DB
	handler http.Handler
	authKey string
	admin   *users.User
	user    *users.User
}

func newAuditQueryHTTPFixture(t *testing.T) *auditQueryHTTPFixture {
	t.Helper()
	db, err := storm.Open(filepath.Join(t.TempDir(), "audit-query-http.db"))
	if err != nil {
		t.Fatalf("open audit query HTTP database: %v", err)
	}
	testStore, err := bolt.NewStorage(db)
	if err != nil {
		_ = db.Close()
		t.Fatalf("create audit query HTTP storage: %v", err)
	}

	previousStore := store
	previousConfig := config
	previousAuth := settings.Config.Auth
	authKey := "stable-audit-query-signing-key-at-least-32-bytes"
	testAuth := settings.Auth{Key: authKey}
	store = testStore
	config = &settings.Settings{Auth: testAuth}
	settings.Config.Auth = testAuth

	fixture := &auditQueryHTTPFixture{
		db:      db,
		handler: withAdmin(auditQueryHandler),
		authKey: authKey,
	}
	fixture.admin = fixture.saveUser(t, "audit-admin", users.Permissions{Api: true, Admin: true})
	fixture.user = fixture.saveUser(t, "audit-user", users.Permissions{Api: true})
	t.Cleanup(func() {
		store = previousStore
		config = previousConfig
		settings.Config.Auth = previousAuth
		if err := db.Close(); err != nil {
			t.Errorf("close audit query HTTP database: %v", err)
		}
	})
	return fixture
}

func (fixture *auditQueryHTTPFixture) saveUser(t *testing.T, username string, permissions users.Permissions) *users.User {
	t.Helper()
	user := &users.User{Username: username, Permissions: permissions}
	if err := store.Users.Save(user, false, false); err != nil {
		t.Fatalf("save audit query user %q: %v", username, err)
	}
	return user
}

func (fixture *auditQueryHTTPFixture) sessionToken(t *testing.T, user *users.User) string {
	t.Helper()
	token, _, err := auth.MakeSignedTokenAPI(user, "WEB_TOKEN_audit_query", time.Hour, user.Permissions, false)
	if err != nil {
		t.Fatalf("issue audit query session: %v", err)
	}
	return token
}

func (fixture *auditQueryHTTPFixture) apiToken(
	t *testing.T,
	user *users.User,
	name string,
	permissions users.Permissions,
) string {
	t.Helper()
	token, metadata, err := auth.MakeSignedTokenAPI(user, name, time.Hour, permissions, false)
	if err != nil {
		t.Fatalf("issue audit query API token: %v", err)
	}
	if err := store.Users.AddApiToken(user.ID, name, token, metadata); err != nil {
		t.Fatalf("persist audit query API token: %v", err)
	}
	if err := store.Access.AddApiToken(token, user.ID); err != nil {
		t.Fatalf("index audit query API token: %v", err)
	}
	return token
}

func (fixture *auditQueryHTTPFixture) appendEvent(
	t *testing.T,
	requestID string,
	timestamp time.Time,
	username string,
) auditdb.Event {
	t.Helper()
	event := queryHTTPAuditEvent(requestID, timestamp, username)
	stored, err := store.Audit.AppendTerminal(event)
	if err != nil {
		t.Fatalf("append HTTP audit query event %q: %v", requestID, err)
	}
	return *stored
}

func (fixture *auditQueryHTTPFixture) request(token, rawQuery string) *httptest.ResponseRecorder {
	requestURL := "/api/audit"
	if rawQuery != "" {
		requestURL += "?" + rawQuery
	}
	request := httptest.NewRequest(http.MethodGet, requestURL, nil)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	return response
}

func queryHTTPAuditEvent(requestID string, timestamp time.Time, username string) auditdb.Event {
	userID := uint(42)
	status := http.StatusOK
	return auditdb.Event{
		SchemaVersion: auditdb.CurrentSchemaVersion,
		TimestampUTC:  timestamp,
		RequestID:     requestID,
		UserID:        &userID,
		Username:      username,
		AuthMethod:    auditdb.AuthMethodSession,
		ClientIP:      "192.0.2.42",
		Action:        auditdb.ActionAuditQuery,
		Origin:        auditdb.OriginHTTP,
		Source:        "primary",
		Path:          "/audit/query",
		CanonicalPath: "/audit/query",
		EffectivePermissions: &auditdb.Permissions{
			API: true, Admin: true,
		},
		Result:     auditdb.ResultSuccess,
		HTTPStatus: &status,
		Metadata: &auditdb.MetadataV1{
			SchemaVersion: auditdb.CurrentMetadataSchemaVersion,
			Method:        auditdb.MethodGET,
		},
	}
}

type auditQueryTestPage struct {
	Items      []auditQueryTestItem `json:"items"`
	NextCursor string               `json:"nextCursor"`
	HasMore    bool                 `json:"hasMore"`
}

type auditQueryTestItem struct {
	RequestID string `json:"requestId"`
	Username  string `json:"username"`
}

func decodeAuditQueryTestPage(t *testing.T, response *httptest.ResponseRecorder, wantStatus int) auditQueryTestPage {
	t.Helper()
	if response.Code != wantStatus {
		t.Fatalf("status: got %d, want %d; body=%s", response.Code, wantStatus, response.Body.String())
	}
	var page auditQueryTestPage
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode audit query response: %v; body=%s", err, response.Body.String())
	}
	return page
}

func assertAuditQueryTestRequestIDs(t *testing.T, items []auditQueryTestItem, want []string) {
	t.Helper()
	if len(items) != len(want) {
		t.Fatalf("item count: got %d, want %d (%+v)", len(items), len(want), items)
	}
	for index := range want {
		if items[index].RequestID != want[index] {
			t.Fatalf("item %d request ID: got %q, want %q", index, items[index].RequestID, want[index])
		}
	}
}

func assertAuditCursorOpaque(t *testing.T, cursor string, forbidden []string) {
	t.Helper()
	parts := strings.Split(cursor, ".")
	if len(parts) != 2 {
		t.Fatalf("cursor segment count: got %d, want 2", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode cursor payload: %v", err)
	}
	for _, value := range forbidden {
		if strings.Contains(cursor, value) || strings.Contains(string(payload), value) {
			t.Fatalf("cursor exposed forbidden value %q", value)
		}
	}
}

func cursorReplacement(last byte) string {
	if last == 'A' {
		return "B"
	}
	return "A"
}
