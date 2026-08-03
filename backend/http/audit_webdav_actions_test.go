package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

const auditWebDAVLockBody = `<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner><D:href>audit-webdav-owner-secret</D:href></D:owner></D:lockinfo>`

type auditWebDAVFixture struct {
	sourcePath string
	user       *users.User
	token      string
	store      *auditStoreStub
	service    *AuditService
	handler    http.Handler
}

func newAuditWebDAVFixture(t *testing.T, permissions users.Permissions) *auditWebDAVFixture {
	t.Helper()

	if config == nil {
		config = &settings.Settings{}
	}
	sourcePath, secondSourcePath := setupWebDAVTestEnv(t)
	installPermissionWebDAVSecurityFilesystemMocks(sourcePath, secondSourcePath)
	configurePermissionWebDAVAuth(t)
	user := &users.User{
		Username:    "audit-webdav-user",
		Permissions: permissions,
		Scopes: []users.SourceScope{
			{Name: sourcePath, Scope: "/"},
		},
	}
	savePermissionWebDAVUser(t, user)
	token := issuePermissionReadWebToken(t, user)
	auditStore := newAuditStoreStub()
	service := NewAuditService(auditStore)
	router := http.NewServeMux()
	router.Handle("/dav/{source}/{path...}", withAuditWebDAV(webDAVHandler))

	return &auditWebDAVFixture{
		sourcePath: sourcePath,
		user:       user,
		token:      token,
		store:      auditStore,
		service:    service,
		handler:    AuditMiddleware(LoggingMiddleware(router), service),
	}
}

func auditWebDAVFullPermissions() users.Permissions {
	return users.Permissions{
		Api:      true,
		Modify:   true,
		Delete:   true,
		Create:   true,
		Browse:   true,
		Download: true,
	}
}

func (fixture *auditWebDAVFixture) request(method, requestPath string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "/dav/source1"+requestPath, bytes.NewReader(body))
	request.SetBasicAuth("ignored", fixture.token)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	return response
}

func (fixture *auditWebDAVFixture) directRequest(t *testing.T, method, requestPath string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequest(method, "/dav/source1"+requestPath, bytes.NewReader(body))
	request.SetPathValue("source", "source1")
	request.SetPathValue("path", requestPath)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	status, err := webDAVHandler(response, request, &requestContext{user: fixture.user})
	if err != nil {
		t.Fatalf("direct WebDAV %s failed: status=%d err=%v", method, status, err)
	}
	if status != 0 && status != http.StatusOK && response.Code == http.StatusOK {
		response.Code = status
	}
	return response
}

func auditWebDAVStoreSnapshot(store *auditStoreStub) (creates, finalizes, appends, pending, terminal int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.createCalls, store.finalizeCalls, store.appendCalls, len(store.pending), len(store.appended)
}

func requireAuditWebDAVReadEvent(t *testing.T, fixture *auditWebDAVFixture, response *httptest.ResponseRecorder, result auditdb.Result) auditdb.Event {
	t.Helper()

	creates, finalizes, appends, pending, terminal := auditWebDAVStoreSnapshot(fixture.store)
	if creates != 0 || finalizes != 0 || appends != 1 || pending != 0 || terminal != 1 {
		t.Fatalf("read audit writes: create=%d finalize=%d append=%d pending=%d terminal=%d; want 0,0,1,0,1",
			creates, finalizes, appends, pending, terminal)
	}
	event := fixture.store.singleAppended(t)
	if event.Action != auditdb.ActionWebDAVRead || event.Origin != auditdb.OriginWebDAV || event.Result != result {
		t.Errorf("read action/origin/result: got %q/%q/%q", event.Action, event.Origin, event.Result)
	}
	if event.HTTPStatus == nil || *event.HTTPStatus != response.Code {
		t.Errorf("HTTP status: got %v, want %d", event.HTTPStatus, response.Code)
	}
	if event.Metadata == nil || event.Metadata.Bytes == nil || *event.Metadata.Bytes != int64(response.Body.Len()) {
		t.Errorf("response bytes: metadata=%+v want=%d", event.Metadata, response.Body.Len())
	}
	return event
}

func requireAuditWebDAVWriteEvent(t *testing.T, fixture *auditWebDAVFixture, response *httptest.ResponseRecorder, method string, result auditdb.Result) auditdb.Event {
	t.Helper()

	creates, finalizes, appends, pending, terminal := auditWebDAVStoreSnapshot(fixture.store)
	if creates != 1 || finalizes != 1 || appends != 0 || pending != 0 || terminal != 1 {
		t.Fatalf("write audit writes: create=%d finalize=%d append=%d pending=%d terminal=%d; want 1,1,0,0,1",
			creates, finalizes, appends, pending, terminal)
	}
	event := fixture.store.singleAppended(t)
	if event.Action != auditdb.ActionWebDAVWrite || event.Origin != auditdb.OriginWebDAV || event.Result != result {
		t.Errorf("write action/origin/result: got %q/%q/%q", event.Action, event.Origin, event.Result)
	}
	if event.HTTPStatus == nil || *event.HTTPStatus != response.Code {
		t.Errorf("HTTP status: got %v, want %d", event.HTTPStatus, response.Code)
	}
	if event.Metadata == nil || event.Metadata.Method != auditdb.Method(method) || event.Metadata.Bytes == nil || *event.Metadata.Bytes != int64(response.Body.Len()) {
		t.Errorf("method/bytes metadata: got %+v, want method=%s bytes=%d", event.Metadata, method, response.Body.Len())
	}
	return event
}

func requireAuditWebDAVActor(t *testing.T, fixture *auditWebDAVFixture, event auditdb.Event) {
	t.Helper()

	if event.AuthMethod != auditdb.AuthMethodWebDAV {
		t.Errorf("auth method: got %q, want %q", event.AuthMethod, auditdb.AuthMethodWebDAV)
	}
	if event.UserID == nil || *event.UserID != fixture.user.ID || event.Username != fixture.user.Username {
		t.Errorf("actor: got %v/%q, want %d/%q", event.UserID, event.Username, fixture.user.ID, fixture.user.Username)
	}
	wantPermissions := auditPermissions(fixture.user.Permissions)
	if event.EffectivePermissions == nil || *event.EffectivePermissions != wantPermissions {
		t.Errorf("effective permissions: got %+v, want %+v", event.EffectivePermissions, wantPermissions)
	}
	if event.TokenRef != "" || event.ShareRef != "" {
		t.Errorf("session WebDAV references: token=%q share=%q", event.TokenRef, event.ShareRef)
	}
}

func requireAuditWebDAVResource(t *testing.T, event auditdb.Event, path, canonicalPath string) {
	t.Helper()

	if event.Source != "source1" || event.Path != path || event.CanonicalPath != canonicalPath {
		t.Errorf("resource: source=%q path=%q canonical=%q, want source1/%q/%q",
			event.Source, event.Path, event.CanonicalPath, path, canonicalPath)
	}
}

func assertAuditWebDAVSecretsAbsent(t *testing.T, event auditdb.Event, secrets ...string) {
	t.Helper()

	serialized, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		encoded, err := json.Marshal(secret)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(serialized, encoded[1:len(encoded)-1]) {
			t.Errorf("audit event leaked secret %q: %s", secret, serialized)
		}
	}
	for _, value := range []string{event.Source, event.Path, event.CanonicalPath, event.TargetSource, event.TargetPath, event.TargetCanonicalPath} {
		if volume := filepath.VolumeName(value); volume != "" || strings.Contains(value, `\`) ||
			strings.Contains(value, "://") || strings.ContainsAny(value, "\r\n") {
			t.Errorf("audit event leaked a host path %q", value)
		}
	}
}

func TestAuditWebDAVReadActions(t *testing.T) {
	for _, test := range []struct {
		name        string
		method      string
		path        string
		headers     map[string]string
		permissions users.Permissions
		wantStatus  int
		wantResult  auditdb.Result
		wantPath    string
	}{
		{name: "PROPFIND success", method: "PROPFIND", path: "/public/", headers: map[string]string{"Depth": "1"}, permissions: auditWebDAVFullPermissions(), wantStatus: http.StatusMultiStatus, wantResult: auditdb.ResultSuccess, wantPath: "/public"},
		{name: "PROPFIND denied", method: "PROPFIND", path: "/public/", headers: map[string]string{"Depth": "1"}, permissions: users.Permissions{Download: true}, wantStatus: http.StatusForbidden, wantResult: auditdb.ResultDenied},
		{name: "GET success", method: http.MethodGet, path: "/public/readme.txt", permissions: auditWebDAVFullPermissions(), wantStatus: http.StatusOK, wantResult: auditdb.ResultSuccess, wantPath: "/public/readme.txt"},
		{name: "HEAD success", method: http.MethodHead, path: "/public/readme.txt", permissions: auditWebDAVFullPermissions(), wantStatus: http.StatusOK, wantResult: auditdb.ResultSuccess, wantPath: "/public/readme.txt"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAuditWebDAVFixture(t, test.permissions)
			response := fixture.request(test.method, test.path, nil, test.headers)
			if response.Code != test.wantStatus {
				t.Fatalf("business status: got %d, want %d (body=%q)", response.Code, test.wantStatus, response.Body.String())
			}
			event := requireAuditWebDAVReadEvent(t, fixture, response, test.wantResult)
			requireAuditWebDAVActor(t, fixture, event)
			if test.wantPath != "" {
				requireAuditWebDAVResource(t, event, test.wantPath, test.wantPath)
			} else if event.Source != "" || event.Path != "" || event.CanonicalPath != "" ||
				event.TargetSource != "" || event.TargetPath != "" || event.TargetCanonicalPath != "" {
				t.Errorf("denied request recorded unverified resource: %+v", event)
			}
			if test.method == http.MethodHead && response.Body.Len() != 0 {
				t.Errorf("HEAD response body: got %q", response.Body.String())
			}
			assertAuditWebDAVSecretsAbsent(t, event, fixture.sourcePath, fixture.token)
		})
	}
}

func TestAuditWebDAVPreAuthentication401(t *testing.T) {
	fixture := newAuditWebDAVFixture(t, auditWebDAVFullPermissions())
	const unverifiedPath = "/public/unauthenticated-path-secret.txt"
	request := httptest.NewRequest(http.MethodGet, "/dav/source1"+unverifiedPath, nil)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("business status: got %d, want 401 (body=%q)", response.Code, response.Body.String())
	}

	event := requireAuditWebDAVReadEvent(t, fixture, response, auditdb.ResultDenied)
	if event.AuthMethod != auditdb.AuthMethodWebDAV {
		t.Errorf("auth method: got %q, want %q", event.AuthMethod, auditdb.AuthMethodWebDAV)
	}
	if event.UserID != nil || event.Username != "" || event.EffectivePermissions != nil || event.TokenRef != "" {
		t.Errorf("unauthenticated identity leaked into audit event: user=%v/%q permissions=%+v token=%q",
			event.UserID, event.Username, event.EffectivePermissions, event.TokenRef)
	}
	if event.Source != "" || event.Path != "" || event.CanonicalPath != "" {
		t.Errorf("unauthenticated request recorded unverified resource: source=%q path=%q canonical=%q",
			event.Source, event.Path, event.CanonicalPath)
	}
	assertAuditWebDAVSecretsAbsent(t, event, unverifiedPath)
}

func TestAuditWebDAVOptionsDoesNotRecordAction(t *testing.T) {
	fixture := newAuditWebDAVFixture(t, auditWebDAVFullPermissions())
	response := fixture.request(http.MethodOptions, "/public/", nil, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("OPTIONS status: got %d, want 200 (body=%q)", response.Code, response.Body.String())
	}
	creates, finalizes, appends, pending, terminal := auditWebDAVStoreSnapshot(fixture.store)
	if creates != 0 || finalizes != 0 || appends != 0 || pending != 0 || terminal != 0 {
		t.Fatalf("OPTIONS audit writes: create=%d finalize=%d append=%d pending=%d terminal=%d; want all zero",
			creates, finalizes, appends, pending, terminal)
	}
}

func TestAuditWebDAVAPITokenPermissionIntersection(t *testing.T) {
	fixture := newAuditWebDAVFixture(t, auditWebDAVFullPermissions())
	tokenPermissions := users.Permissions{Browse: true}
	token := issuePermissionWebDAVAPIToken(t, fixture.user, "audit-webdav-browse-token", tokenPermissions)
	fixture.token = token

	response := fixture.request("PROPFIND", "/public/", nil, map[string]string{"Depth": "1"})
	if response.Code != http.StatusMultiStatus {
		t.Fatalf("business status: got %d, want 207 (body=%q)", response.Code, response.Body.String())
	}
	event := requireAuditWebDAVReadEvent(t, fixture, response, auditdb.ResultSuccess)
	if event.AuthMethod != auditdb.AuthMethodToken {
		t.Errorf("auth method: got %q, want %q", event.AuthMethod, auditdb.AuthMethodToken)
	}
	if event.UserID == nil || *event.UserID != fixture.user.ID || event.Username != fixture.user.Username {
		t.Errorf("actor: got %v/%q, want %d/%q", event.UserID, event.Username, fixture.user.ID, fixture.user.Username)
	}
	wantPermissions := auditPermissions(users.IntersectPermissions(fixture.user.Permissions, tokenPermissions))
	if event.EffectivePermissions == nil || *event.EffectivePermissions != wantPermissions {
		t.Errorf("effective permissions: got %+v, want %+v", event.EffectivePermissions, wantPermissions)
	}
	wantTokenRef := auditdb.DeriveTokenRef(utils.HashSHA256(token))
	if event.TokenRef != wantTokenRef || event.TokenRef == "" || event.ShareRef != "" {
		t.Errorf("references: got token=%q share=%q, want token=%q and no share", event.TokenRef, event.ShareRef, wantTokenRef)
	}
	requireAuditWebDAVResource(t, event, "/public", "/public")
	assertAuditWebDAVSecretsAbsent(t, event, token, utils.HashSHA256(token), fixture.sourcePath)
}

func TestAuditWebDAVAPITokenDeniedIntersection(t *testing.T) {
	fixture := newAuditWebDAVFixture(t, auditWebDAVFullPermissions())
	tokenPermissions := users.Permissions{Download: true}
	token := issuePermissionWebDAVAPIToken(t, fixture.user, "audit-webdav-download-token", tokenPermissions)
	fixture.token = token

	response := fixture.request("PROPFIND", "/public/", nil, map[string]string{"Depth": "1"})
	if response.Code != http.StatusForbidden {
		t.Fatalf("business status: got %d, want 403 (body=%q)", response.Code, response.Body.String())
	}
	event := requireAuditWebDAVReadEvent(t, fixture, response, auditdb.ResultDenied)
	wantPermissions := auditPermissions(users.IntersectPermissions(fixture.user.Permissions, tokenPermissions))
	wantTokenRef := auditdb.DeriveTokenRef(utils.HashSHA256(token))
	if event.AuthMethod != auditdb.AuthMethodToken || event.EffectivePermissions == nil ||
		*event.EffectivePermissions != wantPermissions || event.TokenRef != wantTokenRef {
		t.Errorf("denied token identity: auth=%q permissions=%+v token=%q", event.AuthMethod, event.EffectivePermissions, event.TokenRef)
	}
	if event.Source != "" || event.Path != "" || event.CanonicalPath != "" {
		t.Errorf("denied token recorded unverified resource: %+v", event)
	}
	assertAuditWebDAVSecretsAbsent(t, event, token, utils.HashSHA256(token), fixture.sourcePath)
}

func TestAuditWebDAVClientCancellation(t *testing.T) {
	fixture := newAuditWebDAVFixture(t, auditWebDAVFullPermissions())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer := newCoreFileAuditCancelWriter(cancel)
	request := httptest.NewRequest(http.MethodGet, "/dav/source1/public/readme.txt", nil).WithContext(ctx)
	request.SetBasicAuth("ignored", fixture.token)
	fixture.handler.ServeHTTP(writer, request)

	creates, finalizes, appends, pending, terminal := auditWebDAVStoreSnapshot(fixture.store)
	if creates != 0 || finalizes != 0 || appends != 1 || pending != 0 || terminal != 1 {
		t.Fatalf("cancelled audit writes: create=%d finalize=%d append=%d pending=%d terminal=%d; want 0,0,1,0,1",
			creates, finalizes, appends, pending, terminal)
	}
	event := fixture.store.singleAppended(t)
	if event.Action != auditdb.ActionWebDAVRead || event.Result != auditdb.ResultCancelled {
		t.Errorf("cancelled action/result: got %q/%q", event.Action, event.Result)
	}
	if event.HTTPStatus == nil || *event.HTTPStatus != writer.statusCode() {
		t.Errorf("HTTP status: got %v, want %d", event.HTTPStatus, writer.statusCode())
	}
	if event.Metadata == nil || event.Metadata.ClientCancelled == nil || !*event.Metadata.ClientCancelled {
		t.Errorf("client cancellation metadata: got %+v", event.Metadata)
	}
	if event.Metadata == nil || event.Metadata.Bytes == nil || *event.Metadata.Bytes != int64(writer.body.Len()) {
		t.Errorf("response bytes: metadata=%+v want=%d", event.Metadata, writer.body.Len())
	}
	requireAuditWebDAVResource(t, event, "/public/readme.txt", "/public/readme.txt")
}

func TestAuditWebDAVRealFailureStatuses(t *testing.T) {
	t.Run("404 missing read", func(t *testing.T) {
		fixture := newAuditWebDAVFixture(t, auditWebDAVFullPermissions())
		response := fixture.request(http.MethodGet, "/public/missing.txt", nil, nil)
		if response.Code != http.StatusNotFound {
			t.Fatalf("business status: got %d, want 404 (body=%q)", response.Code, response.Body.String())
		}
		event := requireAuditWebDAVReadEvent(t, fixture, response, auditdb.ResultFailed)
		if event.Source != "" || event.Path != "" || event.CanonicalPath != "" {
			t.Errorf("missing read recorded unverified resource: %+v", event)
		}
	})

	t.Run("409 stale unlock", func(t *testing.T) {
		fixture := newAuditWebDAVFixture(t, auditWebDAVFullPermissions())
		locked := fixture.directRequest(t, "LOCK", "/public/readme.txt", []byte(auditWebDAVLockBody), nil)
		lockToken := locked.Header().Get("Lock-Token")
		if locked.Code != http.StatusOK || lockToken == "" {
			t.Fatalf("setup LOCK status=%d token=%q body=%q", locked.Code, lockToken, locked.Body.String())
		}
		unlocked := fixture.directRequest(t, "UNLOCK", "/public/readme.txt", nil, map[string]string{"Lock-Token": lockToken})
		if unlocked.Code != http.StatusNoContent {
			t.Fatalf("setup UNLOCK status=%d body=%q", unlocked.Code, unlocked.Body.String())
		}

		response := fixture.request("UNLOCK", "/public/readme.txt", nil, map[string]string{"Lock-Token": lockToken})
		if response.Code != http.StatusConflict {
			t.Fatalf("business status: got %d, want 409 (body=%q)", response.Code, response.Body.String())
		}
		event := requireAuditWebDAVWriteEvent(t, fixture, response, "UNLOCK", auditdb.ResultFailed)
		requireAuditWebDAVResource(t, event, "/public/readme.txt", "/public/readme.txt")
		assertAuditWebDAVSecretsAbsent(t, event, lockToken)
	})

	t.Run("412 mismatched lock refresh", func(t *testing.T) {
		fixture := newAuditWebDAVFixture(t, auditWebDAVFullPermissions())
		locked := fixture.directRequest(t, "LOCK", "/public/readme.txt", []byte(auditWebDAVLockBody), nil)
		lockToken := locked.Header().Get("Lock-Token")
		if locked.Code != http.StatusOK || lockToken == "" {
			t.Fatalf("setup LOCK status=%d token=%q body=%q", locked.Code, lockToken, locked.Body.String())
		}
		t.Cleanup(func() {
			fixture.directRequest(t, "UNLOCK", "/public/readme.txt", nil, map[string]string{"Lock-Token": lockToken})
		})

		ifHeader := "(" + lockToken + ")"
		response := fixture.request("LOCK", "/public/refresh-target.txt", nil, map[string]string{"If": ifHeader})
		if response.Code != http.StatusPreconditionFailed {
			t.Fatalf("business status: got %d, want 412 (body=%q)", response.Code, response.Body.String())
		}
		event := requireAuditWebDAVWriteEvent(t, fixture, response, "LOCK", auditdb.ResultFailed)
		requireAuditWebDAVResource(t, event, "/public/refresh-target.txt", "/public/refresh-target.txt")
		assertAuditWebDAVSecretsAbsent(t, event, lockToken, ifHeader)
	})

	t.Run("423 put blocked by lock", func(t *testing.T) {
		fixture := newAuditWebDAVFixture(t, auditWebDAVFullPermissions())
		locked := fixture.directRequest(t, "LOCK", "/public/readme.txt", []byte(auditWebDAVLockBody), nil)
		lockToken := locked.Header().Get("Lock-Token")
		if locked.Code != http.StatusOK || lockToken == "" {
			t.Fatalf("setup LOCK status=%d token=%q body=%q", locked.Code, lockToken, locked.Body.String())
		}
		t.Cleanup(func() {
			fixture.directRequest(t, "UNLOCK", "/public/readme.txt", nil, map[string]string{"Lock-Token": lockToken})
		})

		response := fixture.request(http.MethodPut, "/public/readme.txt", []byte("must not replace locked file"), nil)
		if response.Code != http.StatusLocked {
			t.Fatalf("business status: got %d, want 423 (body=%q)", response.Code, response.Body.String())
		}
		event := requireAuditWebDAVWriteEvent(t, fixture, response, http.MethodPut, auditdb.ResultFailed)
		requireAuditWebDAVResource(t, event, "/public/readme.txt", "/public/readme.txt")
		content, err := os.ReadFile(filepath.Join(fixture.sourcePath, "public", "readme.txt"))
		if err != nil || string(content) != "public content" {
			t.Errorf("locked PUT changed target: content=%q err=%v", content, err)
		}
	})
}

func TestAuditWebDAVWriteActions(t *testing.T) {
	for _, method := range []string{http.MethodPut, "PUT_OVERWRITE", "MKCOL", "COPY", "MOVE", http.MethodDelete, "LOCK", "UNLOCK"} {
		t.Run(method, func(t *testing.T) {
			fixture := newAuditWebDAVFixture(t, auditWebDAVFullPermissions())
			requestMethod := method
			requestPath := "/public/audit-write.txt"
			body := []byte("audit webdav write")
			headers := map[string]string{}
			wantStatus := http.StatusCreated
			wantPath := requestPath
			wantTarget := ""
			secrets := []string{fixture.sourcePath, fixture.token}

			switch method {
			case "PUT_OVERWRITE":
				requestMethod = http.MethodPut
				requestPath = "/public/readme.txt"
				wantPath = requestPath
			case "MKCOL":
				body = nil
				requestPath = "/public/audit-directory"
				wantPath = requestPath
			case "COPY":
				body = nil
				requestPath = "/public/readme.txt"
				wantPath = requestPath
				wantTarget = "/public/audit-copy.txt"
				destinationSecret := "destination-query-secret"
				headers["Destination"] = "http://example.com/dav/source1" + wantTarget + "?credential=" + destinationSecret + "#fragment-secret"
				secrets = append(secrets, headers["Destination"], destinationSecret, "fragment-secret")
			case "MOVE":
				body = nil
				requestPath = "/public/audit-move-source.txt"
				wantPath = requestPath
				wantTarget = "/public/audit-move-target.txt"
				if err := os.WriteFile(filepath.Join(fixture.sourcePath, "public", "audit-move-source.txt"), []byte("move body"), 0o644); err != nil {
					t.Fatal(err)
				}
				headers["Destination"] = "http://example.com/dav/source1" + wantTarget
			case http.MethodDelete:
				body = nil
				requestPath = "/public/audit-delete.txt"
				wantPath = requestPath
				wantStatus = http.StatusNoContent
				if err := os.WriteFile(filepath.Join(fixture.sourcePath, "public", "audit-delete.txt"), []byte("delete body"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "LOCK":
				requestPath = "/public/readme.txt"
				wantPath = requestPath
				wantStatus = http.StatusOK
				body = []byte(auditWebDAVLockBody)
				headers["Timeout"] = "Second-3600"
				secrets = append(secrets, "audit-webdav-owner-secret", auditWebDAVLockBody, headers["Timeout"])
			case "UNLOCK":
				requestPath = "/public/readme.txt"
				wantPath = requestPath
				body = nil
				wantStatus = http.StatusNoContent
				locked := fixture.directRequest(t, "LOCK", requestPath, []byte(auditWebDAVLockBody), nil)
				lockToken := locked.Header().Get("Lock-Token")
				if lockToken == "" {
					t.Fatal("direct LOCK did not return a token")
				}
				headers["Lock-Token"] = lockToken
				headers["If"] = "(" + lockToken + ")"
				secrets = append(secrets, lockToken, headers["If"])
			}

			response := fixture.request(requestMethod, requestPath, body, headers)
			if response.Code != wantStatus {
				t.Fatalf("business status: got %d, want %d (body=%q)", response.Code, wantStatus, response.Body.String())
			}
			event := requireAuditWebDAVWriteEvent(t, fixture, response, requestMethod, auditdb.ResultSuccess)
			requireAuditWebDAVActor(t, fixture, event)
			requireAuditWebDAVResource(t, event, wantPath, wantPath)
			if wantTarget != "" && (event.TargetSource != "source1" || event.TargetPath != wantTarget || event.TargetCanonicalPath != wantTarget) {
				t.Errorf("target: source=%q path=%q canonical=%q, want source1/%q/%q",
					event.TargetSource, event.TargetPath, event.TargetCanonicalPath, wantTarget, wantTarget)
			}
			assertAuditWebDAVSecretsAbsent(t, event, secrets...)
		})
	}
}

func TestAuditWebDAVReservationFailureHasNoSideEffects(t *testing.T) {
	for _, method := range []string{http.MethodPut, "PUT_OVERWRITE", "MKCOL", "COPY", "MOVE", http.MethodDelete, "LOCK", "UNLOCK"} {
		t.Run(method, func(t *testing.T) {
			fixture := newAuditWebDAVFixture(t, auditWebDAVFullPermissions())
			fixture.store.createErr = errors.New("reservation failed with hidden audit secret")
			requestMethod := method
			requestPath := "/public/reservation-target.txt"
			body := []byte("must not be written")
			headers := map[string]string{}
			businessPath := filepath.Join(fixture.sourcePath, "public", "reservation-target.txt")
			wantExistingContent := ""
			moveSourcePath := ""
			lockToken := ""
			checkBusinessPath := true

			switch method {
			case "PUT_OVERWRITE":
				requestMethod = http.MethodPut
				requestPath = "/public/reservation-overwrite.txt"
				businessPath = filepath.Join(fixture.sourcePath, "public", "reservation-overwrite.txt")
				wantExistingContent = "original content must survive"
				if err := os.WriteFile(businessPath, []byte(wantExistingContent), 0o644); err != nil {
					t.Fatal(err)
				}
			case "MKCOL":
				body = nil
				businessPath = filepath.Join(fixture.sourcePath, "public", "reservation-directory")
				requestPath = "/public/reservation-directory"
			case "COPY":
				body = nil
				requestPath = "/public/readme.txt"
				headers["Destination"] = "http://example.com/dav/source1/public/reservation-copy.txt"
				businessPath = filepath.Join(fixture.sourcePath, "public", "reservation-copy.txt")
			case "MOVE":
				body = nil
				requestPath = "/public/reservation-move-source.txt"
				moveSourcePath = filepath.Join(fixture.sourcePath, "public", "reservation-move-source.txt")
				if err := os.WriteFile(moveSourcePath, []byte("move source must survive"), 0o644); err != nil {
					t.Fatal(err)
				}
				headers["Destination"] = "http://example.com/dav/source1/public/reservation-move-target.txt"
				businessPath = filepath.Join(fixture.sourcePath, "public", "reservation-move-target.txt")
			case http.MethodDelete:
				body = nil
				requestPath = "/public/reservation-delete.txt"
				businessPath = filepath.Join(fixture.sourcePath, "public", "reservation-delete.txt")
				wantExistingContent = "must survive"
				if err := os.WriteFile(businessPath, []byte(wantExistingContent), 0o644); err != nil {
					t.Fatal(err)
				}
			case "LOCK":
				body = []byte(auditWebDAVLockBody)
			case "UNLOCK":
				requestPath = "/public/readme.txt"
				body = nil
				checkBusinessPath = false
				locked := fixture.directRequest(t, "LOCK", requestPath, []byte(auditWebDAVLockBody), nil)
				lockToken = locked.Header().Get("Lock-Token")
				if lockToken == "" {
					t.Fatal("direct LOCK did not return a token")
				}
				headers["Lock-Token"] = lockToken
			}

			response := fixture.request(requestMethod, requestPath, body, headers)
			if response.Code != http.StatusServiceUnavailable {
				t.Errorf("reservation failure status: got %d, want 503 (body=%q)", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "reservation failed with hidden audit secret") {
				t.Errorf("reservation failure response leaked audit error: %q", response.Body.String())
			}
			if checkBusinessPath && wantExistingContent == "" {
				if _, err := os.Stat(businessPath); !os.IsNotExist(err) {
					t.Errorf("reservation failure caused a business side effect at %s: %v", businessPath, err)
				}
			} else if checkBusinessPath {
				content, err := os.ReadFile(businessPath)
				if err != nil || string(content) != wantExistingContent {
					t.Errorf("reservation failure changed existing content: content=%q err=%v", content, err)
				}
			}
			if moveSourcePath != "" {
				content, err := os.ReadFile(moveSourcePath)
				if err != nil || string(content) != "move source must survive" {
					t.Errorf("reservation failure moved or changed source: content=%q err=%v", content, err)
				}
			}
			if lockToken != "" {
				unlocked := fixture.directRequest(t, "UNLOCK", requestPath, nil, map[string]string{"Lock-Token": lockToken})
				if unlocked.Code != http.StatusNoContent {
					t.Errorf("reservation failure removed lock: cleanup UNLOCK status=%d body=%q", unlocked.Code, unlocked.Body.String())
				}
			}
			if method == "LOCK" {
				locked := fixture.directRequest(t, "LOCK", requestPath, []byte(auditWebDAVLockBody), nil)
				if locked.Code != http.StatusCreated {
					t.Errorf("reservation failure left a lock: verification LOCK status=%d body=%q", locked.Code, locked.Body.String())
				} else if token := locked.Header().Get("Lock-Token"); token == "" {
					t.Error("verification LOCK did not return a lock token")
				} else {
					unlocked := fixture.directRequest(t, "UNLOCK", requestPath, nil, map[string]string{"Lock-Token": token})
					if unlocked.Code != http.StatusNoContent {
						t.Errorf("verification lock cleanup status=%d body=%q", unlocked.Code, unlocked.Body.String())
					}
				}
			}
			creates, finalizes, appends, pending, terminal := auditWebDAVStoreSnapshot(fixture.store)
			if creates != 1 || finalizes != 0 || appends != 0 || pending != 0 || terminal != 0 {
				t.Errorf("reservation failure writes: create=%d finalize=%d append=%d pending=%d terminal=%d; want 1,0,0,0,0",
					creates, finalizes, appends, pending, terminal)
			}
			if !fixture.service.IsDegraded() || fixture.service.LastFailureCategory() != AuditFailureReservation {
				t.Errorf("reservation failure degraded state: degraded=%v category=%q",
					fixture.service.IsDegraded(), fixture.service.LastFailureCategory())
			}
		})
	}
}

func TestAuditWebDAVFinalizeFailureRetainsPending(t *testing.T) {
	fixture := newAuditWebDAVFixture(t, auditWebDAVFullPermissions())
	fixture.store.finalizeErr = errors.New("finalize failed with hidden audit secret")
	const content = "committed before finalize failure"
	response := fixture.request(http.MethodPut, "/public/finalize-failure.txt", []byte(content), nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("business status: got %d, want 201 (body=%q)", response.Code, response.Body.String())
	}
	written, err := os.ReadFile(filepath.Join(fixture.sourcePath, "public", "finalize-failure.txt"))
	if err != nil || string(written) != content {
		t.Fatalf("committed file: content=%q err=%v", written, err)
	}

	creates, finalizes, appends, pending, terminal := auditWebDAVStoreSnapshot(fixture.store)
	if creates != 1 || finalizes != 1 || appends != 0 || pending != 1 || terminal != 0 {
		t.Fatalf("finalize failure writes: create=%d finalize=%d append=%d pending=%d terminal=%d; want 1,1,0,1,0",
			creates, finalizes, appends, pending, terminal)
	}
	pendingEvent := fixture.store.singlePending(t)
	if pendingEvent.Action != auditdb.ActionWebDAVWrite || pendingEvent.Result != "" || pendingEvent.HTTPStatus != nil {
		t.Errorf("pending event was terminalized after finalize failure: %+v", pendingEvent)
	}
	requireAuditWebDAVResource(t, pendingEvent, "/public/finalize-failure.txt", "/public/finalize-failure.txt")
	assertAuditWebDAVSecretsAbsent(t, pendingEvent, "finalize failed with hidden audit secret", fixture.sourcePath, fixture.token)
	if !fixture.service.IsDegraded() || fixture.service.LastFailureCategory() != AuditFailureFinalize {
		t.Errorf("finalize failure degraded state: degraded=%v category=%q",
			fixture.service.IsDegraded(), fixture.service.LastFailureCategory())
	}
}

func TestWebDAVDelayedBodyAuditDoesNotDeadlock(t *testing.T) {
	fixture := newAuditWebDAVFixture(t, auditWebDAVFullPermissions())
	started := make(chan struct{})
	release := make(chan struct{})
	body := &permissionWebDAVBlockingReader{
		reader:  strings.NewReader("delayed audit body"),
		started: started,
		release: release,
	}
	request := httptest.NewRequest(http.MethodPut, "/dav/source1/public/delayed-audit.txt", body)
	request.SetBasicAuth("ignored", fixture.token)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		fixture.handler.ServeHTTP(response, request)
		close(done)
	}()

	select {
	case <-started:
	case <-done:
		t.Fatalf("audited delayed-body WebDAV request returned before reading the body: status=%d body=%q",
			response.Code, response.Body.String())
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("audited delayed-body WebDAV request did not begin reading the body")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("audited delayed-body WebDAV request deadlocked")
	}
	if response.Code != http.StatusCreated {
		t.Fatalf("delayed PUT status: got %d, want 201", response.Code)
	}
	event := requireAuditWebDAVWriteEvent(t, fixture, response, http.MethodPut, auditdb.ResultSuccess)
	requireAuditWebDAVResource(t, event, "/public/delayed-audit.txt", "/public/delayed-audit.txt")
}
