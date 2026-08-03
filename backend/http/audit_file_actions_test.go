package http

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	dbshare "github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/preview"
)

const coreFileAuditUploadBody = "core-file-audit-upload-body"

type coreFileAuditEnvironment struct {
	sourcePath string
	token      string
}

func newCoreFileAuditEnvironment(t *testing.T) *coreFileAuditEnvironment {
	t.Helper()

	harness := newPermissionReadSecurityHarness(t)
	indexPermissionReadPublicDirectory(t)
	configurePermissionReadAuth(t)
	permissions := users.Permissions{
		Api:      true,
		Modify:   true,
		Share:    true,
		Delete:   true,
		Create:   true,
		Browse:   true,
		Preview:  true,
		Download: true,
	}
	user := &users.User{
		Username:    "core-file-audit-user",
		Permissions: permissions,
		Scopes: []users.SourceScope{
			{Name: harness.sourcePath, Scope: "/"},
		},
	}
	savePermissionReadUser(t, user)
	return &coreFileAuditEnvironment{
		sourcePath: harness.sourcePath,
		token:      issuePermissionReadWebToken(t, user),
	}
}

func newCoreFileAuditUserToken(t *testing.T, sourcePath, username string, permissions users.Permissions) string {
	t.Helper()
	user := &users.User{
		Username:    username,
		Permissions: permissions,
		Scopes: []users.SourceScope{
			{Name: sourcePath, Scope: "/"},
		},
	}
	savePermissionReadUser(t, user)
	return issuePermissionReadWebToken(t, user)
}

func newCoreFileAuditRouter(auditStore *auditStoreStub) http.Handler {
	api := http.NewServeMux()
	publicAPI := http.NewServeMux()
	registerCoreFileActionRoutes(api, publicAPI)

	router := http.NewServeMux()
	router.Handle("/api/", http.StripPrefix("/api", api))
	router.Handle("/public/api/", http.StripPrefix("/public/api", publicAPI))
	return AuditMiddleware(LoggingMiddleware(router), NewAuditService(auditStore))
}

func coreFileAuditURL(path string, query url.Values) string {
	if len(query) == 0 {
		return path
	}
	return path + "?" + query.Encode()
}

func coreFileAuditRequest(
	t *testing.T,
	handler http.Handler,
	token, method, path string,
	query url.Values,
	body io.Reader,
	headers map[string]string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, coreFileAuditURL(path, query), body)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func coreFileAuditJSONBody(t *testing.T, value any) *bytes.Reader {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(payload)
}

func requireCoreFileAuditStatus(t *testing.T, response *httptest.ResponseRecorder, want int) {
	t.Helper()
	if response.Code != want {
		t.Fatalf("status: got %d, want %d (body: %q)", response.Code, want, response.Body.String())
	}
}

func coreFileAuditStoreCounts(store *auditStoreStub) (creates, finalizes, appends, pending, terminal int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.createCalls, store.finalizeCalls, store.appendCalls, len(store.pending), len(store.appended)
}

func requireCoreFileAuditReadEvent(t *testing.T, store *auditStoreStub) auditdb.Event {
	t.Helper()
	creates, finalizes, appends, pending, terminal := coreFileAuditStoreCounts(store)
	if creates != 0 || finalizes != 0 || appends != 1 || pending != 0 || terminal != 1 {
		t.Fatalf("read audit writes: create=%d finalize=%d append=%d pending=%d terminal=%d; want 0,0,1,0,1",
			creates, finalizes, appends, pending, terminal)
	}
	return store.singleAppended(t)
}

func requireCoreFileAuditWriteEvent(t *testing.T, store *auditStoreStub) auditdb.Event {
	t.Helper()
	creates, finalizes, appends, pending, terminal := coreFileAuditStoreCounts(store)
	if creates != 1 || finalizes != 1 || appends != 0 || pending != 0 || terminal != 1 {
		t.Fatalf("write audit writes: create=%d finalize=%d append=%d pending=%d terminal=%d; want 1,1,0,0,1",
			creates, finalizes, appends, pending, terminal)
	}
	return store.singleAppended(t)
}

func requireCoreFileAuditEvent(
	t *testing.T,
	event auditdb.Event,
	action auditdb.Action,
	result auditdb.Result,
	status int,
	source, path string,
) {
	t.Helper()
	if event.Action != action || event.Result != result {
		t.Errorf("action/result: got %q/%q, want %q/%q", event.Action, event.Result, action, result)
	}
	if event.HTTPStatus == nil || *event.HTTPStatus != status {
		t.Errorf("HTTP status: got %v, want %d", event.HTTPStatus, status)
	}
	if source != "" && event.Source != source {
		t.Errorf("source: got %q, want %q", event.Source, source)
	}
	if path != "" && (event.Path != path || event.CanonicalPath != path) {
		t.Errorf("path/canonicalPath: got %q/%q, want %q/%q", event.Path, event.CanonicalPath, path, path)
	}
	if event.Metadata == nil || event.Metadata.SchemaVersion != auditdb.CurrentMetadataSchemaVersion {
		t.Fatalf("metadata missing or invalid: %+v", event.Metadata)
	}
}

func requireCoreFileAuditAuthenticated(t *testing.T, event auditdb.Event) {
	t.Helper()
	if event.AuthMethod != auditdb.AuthMethodSession {
		t.Errorf("auth method: got %q, want %q", event.AuthMethod, auditdb.AuthMethodSession)
	}
	if event.UserID == nil || event.Username == "" || event.Username == "anonymous" {
		t.Errorf("authenticated actor missing: userID=%v username=%q", event.UserID, event.Username)
	}
	if event.EffectivePermissions == nil {
		t.Error("effective permissions missing")
	}
	if event.TokenRef != "" {
		t.Errorf("session request unexpectedly recorded token ref %q", event.TokenRef)
	}
}

func requireCoreFileAuditAPIToken(
	t *testing.T,
	event auditdb.Event,
	user *users.User,
	effective users.Permissions,
	token string,
) {
	t.Helper()
	if event.AuthMethod != auditdb.AuthMethodToken {
		t.Errorf("auth method: got %q, want %q", event.AuthMethod, auditdb.AuthMethodToken)
	}
	if event.UserID == nil || *event.UserID != user.ID || event.Username != user.Username {
		t.Errorf("API token actor: userID=%v username=%q, want %d/%q", event.UserID, event.Username, user.ID, user.Username)
	}
	wantPermissions := auditPermissionsForTest(effective)
	if event.EffectivePermissions == nil || *event.EffectivePermissions != wantPermissions {
		t.Errorf("effective permissions: got %+v, want %+v", event.EffectivePermissions, wantPermissions)
	}
	tokenHash := utils.HashSHA256(token)
	wantRef := auditdb.DeriveTokenRef(tokenHash)
	if event.TokenRef != wantRef || event.TokenRef == "" {
		t.Errorf("token ref: got %q, want %q", event.TokenRef, wantRef)
	}
	if event.ShareRef != "" {
		t.Errorf("API token request recorded share ref %q", event.ShareRef)
	}
}

func requireCoreFileAuditNoPaths(t *testing.T, event auditdb.Event) {
	t.Helper()
	if event.Path != "" || event.CanonicalPath != "" || event.TargetPath != "" || event.TargetCanonicalPath != "" {
		t.Errorf("unverified audit paths: path=%q canonical=%q target=%q targetCanonical=%q",
			event.Path, event.CanonicalPath, event.TargetPath, event.TargetCanonicalPath)
	}
}

func requireCoreFileAuditMetadataCounts(t *testing.T, event auditdb.Event, items, succeeded, failed, denied int64) {
	t.Helper()
	metadata := event.Metadata
	if metadata == nil {
		t.Fatal("metadata missing")
	}
	value := func(pointer *int64) int64 {
		if pointer == nil {
			return 0
		}
		return *pointer
	}
	if value(metadata.ItemCount) != items || value(metadata.SuccessCount) != succeeded ||
		value(metadata.FailedCount) != failed || value(metadata.DeniedCount) != denied {
		t.Errorf("counts: item=%d success=%d failed=%d denied=%d; want %d,%d,%d,%d",
			value(metadata.ItemCount), value(metadata.SuccessCount), value(metadata.FailedCount), value(metadata.DeniedCount),
			items, succeeded, failed, denied)
	}
}

func TestCoreFileActionAuditReads(t *testing.T) {
	environment := newCoreFileAuditEnvironment(t)

	browseDeniedToken := newCoreFileAuditUserToken(t, environment.sourcePath, "core-audit-browse-denied", users.Permissions{
		Preview: true, Download: true,
	})
	previewDeniedToken := newCoreFileAuditUserToken(t, environment.sourcePath, "core-audit-preview-denied", users.Permissions{
		Browse: true, Download: true,
	})

	t.Run("browse success", func(t *testing.T) {
		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), environment.token,
			http.MethodGet, "/api/resources", url.Values{"source": {"source1"}, "path": {"/public"}}, nil, nil)
		requireCoreFileAuditStatus(t, response, http.StatusOK)
		event := requireCoreFileAuditReadEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionFileBrowse, auditdb.ResultSuccess, http.StatusOK, "source1", "/public")
		requireCoreFileAuditAuthenticated(t, event)
	})

	t.Run("browse denied", func(t *testing.T) {
		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), browseDeniedToken,
			http.MethodGet, "/api/resources", url.Values{"source": {"source1"}, "path": {"/public"}}, nil, nil)
		requireCoreFileAuditStatus(t, response, http.StatusForbidden)
		event := requireCoreFileAuditReadEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionFileBrowse, auditdb.ResultDenied, http.StatusForbidden, "", "")
		requireCoreFileAuditAuthenticated(t, event)
		requireCoreFileAuditNoPaths(t, event)
	})

	t.Run("preview success", func(t *testing.T) {
		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), environment.token,
			http.MethodGet, "/api/resources/preview", url.Values{
				"source": {"source1"}, "path": {"/public/preview.jpg"}, "size": {"small"},
			}, nil, nil)
		requireCoreFileAuditStatus(t, response, http.StatusOK)
		event := requireCoreFileAuditReadEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionFilePreview, auditdb.ResultSuccess, http.StatusOK, "source1", "/public/preview.jpg")
		requireCoreFileAuditAuthenticated(t, event)
	})

	t.Run("preview denied", func(t *testing.T) {
		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), previewDeniedToken,
			http.MethodGet, "/api/resources/preview", url.Values{
				"source": {"source1"}, "path": {"/public/preview.jpg"}, "size": {"small"},
			}, nil, nil)
		requireCoreFileAuditStatus(t, response, http.StatusForbidden)
		event := requireCoreFileAuditReadEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionFilePreview, auditdb.ResultDenied, http.StatusForbidden, "", "")
		requireCoreFileAuditAuthenticated(t, event)
		requireCoreFileAuditNoPaths(t, event)
	})

	for _, test := range []struct {
		name       string
		rangeValue string
		wantStatus int
		wantResult auditdb.Result
		wantStart  *int64
		wantEnd    *int64
	}{
		{name: "download 200", wantStatus: http.StatusOK, wantResult: auditdb.ResultSuccess},
		{name: "download range 206", rangeValue: "bytes=2-6", wantStatus: http.StatusPartialContent, wantResult: auditdb.ResultSuccess, wantStart: coreFileAuditInt64(2), wantEnd: coreFileAuditInt64(6)},
		{name: "download invalid range 416", rangeValue: "bytes=999-1000", wantStatus: http.StatusRequestedRangeNotSatisfiable, wantResult: auditdb.ResultFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			auditStore := newAuditStoreStub()
			headers := map[string]string{}
			if test.rangeValue != "" {
				headers["Range"] = test.rangeValue
			}
			response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), environment.token,
				http.MethodGet, "/api/resources/download", url.Values{
					"source": {"source1"}, "file": {"/public/secret.txt"},
				}, nil, headers)
			requireCoreFileAuditStatus(t, response, test.wantStatus)
			event := requireCoreFileAuditReadEvent(t, auditStore)
			requireCoreFileAuditEvent(t, event, auditdb.ActionFileDownload, test.wantResult, test.wantStatus, "source1", "/public/secret.txt")
			requireCoreFileAuditAuthenticated(t, event)
			if event.Metadata.Bytes == nil || *event.Metadata.Bytes != int64(response.Body.Len()) {
				t.Errorf("download bytes: got %v, want %d", event.Metadata.Bytes, response.Body.Len())
			}
			requireCoreFileAuditRange(t, event.Metadata, test.wantStart, test.wantEnd)
		})
	}

	t.Run("download client cancellation", func(t *testing.T) {
		auditStore := newAuditStoreStub()
		handler := newCoreFileAuditRouter(auditStore)
		ctx, cancel := context.WithCancel(context.Background())
		writer := newCoreFileAuditCancelWriter(cancel)
		request := httptest.NewRequest(http.MethodGet, coreFileAuditURL("/api/resources/download", url.Values{
			"source": {"source1"}, "file": {"/public/secret.txt"},
		}), nil).WithContext(ctx)
		request.Header.Set("Authorization", "Bearer "+environment.token)
		handler.ServeHTTP(writer, request)

		event := requireCoreFileAuditReadEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionFileDownload, auditdb.ResultCancelled, writer.statusCode(), "source1", "/public/secret.txt")
		if event.Metadata.ClientCancelled == nil || !*event.Metadata.ClientCancelled {
			t.Errorf("clientCancelled: got %v, want true", event.Metadata.ClientCancelled)
		}
		if event.Metadata.Bytes == nil || *event.Metadata.Bytes != int64(writer.body.Len()) {
			t.Errorf("cancelled bytes: got %v, want %d", event.Metadata.Bytes, writer.body.Len())
		}
		if writer.body.Len() == 0 || writer.body.Len() >= len(permissionReadSecret) {
			t.Errorf("cancelled download accepted %d bytes; want a non-zero partial payload below %d", writer.body.Len(), len(permissionReadSecret))
		}
	})

	t.Run("download archive binds first permitted target", func(t *testing.T) {
		const deniedPath = "/public/audit-download-denied.txt"
		if err := os.WriteFile(coreFileAuditRealPath(environment.sourcePath, deniedPath), []byte("denied"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := store.Access.DenyUser(environment.sourcePath, deniedPath, "core-file-audit-user"); err != nil {
			t.Fatal(err)
		}

		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), environment.token,
			http.MethodGet, "/api/resources/download", url.Values{
				"source": {"source1"}, "file": {deniedPath, "/public/secret.txt"},
			}, nil, nil)
		requireCoreFileAuditStatus(t, response, http.StatusOK)
		event := requireCoreFileAuditReadEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionFileDownload, auditdb.ResultSuccess, http.StatusOK, "source1", "/public/secret.txt")
		if event.Metadata.ItemCount == nil || *event.Metadata.ItemCount != 2 {
			t.Errorf("download item count: got %v, want 2", event.Metadata.ItemCount)
		}
	})
}

func TestCoreFileActionAuditAPITokenIntersection(t *testing.T) {
	environment := newCoreFileAuditEnvironment(t)
	accountPermissions := users.Permissions{
		Api: true, Browse: true, Preview: true, Download: true,
	}
	user := &users.User{
		Username:    "core-file-audit-api-token-user",
		Permissions: accountPermissions,
		Scopes: []users.SourceScope{
			{Name: environment.sourcePath, Scope: "/"},
		},
	}
	savePermissionReadUser(t, user)
	tokenPermissions := users.Permissions{Api: true, Browse: true}
	token := issuePermissionReadAPIToken(t, user, "core-file-audit-api-token", tokenPermissions)
	tokenHash := utils.HashSHA256(token)

	t.Run("success records current intersection", func(t *testing.T) {
		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), token,
			http.MethodGet, "/api/resources", url.Values{
				"source": {"source1"}, "path": {"/public"},
			}, nil, nil)
		requireCoreFileAuditStatus(t, response, http.StatusOK)
		event := requireCoreFileAuditReadEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionFileBrowse, auditdb.ResultSuccess,
			http.StatusOK, "source1", "/public")
		requireCoreFileAuditAPIToken(t, event, user,
			users.IntersectPermissions(accountPermissions, tokenPermissions), token)
		coreFileAuditAssertSecretsAbsent(t, event, token, tokenHash, environment.sourcePath)
	})

	t.Run("account revocation denies without unverified paths", func(t *testing.T) {
		storedUser, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal(err)
		}
		revokedUser := *storedUser
		revokedUser.Permissions.Browse = false
		if err = store.Users.Update(&revokedUser, true, "Permissions"); err != nil {
			t.Fatal(err)
		}

		const unnormalizedSecret = "/public//CORE-FILE-AUDIT-UNVERIFIED-PATH-SECRET"
		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), token,
			http.MethodGet, "/api/resources", url.Values{
				"source": {"source1"}, "path": {unnormalizedSecret},
			}, nil, nil)
		requireCoreFileAuditStatus(t, response, http.StatusForbidden)
		event := requireCoreFileAuditReadEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionFileBrowse, auditdb.ResultDenied,
			http.StatusForbidden, "", "")
		requireCoreFileAuditAPIToken(t, event, user,
			users.IntersectPermissions(revokedUser.Permissions, tokenPermissions), token)
		requireCoreFileAuditNoPaths(t, event)
		coreFileAuditAssertSecretsAbsent(t, event, token, tokenHash, unnormalizedSecret, environment.sourcePath)
	})
}

func coreFileAuditInt64(value int64) *int64 { return &value }

func requireCoreFileAuditRange(t *testing.T, metadata *auditdb.MetadataV1, start, end *int64) {
	t.Helper()
	if metadata == nil {
		t.Fatal("metadata missing")
	}
	if !coreFileAuditEqualInt64(metadata.RangeStart, start) || !coreFileAuditEqualInt64(metadata.RangeEnd, end) {
		t.Errorf("normalized range: got %v-%v, want %v-%v", metadata.RangeStart, metadata.RangeEnd, start, end)
	}
}

func coreFileAuditEqualInt64(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

type coreFileAuditCancelWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
	cancel context.CancelFunc
	once   sync.Once
}

type coreFileAuditMutatingReader struct {
	reader io.Reader
	mutate func()
	once   sync.Once
}

func (reader *coreFileAuditMutatingReader) Read(buffer []byte) (int, error) {
	reader.once.Do(reader.mutate)
	return reader.reader.Read(buffer)
}

func newCoreFileAuditCancelWriter(cancel context.CancelFunc) *coreFileAuditCancelWriter {
	return &coreFileAuditCancelWriter{header: make(http.Header), cancel: cancel}
}

func (writer *coreFileAuditCancelWriter) Header() http.Header { return writer.header }

func (writer *coreFileAuditCancelWriter) WriteHeader(status int) {
	if writer.status == 0 {
		writer.status = status
	}
}

func (writer *coreFileAuditCancelWriter) Write(payload []byte) (int, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	limit := len(payload) / 2
	if limit == 0 && len(payload) != 0 {
		limit = 1
	}
	written, _ := writer.body.Write(payload[:limit])
	writer.once.Do(writer.cancel)
	return written, io.ErrClosedPipe
}

func (writer *coreFileAuditCancelWriter) statusCode() int {
	if writer.status == 0 {
		return http.StatusOK
	}
	return writer.status
}

func TestCoreFileActionAuditWrites(t *testing.T) {
	environment := newCoreFileAuditEnvironment(t)
	if preview.GetService() == nil {
		if err := preview.StartPreviewGenerator(1, filepath.Join(filepath.Dir(environment.sourcePath), "core-file-audit-preview-cache")); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("upload new file", func(t *testing.T) {
		const logicalPath = "/public/audit-upload-new.txt"
		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), environment.token,
			http.MethodPost, "/api/resources", url.Values{"source": {"source1"}, "path": {logicalPath}},
			strings.NewReader(coreFileAuditUploadBody), nil)
		requireCoreFileAuditStatus(t, response, http.StatusOK)
		assertAPITokenFileState(t, coreFileAuditRealPath(environment.sourcePath, logicalPath), true, coreFileAuditUploadBody)
		event := requireCoreFileAuditWriteEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionFileUpload, auditdb.ResultSuccess, http.StatusOK, "source1", logicalPath)
		requireCoreFileAuditAuthenticated(t, event)
		requireCoreFileAuditOverwriteAndBytes(t, event, false, int64(len(coreFileAuditUploadBody)))
	})

	t.Run("modify existing file", func(t *testing.T) {
		const logicalPath = "/public/audit-modify-existing.txt"
		realPath := coreFileAuditRealPath(environment.sourcePath, logicalPath)
		if err := os.WriteFile(realPath, []byte("original"), 0o644); err != nil {
			t.Fatal(err)
		}
		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), environment.token,
			http.MethodPut, "/api/resources", url.Values{"source": {"source1"}, "path": {logicalPath}},
			strings.NewReader(coreFileAuditUploadBody), nil)
		requireCoreFileAuditStatus(t, response, http.StatusOK)
		assertAPITokenFileState(t, realPath, true, coreFileAuditUploadBody)
		event := requireCoreFileAuditWriteEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionFileModify, auditdb.ResultSuccess, http.StatusOK, "source1", logicalPath)
		requireCoreFileAuditAuthenticated(t, event)
		requireCoreFileAuditOverwriteAndBytes(t, event, true, int64(len(coreFileAuditUploadBody)))
	})

	for _, action := range []string{"rename", "move"} {
		t.Run(action+" records source and target", func(t *testing.T) {
			fromPath := "/public/audit-" + action + "-from.txt"
			toPath := "/public/audit-" + action + "-to.txt"
			fromReal := coreFileAuditRealPath(environment.sourcePath, fromPath)
			toReal := coreFileAuditRealPath(environment.sourcePath, toPath)
			if err := os.WriteFile(fromReal, []byte(action+" content"), 0o644); err != nil {
				t.Fatal(err)
			}
			payload := MoveCopyRequest{Action: action, Items: []MoveCopyItem{{
				FromSource: "source1", FromPath: fromPath, ToSource: "source1", ToPath: toPath,
			}}}
			auditStore := newAuditStoreStub()
			response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), environment.token,
				http.MethodPatch, "/api/resources", nil, coreFileAuditJSONBody(t, payload),
				map[string]string{"Content-Type": "application/json"})
			requireCoreFileAuditStatus(t, response, http.StatusOK)
			assertAPITokenRenameState(t, fromReal, toReal, action+" content", true)

			wantAction := auditdb.ActionFileRename
			if action == "move" {
				wantAction = auditdb.ActionFileMove
			}
			event := requireCoreFileAuditWriteEvent(t, auditStore)
			requireCoreFileAuditEvent(t, event, wantAction, auditdb.ResultSuccess, http.StatusOK, "source1", fromPath)
			requireCoreFileAuditAuthenticated(t, event)
			if event.TargetSource != "source1" || event.TargetPath != toPath || event.TargetCanonicalPath != toPath {
				t.Errorf("target source/path/canonical: got %q/%q/%q, want source1/%s/%s",
					event.TargetSource, event.TargetPath, event.TargetCanonicalPath, toPath, toPath)
			}
			requireCoreFileAuditMetadataCounts(t, event, 1, 1, 0, 0)
		})
	}

	t.Run("delete", func(t *testing.T) {
		const logicalPath = "/public/audit-delete.txt"
		realPath := coreFileAuditRealPath(environment.sourcePath, logicalPath)
		if err := os.WriteFile(realPath, []byte("delete content"), 0o644); err != nil {
			t.Fatal(err)
		}
		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), environment.token,
			http.MethodDelete, "/api/resources", url.Values{"source": {"source1"}, "path": {logicalPath}}, nil, nil)
		requireCoreFileAuditStatus(t, response, http.StatusOK)
		assertAPITokenFileState(t, realPath, false, "")
		event := requireCoreFileAuditWriteEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionFileDelete, auditdb.ResultSuccess, http.StatusOK, "source1", logicalPath)
		requireCoreFileAuditAuthenticated(t, event)
		requireCoreFileAuditMetadataCounts(t, event, 1, 1, 0, 0)
	})

	t.Run("archive create", func(t *testing.T) {
		const destination = "/public/audit-created.zip"
		payload := archiveCreateRequest{
			FromSource: "source1", Paths: []string{"/public/secret.txt"}, Destination: destination, Format: "zip",
		}
		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), environment.token,
			http.MethodPost, "/api/resources/archive", nil, coreFileAuditJSONBody(t, payload),
			map[string]string{"Content-Type": "application/json"})
		requireCoreFileAuditStatus(t, response, http.StatusOK)
		if info, err := os.Stat(coreFileAuditRealPath(environment.sourcePath, destination)); err != nil || info.Size() == 0 {
			t.Fatalf("created archive missing or empty: info=%v err=%v", info, err)
		}
		event := requireCoreFileAuditWriteEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionArchiveCreate, auditdb.ResultSuccess, http.StatusOK, "source1", destination)
		requireCoreFileAuditAuthenticated(t, event)
		requireCoreFileAuditMetadataCounts(t, event, 1, 1, 0, 0)
	})

	t.Run("archive extract", func(t *testing.T) {
		const (
			archivePath = "/public/audit-input.zip"
			destination = "/public/audit-extracted"
			entry       = "internal-secret/member.txt"
		)
		coreFileAuditWriteZip(t, coreFileAuditRealPath(environment.sourcePath, archivePath), entry, "extracted content")
		if err := os.Mkdir(coreFileAuditRealPath(environment.sourcePath, destination), 0o755); err != nil {
			t.Fatal(err)
		}
		payload := unarchiveRequest{FromSource: "source1", Path: archivePath, Destination: destination}
		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), environment.token,
			http.MethodPost, "/api/resources/unarchive", nil, coreFileAuditJSONBody(t, payload),
			map[string]string{"Content-Type": "application/json"})
		requireCoreFileAuditStatus(t, response, http.StatusOK)
		assertAPITokenFileState(t, filepath.Join(coreFileAuditRealPath(environment.sourcePath, destination), filepath.FromSlash(entry)), true, "extracted content")
		event := requireCoreFileAuditWriteEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionArchiveExtract, auditdb.ResultSuccess, http.StatusOK, "source1", destination)
		requireCoreFileAuditAuthenticated(t, event)
		requireCoreFileAuditMetadataCounts(t, event, 1, 1, 0, 0)
		coreFileAuditAssertSecretsAbsent(t, event, entry, coreFileAuditRealPath(environment.sourcePath, archivePath))
	})
}

func TestCoreFileActionAuditDeniedBatchCounts(t *testing.T) {
	environment := newCoreFileAuditEnvironment(t)
	if preview.GetService() == nil {
		if err := preview.StartPreviewGenerator(1, filepath.Join(filepath.Dir(environment.sourcePath), "core-file-audit-denied-cache")); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("bulk delete distinguishes denied items", func(t *testing.T) {
		const (
			deniedPath  = "/public/audit-bulk-delete-denied.txt"
			allowedPath = "/public/audit-bulk-delete-allowed.txt"
		)
		for _, logicalPath := range []string{deniedPath, allowedPath} {
			if err := os.WriteFile(coreFileAuditRealPath(environment.sourcePath, logicalPath), []byte(logicalPath), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.Access.DenyUser(environment.sourcePath, deniedPath, "core-file-audit-user"); err != nil {
			t.Fatal(err)
		}

		payload := []BulkDeleteItem{{Source: "source1", Path: deniedPath}, {Source: "source1", Path: allowedPath}}
		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), environment.token,
			http.MethodDelete, "/api/resources/bulk", nil, coreFileAuditJSONBody(t, payload),
			map[string]string{"Content-Type": "application/json"})
		requireCoreFileAuditStatus(t, response, http.StatusMultiStatus)
		assertAPITokenFileState(t, coreFileAuditRealPath(environment.sourcePath, deniedPath), true, deniedPath)
		assertAPITokenFileState(t, coreFileAuditRealPath(environment.sourcePath, allowedPath), false, "")
		event := requireCoreFileAuditWriteEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionFileDelete, auditdb.ResultSuccess,
			http.StatusMultiStatus, "source1", allowedPath)
		requireCoreFileAuditMetadataCounts(t, event, 2, 1, 0, 1)
	})

	t.Run("rename distinguishes denied items", func(t *testing.T) {
		const (
			deniedFrom  = "/public/audit-rename-denied-from.txt"
			deniedTo    = "/public/audit-rename-denied-to.txt"
			allowedFrom = "/public/audit-rename-allowed-from.txt"
			allowedTo   = "/public/audit-rename-allowed-to.txt"
		)
		for _, logicalPath := range []string{deniedFrom, allowedFrom} {
			if err := os.WriteFile(coreFileAuditRealPath(environment.sourcePath, logicalPath), []byte(logicalPath), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.Access.DenyUser(environment.sourcePath, deniedFrom, "core-file-audit-user"); err != nil {
			t.Fatal(err)
		}

		payload := MoveCopyRequest{Action: "rename", Items: []MoveCopyItem{
			{FromSource: "source1", FromPath: deniedFrom, ToSource: "source1", ToPath: deniedTo},
			{FromSource: "source1", FromPath: allowedFrom, ToSource: "source1", ToPath: allowedTo},
		}}
		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), environment.token,
			http.MethodPatch, "/api/resources", nil, coreFileAuditJSONBody(t, payload),
			map[string]string{"Content-Type": "application/json"})
		requireCoreFileAuditStatus(t, response, http.StatusMultiStatus)
		assertAPITokenRenameState(t, coreFileAuditRealPath(environment.sourcePath, deniedFrom),
			coreFileAuditRealPath(environment.sourcePath, deniedTo), deniedFrom, false)
		assertAPITokenRenameState(t, coreFileAuditRealPath(environment.sourcePath, allowedFrom),
			coreFileAuditRealPath(environment.sourcePath, allowedTo), allowedFrom, true)
		event := requireCoreFileAuditWriteEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionFileRename, auditdb.ResultSuccess,
			http.StatusMultiStatus, "source1", allowedFrom)
		requireCoreFileAuditMetadataCounts(t, event, 2, 1, 0, 1)
	})
}

func TestCoreFileActionAuditRejectsTargetChangesAfterReservation(t *testing.T) {
	environment := newCoreFileAuditEnvironment(t)

	for _, test := range []struct {
		name    string
		headers map[string]string
	}{
		{name: "regular upload"},
		{name: "completed chunk upload", headers: map[string]string{
			"X-File-Chunk-Offset": "0",
			"X-File-Total-Size":   strconv.Itoa(len(coreFileAuditUploadBody)),
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			logicalPath := "/public/audit-target-change-" + strings.ReplaceAll(test.name, " ", "-") + ".txt"
			realPath := coreFileAuditRealPath(environment.sourcePath, logicalPath)
			var mutationErr error
			body := &coreFileAuditMutatingReader{
				reader: strings.NewReader(coreFileAuditUploadBody),
				mutate: func() {
					mutationErr = os.WriteFile(realPath, []byte("racing target"), 0o644)
				},
			}
			auditStore := newAuditStoreStub()
			response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), environment.token,
				http.MethodPost, "/api/resources", url.Values{
					"source": {"source1"}, "path": {logicalPath}, "override": {"true"},
				}, body, test.headers)
			if mutationErr != nil {
				t.Fatal(mutationErr)
			}
			requireCoreFileAuditStatus(t, response, http.StatusConflict)
			assertAPITokenFileState(t, realPath, true, "racing target")
			event := requireCoreFileAuditWriteEvent(t, auditStore)
			requireCoreFileAuditEvent(t, event, auditdb.ActionFileUpload, auditdb.ResultFailed,
				http.StatusConflict, "source1", logicalPath)
			requireCoreFileAuditMetadataCounts(t, event, 1, 0, 1, 0)
		})
	}
}

func requireCoreFileAuditOverwriteAndBytes(t *testing.T, event auditdb.Event, overwrite bool, bytesWritten int64) {
	t.Helper()
	if event.Metadata == nil {
		t.Fatal("metadata missing")
	}
	if event.Metadata.Overwrite == nil || *event.Metadata.Overwrite != overwrite {
		t.Errorf("overwrite: got %v, want %t", event.Metadata.Overwrite, overwrite)
	}
	if event.Metadata.Bytes == nil || *event.Metadata.Bytes != bytesWritten {
		t.Errorf("bytes: got %v, want %d", event.Metadata.Bytes, bytesWritten)
	}
}

func coreFileAuditRealPath(sourcePath, logicalPath string) string {
	return filepath.Join(sourcePath, filepath.FromSlash(strings.TrimPrefix(logicalPath, "/")))
}

func coreFileAuditWriteZip(t *testing.T, archivePath, entryName, content string) {
	t.Helper()
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	entry, err := writer.Create(entryName)
	if err != nil {
		_ = writer.Close()
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err = entry.Write([]byte(content)); err != nil {
		_ = writer.Close()
		_ = file.Close()
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCoreFileActionAuditShareAccess(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	shareHarness := newPermissionShareSecurityHarness(t, sourcePath)
	owner := shareHarness.newOwner(t, "core-file-audit-share-owner", users.Permissions{
		Browse: true, Preview: true, Download: true,
	})
	const shareHash = "core-file-audit-share-hash-secret"
	shareHarness.saveShare(t, owner, shareHash, "/public", nil)

	t.Run("share info success", func(t *testing.T) {
		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), "",
			http.MethodGet, "/public/api/share/info", url.Values{"hash": {shareHash}}, nil, nil)
		requireCoreFileAuditStatus(t, response, http.StatusOK)
		event := requireCoreFileAuditReadEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionShareAccess, auditdb.ResultSuccess, http.StatusOK, "source1", "/public")
		requireCoreFileAuditShareIdentity(t, event, shareHash)
		coreFileAuditAssertSecretsAbsent(t, event, shareHash, sourcePath)
	})

	t.Run("wrong password denied", func(t *testing.T) {
		const passwordHash = "$2y$10$TFAmdCbyd/mEZDe5fUeZJu.MaJQXRTwdqb/IQV.eTn6dWrF58gCSe"
		link := shareHarness.saveShare(t, owner, "core-file-audit-password-share-secret", "/public", nil)
		link.PasswordHash = passwordHash
		if err := store.Share.Save(link); err != nil {
			t.Fatal(err)
		}

		auditStore := newAuditStoreStub()
		const wrongPassword = "core-file-audit-wrong-password-secret"
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), "",
			http.MethodGet, "/public/api/resources", url.Values{
				"hash": {link.Hash}, "path": {"/secret.txt"},
			}, nil, map[string]string{"X-SHARE-PASSWORD": wrongPassword})
		requireCoreFileAuditStatus(t, response, http.StatusUnauthorized)
		event := requireCoreFileAuditReadEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionShareAccess, auditdb.ResultDenied, http.StatusUnauthorized, "", "")
		requireCoreFileAuditShareIdentity(t, event, link.Hash)
		requireCoreFileAuditNoPaths(t, event)
		coreFileAuditAssertSecretsAbsent(t, event, link.Hash, wrongPassword, passwordHash, sourcePath)
	})

	t.Run("expired share failed", func(t *testing.T) {
		link := shareHarness.saveShare(t, owner, "core-file-audit-expired-share-secret", "/public", nil)
		link.Expire = time.Now().Add(-time.Minute).Unix()
		if err := store.Share.Save(link); err != nil {
			t.Fatal(err)
		}

		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), "",
			http.MethodGet, "/public/api/share/info", url.Values{"hash": {link.Hash}}, nil, nil)
		requireCoreFileAuditStatus(t, response, http.StatusNotFound)
		event := requireCoreFileAuditReadEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionShareAccess, auditdb.ResultFailed, http.StatusNotFound, "", "")
		requireCoreFileAuditShareIdentity(t, event, link.Hash)
		requireCoreFileAuditNoPaths(t, event)
		coreFileAuditAssertSecretsAbsent(t, event, link.Hash, sourcePath)
	})

	t.Run("unknown share failed", func(t *testing.T) {
		const unknownHash = "core-file-audit-unknown-share-secret"
		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), "",
			http.MethodGet, "/public/api/share/info", url.Values{"hash": {unknownHash}}, nil, nil)
		requireCoreFileAuditStatus(t, response, http.StatusNotFound)
		event := requireCoreFileAuditReadEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionShareAccess, auditdb.ResultFailed, http.StatusNotFound, "", "")
		requireCoreFileAuditShareIdentity(t, event, unknownHash)
		requireCoreFileAuditNoPaths(t, event)
		coreFileAuditAssertSecretsAbsent(t, event, unknownHash, sourcePath)
	})

	t.Run("download capability denied", func(t *testing.T) {
		capabilityOwner := shareHarness.newOwner(t, "core-file-audit-capability-owner", users.Permissions{Browse: true})
		link := shareHarness.saveShare(t, capabilityOwner, "core-file-audit-capability-share-secret", "/public", nil)
		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), "",
			http.MethodGet, "/public/api/resources/download", url.Values{
				"hash": {link.Hash}, "file": {"/secret.txt"},
			}, nil, nil)
		requireCoreFileAuditStatus(t, response, http.StatusForbidden)
		event := requireCoreFileAuditReadEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionShareAccess, auditdb.ResultDenied,
			http.StatusForbidden, "source1", "")
		requireCoreFileAuditShareIdentity(t, event, link.Hash)
		requireCoreFileAuditNoPaths(t, event)
		coreFileAuditAssertSecretsAbsent(t, event, link.Hash, sourcePath)
	})

	t.Run("media capability denial is audited", func(t *testing.T) {
		mediaOwner := shareHarness.newOwner(t, "core-file-audit-media-owner", users.Permissions{Browse: true})
		link := shareHarness.saveShare(t, mediaOwner, "core-file-audit-media-share-secret", "/public", nil)
		auditStore := newAuditStoreStub()
		response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), "",
			http.MethodGet, "/public/api/media/lyrics", url.Values{
				"hash": {link.Hash}, "path": {"/secret.txt"},
			}, nil, nil)
		requireCoreFileAuditStatus(t, response, http.StatusForbidden)
		event := requireCoreFileAuditReadEvent(t, auditStore)
		requireCoreFileAuditEvent(t, event, auditdb.ActionShareAccess, auditdb.ResultDenied,
			http.StatusForbidden, "source1", "")
		requireCoreFileAuditShareIdentity(t, event, link.Hash)
		requireCoreFileAuditNoPaths(t, event)
		coreFileAuditAssertSecretsAbsent(t, event, link.Hash, sourcePath)
	})
}

func requireCoreFileAuditShareIdentity(t *testing.T, event auditdb.Event, hash string) {
	t.Helper()
	if event.AuthMethod != auditdb.AuthMethodShare {
		t.Errorf("share auth method: got %q, want %q", event.AuthMethod, auditdb.AuthMethodShare)
	}
	wantRef := auditdb.DeriveShareRef(hash)
	if event.ShareRef != wantRef || event.ShareRef == "" {
		t.Errorf("share ref: got %q, want %q", event.ShareRef, wantRef)
	}
	if event.TokenRef != "" {
		t.Errorf("share request recorded token ref %q", event.TokenRef)
	}
}

func TestCoreFileActionAuditReservationFailureHasZeroSideEffects(t *testing.T) {
	environment := newCoreFileAuditEnvironment(t)

	tests := []struct {
		name    string
		request func(*testing.T) (method, path string, query url.Values, body io.Reader, headers map[string]string)
		assert  func(*testing.T)
	}{
		{
			name: "upload",
			request: func(*testing.T) (string, string, url.Values, io.Reader, map[string]string) {
				return http.MethodPost, "/api/resources", url.Values{
					"source": {"source1"}, "path": {"/public/reservation-upload.txt"},
				}, strings.NewReader("must not upload"), nil
			},
			assert: func(t *testing.T) {
				assertAPITokenFileState(t, coreFileAuditRealPath(environment.sourcePath, "/public/reservation-upload.txt"), false, "")
			},
		},
		{
			name: "modify",
			request: func(t *testing.T) (string, string, url.Values, io.Reader, map[string]string) {
				realPath := coreFileAuditRealPath(environment.sourcePath, "/public/reservation-modify.txt")
				if err := os.WriteFile(realPath, []byte("original modify"), 0o644); err != nil {
					t.Fatal(err)
				}
				return http.MethodPut, "/api/resources", url.Values{
					"source": {"source1"}, "path": {"/public/reservation-modify.txt"},
				}, strings.NewReader("must not modify"), nil
			},
			assert: func(t *testing.T) {
				assertAPITokenFileState(t, coreFileAuditRealPath(environment.sourcePath, "/public/reservation-modify.txt"), true, "original modify")
			},
		},
		{
			name:    "rename",
			request: coreFileAuditReservationMoveRequest(environment.sourcePath, "rename"),
			assert:  coreFileAuditReservationMoveAssertion(environment.sourcePath, "rename"),
		},
		{
			name:    "move",
			request: coreFileAuditReservationMoveRequest(environment.sourcePath, "move"),
			assert:  coreFileAuditReservationMoveAssertion(environment.sourcePath, "move"),
		},
		{
			name: "delete",
			request: func(t *testing.T) (string, string, url.Values, io.Reader, map[string]string) {
				realPath := coreFileAuditRealPath(environment.sourcePath, "/public/reservation-delete.txt")
				if err := os.WriteFile(realPath, []byte("must not delete"), 0o644); err != nil {
					t.Fatal(err)
				}
				return http.MethodDelete, "/api/resources", url.Values{
					"source": {"source1"}, "path": {"/public/reservation-delete.txt"},
				}, nil, nil
			},
			assert: func(t *testing.T) {
				assertAPITokenFileState(t, coreFileAuditRealPath(environment.sourcePath, "/public/reservation-delete.txt"), true, "must not delete")
			},
		},
		{
			name: "archive create",
			request: func(t *testing.T) (string, string, url.Values, io.Reader, map[string]string) {
				payload := archiveCreateRequest{
					FromSource: "source1", Paths: []string{"/public/secret.txt"},
					Destination: "/public/reservation-created.zip", Format: "zip",
				}
				return http.MethodPost, "/api/resources/archive", nil, coreFileAuditJSONBody(t, payload), map[string]string{"Content-Type": "application/json"}
			},
			assert: func(t *testing.T) {
				assertAPITokenFileState(t, coreFileAuditRealPath(environment.sourcePath, "/public/reservation-created.zip"), false, "")
			},
		},
		{
			name: "archive extract",
			request: func(t *testing.T) (string, string, url.Values, io.Reader, map[string]string) {
				coreFileAuditWriteZip(t, coreFileAuditRealPath(environment.sourcePath, "/public/reservation-input.zip"), "blocked.txt", "must not extract")
				if err := os.Mkdir(coreFileAuditRealPath(environment.sourcePath, "/public/reservation-extract"), 0o755); err != nil {
					t.Fatal(err)
				}
				payload := unarchiveRequest{
					FromSource: "source1", Path: "/public/reservation-input.zip", Destination: "/public/reservation-extract",
				}
				return http.MethodPost, "/api/resources/unarchive", nil, coreFileAuditJSONBody(t, payload), map[string]string{"Content-Type": "application/json"}
			},
			assert: func(t *testing.T) {
				assertAPITokenFileState(t, coreFileAuditRealPath(environment.sourcePath, "/public/reservation-extract/blocked.txt"), false, "")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			method, path, query, body, headers := test.request(t)
			auditStore := newAuditStoreStub()
			auditStore.createErr = errors.New("injected audit reservation failure")
			response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), environment.token,
				method, path, query, body, headers)
			requireCoreFileAuditStatus(t, response, http.StatusServiceUnavailable)
			test.assert(t)
			creates, finalizes, appends, pending, terminal := coreFileAuditStoreCounts(auditStore)
			if creates != 1 || finalizes != 0 || appends != 0 || pending != 0 || terminal != 0 {
				t.Errorf("reservation failure writes: create=%d finalize=%d append=%d pending=%d terminal=%d; want 1,0,0,0,0",
					creates, finalizes, appends, pending, terminal)
			}
		})
	}
}

func coreFileAuditReservationMoveRequest(sourcePath, action string) func(*testing.T) (string, string, url.Values, io.Reader, map[string]string) {
	return func(t *testing.T) (string, string, url.Values, io.Reader, map[string]string) {
		fromPath := "/public/reservation-" + action + "-from.txt"
		if err := os.WriteFile(coreFileAuditRealPath(sourcePath, fromPath), []byte("must not "+action), 0o644); err != nil {
			t.Fatal(err)
		}
		payload := MoveCopyRequest{Action: action, Items: []MoveCopyItem{{
			FromSource: "source1", FromPath: fromPath,
			ToSource: "source1", ToPath: "/public/reservation-" + action + "-to.txt",
		}}}
		return http.MethodPatch, "/api/resources", nil, coreFileAuditJSONBody(t, payload), map[string]string{"Content-Type": "application/json"}
	}
}

func coreFileAuditReservationMoveAssertion(sourcePath, action string) func(*testing.T) {
	return func(t *testing.T) {
		assertAPITokenRenameState(t,
			coreFileAuditRealPath(sourcePath, "/public/reservation-"+action+"-from.txt"),
			coreFileAuditRealPath(sourcePath, "/public/reservation-"+action+"-to.txt"),
			"must not "+action, false)
	}
}

func TestCoreFileActionAuditShareReservationFailureHasZeroSideEffects(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	shareHarness := newPermissionShareSecurityHarness(t, sourcePath)
	owner := shareHarness.newOwner(t, "core-audit-share-upload-owner", users.Permissions{Create: true, Modify: true})
	link := shareHarness.saveShare(t, owner, "core-audit-share-upload-secret", "/public", func(common *dbshare.CommonShare) {
		common.ShareType = "upload"
		common.AllowCreate = true
	})
	link.PerUserDownloadLimit = true
	link.DownloadsLimit = 10
	link.UserDownloads = map[string]int{owner.Username: 3}
	if err := store.Share.Save(link); err != nil {
		t.Fatal(err)
	}
	beforeDownloads := link.Downloads
	beforeUserDownloads := link.GetUserDownloadCount(owner.Username)
	uploadToken := issuePermissionReadWebToken(t, owner)

	auditStore := newAuditStoreStub()
	auditStore.createErr = errors.New("injected public upload audit reservation failure")
	response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), uploadToken,
		http.MethodPost, "/public/api/resources", url.Values{
			"hash": {link.Hash}, "path": {"/reservation-public-upload.txt"},
		}, strings.NewReader("must not upload through share"), nil)
	requireCoreFileAuditStatus(t, response, http.StatusServiceUnavailable)
	assertAPITokenFileState(t, coreFileAuditRealPath(sourcePath, "/public/reservation-public-upload.txt"), false, "")
	stored, err := store.Share.GetByHash(link.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Downloads != beforeDownloads {
		t.Errorf("share count changed after reservation failure: got %d, want %d", stored.Downloads, beforeDownloads)
	}
	if got := stored.GetUserDownloadCount(owner.Username); got != beforeUserDownloads {
		t.Errorf("share user count changed after reservation failure: got %d, want %d", got, beforeUserDownloads)
	}
	creates, finalizes, appends, pending, terminal := coreFileAuditStoreCounts(auditStore)
	if creates != 1 || finalizes != 0 || appends != 0 || pending != 0 || terminal != 0 {
		t.Errorf("share reservation failure writes: create=%d finalize=%d append=%d pending=%d terminal=%d; want 1,0,0,0,0",
			creates, finalizes, appends, pending, terminal)
	}

	t.Run("rename preserves service unavailable", func(t *testing.T) {
		owner := shareHarness.newOwner(t, "core-audit-share-rename-owner", users.Permissions{
			Create: true, Modify: true, Delete: true,
		})
		renameLink := shareHarness.saveShare(t, owner, "core-audit-share-rename-secret", "/public", func(common *dbshare.CommonShare) {
			common.AllowCreate = true
			common.AllowModify = true
			common.AllowDelete = true
		})
		renameLink.PerUserDownloadLimit = true
		renameLink.DownloadsLimit = 10
		renameLink.UserDownloads = map[string]int{owner.Username: 4}
		if err := store.Share.Save(renameLink); err != nil {
			t.Fatal(err)
		}
		beforeRenameDownloads := renameLink.Downloads
		beforeRenameUserDownloads := renameLink.GetUserDownloadCount(owner.Username)
		renameToken := issuePermissionReadWebToken(t, owner)
		const (
			fromPath = "/public/reservation-public-rename-from.txt"
			toPath   = "/public/reservation-public-rename-to.txt"
		)
		if err := os.WriteFile(coreFileAuditRealPath(sourcePath, fromPath), []byte("must not rename through share"), 0o644); err != nil {
			t.Fatal(err)
		}
		payload := MoveCopyRequest{Action: "rename", Items: []MoveCopyItem{{
			FromPath: "/reservation-public-rename-from.txt",
			ToPath:   "/reservation-public-rename-to.txt",
		}}}
		renameAuditStore := newAuditStoreStub()
		renameAuditStore.createErr = errors.New("injected public rename audit reservation failure")
		renameResponse := coreFileAuditRequest(t, newCoreFileAuditRouter(renameAuditStore), renameToken,
			http.MethodPatch, "/public/api/resources", url.Values{
				"hash": {renameLink.Hash}, "path": {"/"},
			}, coreFileAuditJSONBody(t, payload), map[string]string{"Content-Type": "application/json"})
		requireCoreFileAuditStatus(t, renameResponse, http.StatusServiceUnavailable)
		assertAPITokenRenameState(t, coreFileAuditRealPath(sourcePath, fromPath), coreFileAuditRealPath(sourcePath, toPath),
			"must not rename through share", false)
		storedRename, err := store.Share.GetByHash(renameLink.Hash)
		if err != nil {
			t.Fatal(err)
		}
		if storedRename.Downloads != beforeRenameDownloads ||
			storedRename.GetUserDownloadCount(owner.Username) != beforeRenameUserDownloads {
			t.Errorf("share counts changed after rename reservation failure: global=%d user=%d, want %d/%d",
				storedRename.Downloads, storedRename.GetUserDownloadCount(owner.Username),
				beforeRenameDownloads, beforeRenameUserDownloads)
		}
		creates, finalizes, appends, pending, terminal := coreFileAuditStoreCounts(renameAuditStore)
		if creates != 1 || finalizes != 0 || appends != 0 || pending != 0 || terminal != 0 {
			t.Errorf("rename reservation failure writes: create=%d finalize=%d append=%d pending=%d terminal=%d; want 1,0,0,0,0",
				creates, finalizes, appends, pending, terminal)
		}
	})
}

func TestCoreFileActionAuditFinalizeFailureRetainsPending(t *testing.T) {
	environment := newCoreFileAuditEnvironment(t)
	const logicalPath = "/public/finalize-failure-upload.txt"
	auditStore := newAuditStoreStub()
	auditStore.finalizeErr = errors.New("injected audit finalize failure")
	response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), environment.token,
		http.MethodPost, "/api/resources", url.Values{"source": {"source1"}, "path": {logicalPath}},
		strings.NewReader(coreFileAuditUploadBody), nil)
	requireCoreFileAuditStatus(t, response, http.StatusOK)
	assertAPITokenFileState(t, coreFileAuditRealPath(environment.sourcePath, logicalPath), true, coreFileAuditUploadBody)

	creates, finalizes, appends, pending, terminal := coreFileAuditStoreCounts(auditStore)
	if creates != 1 || finalizes != 1 || appends != 0 || pending != 1 || terminal != 0 {
		t.Fatalf("finalize failure writes: create=%d finalize=%d append=%d pending=%d terminal=%d; want 1,1,0,1,0",
			creates, finalizes, appends, pending, terminal)
	}
	pendingEvent := auditStore.singlePending(t)
	if pendingEvent.Action != auditdb.ActionFileUpload || pendingEvent.Result != "" || pendingEvent.HTTPStatus != nil {
		t.Errorf("pending event was terminalized after finalize failure: %+v", pendingEvent)
	}
}

func TestCoreFileActionAuditNoDuplicateAndNoSecretOrHostPathLeakage(t *testing.T) {
	environment := newCoreFileAuditEnvironment(t)
	const (
		querySecret  = "CORE-FILE-AUDIT-RAW-QUERY-SECRET"
		headerSecret = "CORE-FILE-AUDIT-RAW-HEADER-SECRET"
	)
	auditStore := newAuditStoreStub()
	response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), environment.token,
		http.MethodGet, "/api/resources", url.Values{
			"source": {"source1"},
			"path":   {"/public//secret.txt"},
			"token":  {querySecret},
		}, nil, map[string]string{
			"X-Core-Audit-Secret": headerSecret,
			"Range":               "bytes=0-1",
		})
	requireCoreFileAuditStatus(t, response, http.StatusOK)
	event := requireCoreFileAuditReadEvent(t, auditStore)
	requireCoreFileAuditEvent(t, event, auditdb.ActionFileBrowse, auditdb.ResultSuccess, http.StatusOK, "source1", "/public/secret.txt")
	coreFileAuditAssertSecretsAbsent(t, event,
		environment.token,
		querySecret,
		headerSecret,
		"bytes=0-1",
		"/public//secret.txt",
		environment.sourcePath,
	)
}

func TestCoreFileAuditSourceIdentifierCompatibility(t *testing.T) {
	if got := normalizeAuditSourceIdentifier("source1"); got != "source1" {
		t.Fatalf("compatible source changed: got %q", got)
	}
	for _, source := range []string{"\u5185\u90e8\u6587\u4ef6", "source.reserved-name", `C:\host\private`} {
		t.Run(source, func(t *testing.T) {
			want := auditdb.DeriveSourceRef(source)
			if want == "" || want == source || !strings.HasPrefix(want, "source.") {
				t.Fatalf("derived source identifier: got %q for %q", want, source)
			}
			auditStore := newAuditStoreStub()
			recorder := newAuditRecorder(NewAuditService(auditStore), newTestRequestID(), "192.0.2.44", time.Now())
			mustConfigureAuditRecorder(t, recorder, auditdb.ActionFileRename, auditdb.AuthMethodAnonymous)
			if err := recorder.SetResource(source, "/from.txt", "/from.txt"); err != nil {
				t.Fatal(err)
			}
			if err := recorder.SetTarget(source, "/to.txt", "/to.txt"); err != nil {
				t.Fatal(err)
			}
			if err := recorder.ReservePending(); err != nil {
				t.Fatal(err)
			}
			pending := auditStore.singlePending(t)
			if err := recorder.Finalize(AuditFinalization{HTTPStatus: http.StatusOK}); err != nil {
				t.Fatal(err)
			}
			terminal := auditStore.singleAppended(t)
			for _, event := range []auditdb.Event{pending, terminal} {
				if event.Source != want || event.TargetSource != want {
					t.Errorf("normalized source/target: got %q/%q, want %q", event.Source, event.TargetSource, want)
				}
				coreFileAuditAssertSecretsAbsent(t, event, source)
			}
		})
	}
}

func coreFileAuditAssertSecretsAbsent(t *testing.T, event auditdb.Event, secrets ...string) {
	t.Helper()
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	fields := []string{
		event.Source, event.Path, event.CanonicalPath,
		event.TargetSource, event.TargetPath, event.TargetCanonicalPath,
		event.Username, event.TokenRef, event.ShareRef, event.ErrorCode,
	}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if bytes.Contains(payload, []byte(secret)) || bytes.Contains(payload, []byte(strings.ReplaceAll(secret, `\`, `\\`))) {
			t.Errorf("audit event JSON leaked secret or host path %q: %s", secret, payload)
		}
		for _, field := range fields {
			if strings.Contains(field, secret) {
				t.Errorf("audit field %q leaked secret or host path %q", field, secret)
			}
		}
	}
}
