package http

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/access"
	dbshare "github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
)

const (
	permissionReadSecret = "top-secret-original"
)

type permissionReadSecurityHarness struct {
	sourcePath  string
	secretPath  string
	previewPath string
	previewData []byte
}

type permissionReadCallbackWriter struct {
	writer   io.Writer
	once     sync.Once
	callback func()
}

func (w *permissionReadCallbackWriter) Write(p []byte) (int, error) {
	w.once.Do(w.callback)
	return w.writer.Write(p)
}

func newPermissionReadSecurityHarness(t *testing.T) *permissionReadSecurityHarness {
	t.Helper()

	sourcePath := setupResourcePutTestEnv(t)
	secretPath := filepath.Join(sourcePath, "public", "secret.txt")
	previewPath := filepath.Join(sourcePath, "public", "preview.jpg")
	if err := os.WriteFile(secretPath, []byte(permissionReadSecret), 0644); err != nil {
		t.Fatal(err)
	}
	previewData := createPermissionReadJPEG(t, previewPath)
	oldTime := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(secretPath, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(settings.DownloadCacheDir(), 0755); err != nil {
		t.Fatal(err)
	}

	idx := indexing.GetIndex("source1")
	if idx == nil {
		t.Fatal("source1 index was not initialized")
	}
	idx.CreateMockData(1, 1)

	return &permissionReadSecurityHarness{
		sourcePath:  sourcePath,
		secretPath:  secretPath,
		previewPath: previewPath,
		previewData: previewData,
	}
}

func indexPermissionReadPublicDirectory(t *testing.T) {
	t.Helper()

	idx := indexing.GetIndex("source1")
	if idx == nil {
		t.Fatal("source1 index was not initialized")
	}
	if ok := idx.UpdateMetadata(&iteminfo.FileInfo{
		ItemInfo: iteminfo.ItemInfo{
			Name:    "public",
			Type:    "directory",
			ModTime: time.Now(),
		},
		Path:  "/public",
		IsDir: true,
		Files: []iteminfo.ExtendedItemInfo{
			{ItemInfo: iteminfo.ItemInfo{Name: "secret.txt", Size: int64(len(permissionReadSecret)), Type: "text/plain", ModTime: time.Now()}},
			{ItemInfo: iteminfo.ItemInfo{Name: "preview.jpg", Type: "image/jpeg", ModTime: time.Now()}},
		},
	}, nil, true); !ok {
		t.Fatal("index permission read public directory")
	}
}

func (h *permissionReadSecurityHarness) user(t *testing.T, browse, preview, download bool) *users.User {
	t.Helper()

	permissions := users.Permissions{
		Browse:   browse,
		Preview:  preview,
		Download: download,
	}
	return &users.User{
		Username:    "permission-read-user",
		Permissions: permissions,
		Scopes: []users.SourceScope{
			{Name: h.sourcePath, Scope: "/"},
		},
	}
}

func permissionHandlerStatus(returned int, recorder *httptest.ResponseRecorder) int {
	if returned != 0 && returned != http.StatusOK {
		return returned
	}
	return recorder.Code
}

func assertPermissionReadDenied(t *testing.T, status int, err error, context string) {
	t.Helper()

	if status == http.StatusForbidden || status == http.StatusNotFound {
		return
	}
	if status == http.StatusOK || status == http.StatusPartialContent || status == http.StatusNotModified {
		t.Errorf("%s returned successful status %d (err: %v)", context, status, err)
		return
	}
	t.Errorf("%s: expected safe denial status 403 or 404, got %d (err: %v)", context, status, err)
}

type permissionFileInfoReadProbe struct {
	total    int
	content  int
	metadata int
}

type permissionReadBlockingResponseWriter struct {
	header      http.Header
	status      int
	started     chan struct{}
	release     chan struct{}
	startOnce   sync.Once
	releaseOnce sync.Once
}

type permissionReadPanicResponseWriter struct {
	header http.Header
}

type permissionReadHeaderPanicResponseWriter struct{}

func newPermissionReadBlockingResponseWriter() *permissionReadBlockingResponseWriter {
	return &permissionReadBlockingResponseWriter{
		header:  make(http.Header),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func newPermissionReadPanicResponseWriter() *permissionReadPanicResponseWriter {
	return &permissionReadPanicResponseWriter{header: make(http.Header)}
}

func (w *permissionReadBlockingResponseWriter) Header() http.Header {
	return w.header
}

func (w *permissionReadBlockingResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *permissionReadBlockingResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.startOnce.Do(func() { close(w.started) })
	<-w.release
	return len(p), nil
}

func (w *permissionReadBlockingResponseWriter) unblock() {
	w.releaseOnce.Do(func() { close(w.release) })
}

func (w *permissionReadPanicResponseWriter) Header() http.Header {
	return w.header
}

func (w *permissionReadPanicResponseWriter) WriteHeader(int) {}

func (w *permissionReadPanicResponseWriter) Write([]byte) (int, error) {
	panic("permission read response panic")
}

func (*permissionReadHeaderPanicResponseWriter) Header() http.Header {
	panic("permission read header panic")
}

func (*permissionReadHeaderPanicResponseWriter) WriteHeader(int) {}

func (*permissionReadHeaderPanicResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func waitForPermissionReadSignal(t *testing.T, signal <-chan struct{}, context string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", context)
	}
}

func createPermissionReadArchiveSpool(t *testing.T, content string) (string, os.FileInfo) {
	t.Helper()
	file, info, err := settings.CreateDownloadArchiveSpool(".zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteString(content); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	return file.Name(), info
}

func observePermissionFileInfoReads(t *testing.T) *permissionFileInfoReadProbe {
	t.Helper()

	original := files.FileInfoFasterFunc
	probe := &permissionFileInfoReadProbe{}
	files.FileInfoFasterFunc = func(opts utils.FileOptions, accessStorage *access.Storage, user *users.User, shareStorage *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
		probe.total++
		if opts.Content {
			probe.content++
		}
		if opts.Metadata {
			probe.metadata++
		}
		return original(opts, accessStorage, user, shareStorage)
	}
	t.Cleanup(func() {
		files.FileInfoFasterFunc = original
	})
	return probe
}

func assertNoOriginalHeaders(t *testing.T, header http.Header) {
	t.Helper()

	for _, name := range []string{
		"Accept-Ranges",
		"Content-Disposition",
		"Content-Length",
		"Content-Range",
		"ETag",
		"Last-Modified",
		"X-Archive-Token",
	} {
		if value := header.Get(name); value != "" {
			t.Errorf("unauthorized response leaked %s=%q", name, value)
		}
	}
	if contentType := header.Get("Content-Type"); contentType != "" && !strings.HasPrefix(contentType, "application/json") {
		t.Errorf("unauthorized response leaked original Content-Type=%q", contentType)
	}
}

func assertNoPermissionReadBytes(t *testing.T, body []byte, context string) {
	t.Helper()
	probe := []byte(permissionReadSecret[:6])
	if bytes.Contains(body, probe) {
		t.Errorf("%s leaked original byte fragment %q", context, body)
	}
}

func configurePermissionReadAuth(t *testing.T) {
	t.Helper()

	previousSettingsAuth := settings.Config.Auth
	var previousConfigAuth settings.Auth
	hadConfig := config != nil
	if hadConfig {
		previousConfigAuth = config.Auth
	}
	testAuth := settings.Auth{Key: "permission-read-security-auth-key"}
	settings.Config.Auth = testAuth
	if config != nil {
		config.Auth = testAuth
	}
	t.Cleanup(func() {
		settings.Config.Auth = previousSettingsAuth
		if hadConfig && config != nil {
			config.Auth = previousConfigAuth
		}
	})
}

func savePermissionReadUser(t *testing.T, user *users.User) {
	t.Helper()

	if err := store.Users.Save(user, false, false); err != nil {
		t.Fatal(err)
	}
	if user.ID == 0 {
		t.Fatal("saved permission read user has no ID")
	}
}

func issuePermissionReadWebToken(t *testing.T, user *users.User) string {
	t.Helper()

	token, _, err := auth.MakeSignedTokenAPI(user, "WEB_TOKEN_permission_read", time.Hour, user.Permissions, false)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func issuePermissionReadAPIToken(t *testing.T, user *users.User, name string, permissions users.Permissions) string {
	t.Helper()

	token, metadata, err := auth.MakeSignedTokenAPI(user, name, time.Hour, permissions, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Users.AddApiToken(user.ID, name, token, metadata); err != nil {
		t.Fatal(err)
	}
	if err = store.Access.AddApiToken(token, user.ID); err != nil {
		t.Fatal(err)
	}
	return token
}

func permissionReadAPIRouter() *http.ServeMux {
	api := http.NewServeMux()
	api.HandleFunc("GET /resources/download", withUser(downloadHandler))
	api.HandleFunc("GET /resources/preview", withTimeout(30*time.Second, withUserHelper(previewHandler)))
	api.HandleFunc("GET /resources/preview-source/{ticket}", authenticatedPreviewSnapshotHandler)
	api.HandleFunc("GET /raw", withUser(downloadHandler))
	router := http.NewServeMux()
	router.Handle("/api/", http.StripPrefix("/api", api))
	return router
}

func TestPermissionReadSecurity_BrowseEndpoints(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	user := h.user(t, false, true, true)

	t.Run("Browse=false rejects directory listings before metadata lookup", func(t *testing.T) {
		reads := observePermissionFileInfoReads(t)
		query := url.Values{"source": {"source1"}, "path": {"/public"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := resourceGetHandler(recorder, req, &requestContext{user: user})
		assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "Browse=false directory status")
		if reads.total != 0 {
			t.Errorf("Browse=false directory listing performed %d metadata lookup(s) before denial", reads.total)
		}
		if body := recorder.Body.String(); body != "" {
			t.Errorf("Browse=false directory listing leaked response body %q", body)
		}
	})

	t.Run("Browse=false rejects file details before metadata lookup", func(t *testing.T) {
		reads := observePermissionFileInfoReads(t)
		query := url.Values{"source": {"source1"}, "path": {"/public/secret.txt"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := resourceGetHandler(recorder, req, &requestContext{user: user})
		assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "Browse=false file detail status")
		if reads.total != 0 {
			t.Errorf("Browse=false file detail performed %d metadata lookup(s) before denial", reads.total)
		}
		if body := recorder.Body.String(); body != "" {
			t.Errorf("Browse=false file detail leaked response body %q", body)
		}
	})

	t.Run("Admin=true does not bypass Browse=false", func(t *testing.T) {
		admin := h.user(t, false, true, true)
		admin.Permissions.Admin = true
		reads := observePermissionFileInfoReads(t)
		query := url.Values{"source": {"source1"}, "path": {"/public/secret.txt"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := resourceGetHandler(recorder, req, &requestContext{user: admin})
		assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "admin Browse=false status")
		if reads.total != 0 {
			t.Errorf("admin Browse=false performed %d metadata lookup(s) before denial", reads.total)
		}
	})

	t.Run("Browse=false rejects indexed search output", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/tools/search?source=source1&largest=true", nil)
		req.Header.Set("SessionId", t.Name())
		recorder := httptest.NewRecorder()

		returned, err := searchHandler(recorder, req, &requestContext{user: user})
		assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "Browse=false search status")
		if body := recorder.Body.String(); body != "" {
			t.Errorf("Browse=false search emitted index output %q", body)
		}
	})

	t.Run("Browse=false rejects items index output", func(t *testing.T) {
		query := url.Values{"source": {"source1"}, "path": {"/public"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources/items?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := itemsGetHandler(recorder, req, &requestContext{user: user})
		assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "Browse=false items status")
		if body := recorder.Body.String(); body != "" {
			t.Errorf("Browse=false items endpoint emitted index output %q", body)
		}
	})

	t.Run("Browse=false known path does not create an existence oracle", func(t *testing.T) {
		type observation struct {
			status int
			body   string
		}
		observe := func(path string) observation {
			query := url.Values{"source": {"source1"}, "path": {path}}
			req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
			recorder := httptest.NewRecorder()
			returned, _ := resourceGetHandler(recorder, req, &requestContext{user: user})
			return observation{
				status: permissionHandlerStatus(returned, recorder),
				body:   recorder.Body.String(),
			}
		}

		existing := observe("/public/secret.txt")
		missing := observe("/public/does-not-exist.txt")
		if existing.status != http.StatusForbidden && existing.status != http.StatusNotFound {
			t.Errorf("Browse=false known path returned observable status %d", existing.status)
		}
		if existing != missing {
			t.Errorf("Browse=false existence oracle: existing=%+v missing=%+v", existing, missing)
		}
	})

	t.Run("Browse read endpoints reject unsafe paths before lookup", func(t *testing.T) {
		authorized := h.user(t, true, true, true)
		for _, path := range []string{"/public/../private/secret.txt", `C:\Windows\win.ini`} {
			t.Run("resource "+path, func(t *testing.T) {
				reads := observePermissionFileInfoReads(t)
				query := url.Values{"source": {"source1"}, "path": {path}}
				req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
				recorder := httptest.NewRecorder()

				returned, err := resourceGetHandler(recorder, req, &requestContext{user: authorized})
				if got := permissionHandlerStatus(returned, recorder); got != http.StatusBadRequest {
					t.Errorf("unsafe resource path status: got %d, want %d (err: %v)", got, http.StatusBadRequest, err)
				}
				if reads.total != 0 {
					t.Errorf("unsafe resource path performed %d lookup(s)", reads.total)
				}
			})
		}

		itemsQuery := url.Values{"source": {"source1"}, "path": {"/public/../private"}}
		itemsReq := httptest.NewRequest(http.MethodGet, "/api/resources/items?"+itemsQuery.Encode(), nil)
		itemsRecorder := httptest.NewRecorder()
		returned, err := itemsGetHandler(itemsRecorder, itemsReq, &requestContext{user: authorized})
		if got := permissionHandlerStatus(returned, itemsRecorder); got != http.StatusBadRequest {
			t.Errorf("unsafe items path status: got %d, want %d (err: %v)", got, http.StatusBadRequest, err)
		}

		searchQuery := url.Values{"scope": {"source1:/public/../private"}, "largest": {"true"}}
		searchReq := httptest.NewRequest(http.MethodGet, "/api/tools/search?"+searchQuery.Encode(), nil)
		searchReq.Header.Set("SessionId", t.Name())
		searchRecorder := httptest.NewRecorder()
		returned, err = searchHandler(searchRecorder, searchReq, &requestContext{user: authorized})
		if got := permissionHandlerStatus(returned, searchRecorder); got != http.StatusBadRequest {
			t.Errorf("unsafe search scope status: got %d, want %d (err: %v)", got, http.StatusBadRequest, err)
		}
	})
}

func TestPermissionReadSecurity_SearchRechecksPermissionsAfterQuery(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	user := h.user(t, true, true, true)
	user.Username = "permission-search-post-query-revocation-user"
	savePermissionReadUser(t, user)

	previousHook := authenticatedSearchAfterQueryHook
	authenticatedSearchAfterQueryHook = func() {
		updated := *user
		updated.Permissions.Browse = false
		if err := store.Users.Update(&updated, true, "Permissions"); err != nil {
			t.Errorf("revoke Browse after search query: %v", err)
		}
	}
	t.Cleanup(func() { authenticatedSearchAfterQueryHook = previousHook })

	request := httptest.NewRequest(http.MethodGet, "/api/tools/search?source=source1&largest=true", nil)
	request.Header.Set("SessionId", t.Name())
	recorder := httptest.NewRecorder()
	returned, err := searchHandler(recorder, request, &requestContext{user: user})
	assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "search permission revoked after index query")
	if recorder.Body.Len() != 0 {
		t.Errorf("post-query revoked search emitted response %q", recorder.Body.Bytes())
	}
}

func TestPermissionReadSecurity_SearchReturnsAuthorizedScopedResults(t *testing.T) {
	for _, tc := range []struct {
		name      string
		userScope string
		query     string
	}{
		{name: "non-root user scope", userScope: "/public", query: "source=source1&largest=true"},
		{name: "explicit search scope", userScope: "/", query: "scope=source1%3A%2Fpublic&largest=true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newPermissionReadSecurityHarness(t)
			indexPermissionReadPublicDirectory(t)
			user := h.user(t, true, true, true)
			user.Username = "permission-search-scope-" + strings.ReplaceAll(tc.name, " ", "-")
			user.Scopes[0].Scope = tc.userScope

			request := httptest.NewRequest(http.MethodGet, "/api/tools/search?"+tc.query, nil)
			request.Header.Set("SessionId", t.Name())
			recorder := httptest.NewRecorder()
			returned, err := searchHandler(recorder, request, &requestContext{user: user})
			if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
				t.Fatalf("scoped search status: got %d, want %d (err: %v, body: %q)", got, http.StatusOK, err, recorder.Body.String())
			}

			var results []*indexing.SearchResult
			if err := json.Unmarshal(recorder.Body.Bytes(), &results); err != nil {
				t.Fatalf("decode scoped search response: %v", err)
			}
			found := false
			for _, result := range results {
				if result.Source == "source1" && result.Path == "secret.txt" {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("authorized scoped result was filtered out: %+v", results)
			}
		})
	}
}

func TestPermissionReadSecurity_SearchScopeACLBeforeQuery(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	indexPermissionReadPublicDirectory(t)
	user := h.user(t, true, true, true)
	user.Username = "permission-search-scope-acl-user"
	savePermissionReadUser(t, user)
	if err := store.Access.DenyUser(h.sourcePath, "/public", user.Username); err != nil {
		t.Fatal(err)
	}

	queried := false
	previousHook := authenticatedSearchAfterQueryHook
	authenticatedSearchAfterQueryHook = func() { queried = true }
	t.Cleanup(func() { authenticatedSearchAfterQueryHook = previousHook })

	search := func() (int, *httptest.ResponseRecorder, error) {
		request := httptest.NewRequest(http.MethodGet, "/api/tools/search?scope=source1%3A%2Fpublic&largest=true", nil)
		request.Header.Set("SessionId", t.Name())
		recorder := httptest.NewRecorder()
		returned, err := searchHandler(recorder, request, &requestContext{user: user})
		return permissionHandlerStatus(returned, recorder), recorder, err
	}

	status, recorder, err := search()
	if status != http.StatusForbidden {
		t.Errorf("denied search scope status: got %d, want %d (err: %v, body: %q)", status, http.StatusForbidden, err, recorder.Body.String())
	}
	if queried {
		t.Error("denied search scope reached the index query")
	}

	if allowErr := store.Access.AllowUser(h.sourcePath, "/public/secret.txt", user.Username); allowErr != nil {
		t.Fatal(allowErr)
	}
	queried = false
	status, recorder, err = search()
	if status != http.StatusOK {
		t.Fatalf("search scope with explicitly allowed child status: got %d, want %d (err: %v, body: %q)", status, http.StatusOK, err, recorder.Body.String())
	}
	if !queried {
		t.Error("search scope with explicitly allowed child did not query the index")
	}
	if !strings.Contains(recorder.Body.String(), `"path":"secret.txt"`) {
		t.Errorf("explicitly allowed child was not returned: %s", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "preview.jpg") {
		t.Errorf("inherited-denied child was returned: %s", recorder.Body.String())
	}
}

func TestPermissionReadSecurity_ResourceAndItemsRefreshBeforeLookup(t *testing.T) {
	for _, revoke := range []string{"account Browse", "token"} {
		t.Run(revoke, func(t *testing.T) {
			h := newPermissionReadSecurityHarness(t)
			indexPermissionReadPublicDirectory(t)
			configurePermissionReadAuth(t)
			user := h.user(t, true, true, true)
			user.Username = "permission-resource-fresh-" + strings.ReplaceAll(revoke, " ", "-")
			savePermissionReadUser(t, user)

			token := ""
			if revoke == "token" {
				token = issuePermissionReadAPIToken(t, user, "resource-fresh-token", user.Permissions)
				if err := auth.RevokeApiToken(store.Access, token); err != nil {
					t.Fatalf("revoke API token: %v", err)
				}
			} else {
				updated := *user
				updated.Permissions.Browse = false
				if err := store.Users.Update(&updated, true, "Permissions"); err != nil {
					t.Fatalf("revoke account Browse: %v", err)
				}
			}

			probe := observePermissionFileInfoReads(t)
			for _, endpoint := range []struct {
				name string
				path string
				call func(*httptest.ResponseRecorder, *http.Request, *requestContext) (int, error)
			}{
				{name: "resource existing", path: "/public/secret.txt", call: func(w *httptest.ResponseRecorder, r *http.Request, d *requestContext) (int, error) {
					return resourceGetHandler(w, r, d)
				}},
				{name: "resource missing", path: "/public/does-not-exist.txt", call: func(w *httptest.ResponseRecorder, r *http.Request, d *requestContext) (int, error) {
					return resourceGetHandler(w, r, d)
				}},
				{name: "items existing", path: "/public", call: func(w *httptest.ResponseRecorder, r *http.Request, d *requestContext) (int, error) {
					return itemsGetHandler(w, r, d)
				}},
				{name: "items missing", path: "/does-not-exist", call: func(w *httptest.ResponseRecorder, r *http.Request, d *requestContext) (int, error) {
					return itemsGetHandler(w, r, d)
				}},
			} {
				t.Run(endpoint.name, func(t *testing.T) {
					query := url.Values{"source": {"source1"}, "path": {endpoint.path}}
					request := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
					recorder := httptest.NewRecorder()
					returned, err := endpoint.call(recorder, request, &requestContext{user: user, token: token})
					if got := permissionHandlerStatus(returned, recorder); got != http.StatusForbidden {
						t.Errorf("revoked %s status: got %d, want %d (err: %v, body: %q)", endpoint.name, got, http.StatusForbidden, err, recorder.Body.String())
					}
					if recorder.Body.Len() != 0 {
						t.Errorf("revoked %s emitted body %q", endpoint.name, recorder.Body.Bytes())
					}
				})
			}
			if probe.total != 0 {
				t.Errorf("revoked read reached FileInfoFaster %d time(s) before fresh authorization", probe.total)
			}
		})
	}
}

func TestPermissionReadSecurity_PreviewAndDownloadRequireBrowse(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)

	for _, tc := range []struct {
		name       string
		browse     bool
		preview    bool
		wantStatus int
	}{
		{name: "Preview=true cannot bypass Browse=false", browse: false, preview: true, wantStatus: http.StatusForbidden},
		{name: "Browse=true cannot bypass Preview=false", browse: true, preview: false, wantStatus: http.StatusForbidden},
		{name: "Browse=true and Preview=true allow preview", browse: true, preview: true, wantStatus: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := h.user(t, tc.browse, tc.preview, true)
			reads := observePermissionFileInfoReads(t)
			query := url.Values{"source": {"source1"}, "path": {"/public/preview.jpg"}}
			req := httptest.NewRequest(http.MethodGet, "/api/resources/preview?"+query.Encode(), nil)
			recorder := httptest.NewRecorder()

			returned, err := previewHandler(recorder, req, &requestContext{user: user})
			if tc.wantStatus == http.StatusForbidden {
				assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "preview status")
				if reads.total != 0 {
					t.Errorf("unauthorized preview performed %d metadata lookup(s) before denial", reads.total)
				}
				if bytes.Equal(recorder.Body.Bytes(), h.previewData) {
					t.Error("unauthorized preview returned the original image")
				}
				return
			}
			if got := permissionHandlerStatus(returned, recorder); got != tc.wantStatus {
				t.Errorf("preview status: expected %d, got %d (err: %v)", tc.wantStatus, got, err)
			}
			if !bytes.Equal(recorder.Body.Bytes(), h.previewData) {
				t.Errorf("authorized preview body did not match the JPEG fixture: got %d bytes, want %d", recorder.Body.Len(), len(h.previewData))
			}
		})
	}

	t.Run("Download=true cannot bypass Browse=false", func(t *testing.T) {
		user := h.user(t, false, true, true)
		query := url.Values{"source": {"source1"}, "file": {"/public/secret.txt"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := downloadHandler(recorder, req, &requestContext{user: user})
		assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "Browse=false download status")
		assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "Browse=false download")
	})
}

func TestPermissionReadSecurity_DownloadOriginalAccess(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	const mediaTextContent = "metadata fixture"
	if err := os.WriteFile(filepath.Join(h.sourcePath, "public", "song.mp3"), []byte(mediaTextContent), 0o644); err != nil {
		t.Fatal(err)
	}
	fileQuery := url.Values{"source": {"source1"}, "file": {"/public/secret.txt"}}

	t.Run("Download=false rejects ordinary GET", func(t *testing.T) {
		user := h.user(t, true, true, false)
		req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+fileQuery.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := downloadHandler(recorder, req, &requestContext{user: user})
		assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "Download=false GET status")
		assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "Download=false GET")
	})

	t.Run("Admin=true does not bypass Download=false", func(t *testing.T) {
		admin := h.user(t, true, true, false)
		admin.Permissions.Admin = true
		req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+fileQuery.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := downloadHandler(recorder, req, &requestContext{user: admin})
		assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "admin Download=false status")
		assertNoOriginalHeaders(t, recorder.Header())
		assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "admin Download=false")
	})

	t.Run("Browse=false download does not reveal path existence", func(t *testing.T) {
		user := h.user(t, false, true, true)
		type observation struct {
			status int
			body   string
		}
		observe := func(file string) observation {
			query := url.Values{"source": {"source1"}, "file": {file}}
			req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
			recorder := httptest.NewRecorder()
			returned, err := downloadHandler(recorder, req, &requestContext{user: user})
			status := permissionHandlerStatus(returned, recorder)
			assertPermissionReadDenied(t, status, err, "Browse=false download status")
			assertNoOriginalHeaders(t, recorder.Header())
			return observation{status: status, body: recorder.Body.String()}
		}

		existing := observe("/public/secret.txt")
		missing := observe("/public/does-not-exist.txt")
		if existing != missing {
			t.Errorf("Browse=false download existence oracle: existing=%+v missing=%+v", existing, missing)
		}
	})

	t.Run("download rejects unsafe paths before resolution", func(t *testing.T) {
		user := h.user(t, true, true, true)
		for _, filePath := range []string{
			"/public/../private/secret.txt",
			"../private/secret.txt",
			`C:\Windows\win.ini`,
			"C:/Windows/win.ini",
			`\\server\share\secret.txt`,
			"//server/share/secret.txt",
			`\\?\C:\Windows\win.ini`,
		} {
			t.Run(filePath, func(t *testing.T) {
				query := url.Values{"source": {"source1"}, "file": {filePath}}
				req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
				recorder := httptest.NewRecorder()

				returned, err := downloadHandler(recorder, req, &requestContext{user: user})
				if got := permissionHandlerStatus(returned, recorder); got != http.StatusBadRequest {
					t.Errorf("unsafe path status: got %d, want %d (err: %v)", got, http.StatusBadRequest, err)
				}
				assertNoOriginalHeaders(t, recorder.Header())
				assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "unsafe path response")
			})
		}
	})

	t.Run("download rejects malformed repeated path query", func(t *testing.T) {
		user := h.user(t, true, true, true)
		req := httptest.NewRequest(http.MethodGet, "/api/resources/download?source=source1", nil)
		req.URL.RawQuery = "source=source1&file=%2Fpublic%2Fsecret.txt&file=%ZZ"
		recorder := httptest.NewRecorder()

		returned, err := downloadHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusBadRequest {
			t.Errorf("malformed repeated path status: got %d, want %d (err: %v)", got, http.StatusBadRequest, err)
		}
		assertNoOriginalHeaders(t, recorder.Header())
		assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "malformed repeated path response")
	})

	t.Run("logical root path is joined to Scope before access", func(t *testing.T) {
		user := h.user(t, true, true, true)
		user.Scopes[0].Scope = "/public"
		query := url.Values{"source": {"source1"}, "file": {"/secret.txt"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := downloadHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
			t.Fatalf("scoped logical path status: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}
		if body := recorder.Body.String(); body != permissionReadSecret {
			t.Errorf("scoped logical path body: got %q, want %q", body, permissionReadSecret)
		}
	})

	t.Run("Access Rule receives the Scope-joined logical path", func(t *testing.T) {
		user := h.user(t, true, true, true)
		user.Username = "permission-read-scoped-access-user"
		user.Scopes[0].Scope = "/public"
		savePermissionReadUser(t, user)
		if err := store.Access.DenyUser(h.sourcePath, "/public/secret.txt", user.Username); err != nil {
			t.Fatal(err)
		}
		query := url.Values{"source": {"source1"}, "file": {"/secret.txt"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := downloadHandler(recorder, req, &requestContext{user: user})
		assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "scope-joined Access Rule status")
		assertNoOriginalHeaders(t, recorder.Header())
		assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "scope-joined Access Rule response")
	})

	t.Run("denied access rule does not reveal path existence", func(t *testing.T) {
		privateDir := filepath.Join(h.sourcePath, "private")
		if err := os.MkdirAll(privateDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(privateDir, "existing.txt"), []byte(permissionReadSecret), 0644); err != nil {
			t.Fatal(err)
		}

		user := h.user(t, true, true, true)
		user.Username = "permission-read-denied-path-user"
		savePermissionReadUser(t, user)
		if err := store.Access.DenyUser(h.sourcePath, "/private", user.Username); err != nil {
			t.Fatal(err)
		}

		type observation struct {
			status int
			body   string
		}
		observe := func(file string) observation {
			query := url.Values{"source": {"source1"}, "file": {file}}
			req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
			recorder := httptest.NewRecorder()
			returned, err := downloadHandler(recorder, req, &requestContext{user: user})
			status := permissionHandlerStatus(returned, recorder)
			assertPermissionReadDenied(t, status, err, "access-denied download status")
			assertNoOriginalHeaders(t, recorder.Header())
			return observation{status: status, body: recorder.Body.String()}
		}

		existing := observe("/private/existing.txt")
		missing := observe("/private/missing.txt")
		if existing != missing {
			t.Errorf("access rule existence oracle: existing=%+v missing=%+v", existing, missing)
		}
	})

	t.Run("HEAD rejects before original metadata is exposed", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			browse   bool
			download bool
		}{
			{name: "Browse=false Download=true", browse: false, download: true},
			{name: "Browse=true Download=false", browse: true, download: false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				user := h.user(t, tc.browse, true, tc.download)
				req := httptest.NewRequest(http.MethodHead, "/api/resources/download?"+fileQuery.Encode(), nil)
				recorder := httptest.NewRecorder()

				returned, err := downloadHandler(recorder, req, &requestContext{user: user})
				assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "unauthorized HEAD status")
				assertNoOriginalHeaders(t, recorder.Header())
				if recorder.Body.Len() != 0 {
					t.Errorf("unauthorized HEAD leaked body %q", recorder.Body.Bytes())
				}
			})
		}
	})

	t.Run("Range and 206 require Browse and Download", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			browse     bool
			download   bool
			wantStatus int
		}{
			{name: "both permissions", browse: true, download: true, wantStatus: http.StatusPartialContent},
			{name: "Browse missing", browse: false, download: true, wantStatus: http.StatusForbidden},
			{name: "Download missing", browse: true, download: false, wantStatus: http.StatusForbidden},
		} {
			t.Run(tc.name, func(t *testing.T) {
				user := h.user(t, tc.browse, true, tc.download)
				req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+fileQuery.Encode(), nil)
				req.Header.Set("Range", "bytes=0-5")
				recorder := httptest.NewRecorder()

				returned, err := downloadHandler(recorder, req, &requestContext{user: user})
				if tc.wantStatus == http.StatusPartialContent {
					if got := permissionHandlerStatus(returned, recorder); got != tc.wantStatus {
						t.Errorf("Range status: expected %d, got %d (err: %v)", tc.wantStatus, got, err)
					}
					if body := recorder.Body.String(); body != permissionReadSecret[:6] {
						t.Errorf("authorized Range body: expected %q, got %q", permissionReadSecret[:6], body)
					}
					return
				}
				assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "unauthorized Range status")
				assertNoOriginalHeaders(t, recorder.Header())
				if recorder.Header().Get("Content-Range") != "" {
					t.Errorf("unauthorized Range leaked Content-Range %q", recorder.Header().Get("Content-Range"))
				}
				if body := recorder.Body.String(); body != "" {
					t.Errorf("unauthorized Range leaked body %q", body)
				}
			})
		}
	})

	t.Run("content=true requires Download before reading full text", func(t *testing.T) {
		user := h.user(t, true, true, false)
		reads := observePermissionFileInfoReads(t)
		query := url.Values{"source": {"source1"}, "path": {"/public/secret.txt"}, "content": {"true"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := resourceGetHandler(recorder, req, &requestContext{user: user})
		assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "Download=false content status")
		if reads.total != 0 {
			t.Errorf("Download=false content reached metadata/disk path %d time(s) before denial", reads.total)
		}
		if reads.content != 0 {
			t.Errorf("Download=false content read path was entered %d time(s) before denial", reads.content)
		}
		assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "Download=false content response")
	})

	t.Run("metadata=true returns Browse-only file information without content", func(t *testing.T) {
		user := h.user(t, true, false, false)
		reads := observePermissionFileInfoReads(t)
		query := url.Values{"source": {"source1"}, "path": {"/public/secret.txt"}, "metadata": {"true"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := resourceGetHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
			t.Fatalf("Browse-only metadata status: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}
		if reads.total != 1 || reads.content != 0 || reads.metadata != 0 {
			t.Errorf("Browse-only metadata reads: total=%d content=%d metadata=%d, want 1/0/0", reads.total, reads.content, reads.metadata)
		}
		var response iteminfo.ExtendedFileInfo
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode Browse-only metadata response: %v", err)
		}
		if response.Name != "secret.txt" || response.Type == "" {
			t.Errorf("Browse-only metadata omitted basic file information: %+v", response.FileInfo)
		}
		if response.Content != "" || bytes.Contains(recorder.Body.Bytes(), []byte(permissionReadSecret)) {
			t.Errorf("Browse-only metadata leaked file content %q", recorder.Body.Bytes())
		}
	})

	t.Run("metadata=true permits Preview enrichment without Download", func(t *testing.T) {
		user := h.user(t, true, true, false)
		reads := observePermissionFileInfoReads(t)
		query := url.Values{"source": {"source1"}, "path": {"/public"}, "metadata": {"true"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := resourceGetHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
			t.Fatalf("Browse+Preview metadata status: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}
		if reads.total != 2 || reads.content != 0 || reads.metadata != 1 {
			t.Errorf("Browse+Preview metadata reads: total=%d content=%d metadata=%d, want 2/0/1", reads.total, reads.content, reads.metadata)
		}
		assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "Browse+Preview metadata response")
	})

	t.Run("metadata=true returns safe Preview-derived fields without content", func(t *testing.T) {
		user := h.user(t, true, true, false)
		original := files.FileInfoFasterFunc
		var calls []utils.FileOptions
		files.FileInfoFasterFunc = func(opts utils.FileOptions, _ *access.Storage, _ *users.User, _ *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
			calls = append(calls, opts)
			response := &iteminfo.ExtendedFileInfo{
				FileInfo: iteminfo.FileInfo{
					ItemInfo: iteminfo.ItemInfo{Name: "song.mp3", Size: 1234, Type: "audio/mpeg"},
					Path:     "/public/song.mp3",
				},
				RealPath: h.secretPath,
			}
			if opts.Metadata {
				response.Metadata = &iteminfo.MediaMetadata{Title: "safe title", Duration: 42}
				response.Content = permissionReadSecret
			}
			return response, nil
		}
		t.Cleanup(func() { files.FileInfoFasterFunc = original })

		query := url.Values{"source": {"source1"}, "path": {"/public/song.mp3"}, "metadata": {"true"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()
		returned, err := resourceGetHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
			t.Fatalf("Preview-derived metadata status: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}
		if len(calls) != 2 || calls[0].Metadata || !calls[1].Metadata || calls[0].Content || calls[1].Content || calls[1].ReadPath == "" {
			t.Fatalf("Preview-derived metadata options: %+v", calls)
		}
		var response iteminfo.ExtendedFileInfo
		if err = json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode Preview-derived metadata response: %v", err)
		}
		if response.Metadata == nil || response.Metadata.Title != "safe title" || response.Metadata.Duration != 42 {
			t.Errorf("Preview-derived metadata missing safe fields: %+v", response.Metadata)
		}
		if response.Content != "" || bytes.Contains(recorder.Body.Bytes(), []byte(permissionReadSecret)) {
			t.Errorf("Preview-derived metadata leaked content %q", recorder.Body.Bytes())
		}
	})

	t.Run("metadata=true with Preview skips non-media text content", func(t *testing.T) {
		user := h.user(t, true, true, false)
		reads := observePermissionFileInfoReads(t)
		query := url.Values{"source": {"source1"}, "path": {"/public/secret.txt"}, "metadata": {"true"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := resourceGetHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
			t.Fatalf("Preview text metadata status: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}
		if reads.total != 1 || reads.content != 0 || reads.metadata != 0 {
			t.Errorf("Preview text metadata reads: total=%d content=%d metadata=%d, want 1/0/0", reads.total, reads.content, reads.metadata)
		}
		assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "Preview text metadata response")
	})

	t.Run("content and metadata do not let Download substitute for Preview", func(t *testing.T) {
		user := h.user(t, true, false, true)
		original := files.FileInfoFasterFunc
		var calls []utils.FileOptions
		files.FileInfoFasterFunc = func(opts utils.FileOptions, _ *access.Storage, _ *users.User, _ *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
			calls = append(calls, opts)
			response := &iteminfo.ExtendedFileInfo{
				FileInfo: iteminfo.FileInfo{
					ItemInfo: iteminfo.ItemInfo{Name: "song.mp3", Size: 1234, Type: "audio/mpeg"},
					Path:     "/public/song.mp3",
				},
				RealPath: h.secretPath,
			}
			if opts.Content {
				response.Content = permissionReadSecret
			}
			response.Metadata = &iteminfo.MediaMetadata{Title: "preview-only", AlbumArt: []byte("album-art")}
			response.Subtitles = []utils.SubtitleTrack{{Name: "preview-only.srt"}}
			return response, nil
		}
		t.Cleanup(func() { files.FileInfoFasterFunc = original })

		query := url.Values{
			"source":   {"source1"},
			"path":     {"/public/song.mp3"},
			"metadata": {"true"},
			"content":  {"true"},
		}
		req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()
		returned, err := resourceGetHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
			t.Fatalf("Download content without Preview status: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}
		if len(calls) != 1 || calls[0].Content || calls[0].Metadata || calls[0].ReadPath != "" {
			t.Fatalf("audio content options: %+v", calls)
		}
		var response iteminfo.ExtendedFileInfo
		if err = json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode Download content without Preview response: %v", err)
		}
		if response.Content != mediaTextContent {
			t.Errorf("Download content was removed: got %q, want %q", response.Content, mediaTextContent)
		}
		if response.Metadata != nil || len(response.Subtitles) != 0 {
			t.Errorf("Download substituted for Preview: metadata=%+v subtitles=%+v", response.Metadata, response.Subtitles)
		}
	})

	t.Run("metadata=true does not let Download substitute for Preview", func(t *testing.T) {
		user := h.user(t, true, false, true)
		reads := observePermissionFileInfoReads(t)
		query := url.Values{"source": {"source1"}, "path": {"/public"}, "metadata": {"true"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := resourceGetHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
			t.Fatalf("Browse+Download metadata status: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}
		if reads.total != 1 || reads.content != 0 || reads.metadata != 0 {
			t.Errorf("Browse+Download metadata reads: total=%d content=%d metadata=%d, want 1/0/0", reads.total, reads.content, reads.metadata)
		}
		assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "Browse+Download metadata response")
	})

	t.Run("metadata=true still requires Browse before lookup", func(t *testing.T) {
		user := h.user(t, false, true, false)
		reads := observePermissionFileInfoReads(t)
		query := url.Values{"source": {"source1"}, "path": {"/public/secret.txt"}, "metadata": {"true"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := resourceGetHandler(recorder, req, &requestContext{user: user})
		assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "Browse=false metadata status")
		if reads.total != 0 {
			t.Errorf("Browse=false metadata performed %d lookup(s) before denial", reads.total)
		}
		if body := recorder.Body.String(); body != "" {
			t.Errorf("Browse=false metadata emitted response body %q", body)
		}
	})

	t.Run("checksum requires Download before disk access", func(t *testing.T) {
		user := h.user(t, true, true, false)
		reads := observePermissionFileInfoReads(t)
		query := url.Values{"source": {"source1"}, "path": {"/public/secret.txt"}, "checksum": {"sha256"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := resourceGetHandler(recorder, req, &requestContext{user: user})
		assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "Download=false checksum status")
		if reads.total != 0 {
			t.Errorf("Download=false checksum reached metadata/disk path %d time(s) before denial", reads.total)
		}
		if body := recorder.Body.String(); body != "" {
			t.Errorf("Download=false checksum emitted response body %q", body)
		}
	})

	t.Run("raw download and conditional requests cannot bypass Browse", func(t *testing.T) {
		configurePermissionReadAuth(t)
		user := h.user(t, false, true, true)
		user.Username = "permission-read-route-user"
		savePermissionReadUser(t, user)
		token := issuePermissionReadWebToken(t, user)
		router := permissionReadAPIRouter()
		future := time.Now().Add(24 * time.Hour).UTC().Format(http.TimeFormat)
		for _, tc := range []struct {
			name        string
			target      string
			conditional bool
		}{
			{name: "download endpoint", target: "/api/resources/download?" + fileQuery.Encode()},
			{name: "raw alias", target: "/api/raw?" + fileQuery.Encode()},
			{name: "conditional download", target: "/api/resources/download?" + fileQuery.Encode(), conditional: true},
			{name: "conditional raw alias", target: "/api/raw?" + fileQuery.Encode(), conditional: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, tc.target, nil)
				req.Header.Set("Authorization", "Bearer "+token)
				if tc.conditional {
					req.Header.Set("If-Modified-Since", future)
				}
				recorder := httptest.NewRecorder()

				router.ServeHTTP(recorder, req)
				assertPermissionReadDenied(t, recorder.Code, nil, "Browse=false raw/download request status")
				assertNoOriginalHeaders(t, recorder.Header())
				assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "Browse=false raw/download request")
			})
		}
	})

	t.Run("conditional request requires Download before 304 metadata", func(t *testing.T) {
		user := h.user(t, true, true, false)
		req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+fileQuery.Encode(), nil)
		req.Header.Set("If-Modified-Since", time.Now().Add(24*time.Hour).UTC().Format(http.TimeFormat))
		recorder := httptest.NewRecorder()

		returned, err := downloadHandler(recorder, req, &requestContext{user: user})
		assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "Download=false conditional status")
		assertNoOriginalHeaders(t, recorder.Header())
		if recorder.Body.Len() != 0 {
			t.Errorf("Download=false conditional request emitted %d byte(s)", recorder.Body.Len())
		}
	})
}

func TestPermissionReadSecurity_ResourceMediaReads(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)

	t.Run("directory metadata excludes unauthorized canonical targets", func(t *testing.T) {
		directoryName := "resource-media-boundaries"
		directoryPath := filepath.Join(h.sourcePath, "public", directoryName)
		aclTargetDirectory := filepath.Join(h.sourcePath, "public", "resource-media-acl-targets")
		privateDirectory := filepath.Join(h.sourcePath, "private")
		if err := os.MkdirAll(directoryPath, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(aclTargetDirectory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(privateDirectory, 0o755); err != nil {
			t.Fatal(err)
		}

		allowedTitle := "allowed resource media title"
		outsideTitle := "outside source media secret"
		scopeTitle := "scope outside media secret"
		aclTitle := "canonical acl media secret"
		allowedPath := filepath.Join(directoryPath, "allowed.mp3")
		outsidePath := filepath.Join(t.TempDir(), "outside.mp3")
		scopePath := filepath.Join(privateDirectory, "scope-outside.mp3")
		aclPath := filepath.Join(aclTargetDirectory, "acl-denied.mp3")
		for targetPath, title := range map[string]string{
			allowedPath: allowedTitle,
			outsidePath: outsideTitle,
			scopePath:   scopeTitle,
			aclPath:     aclTitle,
		} {
			if err := os.WriteFile(targetPath, permissionReadID3Audio(title), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		createPermissionReadSymlink(t, outsidePath, filepath.Join(directoryPath, "outside-link.mp3"))
		createPermissionReadSymlink(t, scopePath, filepath.Join(directoryPath, "scope-link.mp3"))
		createPermissionReadSymlink(t, aclPath, filepath.Join(directoryPath, "acl-link.mp3"))

		user := h.user(t, true, true, false)
		user.Username = "permission-read-resource-media-boundary-user"
		user.Scopes[0].Scope = "/public"
		savePermissionReadUser(t, user)
		if err := store.Access.DenyUser(h.sourcePath, "/public/resource-media-acl-targets/acl-denied.mp3", user.Username); err != nil {
			t.Fatal(err)
		}
		originalFileInfo := files.FileInfoFasterFunc
		metadataCalls := make([]utils.FileOptions, 0)
		files.FileInfoFasterFunc = func(opts utils.FileOptions, accessStorage *access.Storage, currentUser *users.User, shareStorage *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
			if opts.Metadata {
				metadataCalls = append(metadataCalls, opts)
			}
			return originalFileInfo(opts, accessStorage, currentUser, shareStorage)
		}
		t.Cleanup(func() { files.FileInfoFasterFunc = originalFileInfo })

		query := url.Values{"source": {"source1"}, "path": {"/" + directoryName}, "metadata": {"true"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()
		returned, err := resourceGetHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
			t.Fatalf("directory media metadata status: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}

		var response iteminfo.ExtendedFileInfo
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode directory media response: %v", err)
		}
		titles := make(map[string]string)
		for _, child := range response.Files {
			if child.Metadata != nil {
				titles[child.Name] = child.Metadata.Title
			}
		}
		if got := titles["allowed.mp3"]; got != allowedTitle {
			t.Errorf("allowed media metadata title: got %q, want %q; titles=%v", got, allowedTitle, titles)
		}
		if len(metadataCalls) != 1 || metadataCalls[0].Path != "/"+directoryName+"/allowed.mp3" || metadataCalls[0].ReadPath == "" {
			t.Errorf("directory metadata reads were not isolated to the authorized snapshot: %+v", metadataCalls)
		}
		for name, forbiddenTitle := range map[string]string{
			"outside-link.mp3": outsideTitle,
			"scope-link.mp3":   scopeTitle,
			"acl-link.mp3":     aclTitle,
		} {
			if got := titles[name]; got != "" {
				t.Errorf("unauthorized media metadata leaked through %s: got %q, forbidden %q", name, got, forbiddenTitle)
			}
			if bytes.Contains(recorder.Body.Bytes(), []byte(forbiddenTitle)) {
				t.Errorf("unauthorized media title %q leaked in response", forbiddenTitle)
			}
		}
	})

	t.Run("directory alias respects logical child ACL", func(t *testing.T) {
		canonicalDirectory := filepath.Join(h.sourcePath, "public", "resource-media-alias-target")
		aliasPath := filepath.Join(h.sourcePath, "public", "resource-media-alias")
		if err := os.MkdirAll(canonicalDirectory, 0o755); err != nil {
			t.Fatal(err)
		}
		deniedTitle := "logical alias child secret"
		if err := os.WriteFile(filepath.Join(canonicalDirectory, "denied.mp3"), permissionReadID3Audio(deniedTitle), 0o644); err != nil {
			t.Fatal(err)
		}
		createPermissionReadSymlink(t, canonicalDirectory, aliasPath)

		user := h.user(t, true, true, false)
		user.Username = "permission-read-resource-media-alias-user"
		savePermissionReadUser(t, user)
		if err := store.Access.DenyUser(h.sourcePath, "/public/resource-media-alias/denied.mp3", user.Username); err != nil {
			t.Fatal(err)
		}

		originalFileInfo := files.FileInfoFasterFunc
		metadataCalls := make([]utils.FileOptions, 0)
		files.FileInfoFasterFunc = func(opts utils.FileOptions, accessStorage *access.Storage, currentUser *users.User, shareStorage *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
			if opts.Metadata {
				metadataCalls = append(metadataCalls, opts)
			}
			return originalFileInfo(opts, accessStorage, currentUser, shareStorage)
		}
		t.Cleanup(func() { files.FileInfoFasterFunc = originalFileInfo })

		query := url.Values{"source": {"source1"}, "path": {"/public/resource-media-alias"}, "metadata": {"true"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()
		returned, err := resourceGetHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
			t.Fatalf("directory alias metadata status: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}
		if len(metadataCalls) != 0 {
			t.Errorf("logical ACL denied alias child reached media extraction: %+v", metadataCalls)
		}
		if bytes.Contains(recorder.Body.Bytes(), []byte(`"name":"denied.mp3"`)) {
			t.Errorf("logical ACL denied alias child leaked basic listing data in response %q", recorder.Body.Bytes())
		}
		if bytes.Contains(recorder.Body.Bytes(), []byte(deniedTitle)) {
			t.Errorf("logical ACL denied alias child leaked metadata in response %q", recorder.Body.Bytes())
		}

		itemsQuery := url.Values{"source": {"source1"}, "path": {"/public/resource-media-alias"}}
		itemsRequest := httptest.NewRequest(http.MethodGet, "/api/resources/items?"+itemsQuery.Encode(), nil)
		itemsRecorder := httptest.NewRecorder()
		itemsReturned, itemsErr := itemsGetHandler(itemsRecorder, itemsRequest, &requestContext{user: user})
		if got := permissionHandlerStatus(itemsReturned, itemsRecorder); got != http.StatusOK {
			t.Fatalf("directory alias items status: got %d, want %d (err: %v)", got, http.StatusOK, itemsErr)
		}
		if bytes.Contains(itemsRecorder.Body.Bytes(), []byte("denied.mp3")) {
			t.Errorf("logical ACL denied alias child leaked through items response %q", itemsRecorder.Body.Bytes())
		}
	})

	for _, tc := range []struct {
		name  string
		query url.Values
	}{
		{
			name:  "audio metadata reads an authorized snapshot",
			query: url.Values{"source": {"source1"}, "path": {"/public/resource-metadata.mp3"}, "metadata": {"true"}, "skipExtendedAttrs": {"true"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targetPath := filepath.Join(h.sourcePath, filepath.FromSlash(strings.TrimPrefix(tc.query.Get("path"), "/")))
			replacementPath := targetPath + ".replacement"
			backupPath := targetPath + ".original"
			originalTitle := "authorized snapshot title"
			replacementTitle := "replacement media secret"
			if err := os.WriteFile(targetPath, permissionReadID3Audio(originalTitle), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(replacementPath, permissionReadID3Audio(replacementTitle), 0o644); err != nil {
				t.Fatal(err)
			}

			originalFileInfo := files.FileInfoFasterFunc
			files.FileInfoFasterFunc = func(opts utils.FileOptions, accessStorage *access.Storage, user *users.User, shareStorage *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
				if !opts.Content && !opts.Metadata {
					return originalFileInfo(opts, accessStorage, user, shareStorage)
				}
				if err := os.Rename(targetPath, backupPath); err != nil {
					return nil, err
				}
				if err := os.Rename(replacementPath, targetPath); err != nil {
					_ = os.Rename(backupPath, targetPath)
					return nil, err
				}
				response, readErr := originalFileInfo(opts, accessStorage, user, shareStorage)
				restoreErr := os.Rename(targetPath, replacementPath)
				if restoreErr == nil {
					restoreErr = os.Rename(backupPath, targetPath)
				}
				if readErr != nil {
					return response, readErr
				}
				return response, restoreErr
			}
			t.Cleanup(func() { files.FileInfoFasterFunc = originalFileInfo })

			user := h.user(t, true, true, true)
			req := httptest.NewRequest(http.MethodGet, "/api/resources?"+tc.query.Encode(), nil)
			recorder := httptest.NewRecorder()
			returned, err := resourceGetHandler(recorder, req, &requestContext{user: user})
			if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
				t.Fatalf("stable resource media status: got %d, want %d (err: %v)", got, http.StatusOK, err)
			}
			var response iteminfo.ExtendedFileInfo
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode stable resource media response: %v", err)
			}
			if response.Metadata == nil || response.Metadata.Title != originalTitle {
				t.Errorf("resource media did not use authorized snapshot: metadata=%+v", response.Metadata)
			}
			if bytes.Contains(recorder.Body.Bytes(), []byte(replacementTitle)) {
				t.Errorf("resource media leaked replacement title %q", replacementTitle)
			}
		})
	}

	t.Run("permission revocation after basic lookup prevents media conversion", func(t *testing.T) {
		targetPath := filepath.Join(h.sourcePath, "public", "resource-revoked-before-converter.mp3")
		if err := os.WriteFile(targetPath, permissionReadID3Audio("revoked converter secret"), 0o644); err != nil {
			t.Fatal(err)
		}
		user := h.user(t, true, true, false)
		user.Username = "permission-read-resource-converter-revocation-user"
		savePermissionReadUser(t, user)

		original := files.FileInfoFasterFunc
		calls := 0
		converterCalls := 0
		files.FileInfoFasterFunc = func(opts utils.FileOptions, accessStorage *access.Storage, currentUser *users.User, shareStorage *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
			calls++
			if opts.Metadata {
				converterCalls++
			}
			response, err := original(opts, accessStorage, currentUser, shareStorage)
			if calls == 1 && err == nil {
				revoked := *user
				revoked.Permissions.Preview = false
				if updateErr := store.Users.Update(&revoked, true, "Permissions"); updateErr != nil {
					return nil, updateErr
				}
			}
			return response, err
		}
		t.Cleanup(func() { files.FileInfoFasterFunc = original })

		query := url.Values{"source": {"source1"}, "path": {"/public/resource-revoked-before-converter.mp3"}, "metadata": {"true"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()
		returned, err := resourceGetHandler(recorder, req, &requestContext{user: user})
		assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "revoked resource media conversion")
		if calls != 1 || converterCalls != 0 {
			t.Errorf("revoked media read calls: total=%d converter=%d, want 1/0", calls, converterCalls)
		}
		if bytes.Contains(recorder.Body.Bytes(), []byte("revoked converter secret")) {
			t.Errorf("revoked media conversion leaked response %q", recorder.Body.Bytes())
		}
	})

	t.Run("physical media errors do not expose source paths", func(t *testing.T) {
		targetPath := filepath.Join(h.sourcePath, "public", "resource-error.mp3")
		if err := os.WriteFile(targetPath, permissionReadID3Audio("resource error fixture"), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, failCall := range []int{1, 2} {
			t.Run(fmt.Sprintf("file info call %d", failCall), func(t *testing.T) {
				original := files.FileInfoFasterFunc
				calls := 0
				files.FileInfoFasterFunc = func(opts utils.FileOptions, accessStorage *access.Storage, user *users.User, shareStorage *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
					calls++
					if calls == failCall {
						if failCall == 1 {
							return nil, &os.PathError{Op: "open", Path: targetPath, Err: os.ErrNotExist}
						}
						return nil, fmt.Errorf("media helper failed for %s", targetPath)
					}
					return original(opts, accessStorage, user, shareStorage)
				}
				t.Cleanup(func() { files.FileInfoFasterFunc = original })

				query := url.Values{"source": {"source1"}, "path": {"/public/resource-error.mp3"}, "metadata": {"true"}}
				req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
				recorder := httptest.NewRecorder()
				returned, err := resourceGetHandler(recorder, req, &requestContext{user: h.user(t, true, true, false)})
				status := permissionHandlerStatus(returned, recorder)
				if failCall == 1 {
					assertPermissionReadDenied(t, status, err, "resource media path error")
				} else if status != http.StatusInternalServerError {
					t.Errorf("generic media error status: got %d, want %d (err: %v)", status, http.StatusInternalServerError, err)
				}
				if err == nil {
					t.Fatal("resource media path error was unexpectedly nil")
				}
				if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(h.sourcePath)) || strings.Contains(strings.ToLower(err.Error()), strings.ToLower(targetPath)) {
					t.Errorf("resource media error leaked physical path: %v", err)
				}
			})
		}
	})
}

func TestPermissionReadSecurity_TokenPermissionIntersection(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	configurePermissionReadAuth(t)
	router := permissionReadAPIRouter()
	query := url.Values{"source": {"source1"}, "file": {"/public/secret.txt"}}

	for _, tc := range []struct {
		name               string
		userBrowse         bool
		userDownload       bool
		tokenBrowse        bool
		tokenDownload      bool
		revokeUserBrowse   bool
		revokeUserDownload bool
		revokeToken        bool
		wantStatus         int
	}{
		{name: "user and token allow read", userBrowse: true, userDownload: true, tokenBrowse: true, tokenDownload: true, wantStatus: http.StatusOK},
		{name: "token cannot exceed missing Browse", userBrowse: true, userDownload: true, tokenBrowse: false, tokenDownload: true, wantStatus: http.StatusForbidden},
		{name: "user Browse caps token", userBrowse: false, userDownload: true, tokenBrowse: true, tokenDownload: true, wantStatus: http.StatusForbidden},
		{name: "token cannot exceed missing Download", userBrowse: true, userDownload: true, tokenBrowse: true, tokenDownload: false, wantStatus: http.StatusForbidden},
		{name: "user Download caps token", userBrowse: true, userDownload: false, tokenBrowse: true, tokenDownload: true, wantStatus: http.StatusForbidden},
		{name: "old token loses revoked user Browse", userBrowse: true, userDownload: true, tokenBrowse: true, tokenDownload: true, revokeUserBrowse: true, wantStatus: http.StatusForbidden},
		{name: "old token loses revoked user Download", userBrowse: true, userDownload: true, tokenBrowse: true, tokenDownload: true, revokeUserDownload: true, wantStatus: http.StatusForbidden},
		{name: "revoked token is rejected", userBrowse: true, userDownload: true, tokenBrowse: true, tokenDownload: true, revokeToken: true, wantStatus: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			suffix := strings.ReplaceAll(tc.name, " ", "-")
			user := h.user(t, tc.userBrowse, true, tc.userDownload)
			user.Username = "permission-read-token-user-" + suffix
			savePermissionReadUser(t, user)

			tokenPermissions := users.Permissions{
				Browse:   tc.tokenBrowse,
				Preview:  true,
				Download: tc.tokenDownload,
			}
			token := issuePermissionReadAPIToken(t, user, "permission-read-token-"+suffix, tokenPermissions)

			if tc.revokeUserBrowse {
				user.Permissions.Browse = false
			}
			if tc.revokeUserDownload {
				user.Permissions.Download = false
			}
			if tc.revokeUserBrowse || tc.revokeUserDownload {
				if err := store.Users.Update(user, true, "Permissions"); err != nil {
					t.Fatal(err)
				}
			}
			if tc.revokeToken {
				if err := auth.RevokeApiToken(store.Access, token); err != nil {
					t.Fatal(err)
				}
			}

			req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
			req.Header.Set("Authorization", "Bearer "+token)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)
			if tc.wantStatus == http.StatusOK {
				if recorder.Code != tc.wantStatus {
					t.Errorf("token read status: expected %d, got %d", tc.wantStatus, recorder.Code)
				}
				if body := recorder.Body.String(); body != permissionReadSecret {
					t.Errorf("authorized token body: expected %q, got %q", permissionReadSecret, body)
				}
				return
			}
			if tc.wantStatus == http.StatusUnauthorized {
				if recorder.Code != tc.wantStatus {
					t.Errorf("revoked token status: expected %d, got %d", tc.wantStatus, recorder.Code)
				}
			} else {
				assertPermissionReadDenied(t, recorder.Code, nil, "token read status")
			}
			assertNoOriginalHeaders(t, recorder.Header())
			assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "unauthorized API token response")
		})
	}
}

func TestPermissionReadSecurity_PreviewTokenPermissionIntersection(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	configurePermissionReadAuth(t)
	router := permissionReadAPIRouter()
	query := url.Values{"source": {"source1"}, "path": {"/public/preview.jpg"}}

	for _, tc := range []struct {
		name              string
		userPreview       bool
		tokenPreview      bool
		revokeUserPreview bool
		wantStatus        int
	}{
		{name: "user and token allow preview", userPreview: true, tokenPreview: true, wantStatus: http.StatusOK},
		{name: "preview token cannot exceed user", userPreview: false, tokenPreview: true, wantStatus: http.StatusForbidden},
		{name: "user preview cannot exceed token", userPreview: true, tokenPreview: false, wantStatus: http.StatusForbidden},
		{name: "old token loses revoked user Preview", userPreview: true, tokenPreview: true, revokeUserPreview: true, wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			suffix := strings.ReplaceAll(tc.name, " ", "-")
			user := h.user(t, true, tc.userPreview, true)
			user.Username = "permission-preview-token-user-" + suffix
			savePermissionReadUser(t, user)

			tokenPermissions := users.Permissions{
				Browse:   true,
				Preview:  tc.tokenPreview,
				Download: true,
			}
			token := issuePermissionReadAPIToken(t, user, "permission-preview-token-"+suffix, tokenPermissions)
			if tc.revokeUserPreview {
				user.Permissions.Preview = false
				if err := store.Users.Update(user, true, "Permissions"); err != nil {
					t.Fatal(err)
				}
			}

			req := httptest.NewRequest(http.MethodGet, "/api/resources/preview?"+query.Encode(), nil)
			req.Header.Set("Authorization", "Bearer "+token)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)
			if tc.wantStatus == http.StatusOK {
				if recorder.Code != tc.wantStatus {
					t.Errorf("preview token status: expected %d, got %d", tc.wantStatus, recorder.Code)
				}
				if !bytes.Equal(recorder.Body.Bytes(), h.previewData) {
					t.Errorf("authorized preview token body did not match fixture: got %d bytes, want %d", recorder.Body.Len(), len(h.previewData))
				}
				return
			}
			assertPermissionReadDenied(t, recorder.Code, nil, "preview token status")
			assertNoOriginalHeaders(t, recorder.Header())
			if bytes.Equal(recorder.Body.Bytes(), h.previewData) {
				t.Error("unauthorized preview token returned the original image")
			}
		})
	}
}

func TestPermissionReadSecurity_ArchiveReadsRecheckPermissions(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)

	t.Run("archive download creation requires Browse and Download", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			browse   bool
			download bool
		}{
			{name: "Browse missing", browse: false, download: true},
			{name: "Download missing", browse: true, download: false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				user := h.user(t, tc.browse, true, tc.download)
				query := url.Values{"source": {"source1"}, "file": {"/public"}}
				req := httptest.NewRequest(http.MethodHead, "/api/resources/download?"+query.Encode(), nil)
				recorder := httptest.NewRecorder()

				returned, err := downloadHandler(recorder, req, &requestContext{user: user})
				assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "unauthorized archive creation status")
				token := recorder.Header().Get("X-Archive-Token")
				if token != "" {
					t.Errorf("unauthorized archive creation issued resume token %q", token)
					if session, ok := archiveSpoolCache.Get(token); ok {
						t.Cleanup(func() { removeSpooledArchiveNow(token, session.tmpPath) })
					}
				}
				assertNoOriginalHeaders(t, recorder.Header())
			})
		}
	})

	t.Run("archive download filters denied members", func(t *testing.T) {
		allowedName := "archive-allowed.txt"
		deniedName := "archive-denied.txt"
		nestedDirName := "archive-nested"
		nestedDeniedName := "nested-denied.txt"
		if err := os.WriteFile(filepath.Join(h.sourcePath, "public", allowedName), []byte("allowed-archive-member"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(h.sourcePath, "public", deniedName), []byte("denied-archive-member"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(h.sourcePath, "public", nestedDirName), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(h.sourcePath, "public", nestedDirName, nestedDeniedName), []byte("nested-denied-archive-member"), 0644); err != nil {
			t.Fatal(err)
		}

		user := h.user(t, true, true, true)
		user.Username = "permission-read-archive-access-user"
		savePermissionReadUser(t, user)
		if err := store.Access.DenyUser(h.sourcePath, "/public/"+deniedName, user.Username); err != nil {
			t.Fatal(err)
		}
		if err := store.Access.DenyUser(h.sourcePath, "/public/"+nestedDirName+"/"+nestedDeniedName, user.Username); err != nil {
			t.Fatal(err)
		}

		query := url.Values{"source": {"source1"}, "file": {"/public"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()
		returned, err := downloadHandler(recorder, req, &requestContext{user: user})
		if err != nil {
			t.Fatalf("archive download: %v", err)
		}
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
			t.Fatalf("archive status: got %d, want %d", got, http.StatusOK)
		}

		reader, err := zip.NewReader(bytes.NewReader(recorder.Body.Bytes()), int64(recorder.Body.Len()))
		if err != nil {
			t.Fatalf("open response zip: %v", err)
		}
		names := make(map[string]bool, len(reader.File))
		for _, entry := range reader.File {
			names[entry.Name] = true
		}
		if !names["public/"+allowedName] {
			t.Errorf("allowed member missing; entries=%v", names)
		}
		if names["public/"+deniedName] {
			t.Errorf("denied member leaked; entries=%v", names)
		}
		if names["public/"+nestedDirName+"/"+nestedDeniedName] {
			t.Errorf("nested denied member leaked; entries=%v", names)
		}
	})

	t.Run("directory archives exclude unauthorized symlink targets", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			algo string
		}{
			{name: "zip", algo: "zip"},
			{name: "tar.gz", algo: "tar.gz"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				archiveDirName := "archive-symlink-boundary-" + strings.ReplaceAll(tc.name, ".", "-")
				archiveDir := filepath.Join(h.sourcePath, "public", archiveDirName)
				if err := os.MkdirAll(archiveDir, 0755); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.RemoveAll(archiveDir); err != nil {
						t.Errorf("remove archive symlink fixture: %v", err)
					}
				})

				allowedName := "allowed.txt"
				allowedContent := "allowed-archive-symlink-member-" + tc.name
				if err := os.WriteFile(filepath.Join(archiveDir, allowedName), []byte(allowedContent), 0644); err != nil {
					t.Fatal(err)
				}

				outsideSourceContent := "outside-source-archive-secret-" + tc.name
				outsideSourcePath := filepath.Join(t.TempDir(), "outside-source.txt")
				if err := os.WriteFile(outsideSourcePath, []byte(outsideSourceContent), 0644); err != nil {
					t.Fatal(err)
				}

				privateDir := filepath.Join(h.sourcePath, "private")
				if err := os.MkdirAll(privateDir, 0755); err != nil {
					t.Fatal(err)
				}
				scopeOutsideContent := "scope-outside-archive-secret-" + tc.name
				scopeOutsidePath := filepath.Join(privateDir, "scope-outside-"+archiveDirName+".txt")
				if err := os.WriteFile(scopeOutsidePath, []byte(scopeOutsideContent), 0644); err != nil {
					t.Fatal(err)
				}

				aclTargetDir := filepath.Join(h.sourcePath, "public", "archive-acl-targets")
				if err := os.MkdirAll(aclTargetDir, 0755); err != nil {
					t.Fatal(err)
				}
				aclDeniedContent := "canonical-acl-archive-secret-" + tc.name
				aclTargetName := "acl-target-" + archiveDirName + ".txt"
				aclTargetPath := filepath.Join(aclTargetDir, aclTargetName)
				if err := os.WriteFile(aclTargetPath, []byte(aclDeniedContent), 0644); err != nil {
					t.Fatal(err)
				}

				createPermissionReadSymlink(t, outsideSourcePath, filepath.Join(archiveDir, "outside-source-link.txt"))
				createPermissionReadSymlink(t, scopeOutsidePath, filepath.Join(archiveDir, "scope-outside-link.txt"))
				createPermissionReadSymlink(t, aclTargetPath, filepath.Join(archiveDir, "acl-denied-link.txt"))

				user := h.user(t, true, true, true)
				user.Username = "permission-read-archive-symlink-" + strings.ReplaceAll(tc.name, ".", "-")
				user.Scopes[0].Scope = "/public"
				savePermissionReadUser(t, user)
				if err := store.Access.DenyUser(h.sourcePath, "/public/archive-acl-targets/"+aclTargetName, user.Username); err != nil {
					t.Fatal(err)
				}

				query := url.Values{
					"source": {"source1"},
					"file":   {"/" + archiveDirName},
					"algo":   {tc.algo},
				}
				req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
				recorder := httptest.NewRecorder()
				returned, err := downloadHandler(recorder, req, &requestContext{user: user})
				if err != nil {
					t.Fatalf("archive download: %v", err)
				}
				if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
					t.Fatalf("archive status: got %d, want %d", got, http.StatusOK)
				}

				entries := make(map[string]string)
				switch tc.algo {
				case "zip":
					reader, err := zip.NewReader(bytes.NewReader(recorder.Body.Bytes()), int64(recorder.Body.Len()))
					if err != nil {
						t.Fatalf("open response zip: %v", err)
					}
					for _, entry := range reader.File {
						file, err := entry.Open()
						if err != nil {
							t.Fatalf("open zip entry %q: %v", entry.Name, err)
						}
						content, readErr := io.ReadAll(file)
						closeErr := file.Close()
						if readErr != nil || closeErr != nil {
							t.Fatalf("read zip entry %q: read=%v close=%v", entry.Name, readErr, closeErr)
						}
						entries[entry.Name] = string(content)
					}
				case "tar.gz":
					gzipReader, err := gzip.NewReader(bytes.NewReader(recorder.Body.Bytes()))
					if err != nil {
						t.Fatalf("open response gzip: %v", err)
					}
					tarReader := tar.NewReader(gzipReader)
					for {
						header, err := tarReader.Next()
						if errors.Is(err, io.EOF) {
							break
						}
						if err != nil {
							t.Fatalf("read response tar: %v", err)
						}
						content, err := io.ReadAll(tarReader)
						if err != nil {
							t.Fatalf("read tar entry %q: %v", header.Name, err)
						}
						entries[header.Name] = string(content)
					}
					if err := gzipReader.Close(); err != nil {
						t.Fatalf("close response gzip: %v", err)
					}
				}

				allowedArchivePath := archiveDirName + "/" + allowedName
				if got := entries[allowedArchivePath]; got != allowedContent {
					t.Errorf("allowed archive member: got %q, want %q; entries=%v", got, allowedContent, entries)
				}
				for name, content := range entries {
					for _, denied := range []string{outsideSourceContent, scopeOutsideContent, aclDeniedContent} {
						if strings.Contains(content, denied) {
							t.Errorf("unauthorized target bytes leaked through %q: %q", name, content)
						}
					}
				}
				for _, deniedName := range []string{"outside-source-link.txt", "scope-outside-link.txt", "acl-denied-link.txt"} {
					if _, exists := entries[archiveDirName+"/"+deniedName]; exists {
						t.Errorf("unauthorized symlink member %q was archived; entries=%v", deniedName, entries)
					}
				}
			})
		}
	})

	t.Run("archive build aborts after read permission revocation", func(t *testing.T) {
		archiveDirName := "archive-mid-build-revocation"
		archiveDir := filepath.Join(h.sourcePath, "public", archiveDirName)
		if err := os.MkdirAll(archiveDir, 0755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"first.txt", "second.txt", "third.txt"} {
			if err := os.WriteFile(filepath.Join(archiveDir, name), []byte("archive-revocation-"+name), 0644); err != nil {
				t.Fatal(err)
			}
		}

		user := h.user(t, true, true, true)
		var output bytes.Buffer
		writer := &permissionReadCallbackWriter{
			writer: &output,
			callback: func() {
				user.Permissions.Download = false
			},
		}
		tarWriter := tar.NewWriter(writer)
		err := addFile("source1", "/public/"+archiveDirName, &requestContext{user: user}, tarWriter, nil, false, nil)
		_ = tarWriter.Close()
		if !errors.Is(err, errAuthenticatedArchiveReadPermissions) {
			t.Fatalf("archive build after revocation: got %v, want authenticated read permission error", err)
		}
		if got := errToStatus(err); got != http.StatusForbidden {
			t.Errorf("archive build revocation status: got %d, want %d", got, http.StatusForbidden)
		}
		if bytes.Contains(output.Bytes(), []byte("archive-revocation-")) {
			t.Errorf("archive build wrote member content after read permission revocation")
		}
	})

	t.Run("archive download rejects a denied top-level path", func(t *testing.T) {
		user := h.user(t, true, true, true)
		user.Username = "permission-read-archive-denied-root-user"
		savePermissionReadUser(t, user)
		if err := store.Access.DenyUser(h.sourcePath, "/public", user.Username); err != nil {
			t.Fatal(err)
		}

		query := url.Values{"source": {"source1"}, "file": {"/public"}}
		req := httptest.NewRequest(http.MethodHead, "/api/resources/download?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()
		returned, err := downloadHandler(recorder, req, &requestContext{user: user})
		assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "denied top-level archive status")
		if token := recorder.Header().Get("X-Archive-Token"); token != "" {
			t.Errorf("denied top-level archive issued resume token %q", token)
			if session, ok := archiveSpoolCache.Get(token); ok {
				t.Cleanup(func() { removeSpooledArchiveNow(token, session.tmpPath) })
			}
		}
		assertNoOriginalHeaders(t, recorder.Header())
	})

	t.Run("archive resume preserves filtered top-level request identity", func(t *testing.T) {
		allowedName := "archive-resume-allowed.txt"
		deniedName := "archive-resume-denied.txt"
		if err := os.WriteFile(filepath.Join(h.sourcePath, "public", allowedName), []byte("allowed-resume-member"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(h.sourcePath, "public", deniedName), []byte("denied-resume-member"), 0644); err != nil {
			t.Fatal(err)
		}

		user := h.user(t, true, true, true)
		user.Username = "permission-read-archive-filtered-resume-user"
		savePermissionReadUser(t, user)
		if err := store.Access.DenyUser(h.sourcePath, "/public/"+deniedName, user.Username); err != nil {
			t.Fatal(err)
		}

		query := url.Values{
			"source": {"source1"},
			"file":   {"/public/" + allowedName, "/public/" + deniedName},
		}
		headReq := httptest.NewRequest(http.MethodHead, "/api/resources/download?"+query.Encode(), nil)
		headRecorder := httptest.NewRecorder()
		returned, err := downloadHandler(headRecorder, headReq, &requestContext{user: user})
		if err != nil {
			t.Fatalf("start filtered archive session: %v", err)
		}
		if got := permissionHandlerStatus(returned, headRecorder); got != http.StatusOK {
			t.Fatalf("start filtered archive session status: got %d, want %d", got, http.StatusOK)
		}
		token := headRecorder.Header().Get("X-Archive-Token")
		if token == "" {
			t.Fatal("start filtered archive session did not return X-Archive-Token")
		}
		if session, ok := archiveSpoolCache.Get(token); ok {
			t.Cleanup(func() { removeSpooledArchiveNow(token, session.tmpPath) })
		}

		query.Set("archiveToken", token)
		resumeReq := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
		resumeReq.Header.Set("Range", "bytes=0-5")
		resumeRecorder := httptest.NewRecorder()
		returned, err = downloadHandler(resumeRecorder, resumeReq, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, resumeRecorder); got != http.StatusPartialContent {
			t.Fatalf("filtered archive resume status: got %d, want %d (err: %v)", got, http.StatusPartialContent, err)
		}
		if resumeRecorder.Body.Len() != 6 {
			t.Errorf("filtered archive resume body length: got %d, want 6", resumeRecorder.Body.Len())
		}
	})

	t.Run("archive resume rechecks owner scope and member access", func(t *testing.T) {
		startSession := func(t *testing.T, user *users.User) (url.Values, string) {
			t.Helper()
			query := url.Values{"source": {"source1"}, "file": {"/public"}}
			req := httptest.NewRequest(http.MethodHead, "/api/resources/download?"+query.Encode(), nil)
			recorder := httptest.NewRecorder()
			returned, err := downloadHandler(recorder, req, &requestContext{user: user})
			if err != nil {
				t.Fatalf("start archive session: %v", err)
			}
			if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
				t.Fatalf("start archive session status: got %d, want %d", got, http.StatusOK)
			}
			token := recorder.Header().Get("X-Archive-Token")
			if token == "" {
				t.Fatal("start archive session did not return X-Archive-Token")
			}
			session, ok := archiveSpoolCache.Get(token)
			if !ok {
				t.Fatal("start archive session did not retain session state")
			}
			t.Cleanup(func() { removeSpooledArchiveNow(token, session.tmpPath) })
			return query, token
		}

		resume := func(t *testing.T, user *users.User, query url.Values, token string) {
			t.Helper()
			query.Set("archiveToken", token)
			req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
			req.Header.Set("Range", "bytes=0-5")
			recorder := httptest.NewRecorder()
			returned, err := downloadHandler(recorder, req, &requestContext{user: user})
			assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "unauthorized archive resume status")
			assertNoOriginalHeaders(t, recorder.Header())
			if recorder.Body.Len() != 0 {
				t.Errorf("unauthorized archive resume emitted %d byte(s)", recorder.Body.Len())
			}
			if bytes.HasPrefix(recorder.Body.Bytes(), []byte("PK")) {
				t.Errorf("unauthorized archive resume leaked cached ZIP bytes %q", recorder.Body.Bytes())
			}
		}

		t.Run("different user", func(t *testing.T) {
			owner := h.user(t, true, true, true)
			owner.Username = "permission-read-archive-owner"
			query, token := startSession(t, owner)

			other := h.user(t, true, true, true)
			other.Username = "permission-read-archive-other-user"
			resume(t, other, query, token)
		})

		t.Run("same username with a different user ID", func(t *testing.T) {
			owner := h.user(t, true, true, true)
			owner.Username = "permission-read-archive-stable-owner"
			savePermissionReadUser(t, owner)
			query, token := startSession(t, owner)

			recreated := h.user(t, true, true, true)
			recreated.Username = owner.Username
			recreated.ID = owner.ID + 1000
			resume(t, recreated, query, token)
		})

		t.Run("member access revoked", func(t *testing.T) {
			owner := h.user(t, true, true, true)
			owner.Username = "permission-read-archive-revoked-member-user"
			savePermissionReadUser(t, owner)
			query, token := startSession(t, owner)
			if err := store.Access.DenyUser(h.sourcePath, "/public/secret.txt", owner.Username); err != nil {
				t.Fatal(err)
			}
			resume(t, owner, query, token)
		})

		t.Run("member canonical target changed", func(t *testing.T) {
			targetDir := filepath.Join(h.sourcePath, "private", "archive-resume-target-change")
			if err := os.MkdirAll(targetDir, 0755); err != nil {
				t.Fatal(err)
			}
			originalTarget := filepath.Join(targetDir, "original.txt")
			replacementTarget := filepath.Join(targetDir, "replacement.txt")
			if err := os.WriteFile(originalTarget, []byte("original-archive-resume-member"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(replacementTarget, []byte("replacement-archive-resume-member"), 0644); err != nil {
				t.Fatal(err)
			}

			linkPath := filepath.Join(h.sourcePath, "public", "archive-resume-target-link.txt")
			createPermissionReadSymlink(t, originalTarget, linkPath)
			t.Cleanup(func() {
				if err := os.Remove(linkPath); err != nil && !os.IsNotExist(err) {
					t.Errorf("remove archive resume symlink: %v", err)
				}
			})

			owner := h.user(t, true, true, true)
			owner.Username = "permission-read-archive-target-change-user"
			savePermissionReadUser(t, owner)
			query, token := startSession(t, owner)

			if err := os.Remove(linkPath); err != nil {
				t.Fatal(err)
			}
			createPermissionReadSymlink(t, replacementTarget, linkPath)
			if err := store.Access.DenyUser(h.sourcePath, "/private/archive-resume-target-change/original.txt", owner.Username); err != nil {
				t.Fatal(err)
			}
			resume(t, owner, query, token)
		})

		t.Run("scope changed", func(t *testing.T) {
			owner := h.user(t, true, true, true)
			owner.Username = "permission-read-archive-scope-change-user"
			query, token := startSession(t, owner)
			if err := os.MkdirAll(filepath.Join(h.sourcePath, "other"), 0755); err != nil {
				t.Fatal(err)
			}
			owner.Scopes = []users.SourceScope{{Name: h.sourcePath, Scope: "/other"}}
			resume(t, owner, query, token)
		})

		t.Run("source identity changed", func(t *testing.T) {
			owner := h.user(t, true, true, true)
			owner.Username = "permission-read-archive-source-change-user"
			query, token := startSession(t, owner)
			session, ok := archiveSpoolCache.Get(token)
			if !ok {
				t.Fatal("archive session disappeared before source identity check")
			}
			session.sourcePath = filepath.Join(h.sourcePath, "replacement")
			archiveSpoolCache.SetWithExp(token, session, archiveMultiRequestIdle)
			resume(t, owner, query, token)
		})

		t.Run("source name changed", func(t *testing.T) {
			owner := h.user(t, true, true, true)
			owner.Username = "permission-read-archive-source-name-user"
			_, token := startSession(t, owner)
			req := httptest.NewRequest(http.MethodGet, "/api/resources/download?archiveToken="+url.QueryEscape(token), nil)
			req.Header.Set("Range", "bytes=0-5")
			recorder := httptest.NewRecorder()
			returned, err := BuildAndStreamArchive(recorder, req, &requestContext{user: owner}, "renamed-source", []string{"/public"})
			assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "changed source archive resume status")
			assertNoOriginalHeaders(t, recorder.Header())
			if recorder.Body.Len() != 0 {
				t.Errorf("changed source archive resume emitted %d byte(s)", recorder.Body.Len())
			}
			if bytes.HasPrefix(recorder.Body.Bytes(), []byte("PK")) {
				t.Errorf("changed source archive resume leaked cached ZIP bytes %q", recorder.Body.Bytes())
			}
		})

		t.Run("original request list changed", func(t *testing.T) {
			owner := h.user(t, true, true, true)
			owner.Username = "permission-read-archive-request-change-user"
			query, token := startSession(t, owner)
			query["file"] = []string{"/public/secret.txt"}
			resume(t, owner, query, token)
		})
	})

	t.Run("archive resume rechecks current read permissions", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			browse   bool
			download bool
			suffix   string
		}{
			{name: "Browse revoked", browse: false, download: true, suffix: "browse"},
			{name: "Download revoked", browse: true, download: false, suffix: "download"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				user := h.user(t, true, true, true)
				user.Username = "permission-read-archive-permission-revoke-" + tc.suffix
				query := url.Values{"source": {"source1"}, "file": {"/public"}}
				headReq := httptest.NewRequest(http.MethodHead, "/api/resources/download?"+query.Encode(), nil)
				headRecorder := httptest.NewRecorder()
				returned, err := downloadHandler(headRecorder, headReq, &requestContext{user: user})
				if got := permissionHandlerStatus(returned, headRecorder); got != http.StatusOK {
					t.Fatalf("start permission revoke session status: got %d, want %d (err: %v)", got, http.StatusOK, err)
				}
				token := headRecorder.Header().Get("X-Archive-Token")
				session, ok := archiveSpoolCache.Get(token)
				if token == "" || !ok {
					t.Fatal("start permission revoke session did not retain a valid token")
				}
				t.Cleanup(func() { removeSpooledArchiveNow(token, session.tmpPath) })
				session.lifecycle.mu.Lock()
				generationBefore := session.lifecycle.generation
				timerBefore := session.lifecycle.timer
				session.lifecycle.mu.Unlock()

				user.Permissions.Browse = tc.browse
				user.Permissions.Download = tc.download
				query = url.Values{
					"source":       {"source1"},
					"file":         {"/public"},
					"archiveToken": {token},
				}
				req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
				req.Header.Set("Range", "bytes=0-5")
				recorder := httptest.NewRecorder()

				returned, err = downloadHandler(recorder, req, &requestContext{user: user})
				assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "unauthorized archive resume status")
				if recorder.Body.Len() != 0 {
					t.Errorf("unauthorized archive resume emitted %d byte(s)", recorder.Body.Len())
				}
				if body := recorder.Body.Bytes(); bytes.HasPrefix(body, []byte("PK")) {
					t.Errorf("unauthorized archive resume leaked cached ZIP bytes %q", body)
				}
				assertNoOriginalHeaders(t, recorder.Header())
				current, ok := archiveSpoolCache.Get(token)
				if !ok || current.lifecycle != session.lifecycle {
					t.Error("unauthorized archive resume consumed the existing session")
					return
				}
				current.lifecycle.mu.Lock()
				generationAfter := current.lifecycle.generation
				timerAfter := current.lifecycle.timer
				current.lifecycle.mu.Unlock()
				if generationAfter != generationBefore || timerAfter != timerBefore {
					t.Error("unauthorized archive resume refreshed the session idle deadline")
				}
			})
		}
	})

	t.Run("server archive creation rechecks read permissions", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			browse      bool
			download    bool
			destination string
		}{
			{name: "Browse missing", browse: false, download: true, destination: "/public/no-browse.zip"},
			{name: "Download missing", browse: true, download: false, destination: "/public/no-download.zip"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				user := h.user(t, tc.browse, true, tc.download)
				user.Permissions.Create = true
				body := `{"fromSource":"source1","paths":["/public/secret.txt"],"destination":"` + tc.destination + `","format":"zip"}`
				req := httptest.NewRequest(http.MethodPost, "/api/resources/archive", strings.NewReader(body))
				recorder := httptest.NewRecorder()

				returned, err := archiveCreateHandler(recorder, req, &requestContext{user: user})
				assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "unauthorized archive create status")
				realDestination := filepath.Join(h.sourcePath, filepath.FromSlash(strings.TrimPrefix(tc.destination, "/")))
				if _, statErr := os.Stat(realDestination); statErr == nil {
					t.Errorf("unauthorized archive create wrote %s", realDestination)
				} else if !os.IsNotExist(statErr) {
					t.Errorf("stat unauthorized archive destination: %v", statErr)
				}
			})
		}
	})

	t.Run("server archive creation rejects unsafe paths before writing", func(t *testing.T) {
		user := h.user(t, true, true, true)
		user.Permissions.Create = true
		for _, tc := range []struct {
			name        string
			paths       []string
			destination string
		}{
			{name: "source traversal", paths: []string{"/public/../private/secret.txt"}, destination: "/public/unsafe-source.zip"},
			{name: "destination traversal", paths: []string{"/public/secret.txt"}, destination: "/public/../unsafe-destination.zip"},
			{name: "physical source", paths: []string{`C:\Windows\win.ini`}, destination: "/public/unsafe-physical.zip"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				body, err := json.Marshal(map[string]any{
					"fromSource":  "source1",
					"paths":       tc.paths,
					"destination": tc.destination,
					"format":      "zip",
				})
				if err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest(http.MethodPost, "/api/resources/archive", bytes.NewReader(body))
				recorder := httptest.NewRecorder()

				returned, err := archiveCreateHandler(recorder, req, &requestContext{user: user})
				if got := permissionHandlerStatus(returned, recorder); got != http.StatusBadRequest {
					t.Errorf("unsafe archive create status: got %d, want %d (err: %v)", got, http.StatusBadRequest, err)
				}
				realDestination := filepath.Join(h.sourcePath, filepath.FromSlash(strings.TrimPrefix(tc.destination, "/")))
				if _, statErr := os.Stat(realDestination); statErr == nil {
					t.Errorf("unsafe archive create wrote %s", realDestination)
				} else if !os.IsNotExist(statErr) {
					t.Errorf("stat unsafe archive destination: %v", statErr)
				}
			})
		}
	})

	t.Run("directory alias archive enforces logical child ACL", func(t *testing.T) {
		canonicalDirectory := filepath.Join(h.sourcePath, "public", "archive-logical-target")
		aliasDirectory := filepath.Join(h.sourcePath, "public", "archive-logical-alias")
		if err := os.MkdirAll(canonicalDirectory, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"allowed.txt", "denied.txt"} {
			if err := os.WriteFile(filepath.Join(canonicalDirectory, name), []byte("archive "+name), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		createPermissionReadSymlink(t, canonicalDirectory, aliasDirectory)

		user := h.user(t, true, true, true)
		user.Username = "permission-read-archive-logical-alias-user"
		savePermissionReadUser(t, user)
		if err := store.Access.DenyUser(h.sourcePath, "/public/archive-logical-alias/denied.txt", user.Username); err != nil {
			t.Fatal(err)
		}

		query := url.Values{"source": {"source1"}, "file": {"/public/archive-logical-alias"}, "algo": {"zip"}}
		request := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()
		returned, err := downloadHandler(recorder, request, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK || err != nil {
			t.Fatalf("logical alias archive status: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}
		archiveReader, err := zip.NewReader(bytes.NewReader(recorder.Body.Bytes()), int64(recorder.Body.Len()))
		if err != nil {
			t.Fatal(err)
		}
		entryNames := make([]string, 0, len(archiveReader.File))
		for _, entry := range archiveReader.File {
			entryNames = append(entryNames, entry.Name)
		}
		joinedNames := strings.Join(entryNames, "\n")
		if !strings.Contains(joinedNames, "archive-logical-alias/allowed.txt") {
			t.Errorf("logical alias archive omitted allowed entry: %v", entryNames)
		}
		if strings.Contains(joinedNames, "denied.txt") || strings.Contains(joinedNames, "archive-logical-target") {
			t.Errorf("logical alias archive leaked denied or canonical entry names: %v", entryNames)
		}
	})

	t.Run("unarchive permission semantics remain unchanged", func(t *testing.T) {
		archiveName := "restore-existing-permissions.zip"
		archivePath := filepath.Join(h.sourcePath, "public", archiveName)
		createPermissionReadZip(t, archivePath, "restored-secret.txt", permissionReadSecret)
		destination := filepath.Join(h.sourcePath, "public", "restore-existing-permissions")
		if err := os.MkdirAll(destination, 0755); err != nil {
			t.Fatal(err)
		}

		user := h.user(t, false, true, false)
		user.Permissions.Create = true
		body := `{"fromSource":"source1","path":"/public/` + archiveName + `","destination":"/public/restore-existing-permissions"}`
		req := httptest.NewRequest(http.MethodPost, "/api/resources/unarchive", strings.NewReader(body))
		recorder := httptest.NewRecorder()

		returned, err := unarchiveHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
			t.Fatalf("unarchive existing permission status: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}
		restored, err := os.ReadFile(filepath.Join(destination, "restored-secret.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if string(restored) != permissionReadSecret {
			t.Errorf("unarchive restored content: got %q, want %q", restored, permissionReadSecret)
		}
	})
}

func TestPermissionReadSecurity_ArchiveSessionLifecycle(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	user := h.user(t, true, true, true)
	user.Username = "permission-read-archive-lifecycle-user"

	t.Run("startup cleanup removes only generated archive spools", func(t *testing.T) {
		downloadDir := settings.DownloadCacheDir()
		spool, err := os.CreateTemp(downloadDir, "dl-archive-*.zip")
		if err != nil {
			t.Fatal(err)
		}
		spoolPaths := []string{spool.Name()}
		if err = spool.Close(); err != nil {
			t.Fatal(err)
		}
		tarSpool, err := os.CreateTemp(downloadDir, "dl-archive-*.tar.gz")
		if err != nil {
			t.Fatal(err)
		}
		spoolPaths = append(spoolPaths, tarSpool.Name())
		if err = tarSpool.Close(); err != nil {
			t.Fatal(err)
		}

		keepPaths := []string{
			filepath.Join(downloadDir, "keep.txt"),
			filepath.Join(downloadDir, ".keep"),
			filepath.Join(downloadDir, "other-cache.bin"),
			filepath.Join(downloadDir, "dl-archive-not-generated.zip"),
			filepath.Join(downloadDir, "dl-archive-123456.rar"),
			filepath.Join(downloadDir, "123456.zip"),
		}
		for _, keepPath := range keepPaths {
			if err = os.WriteFile(keepPath, []byte("keep"), 0644); err != nil {
				t.Fatal(err)
			}
		}
		matchingDirectory := filepath.Join(downloadDir, "dl-archive-123456.zip")
		if err = os.Mkdir(matchingDirectory, 0755); err != nil {
			t.Fatal(err)
		}
		keepPaths = append(keepPaths, matchingDirectory)

		outsideTarget := filepath.Join(t.TempDir(), "outside-target.txt")
		if err = os.WriteFile(outsideTarget, []byte("outside"), 0644); err != nil {
			t.Fatal(err)
		}
		symlinkPath := filepath.Join(downloadDir, "dl-archive-654321.zip")
		symlinkErr := os.Symlink(outsideTarget, symlinkPath)
		symlinkCreated := symlinkErr == nil
		if symlinkCreated {
			keepPaths = append(keepPaths, symlinkPath)
		} else {
			t.Logf("symlink cleanup assertion unavailable: %v", symlinkErr)
		}

		if err = settings.PrepareDownloadSpoolDir(); err != nil {
			t.Fatalf("prepare download spool: %v", err)
		}
		for _, spoolPath := range spoolPaths {
			if _, err = os.Stat(spoolPath); !os.IsNotExist(err) {
				t.Errorf("generated archive spool was not removed: %v", err)
			}
		}
		for _, keepPath := range keepPaths {
			if _, err = os.Lstat(keepPath); err != nil {
				t.Errorf("cleanup removed unrelated path %s: %v", keepPath, err)
			}
		}
		if symlinkCreated {
			if content, readErr := os.ReadFile(outsideTarget); readErr != nil || string(content) != "outside" {
				t.Errorf("cleanup changed symlink target: content=%q err=%v", content, readErr)
			}
		}
	})

	t.Run("archive spool operations reject a symlink download directory", func(t *testing.T) {
		baseDir := t.TempDir()
		cacheDir := filepath.Join(baseDir, "cache")
		targetDir := filepath.Join(baseDir, "target-downloads")
		if err := os.MkdirAll(cacheDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(targetDir, filepath.Join(cacheDir, "downloads")); err != nil {
			t.Skipf("download directory symlink creation is unavailable on this platform: %v", err)
		}

		originalCacheDir := settings.Config.Server.CacheDir
		settings.Config.Server.CacheDir = cacheDir
		t.Cleanup(func() { settings.Config.Server.CacheDir = originalCacheDir })
		if err := settings.ClearDownloadArchiveSpools(); err == nil {
			t.Error("archive cleanup accepted a symlink download directory")
		}
		if file, _, err := settings.CreateDownloadArchiveSpool(".zip"); err == nil {
			name := file.Name()
			_ = file.Close()
			_ = os.Remove(name)
			t.Error("archive creation accepted a symlink download directory")
		}
	})

	t.Run("runtime cleanup rejects an archive-like path outside the spool directory", func(t *testing.T) {
		outsidePath := filepath.Join(t.TempDir(), "dl-archive-123456.zip")
		if err := os.WriteFile(outsidePath, []byte("outside"), 0644); err != nil {
			t.Fatal(err)
		}

		removeArchiveSpoolFile(outsidePath, nil)
		if content, err := os.ReadFile(outsidePath); err != nil || string(content) != "outside" {
			t.Errorf("runtime cleanup removed an outside file: content=%q err=%v", content, err)
		}

		directPath := filepath.Join(settings.DownloadCacheDir(), "dl-archive-777777.zip")
		if err := os.WriteFile(directPath, []byte("direct"), 0644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(directPath) })
		traversalPath := filepath.Join(settings.DownloadCacheDir(), "nested") + string(filepath.Separator) + ".." + string(filepath.Separator) + filepath.Base(directPath)
		removeArchiveSpoolFile(traversalPath, nil)
		if content, err := os.ReadFile(directPath); err != nil || string(content) != "direct" {
			t.Errorf("runtime cleanup accepted a traversal path: content=%q err=%v", content, err)
		}
	})

	t.Run("resume rejects a replaced spool file", func(t *testing.T) {
		query := url.Values{"source": {"source1"}, "file": {"/public"}}
		headReq := httptest.NewRequest(http.MethodHead, "/api/resources/download?"+query.Encode(), nil)
		headRecorder := httptest.NewRecorder()
		returned, err := downloadHandler(headRecorder, headReq, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, headRecorder); got != http.StatusOK {
			t.Fatalf("start replaced spool session: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}
		token := headRecorder.Header().Get("X-Archive-Token")
		session, ok := archiveSpoolCache.Get(token)
		if token == "" || !ok {
			t.Fatal("start replaced spool session did not retain state")
		}
		originalPath := session.tmpPath + ".original"
		t.Cleanup(func() {
			removeSpooledArchiveNow(token, session.tmpPath)
			_ = os.Remove(session.tmpPath)
			_ = os.Remove(originalPath)
		})
		if err = os.Rename(session.tmpPath, originalPath); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(session.tmpPath, []byte(permissionReadSecret), 0644); err != nil {
			t.Fatal(err)
		}

		query.Set("archiveToken", token)
		req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
		req.Header.Set("Range", "bytes=0-5")
		recorder := httptest.NewRecorder()
		returned, err = downloadHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusGone {
			t.Errorf("replaced spool resume status: got %d, want %d (err: %v)", got, http.StatusGone, err)
		}
		assertNoOriginalHeaders(t, recorder.Header())
		assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "replaced spool resume")
		if recorder.Body.Len() != 0 {
			t.Errorf("replaced spool resume emitted %d byte(s)", recorder.Body.Len())
		}
		if _, ok = archiveSpoolCache.Get(token); ok {
			t.Error("replaced spool failure retained its session")
		}
	})

	t.Run("resume rejects a symlink spool without changing its target", func(t *testing.T) {
		query := url.Values{"source": {"source1"}, "file": {"/public"}}
		headReq := httptest.NewRequest(http.MethodHead, "/api/resources/download?"+query.Encode(), nil)
		headRecorder := httptest.NewRecorder()
		returned, err := downloadHandler(headRecorder, headReq, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, headRecorder); got != http.StatusOK {
			t.Fatalf("start symlink spool session: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}
		token := headRecorder.Header().Get("X-Archive-Token")
		session, ok := archiveSpoolCache.Get(token)
		if token == "" || !ok {
			t.Fatal("start symlink spool session did not retain state")
		}
		t.Cleanup(func() {
			removeSpooledArchiveNow(token, session.tmpPath)
			_ = os.Remove(session.tmpPath)
		})
		targetPath := filepath.Join(t.TempDir(), "outside-target.txt")
		if err = os.WriteFile(targetPath, []byte(permissionReadSecret), 0644); err != nil {
			t.Fatal(err)
		}
		if err = os.Remove(session.tmpPath); err != nil {
			t.Fatal(err)
		}
		if err = os.Symlink(targetPath, session.tmpPath); err != nil {
			t.Skipf("symlink creation is unavailable on this platform: %v", err)
		}

		query.Set("archiveToken", token)
		req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
		req.Header.Set("Range", "bytes=0-5")
		recorder := httptest.NewRecorder()
		returned, err = downloadHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusGone {
			t.Errorf("symlink spool resume status: got %d, want %d (err: %v)", got, http.StatusGone, err)
		}
		assertNoOriginalHeaders(t, recorder.Header())
		assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "symlink spool resume")
		if recorder.Body.Len() != 0 {
			t.Errorf("symlink spool resume emitted %d byte(s)", recorder.Body.Len())
		}
		if content, readErr := os.ReadFile(targetPath); readErr != nil || string(content) != permissionReadSecret {
			t.Errorf("symlink rejection changed target: content=%q err=%v", content, readErr)
		}
	})

	t.Run("initial header panic revokes the new session and removes its spool", func(t *testing.T) {
		before, err := os.ReadDir(settings.DownloadCacheDir())
		if err != nil {
			t.Fatal(err)
		}
		beforeNames := make(map[string]bool, len(before))
		for _, entry := range before {
			beforeNames[entry.Name()] = true
		}

		const token = "permission-read-initial-header-panic-token"
		originalTokenFunc := archiveSpoolTokenFunc
		archiveSpoolTokenFunc = func() (string, error) { return token, nil }
		t.Cleanup(func() { archiveSpoolTokenFunc = originalTokenFunc })

		panicked := false
		func() {
			defer func() { panicked = recover() != nil }()
			query := url.Values{"source": {"source1"}, "file": {"/public"}}
			req := httptest.NewRequest(http.MethodHead, "/api/resources/download?"+query.Encode(), nil)
			_, _ = downloadHandler(&permissionReadHeaderPanicResponseWriter{}, req, &requestContext{user: user})
		}()
		if !panicked {
			t.Fatal("initial header response writer did not panic")
		}
		if session, ok := archiveSpoolCache.Get(token); ok {
			t.Cleanup(func() { removeSpooledArchiveNow(token, session.tmpPath) })
			t.Error("initial header panic retained its archive session")
		}
		after, err := os.ReadDir(settings.DownloadCacheDir())
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range after {
			if !beforeNames[entry.Name()] && strings.HasPrefix(entry.Name(), "dl-archive-") {
				t.Errorf("initial header panic retained spool %s", entry.Name())
			}
		}
	})

	t.Run("delete failure revokes the session without renewal", func(t *testing.T) {
		query := url.Values{"source": {"source1"}, "file": {"/public"}}
		req := httptest.NewRequest(http.MethodHead, "/api/resources/download?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()
		returned, err := downloadHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
			t.Fatalf("start delete failure session: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}
		token := recorder.Header().Get("X-Archive-Token")
		session, ok := archiveSpoolCache.Get(token)
		if token == "" || !ok || session.lifecycle == nil {
			t.Fatal("start delete failure session did not retain lifecycle state")
		}
		session.lifecycle.mu.Lock()
		generation := session.lifecycle.generation
		if session.lifecycle.timer != nil {
			session.lifecycle.timer.Stop()
		}
		session.lifecycle.mu.Unlock()

		originalRemoveFile := archiveSpoolRemoveFile
		archiveSpoolRemoveFile = func(string, os.FileInfo) error { return os.ErrPermission }
		t.Cleanup(func() {
			archiveSpoolRemoveFile = originalRemoveFile
			_ = settings.RemoveDownloadArchiveSpool(session.tmpPath, session.spoolInfo)
		})
		expireArchiveSpool(token, session, generation)

		if _, ok = archiveSpoolCache.Get(token); ok {
			t.Error("delete failure restored the revoked archive session")
		}
		if _, err = os.Stat(session.tmpPath); err != nil {
			t.Errorf("delete failure did not leave the expected orphan for startup cleanup: %v", err)
		}
		session.lifecycle.mu.Lock()
		removed := session.lifecycle.removed
		removePending := session.lifecycle.removePending
		timer := session.lifecycle.timer
		generationAfter := session.lifecycle.generation
		session.lifecycle.mu.Unlock()
		if !removed || !removePending || timer != nil || generationAfter != generation {
			t.Errorf("delete failure lifecycle: removed=%t pending=%t timer=%v generation=%d, want true/true/nil/%d", removed, removePending, timer, generationAfter, generation)
		}

		query.Set("archiveToken", token)
		resumeReq := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
		resumeRecorder := httptest.NewRecorder()
		returned, err = downloadHandler(resumeRecorder, resumeReq, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, resumeRecorder); got != http.StatusGone {
			t.Errorf("delete failure resume status: got %d, want %d (err: %v)", got, http.StatusGone, err)
		}
		assertNoOriginalHeaders(t, resumeRecorder.Header())
	})

	t.Run("unsafe resume path does not refresh the idle deadline", func(t *testing.T) {
		query := url.Values{"source": {"source1"}, "file": {"/public"}}
		req := httptest.NewRequest(http.MethodHead, "/api/resources/download?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()
		returned, err := downloadHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
			t.Fatalf("start unsafe resume session: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}
		token := recorder.Header().Get("X-Archive-Token")
		session, ok := archiveSpoolCache.Get(token)
		if token == "" || !ok || session.lifecycle == nil {
			t.Fatal("start unsafe resume session did not retain lifecycle state")
		}
		t.Cleanup(func() { removeSpooledArchiveNow(token, session.tmpPath) })
		session.lifecycle.mu.Lock()
		generationBefore := session.lifecycle.generation
		timerBefore := session.lifecycle.timer
		session.lifecycle.mu.Unlock()

		unsafeQuery := url.Values{
			"source":       {"source1"},
			"file":         {"/public/../public"},
			"archiveToken": {token},
		}
		resumeReq := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+unsafeQuery.Encode(), nil)
		resumeRecorder := httptest.NewRecorder()
		returned, err = downloadHandler(resumeRecorder, resumeReq, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, resumeRecorder); got != http.StatusBadRequest {
			t.Errorf("unsafe resume status: got %d, want %d (err: %v)", got, http.StatusBadRequest, err)
		}
		assertNoOriginalHeaders(t, resumeRecorder.Header())

		current, ok := archiveSpoolCache.Get(token)
		if !ok || current.lifecycle != session.lifecycle {
			t.Fatal("unsafe resume consumed the existing session")
		}
		current.lifecycle.mu.Lock()
		generationAfter := current.lifecycle.generation
		timerAfter := current.lifecycle.timer
		if timerAfter != nil {
			timerAfter.Stop()
		}
		current.lifecycle.mu.Unlock()
		if generationAfter != generationBefore || timerAfter != timerBefore {
			t.Error("unsafe resume refreshed the session idle deadline")
		}

		expireArchiveSpool(token, current, generationBefore)
		if _, ok := archiveSpoolCache.Get(token); ok {
			t.Error("unsafe resume prevented expiration at the original generation")
		}
		if _, statErr := os.Stat(session.tmpPath); !os.IsNotExist(statErr) {
			t.Errorf("unsafe resume expiration retained spool: %v", statErr)
		}
	})

	t.Run("idle expiration removes cache and spool", func(t *testing.T) {
		query := url.Values{"source": {"source1"}, "file": {"/public"}}
		req := httptest.NewRequest(http.MethodHead, "/api/resources/download?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()
		returned, err := downloadHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
			t.Fatalf("start idle archive session status: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}
		token := recorder.Header().Get("X-Archive-Token")
		session, ok := archiveSpoolCache.Get(token)
		if token == "" || !ok || session.lifecycle == nil {
			t.Fatal("start idle archive session did not retain lifecycle state")
		}
		t.Cleanup(func() { removeSpooledArchiveNow(token, session.tmpPath) })
		session.lifecycle.mu.Lock()
		generation := session.lifecycle.generation
		timer := session.lifecycle.timer
		if timer != nil {
			timer.Stop()
		}
		session.lifecycle.mu.Unlock()
		if timer == nil {
			t.Fatal("idle archive session did not schedule a cleanup timer")
		}

		expireArchiveSpool(token, session, generation)
		if _, ok := archiveSpoolCache.Get(token); ok {
			t.Error("idle expiration retained its archive session")
		}
		if _, err := os.Stat(session.tmpPath); !os.IsNotExist(err) {
			if err == nil {
				t.Errorf("idle expiration retained archive spool %s", session.tmpPath)
			} else {
				t.Errorf("stat expired archive spool: %v", err)
			}
		}
	})

	t.Run("stale idle callback cannot remove a renewed session", func(t *testing.T) {
		token := "permission-read-stale-idle-token"
		spoolPath, spoolInfo := createPermissionReadArchiveSpool(t, "archive-spool")
		archiveSpoolCache.SetWithExp(token, archiveSpoolSession{tmpPath: spoolPath, spoolInfo: spoolInfo}, archiveMultiRequestIdle)
		t.Cleanup(func() { removeSpooledArchiveNow(token, spoolPath) })

		originalAfterFunc := archiveSpoolAfterFunc
		firstStarted := make(chan struct{})
		firstRelease := make(chan struct{})
		firstDone := make(chan struct{})
		calls := 0
		archiveSpoolAfterFunc = func(d time.Duration, fn func()) *time.Timer {
			calls++
			if calls != 1 {
				return time.AfterFunc(time.Hour, fn)
			}
			timer := time.AfterFunc(0, func() {
				close(firstStarted)
				<-firstRelease
				fn()
				close(firstDone)
			})
			<-firstStarted
			return timer
		}
		t.Cleanup(func() { archiveSpoolAfterFunc = originalAfterFunc })

		rescheduleArchiveSpoolIdleCleanup(token, spoolPath)
		rescheduleArchiveSpoolIdleCleanup(token, spoolPath)
		close(firstRelease)
		waitForPermissionReadSignal(t, firstDone, "stale archive idle callback")

		if _, ok := archiveSpoolCache.Get(token); !ok {
			t.Error("stale idle callback removed the renewed archive session")
		}
		if _, err := os.Stat(spoolPath); err != nil {
			t.Errorf("stale idle callback removed the renewed archive spool: %v", err)
		}
	})

	t.Run("missing spool failure clears its idle timer", func(t *testing.T) {
		token := "permission-read-missing-spool-token"
		spoolPath := filepath.Join(settings.DownloadCacheDir(), "dl-archive-100001.zip")
		memberTarget, err := resolveCurrentAuthenticatedArchiveTarget(&requestContext{user: user}, "source1", "/public/secret.txt")
		if err != nil {
			t.Fatalf("resolve missing spool member: %v", err)
		}
		session := archiveSpoolSession{
			tmpPath:          spoolPath,
			originalFileName: "missing.zip",
			userID:           user.ID,
			username:         user.Username,
			source:           "source1",
			sourcePath:       h.sourcePath,
			requestFileList:  []string{"/public"},
			memberPaths:      []string{"/public/secret.txt"},
			memberTargets:    []authenticatedReadTarget{memberTarget},
		}
		archiveSpoolCache.SetWithExp(token, session, archiveMultiRequestIdle)
		t.Cleanup(func() { removeSpooledArchiveNow(token, spoolPath) })

		originalAfterFunc := archiveSpoolAfterFunc
		var scheduled *time.Timer
		archiveSpoolAfterFunc = func(_ time.Duration, fn func()) *time.Timer {
			scheduled = time.AfterFunc(time.Hour, fn)
			return scheduled
		}
		t.Cleanup(func() { archiveSpoolAfterFunc = originalAfterFunc })

		rescheduleArchiveSpoolIdleCleanup(token, spoolPath)
		query := url.Values{
			"source":       {"source1"},
			"file":         {"/public"},
			"archiveToken": {token},
		}
		req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
		req.Header.Set("Range", "bytes=0-5")
		recorder := httptest.NewRecorder()
		returned, _ := downloadHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusGone {
			t.Errorf("missing spool status: got %d, want %d", got, http.StatusGone)
		}
		if _, ok := archiveSpoolCache.Get(token); ok {
			t.Error("missing spool failure retained its archive session")
		}
		if scheduled != nil && scheduled.Stop() {
			t.Error("missing spool failure left an active idle timer")
		}
	})

	t.Run("active release cannot resurrect a revoked session", func(t *testing.T) {
		token := "permission-read-revoked-active-token"
		spoolPath, spoolInfo := createPermissionReadArchiveSpool(t, "archive-spool")
		session := archiveSpoolSession{
			tmpPath:   spoolPath,
			spoolInfo: spoolInfo,
			lifecycle: &archiveSpoolLifecycle{active: 1},
		}
		archiveSpoolCache.SetWithExp(token, session, archiveSpoolActiveCacheTTL)
		t.Cleanup(func() { removeSpooledArchiveNow(token, spoolPath) })

		archiveSpoolCache.Delete(token)
		releaseArchiveSpool(token, session, false)
		if _, ok := archiveSpoolCache.Get(token); ok {
			t.Error("active release resurrected a revoked archive session")
		}
		if _, err := os.Stat(spoolPath); !os.IsNotExist(err) {
			if err == nil {
				t.Errorf("active release retained revoked archive spool %s", spoolPath)
			} else {
				t.Errorf("stat revoked archive spool: %v", err)
			}
		}
	})

	t.Run("response panic cleans active session", func(t *testing.T) {
		query := url.Values{"source": {"source1"}, "file": {"/public"}}
		headReq := httptest.NewRequest(http.MethodHead, "/api/resources/download?"+query.Encode(), nil)
		headRecorder := httptest.NewRecorder()
		returned, err := downloadHandler(headRecorder, headReq, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, headRecorder); got != http.StatusOK {
			t.Fatalf("start panic archive session status: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}
		token := headRecorder.Header().Get("X-Archive-Token")
		session, ok := archiveSpoolCache.Get(token)
		if token == "" || !ok {
			t.Fatal("start panic archive session did not retain a valid token")
		}
		t.Cleanup(func() { removeSpooledArchiveNow(token, session.tmpPath) })
		query.Set("archiveToken", token)

		panicked := false
		func() {
			defer func() {
				panicked = recover() != nil
			}()
			req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
			_, _ = downloadHandler(newPermissionReadPanicResponseWriter(), req, &requestContext{user: user})
		}()
		if !panicked {
			t.Fatal("panic response writer did not panic")
		}
		if _, ok := archiveSpoolCache.Get(token); ok {
			t.Error("response panic retained its archive session")
		}
		if _, statErr := os.Stat(session.tmpPath); !os.IsNotExist(statErr) {
			if statErr == nil {
				t.Errorf("response panic retained archive spool %s", session.tmpPath)
			} else {
				t.Errorf("stat panic archive spool: %v", statErr)
			}
		}
	})

	t.Run("initial EOF range removes the completed session", func(t *testing.T) {
		before, err := os.ReadDir(settings.DownloadCacheDir())
		if err != nil {
			t.Fatal(err)
		}
		beforeNames := make(map[string]bool, len(before))
		for _, entry := range before {
			beforeNames[entry.Name()] = true
		}
		t.Cleanup(func() {
			entries, _ := os.ReadDir(settings.DownloadCacheDir())
			for _, entry := range entries {
				if !beforeNames[entry.Name()] && strings.HasPrefix(entry.Name(), "dl-archive-") {
					_ = os.Remove(filepath.Join(settings.DownloadCacheDir(), entry.Name()))
				}
			}
		})

		query := url.Values{"source": {"source1"}, "file": {"/public"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
		req.Header.Set("Range", "bytes=0-")
		recorder := httptest.NewRecorder()
		returned, err := downloadHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusPartialContent {
			t.Fatalf("initial EOF range status: got %d, want %d (err: %v)", got, http.StatusPartialContent, err)
		}
		token := recorder.Header().Get("X-Archive-Token")
		if token == "" {
			t.Fatal("initial EOF range did not return X-Archive-Token")
		}
		if session, ok := archiveSpoolCache.Get(token); ok {
			t.Cleanup(func() { removeSpooledArchiveNow(token, session.tmpPath) })
			t.Error("completed initial EOF range retained its archive session")
		}
		after, err := os.ReadDir(settings.DownloadCacheDir())
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range after {
			if !beforeNames[entry.Name()] && strings.HasPrefix(entry.Name(), "dl-archive-") {
				t.Errorf("completed initial EOF range retained spool %s", entry.Name())
			}
		}
	})

	t.Run("concurrent completion waits for active range before deleting spool", func(t *testing.T) {
		query := url.Values{"source": {"source1"}, "file": {"/public"}}
		headReq := httptest.NewRequest(http.MethodHead, "/api/resources/download?"+query.Encode(), nil)
		headRecorder := httptest.NewRecorder()
		returned, err := downloadHandler(headRecorder, headReq, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, headRecorder); got != http.StatusOK {
			t.Fatalf("start concurrent archive session status: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}
		token := headRecorder.Header().Get("X-Archive-Token")
		session, ok := archiveSpoolCache.Get(token)
		if token == "" || !ok {
			t.Fatal("start concurrent archive session did not retain a valid token")
		}
		t.Cleanup(func() { removeSpooledArchiveNow(token, session.tmpPath) })
		query.Set("archiveToken", token)

		blockingWriter := newPermissionReadBlockingResponseWriter()
		partialDone := make(chan struct{})
		var partialReturned int
		var partialErr error
		t.Cleanup(func() {
			blockingWriter.unblock()
			waitForPermissionReadSignal(t, partialDone, "partial archive response cleanup")
		})
		go func() {
			defer close(partialDone)
			req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
			req.Header.Set("Range", "bytes=0-5")
			partialReturned, partialErr = downloadHandler(blockingWriter, req, &requestContext{user: user})
		}()
		waitForPermissionReadSignal(t, blockingWriter.started, "blocked partial archive response")

		attacker := h.user(t, true, true, true)
		attacker.Username = "permission-read-archive-concurrent-attacker"
		attackerReq := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
		attackerReq.Header.Set("Range", "bytes=0-5")
		attackerRecorder := httptest.NewRecorder()
		attackerReturned, attackerErr := downloadHandler(attackerRecorder, attackerReq, &requestContext{user: attacker})
		assertPermissionReadDenied(t, permissionHandlerStatus(attackerReturned, attackerRecorder), attackerErr, "concurrent cross-user resume status")
		assertNoOriginalHeaders(t, attackerRecorder.Header())
		if attackerRecorder.Body.Len() != 0 {
			t.Errorf("concurrent cross-user resume leaked body %q", attackerRecorder.Body.Bytes())
		}

		fullReq := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
		fullRecorder := httptest.NewRecorder()
		returned, err = downloadHandler(fullRecorder, fullReq, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, fullRecorder); got != http.StatusOK {
			blockingWriter.unblock()
			waitForPermissionReadSignal(t, partialDone, "partial archive response after full failure")
			t.Fatalf("concurrent full archive status: got %d, want %d (err: %v)", got, http.StatusOK, err)
		}
		if _, ok := archiveSpoolCache.Get(token); ok {
			t.Error("completed concurrent request did not revoke the archive session")
		}
		if _, statErr := os.Stat(session.tmpPath); statErr != nil {
			blockingWriter.unblock()
			waitForPermissionReadSignal(t, partialDone, "partial archive response after premature cleanup")
			t.Fatalf("completed concurrent request deleted spool before active range closed: %v", statErr)
		}
		blockingWriter.unblock()
		waitForPermissionReadSignal(t, partialDone, "partial archive response completion")
		if partialErr != nil || partialReturned != 0 || blockingWriter.status != http.StatusPartialContent {
			t.Errorf("partial archive response: returned=%d status=%d err=%v", partialReturned, blockingWriter.status, partialErr)
		}
		if _, ok := archiveSpoolCache.Get(token); ok {
			t.Error("concurrent completion restored the revoked archive session")
		}

		if _, statErr := os.Stat(session.tmpPath); !os.IsNotExist(statErr) {
			if statErr == nil {
				t.Errorf("concurrent completion retained archive spool %s", session.tmpPath)
			} else {
				t.Errorf("stat concurrent archive spool: %v", statErr)
			}
		}
	})
}

func createPermissionReadJPEG(t *testing.T, path string) []byte {
	t.Helper()

	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 0x1a, G: 0x73, B: 0xe8, A: 0xff})
	img.Set(1, 0, color.RGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff})
	img.Set(0, 1, color.RGBA{R: 0x20, G: 0x20, B: 0x20, A: 0xff})
	img.Set(1, 1, color.RGBA{R: 0xd9, G: 0x30, B: 0x25, A: 0xff})
	var buffer bytes.Buffer
	if err := jpeg.Encode(&buffer, img, &jpeg.Options{Quality: 85}); err != nil {
		t.Fatal(err)
	}
	data := buffer.Bytes()
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), data...)
}

func permissionReadID3Audio(title string) []byte {
	frameBody := append([]byte{3}, []byte(title)...)
	frame := make([]byte, 10, 10+len(frameBody))
	copy(frame, "TIT2")
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(frameBody)))
	frame = append(frame, frameBody...)
	header := []byte{'I', 'D', '3', 3, 0, 0, 0, 0, 0, 0}
	size := len(frame)
	header[6] = byte((size >> 21) & 0x7f)
	header[7] = byte((size >> 14) & 0x7f)
	header[8] = byte((size >> 7) & 0x7f)
	header[9] = byte(size & 0x7f)
	return append(header, frame...)
}

func createPermissionReadZip(t *testing.T, archivePath, name, content string) {
	t.Helper()

	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	entry, err := writer.Create(name)
	if err != nil {
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
