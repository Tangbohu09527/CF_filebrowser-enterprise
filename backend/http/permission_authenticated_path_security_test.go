package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/access"
	dbshare "github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
)

func TestPermissionReadSecurity_LogicalPathNormalization(t *testing.T) {
	got, err := sanitizeAuthenticatedReadPath("/public/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/public/file.txt" {
		t.Errorf("logical path was not normalized with slash separators: got %q", got)
	}
}

func TestPermissionReadSecurity_WindowsLogicalPathAliasesRejected(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows path aliases are platform-specific")
	}
	for _, input := range []string{
		"/public/file.txt:secret",
		"/public/NUL",
		"/public/CON.txt",
		"/public/COM1.log",
		"/public/LPT9",
		"/public/trailing.",
		"/public/trailing ",
	} {
		t.Run(input, func(t *testing.T) {
			if got, err := sanitizeAuthenticatedReadPath(input); err == nil {
				t.Errorf("unsafe Windows logical path was accepted as %q", got)
			}
		})
	}
}

func TestPermissionReadSecurity_WindowsEntryCanonicalACL(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows path aliases are platform-specific")
	}
	h := newPermissionReadSecurityHarness(t)
	aliasPath := filepath.Join(h.sourcePath, "PUBLIC", "SECRET.TXT")
	canonicalInfo, err := os.Stat(h.secretPath)
	if err != nil {
		t.Fatal(err)
	}
	aliasInfo, err := os.Stat(aliasPath)
	if err != nil || !os.SameFile(canonicalInfo, aliasInfo) {
		t.Skip("filesystem does not provide case aliases")
	}

	user := h.user(t, true, true, true)
	user.Username = "permission-entry-canonical-acl-user"
	savePermissionReadUser(t, user)
	if err := store.Access.DenyUser(h.sourcePath, "/public/secret.txt", user.Username); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveAuthenticatedEntryTarget(user, "source1", "/PUBLIC/SECRET.TXT"); err == nil {
		t.Fatal("case-alias entry bypassed the canonical ACL")
	}
}

func createPermissionReadSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("authenticated read symlink assertions unavailable: %v", err)
	}
}

func TestPermissionReadSecurity_CanonicalPathBoundaries(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	outsideDir := t.TempDir()
	outsideSecret := filepath.Join(outsideDir, "outside-secret.txt")
	outsideImage := filepath.Join(outsideDir, "outside-preview.jpg")
	if err := os.WriteFile(outsideSecret, []byte("outside-source-secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outsideImage, h.previewData, 0o644); err != nil {
		t.Fatal(err)
	}
	outsideFileLink := filepath.Join(h.sourcePath, "public", "outside-secret.txt")
	outsideImageLink := filepath.Join(h.sourcePath, "public", "outside-preview.jpg")
	outsideDirLink := filepath.Join(h.sourcePath, "public", "outside-dir")
	createPermissionReadSymlink(t, outsideSecret, outsideFileLink)
	createPermissionReadSymlink(t, outsideImage, outsideImageLink)
	createPermissionReadSymlink(t, outsideDir, outsideDirLink)

	user := h.user(t, true, true, true)
	for _, tc := range []struct {
		name   string
		invoke func(*httptest.ResponseRecorder) (int, error)
	}{
		{
			name: "resource metadata",
			invoke: func(recorder *httptest.ResponseRecorder) (int, error) {
				query := url.Values{"source": {"source1"}, "path": {"/public/outside-secret.txt"}}
				req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
				return resourceGetHandler(recorder, req, &requestContext{user: user})
			},
		},
		{
			name: "resource content",
			invoke: func(recorder *httptest.ResponseRecorder) (int, error) {
				query := url.Values{"source": {"source1"}, "path": {"/public/outside-secret.txt"}, "content": {"true"}}
				req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
				return resourceGetHandler(recorder, req, &requestContext{user: user})
			},
		},
		{
			name: "resource checksum",
			invoke: func(recorder *httptest.ResponseRecorder) (int, error) {
				query := url.Values{"source": {"source1"}, "path": {"/public/outside-secret.txt"}, "checksum": {"md5"}}
				req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
				return resourceGetHandler(recorder, req, &requestContext{user: user})
			},
		},
		{
			name: "directory items",
			invoke: func(recorder *httptest.ResponseRecorder) (int, error) {
				query := url.Values{"source": {"source1"}, "path": {"/public/outside-dir"}}
				req := httptest.NewRequest(http.MethodGet, "/api/resources/items?"+query.Encode(), nil)
				return itemsGetHandler(recorder, req, &requestContext{user: user})
			},
		},
		{
			name: "download GET",
			invoke: func(recorder *httptest.ResponseRecorder) (int, error) {
				query := url.Values{"source": {"source1"}, "file": {"/public/outside-secret.txt"}}
				req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
				return downloadHandler(recorder, req, &requestContext{user: user})
			},
		},
		{
			name: "download HEAD",
			invoke: func(recorder *httptest.ResponseRecorder) (int, error) {
				query := url.Values{"source": {"source1"}, "file": {"/public/outside-secret.txt"}}
				req := httptest.NewRequest(http.MethodHead, "/api/resources/download?"+query.Encode(), nil)
				return downloadHandler(recorder, req, &requestContext{user: user})
			},
		},
		{
			name: "download Range",
			invoke: func(recorder *httptest.ResponseRecorder) (int, error) {
				query := url.Values{"source": {"source1"}, "file": {"/public/outside-secret.txt"}}
				req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
				req.Header.Set("Range", "bytes=0-6")
				return downloadHandler(recorder, req, &requestContext{user: user})
			},
		},
		{
			name: "preview",
			invoke: func(recorder *httptest.ResponseRecorder) (int, error) {
				query := url.Values{"source": {"source1"}, "path": {"/public/outside-preview.jpg"}}
				req := httptest.NewRequest(http.MethodGet, "/api/resources/preview?"+query.Encode(), nil)
				return previewHandler(recorder, req, &requestContext{user: user})
			},
		},
		{
			name: "file watcher",
			invoke: func(recorder *httptest.ResponseRecorder) (int, error) {
				query := url.Values{"source": {"source1"}, "path": {"/public/outside-secret.txt"}}
				req := httptest.NewRequest(http.MethodGet, "/api/tools/fileWatcher?"+query.Encode(), nil)
				return fileWatchHandler(recorder, req, &requestContext{user: user})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			returned, err := tc.invoke(recorder)
			if got := permissionHandlerStatus(returned, recorder); got != http.StatusForbidden {
				t.Errorf("canonical boundary status: got %d, want %d (err: %v)", got, http.StatusForbidden, err)
			}
			assertNoOriginalHeaders(t, recorder.Header())
			if strings.Contains(recorder.Body.String(), "outside-source-secret") ||
				strings.Contains(recorder.Body.String(), "outside-secret.txt") ||
				bytes.Equal(recorder.Body.Bytes(), h.previewData) {
				t.Errorf("canonical boundary leaked target data %q", recorder.Body.String())
			}
		})
	}
}

func TestPermissionReadSecurity_CanonicalScopeAndACL(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	privateDir := filepath.Join(h.sourcePath, "private")
	privateSecret := filepath.Join(privateDir, "private-secret.txt")
	if err := os.MkdirAll(privateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateSecret, []byte("canonical-private-secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	scopeLink := filepath.Join(h.sourcePath, "public", "scope-secret.txt")
	aclLink := filepath.Join(h.sourcePath, "public", "acl-secret.txt")
	createPermissionReadSymlink(t, privateSecret, scopeLink)
	createPermissionReadSymlink(t, privateSecret, aclLink)

	t.Run("scope escape", func(t *testing.T) {
		user := h.user(t, true, true, true)
		user.Username = "permission-canonical-scope-user"
		user.Scopes[0].Scope = "/public"
		query := url.Values{"source": {"source1"}, "file": {"/scope-secret.txt"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := downloadHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusForbidden {
			t.Errorf("scope escape status: got %d, want %d (err: %v)", got, http.StatusForbidden, err)
		}
		assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "canonical scope escape")
		if strings.Contains(recorder.Body.String(), "canonical-private-secret") {
			t.Errorf("scope escape leaked target %q", recorder.Body.String())
		}
	})

	t.Run("canonical ACL", func(t *testing.T) {
		user := h.user(t, true, true, true)
		user.Username = "permission-canonical-acl-user"
		savePermissionReadUser(t, user)
		if err := store.Access.DenyUser(h.sourcePath, "/private/private-secret.txt", user.Username); err != nil {
			t.Fatal(err)
		}
		query := url.Values{"source": {"source1"}, "file": {"/public/acl-secret.txt"}}
		req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := downloadHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusForbidden {
			t.Errorf("canonical ACL status: got %d, want %d (err: %v)", got, http.StatusForbidden, err)
		}
		if strings.Contains(recorder.Body.String(), "canonical-private-secret") {
			t.Errorf("canonical ACL leaked target %q", recorder.Body.String())
		}
	})
}

func TestPermissionReadSecurity_SecureOpenRejectsIdentityReplacement(t *testing.T) {
	t.Run("file replacement", func(t *testing.T) {
		h := newPermissionReadSecurityHarness(t)
		user := h.user(t, true, true, true)
		target, err := resolveAuthenticatedReadTarget(user, "source1", "/public/secret.txt")
		if err != nil {
			t.Fatal(err)
		}
		originalPath := filepath.Join(h.sourcePath, "public", "secret-original.txt")
		if renameErr := os.Rename(h.secretPath, originalPath); renameErr != nil {
			t.Fatal(renameErr)
		}
		if writeErr := os.WriteFile(h.secretPath, []byte("replacement must not be read"), 0o644); writeErr != nil {
			t.Fatal(writeErr)
		}
		file, _, err := openAuthenticatedReadTarget(target)
		if file != nil {
			_ = file.Close()
			t.Error("secure open returned a file handle after identity replacement")
		}
		if err == nil {
			t.Error("secure open accepted a replacement file")
		}
		if _, err := checksumAuthenticatedReadTarget(target, "sha256"); err == nil {
			t.Error("authenticated checksum accepted a replacement file")
		}
		if _, err := readAuthenticatedTextContent(target); err == nil {
			t.Error("authenticated content read accepted a replacement file")
		}
	})

	t.Run("scope root replacement", func(t *testing.T) {
		h := newPermissionReadSecurityHarness(t)
		user := h.user(t, true, true, true)
		user.Scopes[0].Scope = "/public"
		target, err := resolveAuthenticatedReadTarget(user, "source1", "/secret.txt")
		if err != nil {
			t.Fatal(err)
		}
		publicPath := filepath.Join(h.sourcePath, "public")
		originalPath := filepath.Join(h.sourcePath, "public-original")
		if renameErr := os.Rename(publicPath, originalPath); renameErr != nil {
			t.Fatal(renameErr)
		}
		if mkdirErr := os.MkdirAll(publicPath, 0o755); mkdirErr != nil {
			t.Fatal(mkdirErr)
		}
		if writeErr := os.WriteFile(filepath.Join(publicPath, "secret.txt"), []byte("replacement scope must not be read"), 0o644); writeErr != nil {
			t.Fatal(writeErr)
		}
		file, _, err := openAuthenticatedReadTarget(target)
		if file != nil {
			_ = file.Close()
			t.Error("secure open returned a file handle after scope replacement")
		}
		if err == nil {
			t.Error("secure open accepted a replacement scope root")
		}
	})
}

func TestPermissionReadSecurity_DeniedDirectoryRetainsExplicitChildren(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	user := h.user(t, true, true, true)
	user.Username = "permission-directory-child-user"
	savePermissionReadUser(t, user)
	if err := store.Access.DenyUser(h.sourcePath, "/public", user.Username); err != nil {
		t.Fatal(err)
	}
	if err := store.Access.AllowUser(h.sourcePath, "/public/secret.txt", user.Username); err != nil {
		t.Fatal(err)
	}

	for _, endpoint := range []struct {
		name   string
		invoke func(*httptest.ResponseRecorder) (int, error)
	}{
		{
			name: "resource",
			invoke: func(recorder *httptest.ResponseRecorder) (int, error) {
				query := url.Values{"source": {"source1"}, "path": {"/public"}}
				request := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
				return resourceGetHandler(recorder, request, &requestContext{user: user})
			},
		},
		{
			name: "items",
			invoke: func(recorder *httptest.ResponseRecorder) (int, error) {
				query := url.Values{"source": {"source1"}, "path": {"/public"}}
				request := httptest.NewRequest(http.MethodGet, "/api/resources/items?"+query.Encode(), nil)
				return itemsGetHandler(recorder, request, &requestContext{user: user})
			},
		},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			returned, err := endpoint.invoke(recorder)
			if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
				t.Fatalf("denied directory with allowed child status: got %d, want %d (err: %v, body: %q)", got, http.StatusOK, err, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "secret.txt") {
				t.Errorf("allowed child was not listed: %s", recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "preview.jpg") {
				t.Errorf("inherited-denied child was listed: %s", recorder.Body.String())
			}
			if endpoint.name == "resource" {
				var response struct {
					Path string `json:"path"`
				}
				if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
					t.Fatalf("decode denied-parent resource response: %v", err)
				}
				if response.Path != "/public" {
					t.Errorf("denied-parent resource path: got %q, want %q", response.Path, "/public")
				}
			}
		})
	}
	if err := store.Access.AllowUser(h.sourcePath, "/public/preview.jpg", user.Username); err != nil {
		t.Fatal(err)
	}
	reads := observePermissionFileInfoReads(t)
	probedFileInfo := files.FileInfoFasterFunc
	files.FileInfoFasterFunc = func(opts utils.FileOptions, accessStorage *access.Storage, currentUser *users.User, shareStorage *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
		info, err := probedFileInfo(opts, accessStorage, currentUser, shareStorage)
		if err == nil && info.Type == "directory" {
			for i := range info.Files {
				if info.Files[i].Name == "preview.jpg" {
					info.Files[i].HasPreview = true
				}
			}
		}
		return info, err
	}
	previousPreviewGenerator := authenticatedPreviewFileGenerator
	t.Cleanup(func() {
		files.FileInfoFasterFunc = probedFileInfo
		authenticatedPreviewFileGenerator = previousPreviewGenerator
	})
	var generatedPaths []string
	authenticatedPreviewFileGenerator = func(_ context.Context, file iteminfo.ExtendedFileInfo, _ string, _ string, _ int) ([]byte, error) {
		generatedPaths = append(generatedPaths, file.Path)
		return append([]byte(nil), h.previewData...), nil
	}
	previewQuery := url.Values{"source": {"source1"}, "path": {"/public"}}
	previewRequest := httptest.NewRequest(http.MethodGet, "/api/resources/preview?"+previewQuery.Encode(), nil)
	previewRecorder := httptest.NewRecorder()
	previewReturned, previewErr := previewHandler(previewRecorder, previewRequest, &requestContext{user: user})
	if got := permissionHandlerStatus(previewReturned, previewRecorder); got != http.StatusOK {
		t.Errorf("directory preview status: got %d, want %d (err: %v, body: %q)", got, http.StatusOK, previewErr, previewRecorder.Body.String())
	}
	if previewRecorder.Body.Len() == 0 {
		t.Error("directory preview returned an empty response for an explicitly allowed child")
	}
	if reads.total == 0 {
		t.Error("directory preview did not reach filtered metadata lookup")
	}
	files.FileInfoFasterFunc = probedFileInfo
	authenticatedPreviewFileGenerator = previousPreviewGenerator
	if len(generatedPaths) == 0 {
		t.Fatal("directory preview did not reach authenticated preview generation")
	}
	for _, generatedPath := range generatedPaths {
		if generatedPath != "/public/preview.jpg" {
			t.Errorf("directory preview generated unexpected child path %q", generatedPath)
		}
	}
	if removed, err := store.Access.RemoveAllowUser(h.sourcePath, "/public/preview.jpg", user.Username); err != nil || !removed {
		t.Fatalf("remove explicit preview child allow: removed=%t err=%v", removed, err)
	}
	removed, err := store.Access.RemoveAllowUser(h.sourcePath, "/public/secret.txt", user.Username)
	if err != nil || !removed {
		t.Fatalf("remove explicit child allow: removed=%t err=%v", removed, err)
	}
	if _, err := resolveAuthenticatedBrowseTarget(user, "source1", "/public"); err == nil {
		t.Error("denied directory without an allowed descendant reached Browse target resolution")
	}

	deniedReads := observePermissionFileInfoReads(t)
	for _, endpoint := range []struct {
		name   string
		path   string
		invoke func(*httptest.ResponseRecorder, *http.Request) (int, error)
	}{
		{
			name: "resource",
			path: "/api/resources",
			invoke: func(recorder *httptest.ResponseRecorder, request *http.Request) (int, error) {
				return resourceGetHandler(recorder, request, &requestContext{user: user})
			},
		},
		{
			name: "items",
			path: "/api/resources/items",
			invoke: func(recorder *httptest.ResponseRecorder, request *http.Request) (int, error) {
				return itemsGetHandler(recorder, request, &requestContext{user: user})
			},
		},
	} {
		t.Run("revoked "+endpoint.name, func(t *testing.T) {
			query := url.Values{"source": {"source1"}, "path": {"/public"}}
			request := httptest.NewRequest(http.MethodGet, endpoint.path+"?"+query.Encode(), nil)
			recorder := httptest.NewRecorder()
			returned, handlerErr := endpoint.invoke(recorder, request)
			if got := permissionHandlerStatus(returned, recorder); got != http.StatusForbidden {
				t.Errorf("revoked explicit child status: got %d, want %d (err: %v, body: %q)", got, http.StatusForbidden, handlerErr, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "secret.txt") {
				t.Errorf("revoked explicit child remained visible: %s", recorder.Body.String())
			}
		})
	}
	if deniedReads.total != 0 {
		t.Errorf("denied directory without an allowed descendant reached FileInfoFaster %d time(s)", deniedReads.total)
	}
}

func TestPermissionReadSecurity_DeniedBrowsePathDoesNotRevealExistence(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	user := h.user(t, true, true, true)
	user.Username = "permission-denied-path-oracle-user"
	savePermissionReadUser(t, user)
	if err := store.Access.DenyUser(h.sourcePath, "/public", user.Username); err != nil {
		t.Fatal(err)
	}

	var observations []string
	for _, path := range []string{"/public/secret.txt", "/public/does-not-exist.txt"} {
		query := url.Values{"source": {"source1"}, "path": {path}}
		request := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()
		returned, err := resourceGetHandler(recorder, request, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusForbidden {
			t.Errorf("denied Browse path status for %q: got %d, want %d (err: %v)", path, got, http.StatusForbidden, err)
		}
		observations = append(observations, fmt.Sprintf("%d:%v", returned, err))
	}
	if len(observations) != 2 || observations[0] != observations[1] {
		t.Errorf("denied Browse path existence produced distinguishable responses: %v", observations)
	}
}

func TestPermissionReadSecurity_MinimalAndFullTokenRefreshSemantics(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	configurePermissionReadAuth(t)
	user := h.user(t, false, false, false)
	user.Username = "permission-token-refresh-user"
	user.Permissions.Api = true
	savePermissionReadUser(t, user)
	initial := *user

	minimalToken, minimalMetadata, err := auth.MakeSignedTokenAPI(user, "permission-minimal-refresh", time.Hour, users.Permissions{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if addTokenErr := store.Users.AddApiToken(user.ID, "permission-minimal-refresh", minimalToken, minimalMetadata); addTokenErr != nil {
		t.Fatal(addTokenErr)
	}
	if addTokenErr := store.Access.AddApiToken(minimalToken, user.ID); addTokenErr != nil {
		t.Fatal(addTokenErr)
	}
	fullToken := issuePermissionReadAPIToken(t, user, "permission-full-refresh", user.Permissions)

	updated := *user
	updated.Permissions.Browse = true
	updated.Permissions.Preview = true
	updated.Permissions.Download = true
	if updateErr := store.Users.Update(&updated, true, "Permissions"); updateErr != nil {
		t.Fatal(updateErr)
	}

	minimalUser, err := currentAuthenticatedReadUser(&initial, minimalToken)
	if err != nil {
		t.Fatal(err)
	}
	if !minimalUser.Permissions.Browse || !minimalUser.Permissions.Preview || !minimalUser.Permissions.Download {
		t.Errorf("minimal token did not receive current account permissions: %+v", minimalUser.Permissions)
	}
	fullUser, err := currentAuthenticatedReadUser(&initial, fullToken)
	if err != nil {
		t.Fatal(err)
	}
	if fullUser.Permissions.Browse || fullUser.Permissions.Preview || fullUser.Permissions.Download {
		t.Errorf("full token exceeded its original permission snapshot: %+v", fullUser.Permissions)
	}
}

func TestPermissionReadSecurity_SourceAndPathErrorsAreOpaque(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	user := h.user(t, true, true, true)

	var observations []string
	for _, tc := range []struct {
		name   string
		source string
		user   *users.User
	}{
		{name: "unknown source", source: "not-configured", user: user},
		{name: "existing source without scope", source: "source1", user: &users.User{Username: user.Username, Permissions: user.Permissions}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := url.Values{"source": {tc.source}, "file": {"/public/secret.txt"}}
			request := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
			recorder := httptest.NewRecorder()
			returned, err := downloadHandler(recorder, request, &requestContext{user: tc.user})
			if got := permissionHandlerStatus(returned, recorder); got != http.StatusForbidden {
				t.Errorf("source denial status: got %d, want %d (err: %v)", got, http.StatusForbidden, err)
			}
			observations = append(observations, fmt.Sprintf("%d:%v", returned, err))
		})
	}
	if len(observations) != 2 || observations[0] != observations[1] {
		t.Errorf("source existence produced distinguishable denials: %v", observations)
	}

	var searchObservations []string
	for _, tc := range []struct {
		name   string
		source string
	}{
		{name: "unknown source", source: "not-configured"},
		{name: "existing source without scope", source: "source1"},
	} {
		t.Run("search "+tc.name, func(t *testing.T) {
			query := url.Values{"source": {tc.source}, "query": {"secret"}}
			request := httptest.NewRequest(http.MethodGet, "/api/tools/search?"+query.Encode(), nil)
			recorder := httptest.NewRecorder()
			noScopeUser := &users.User{Username: user.Username, Permissions: user.Permissions}
			returned, err := searchHandler(recorder, request, &requestContext{user: noScopeUser})
			if got := permissionHandlerStatus(returned, recorder); got != http.StatusForbidden {
				t.Errorf("search source denial status: got %d, want %d (err: %v)", got, http.StatusForbidden, err)
			}
			searchObservations = append(searchObservations, fmt.Sprintf("%d:%v", returned, err))
		})
	}
	if len(searchObservations) != 2 || searchObservations[0] != searchObservations[1] {
		t.Errorf("search source existence produced distinguishable denials: %v", searchObservations)
	}

	configurePermissionReadAuth(t)
	user.Username = "permission-opaque-path-user"
	savePermissionReadUser(t, user)
	token := issuePermissionReadWebToken(t, user)
	query := url.Values{"source": {"source1"}, "file": {"/public/does-not-exist.txt"}}
	request := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	permissionReadAPIRouter().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing authenticated path status: got %d, want %d (body: %q)", recorder.Code, http.StatusNotFound, recorder.Body.String())
	}
	if strings.Contains(strings.ToLower(recorder.Body.String()), strings.ToLower(h.sourcePath)) || strings.Contains(recorder.Body.String(), `\\`) {
		t.Errorf("missing path response leaked a physical path: %q", recorder.Body.String())
	}

	t.Run("items downstream path errors", func(t *testing.T) {
		originalCheckPermissions := files.CheckPermissionsFunc
		t.Cleanup(func() { files.CheckPermissionsFunc = originalCheckPermissions })
		physicalPath := filepath.Join(h.sourcePath, "public", "disappeared-directory")
		files.CheckPermissionsFunc = func(utils.FileOptions, *access.Storage, *users.User) (string, string, error) {
			return "", "", &os.PathError{Op: "stat", Path: physicalPath, Err: os.ErrNotExist}
		}

		query := url.Values{"source": {"source1"}, "path": {"/public"}}
		request := httptest.NewRequest(http.MethodGet, "/api/resources/items?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()
		returned, err := itemsGetHandler(recorder, request, &requestContext{user: h.user(t, true, true, true)})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusNotFound {
			t.Errorf("items downstream error status: got %d, want %d (err: %v)", got, http.StatusNotFound, err)
		}
		if err == nil || strings.Contains(strings.ToLower(err.Error()), strings.ToLower(h.sourcePath)) || strings.Contains(strings.ToLower(err.Error()), strings.ToLower(physicalPath)) {
			t.Errorf("items downstream error exposed a physical path: %v", err)
		}
	})
}

func TestPermissionReadSecurity_BrokenSymlinkDoesNotRevealTargetExistence(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	outsideDirectory := t.TempDir()
	existingTarget := filepath.Join(outsideDirectory, "existing-secret.txt")
	if err := os.WriteFile(existingTarget, []byte("outside existing secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	missingTarget := filepath.Join(outsideDirectory, "missing-secret.txt")
	for name, target := range map[string]string{
		"existing-link.txt": existingTarget,
		"missing-link.txt":  missingTarget,
	} {
		createPermissionReadSymlink(t, target, filepath.Join(h.sourcePath, "public", name))
	}

	user := h.user(t, true, true, true)
	for _, name := range []string{"existing-link.txt", "missing-link.txt"} {
		t.Run(name, func(t *testing.T) {
			query := url.Values{"source": {"source1"}, "file": {"/public/" + name}}
			request := httptest.NewRequest(http.MethodHead, "/api/resources/download?"+query.Encode(), nil)
			recorder := httptest.NewRecorder()
			returned, err := downloadHandler(recorder, request, &requestContext{user: user})
			assertPermissionReadDenied(t, permissionHandlerStatus(returned, recorder), err, "untrusted symlink target")
			assertNoOriginalHeaders(t, recorder.Header())
			if recorder.Body.Len() != 0 {
				t.Errorf("untrusted symlink target emitted body %q", recorder.Body.Bytes())
			}
		})
	}
}
