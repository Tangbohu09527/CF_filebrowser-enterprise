package http

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/access"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"golang.org/x/net/webdav"
)

func setupPermissionWebDAVSecurityEnv(t *testing.T) (string, string) {
	t.Helper()
	return setupPermissionWebDAVSecurityTestEnv(t)
}

func permissionWebDAVUser(t *testing.T, sourcePath string, browse, download bool) *users.User {
	t.Helper()

	permissions := users.Permissions{Download: download}
	setFutureReadPermission(t, &permissions, "Browse", browse)
	return &users.User{
		Username:    "permission-webdav-user",
		Permissions: permissions,
		Scopes: []users.SourceScope{
			{Name: sourcePath, Scope: "/"},
		},
	}
}

func performPermissionWebDAVRequest(t *testing.T, user *users.User, method, path, body string, headers map[string]string) (int, *httptest.ResponseRecorder, error) {
	t.Helper()

	var requestBody *strings.Reader
	if body == "" {
		requestBody = strings.NewReader("")
	} else {
		requestBody = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "/dav/source1"+path, requestBody)
	req.SetPathValue("source", "source1")
	req.SetPathValue("path", path)
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	returned, err := webDAVHandler(recorder, req, &requestContext{user: user})
	return permissionHandlerStatus(returned, recorder), recorder, err
}

func permissionWebDAVRouter() *http.ServeMux {
	router := http.NewServeMux()
	router.Handle("/dav/{source}/{path...}", withBasicAuth(webDAVHandler))
	return router
}

func TestPermissionWebDAVSecurity_PROPFINDRequiresBrowse(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)

	for _, tc := range []struct {
		name       string
		browse     bool
		download   bool
		wantStatus int
	}{
		{name: "Browse=false is denied even with Download", browse: false, download: true, wantStatus: http.StatusForbidden},
		{name: "Browse alone is sufficient", browse: true, download: false, wantStatus: http.StatusMultiStatus},
		{name: "Browse and Download are allowed", browse: true, download: true, wantStatus: http.StatusMultiStatus},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := permissionWebDAVUser(t, sourcePath, tc.browse, tc.download)
			status, recorder, err := performPermissionWebDAVRequest(t, user, "PROPFIND", "/public/", "", map[string]string{"Depth": "1"})
			if status != tc.wantStatus {
				t.Errorf("PROPFIND status: expected %d, got %d (err: %v)", tc.wantStatus, status, err)
			}
			body := recorder.Body.String()
			if tc.wantStatus == http.StatusForbidden {
				if strings.Contains(body, "readme.txt") || strings.Contains(body, "getcontentlength") {
					t.Errorf("unauthorized PROPFIND leaked directory properties %q", body)
				}
				return
			}
			if !strings.Contains(body, "readme.txt") {
				t.Errorf("authorized PROPFIND did not include readme.txt: %q", body)
			}
		})
	}
}

func TestPermissionWebDAVSecurity_PROPFINDLogicalAliasChildACL(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
	canonicalDirectory := filepath.Join(sourcePath, "public", "webdav-alias-target")
	aliasDirectory := filepath.Join(sourcePath, "public", "webdav-alias")
	if err := os.MkdirAll(canonicalDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"allowed.txt", "denied.txt"} {
		if err := os.WriteFile(filepath.Join(canonicalDirectory, name), []byte(name+" content"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	createPermissionReadSymlink(t, canonicalDirectory, aliasDirectory)

	user := permissionWebDAVUser(t, sourcePath, true, false)
	user.Username = "permission-webdav-logical-alias-user"
	savePermissionWebDAVUser(t, user)
	if err := store.Access.DenyUser(sourcePath, "/public/webdav-alias/denied.txt", user.Username); err != nil {
		t.Fatal(err)
	}

	status, recorder, err := performPermissionWebDAVRequest(t, user, "PROPFIND", "/public/webdav-alias/", "", map[string]string{"Depth": "1"})
	if status != http.StatusMultiStatus {
		t.Fatalf("logical alias PROPFIND status: got %d, want %d (err: %v, body: %q)", status, http.StatusMultiStatus, err, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "webdav-alias") || !strings.Contains(body, "allowed.txt") {
		t.Errorf("logical alias PROPFIND omitted authorized names: %q", body)
	}
	if strings.Contains(body, "denied.txt") || strings.Contains(body, "webdav-alias-target") {
		t.Errorf("logical alias PROPFIND leaked denied or canonical names: %q", body)
	}
}

func TestPermissionWebDAVSecurity_GETRequiresBrowseAndDownload(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)

	for _, tc := range []struct {
		name       string
		browse     bool
		download   bool
		wantStatus int
	}{
		{name: "both permissions", browse: true, download: true, wantStatus: http.StatusOK},
		{name: "Browse missing", browse: false, download: true, wantStatus: http.StatusForbidden},
		{name: "Download missing", browse: true, download: false, wantStatus: http.StatusForbidden},
		{name: "both permissions missing", browse: false, download: false, wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := permissionWebDAVUser(t, sourcePath, tc.browse, tc.download)
			status, recorder, err := performPermissionWebDAVRequest(t, user, http.MethodGet, "/public/readme.txt", "", nil)
			if status != tc.wantStatus {
				t.Errorf("WebDAV GET status: expected %d, got %d (err: %v)", tc.wantStatus, status, err)
			}
			if tc.wantStatus == http.StatusOK {
				if body := recorder.Body.String(); body != "public content" {
					t.Errorf("authorized WebDAV GET body: expected %q, got %q", "public content", body)
				}
				return
			}
			if strings.Contains(recorder.Body.String(), "public content") {
				t.Errorf("unauthorized WebDAV GET leaked original bytes %q", recorder.Body.String())
			}
			assertNoPermissionWebDAVOriginalHeaders(t, recorder.Header())
		})
	}
}

func TestPermissionWebDAVSecurity_RangeGETRequiresBrowseAndDownload(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)

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
			user := permissionWebDAVUser(t, sourcePath, tc.browse, tc.download)
			status, recorder, err := performPermissionWebDAVRequest(t, user, http.MethodGet, "/public/readme.txt", "", map[string]string{"Range": "bytes=0-5"})
			if status != tc.wantStatus {
				t.Errorf("WebDAV Range GET status: expected %d, got %d (err: %v)", tc.wantStatus, status, err)
			}
			if tc.wantStatus == http.StatusPartialContent {
				if body := recorder.Body.String(); body != "public" {
					t.Errorf("authorized WebDAV Range body: expected %q, got %q", "public", body)
				}
				return
			}
			if recorder.Header().Get("Content-Range") != "" {
				t.Errorf("unauthorized WebDAV Range leaked Content-Range %q", recorder.Header().Get("Content-Range"))
			}
			if body := recorder.Body.String(); body != "" {
				t.Errorf("unauthorized WebDAV Range leaked body %q", body)
			}
			assertNoPermissionWebDAVOriginalHeaders(t, recorder.Header())
		})
	}
}

func TestPermissionWebDAVSecurity_HEADDoesNotLeakOriginalMetadata(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)

	for _, tc := range []struct {
		name       string
		browse     bool
		download   bool
		wantStatus int
	}{
		{name: "both permissions", browse: true, download: true, wantStatus: http.StatusOK},
		{name: "Browse missing", browse: false, download: true, wantStatus: http.StatusForbidden},
		{name: "Download missing", browse: true, download: false, wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := permissionWebDAVUser(t, sourcePath, tc.browse, tc.download)
			status, recorder, err := performPermissionWebDAVRequest(t, user, http.MethodHead, "/public/readme.txt", "", nil)
			if status != tc.wantStatus {
				t.Errorf("WebDAV HEAD status: expected %d, got %d (err: %v)", tc.wantStatus, status, err)
			}
			if tc.wantStatus == http.StatusOK {
				if contentLength := recorder.Header().Get("Content-Length"); contentLength != "14" {
					t.Errorf("authorized WebDAV HEAD Content-Length: expected 14, got %q", contentLength)
				}
			} else {
				assertNoPermissionWebDAVOriginalHeaders(t, recorder.Header())
			}
			if recorder.Body.Len() != 0 {
				t.Errorf("WebDAV HEAD emitted body %q", recorder.Body.String())
			}
		})
	}
}

func TestPermissionWebDAVSecurity_AdminDoesNotBypassReadPermissions(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)

	for _, tc := range []struct {
		name     string
		method   string
		browse   bool
		download bool
		headers  map[string]string
	}{
		{name: "PROPFIND requires Browse", method: "PROPFIND", browse: false, download: true, headers: map[string]string{"Depth": "1"}},
		{name: "GET requires Browse", method: http.MethodGet, browse: false, download: true},
		{name: "Range GET requires Browse", method: http.MethodGet, browse: false, download: true, headers: map[string]string{"Range": "bytes=0-5"}},
		{name: "HEAD requires Download", method: http.MethodHead, browse: true, download: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := permissionWebDAVUser(t, sourcePath, tc.browse, tc.download)
			user.Permissions.Admin = true
			status, recorder, err := performPermissionWebDAVRequest(t, user, tc.method, "/public/readme.txt", "", tc.headers)
			if status != http.StatusForbidden {
				t.Errorf("Admin WebDAV %s status: expected %d, got %d (err: %v)", tc.method, http.StatusForbidden, status, err)
			}
			assertNoPermissionWebDAVOriginalHeaders(t, recorder.Header())
			if strings.Contains(recorder.Body.String(), "public content") {
				t.Errorf("Admin without read permissions leaked original bytes %q", recorder.Body.String())
			}
		})
	}
}

func TestPermissionWebDAVSecurity_KnownPathDoesNotCreateBrowseOracle(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
	user := permissionWebDAVUser(t, sourcePath, false, true)

	type observation struct {
		status  int
		headers string
		body    string
	}
	observe := func(path string) observation {
		status, recorder, _ := performPermissionWebDAVRequest(t, user, http.MethodHead, path, "", nil)
		values := make([]string, 0, 7)
		for _, name := range []string{"Accept-Ranges", "Content-Length", "Content-Range", "Content-Type", "ETag", "Last-Modified", "Content-Disposition"} {
			values = append(values, name+"="+recorder.Header().Get(name))
		}
		return observation{
			status:  status,
			headers: strings.Join(values, ";"),
			body:    strings.ReplaceAll(recorder.Body.String(), path, "<requested-path>"),
		}
	}

	existing := observe("/public/readme.txt")
	missing := observe("/public/does-not-exist.txt")
	if existing.status != http.StatusForbidden && existing.status != http.StatusNotFound {
		t.Errorf("Browse=false known WebDAV path returned observable status %d", existing.status)
	}
	if existing != missing {
		t.Errorf("Browse=false WebDAV existence oracle: existing=%+v missing=%+v", existing, missing)
	}
}

func TestPermissionWebDAVSecurity_KnownPathReadAliasesRequireBrowse(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)

	for _, tc := range []struct {
		name       string
		method     string
		path       string
		browse     bool
		download   bool
		wantStatus int
		wantBody   string
		wantAllow  bool
	}{
		{name: "authorized POST retains read behavior", method: http.MethodPost, path: "/public/readme.txt", browse: true, download: true, wantStatus: http.StatusOK, wantBody: "public content"},
		{name: "POST requires Browse", method: http.MethodPost, path: "/public/readme.txt", browse: false, download: true, wantStatus: http.StatusForbidden},
		{name: "POST requires Download", method: http.MethodPost, path: "/public/readme.txt", browse: true, download: false, wantStatus: http.StatusForbidden},
		{name: "Browse-only OPTIONS returns protocol capabilities", method: http.MethodOptions, path: "/public/readme.txt", browse: true, download: false, wantStatus: http.StatusOK, wantAllow: true},
		{name: "OPTIONS cannot inspect an existing path without Browse", method: http.MethodOptions, path: "/public/readme.txt", browse: false, download: true, wantStatus: http.StatusForbidden},
		{name: "OPTIONS cannot inspect a missing path without Browse", method: http.MethodOptions, path: "/public/does-not-exist.txt", browse: false, download: true, wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := permissionWebDAVUser(t, sourcePath, tc.browse, tc.download)
			status, recorder, err := performPermissionWebDAVRequest(t, user, tc.method, tc.path, "", nil)
			if status != tc.wantStatus {
				t.Errorf("WebDAV %s status: expected %d, got %d (err: %v)", tc.method, tc.wantStatus, status, err)
			}
			if tc.wantStatus == http.StatusOK {
				if body := recorder.Body.String(); body != tc.wantBody {
					t.Errorf("authorized WebDAV %s body: expected %q, got %q", tc.method, tc.wantBody, body)
				}
				if tc.wantAllow && recorder.Header().Get("Allow") == "" {
					t.Error("authorized WebDAV OPTIONS did not return an Allow header")
				}
				return
			}
			assertNoPermissionWebDAVOriginalHeaders(t, recorder.Header())
			for _, name := range []string{"Allow", "DAV", "MS-Author-Via"} {
				if value := recorder.Header().Get(name); value != "" {
					t.Errorf("unauthorized WebDAV %s leaked %s %q", tc.method, name, value)
				}
			}
			if recorder.Body.Len() != 0 {
				t.Errorf("unauthorized WebDAV %s emitted body %q", tc.method, recorder.Body.String())
			}
		})
	}
}

func TestPermissionWebDAVSecurity_TokenPermissionIntersection(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
	configurePermissionWebDAVAuth(t)
	router := permissionWebDAVRouter()

	for _, tc := range []struct {
		name               string
		userBrowse         bool
		userDownload       bool
		tokenBrowse        bool
		tokenDownload      bool
		revokeUserBrowse   bool
		revokeUserDownload bool
		wantStatus         int
	}{
		{name: "user and token allow WebDAV read", userBrowse: true, userDownload: true, tokenBrowse: true, tokenDownload: true, wantStatus: http.StatusOK},
		{name: "WebDAV token cannot exceed missing Browse", userBrowse: true, userDownload: true, tokenBrowse: false, tokenDownload: true, wantStatus: http.StatusForbidden},
		{name: "user Browse caps WebDAV token", userBrowse: false, userDownload: true, tokenBrowse: true, tokenDownload: true, wantStatus: http.StatusForbidden},
		{name: "WebDAV token cannot exceed missing Download", userBrowse: true, userDownload: true, tokenBrowse: true, tokenDownload: false, wantStatus: http.StatusForbidden},
		{name: "user Download caps WebDAV token", userBrowse: true, userDownload: false, tokenBrowse: true, tokenDownload: true, wantStatus: http.StatusForbidden},
		{name: "old WebDAV token loses revoked user Browse", userBrowse: true, userDownload: true, tokenBrowse: true, tokenDownload: true, revokeUserBrowse: true, wantStatus: http.StatusForbidden},
		{name: "old WebDAV token loses revoked user Download", userBrowse: true, userDownload: true, tokenBrowse: true, tokenDownload: true, revokeUserDownload: true, wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			suffix := strings.ReplaceAll(tc.name, " ", "-")
			user := permissionWebDAVUser(t, sourcePath, tc.userBrowse, tc.userDownload)
			user.Username = "permission-webdav-token-user-" + suffix
			savePermissionWebDAVUser(t, user)

			tokenPermissions := users.Permissions{Download: tc.tokenDownload}
			setFutureReadPermission(t, &tokenPermissions, "Browse", tc.tokenBrowse)
			token := issuePermissionWebDAVAPIToken(t, user, "permission-webdav-token-"+suffix, tokenPermissions)
			if tc.revokeUserBrowse {
				setFutureReadPermission(t, &user.Permissions, "Browse", false)
			}
			if tc.revokeUserDownload {
				user.Permissions.Download = false
			}
			if tc.revokeUserBrowse || tc.revokeUserDownload {
				if err := store.Users.Update(user, true, "Permissions"); err != nil {
					t.Fatal(err)
				}
			}

			req := httptest.NewRequest(http.MethodGet, "/dav/source1/public/readme.txt", nil)
			req.SetBasicAuth("ignored", token)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)
			if recorder.Code != tc.wantStatus {
				t.Errorf("WebDAV token read status: expected %d, got %d", tc.wantStatus, recorder.Code)
			}
			if tc.wantStatus == http.StatusOK {
				if body := recorder.Body.String(); body != "public content" {
					t.Errorf("authorized WebDAV token body: expected %q, got %q", "public content", body)
				}
				return
			}
			assertNoPermissionWebDAVOriginalHeaders(t, recorder.Header())
			if strings.Contains(recorder.Body.String(), "public content") {
				t.Errorf("unauthorized WebDAV token leaked original bytes %q", recorder.Body.String())
			}
		})
	}
}

func TestPermissionWebDAVSecurity_TokenPROPFINDUsesBrowsePermission(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
	configurePermissionWebDAVAuth(t)
	router := permissionWebDAVRouter()

	for _, tc := range []struct {
		name          string
		tokenBrowse   bool
		tokenDownload bool
		wantStatus    int
	}{
		{name: "Browse-only token can list", tokenBrowse: true, tokenDownload: false, wantStatus: http.StatusMultiStatus},
		{name: "Download-only token cannot list", tokenBrowse: false, tokenDownload: true, wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			suffix := strings.ReplaceAll(tc.name, " ", "-")
			user := permissionWebDAVUser(t, sourcePath, true, true)
			user.Username = "permission-webdav-propfind-token-user-" + suffix
			savePermissionWebDAVUser(t, user)
			tokenPermissions := users.Permissions{Browse: tc.tokenBrowse, Download: tc.tokenDownload}
			token := issuePermissionWebDAVAPIToken(t, user, "permission-webdav-propfind-token-"+suffix, tokenPermissions)

			req := httptest.NewRequest("PROPFIND", "/dav/source1/public/", nil)
			req.SetBasicAuth("ignored", token)
			req.Header.Set("Depth", "1")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)
			if recorder.Code != tc.wantStatus {
				t.Errorf("WebDAV token PROPFIND status: expected %d, got %d", tc.wantStatus, recorder.Code)
			}
			body := recorder.Body.String()
			if tc.wantStatus == http.StatusMultiStatus {
				if !strings.Contains(body, "readme.txt") {
					t.Errorf("authorized WebDAV token PROPFIND did not include readme.txt: %q", body)
				}
			} else if strings.Contains(body, "readme.txt") || strings.Contains(body, "getcontentlength") {
				t.Errorf("unauthorized WebDAV token PROPFIND leaked directory properties %q", body)
			}
		})
	}
}

func TestPermissionWebDAVSecurity_RoutedHEADDoesNotLeakMetadata(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
	configurePermissionWebDAVAuth(t)

	user := permissionWebDAVUser(t, sourcePath, true, true)
	user.Username = "permission-webdav-routed-head-user"
	savePermissionWebDAVUser(t, user)
	token := issuePermissionWebDAVAPIToken(t, user, "permission-webdav-routed-head-token", users.Permissions{Download: true})

	server := httptest.NewServer(permissionWebDAVRouter())
	t.Cleanup(server.Close)
	for _, path := range []string{"/public/readme.txt", "/public/does-not-exist.txt"} {
		t.Run(path, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodHead, server.URL+"/dav/source1"+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.SetBasicAuth("ignored", token)
			req.Header.Set("If-Modified-Since", time.Now().Add(24*time.Hour).UTC().Format(http.TimeFormat))
			response, err := server.Client().Do(req)
			if err != nil {
				t.Fatalf("perform routed WebDAV HEAD: %v", err)
			}
			body, readErr := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if readErr != nil {
				t.Errorf("read routed WebDAV HEAD body: %v", readErr)
			}
			if closeErr != nil {
				t.Errorf("close routed WebDAV HEAD body: %v", closeErr)
			}
			if response.StatusCode != http.StatusForbidden {
				t.Errorf("routed WebDAV HEAD status: expected %d, got %d", http.StatusForbidden, response.StatusCode)
			}
			assertNoPermissionWebDAVOriginalHeaders(t, response.Header)
			if response.ContentLength > 0 {
				t.Errorf("routed WebDAV HEAD leaked Content-Length %d", response.ContentLength)
			}
			if len(body) != 0 {
				t.Errorf("routed WebDAV HEAD emitted body %q", body)
			}
		})
	}
}

func TestPermissionWebDAVSecurity_BrowseDoesNotChangeWritePermissions(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)

	t.Run("existing full write permissions still allow PUT", func(t *testing.T) {
		user := permissionWebDAVUser(t, sourcePath, false, true)
		user.Permissions.Create = true
		user.Permissions.Modify = true
		user.Permissions.Delete = true
		status, _, err := performPermissionWebDAVRequest(t, user, http.MethodPut, "/public/browse-independent.txt", "write content", nil)
		if status != http.StatusCreated {
			t.Errorf("full write permission PUT status: expected %d, got %d (err: %v)", http.StatusCreated, status, err)
		}
		content, readErr := os.ReadFile(filepath.Join(sourcePath, "public", "browse-independent.txt"))
		if readErr != nil {
			t.Errorf("read written WebDAV file: %v", readErr)
		} else if string(content) != "write content" {
			t.Errorf("written WebDAV content: expected %q, got %q", "write content", content)
		}
	})

	t.Run("new target still requires Create", func(t *testing.T) {
		user := permissionWebDAVUser(t, sourcePath, false, true)
		user.Permissions.Modify = true
		user.Permissions.Delete = true
		status, _, err := performPermissionWebDAVRequest(t, user, http.MethodPut, "/public/missing-create.txt", "must not be written", nil)
		if status != http.StatusForbidden {
			t.Errorf("missing Create PUT status: expected %d, got %d (err: %v)", http.StatusForbidden, status, err)
		}
		if _, statErr := os.Stat(filepath.Join(sourcePath, "public", "missing-create.txt")); statErr == nil {
			t.Error("WebDAV PUT wrote a new file without Create permission")
		} else if !os.IsNotExist(statErr) {
			t.Errorf("stat denied WebDAV path: %v", statErr)
		}
	})

	t.Run("existing Download requirement still rejects PUT", func(t *testing.T) {
		user := permissionWebDAVUser(t, sourcePath, false, false)
		user.Permissions.Create = true
		user.Permissions.Modify = true
		user.Permissions.Delete = true
		status, _, err := performPermissionWebDAVRequest(t, user, http.MethodPut, "/public/missing-download.txt", "must not be written", nil)
		if status != http.StatusForbidden {
			t.Errorf("missing Download PUT status: expected %d, got %d (err: %v)", http.StatusForbidden, status, err)
		}
		if _, statErr := os.Stat(filepath.Join(sourcePath, "public", "missing-download.txt")); statErr == nil {
			t.Error("WebDAV PUT wrote a file without the existing Download permission")
		} else if !os.IsNotExist(statErr) {
			t.Errorf("stat denied WebDAV path: %v", statErr)
		}
	})
}

func TestPermissionWebDAVSecurity_COPYSourceRequiresBrowse(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)

	for _, source := range []string{"/public/readme.txt", "/public/does-not-exist.txt"} {
		t.Run(source, func(t *testing.T) {
			user := permissionWebDAVUser(t, sourcePath, false, true)
			user.Permissions.Create = true
			user.Permissions.Modify = true
			user.Permissions.Delete = true
			destinationPath := filepath.Join(sourcePath, "public", "copied.txt")
			headers := map[string]string{
				"Destination": "http://example.com/dav/source1/public/copied.txt",
				"Overwrite":   "F",
			}

			status, recorder, err := performPermissionWebDAVRequest(t, user, "COPY", source, "", headers)
			if status != http.StatusForbidden {
				t.Errorf("WebDAV COPY status: got %d, want %d (err: %v, body: %q)", status, http.StatusForbidden, err, recorder.Body.String())
			}
			assertNoPermissionWebDAVOriginalHeaders(t, recorder.Header())
			if _, statErr := os.Stat(destinationPath); !os.IsNotExist(statErr) {
				t.Errorf("denied WebDAV COPY created destination: %v", statErr)
			}
		})
	}
}

func TestPermissionWebDAVSecurity_CanonicalPathBoundaries(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
	outsideDir := t.TempDir()
	outsideSecret := filepath.Join(outsideDir, "outside-webdav.txt")
	if err := os.WriteFile(outsideSecret, []byte("outside-webdav-secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(sourcePath, "public", "outside-webdav.txt")
	if err := os.Symlink(outsideSecret, linkPath); err != nil {
		t.Skipf("WebDAV canonical symlink assertions unavailable: %v", err)
	}

	user := permissionWebDAVUser(t, sourcePath, true, true)
	user.Permissions.Create = true
	user.Permissions.Modify = true
	user.Permissions.Delete = true
	for _, tc := range []struct {
		name    string
		method  string
		headers map[string]string
	}{
		{name: "GET", method: http.MethodGet},
		{name: "HEAD", method: http.MethodHead},
		{name: "Range GET", method: http.MethodGet, headers: map[string]string{"Range": "bytes=0-6"}},
		{name: "POST", method: http.MethodPost},
		{name: "PROPFIND", method: "PROPFIND", headers: map[string]string{"Depth": "0"}},
		{name: "COPY", method: "COPY", headers: map[string]string{
			"Destination": "http://example.com/dav/source1/public/copied-outside.txt",
			"Overwrite":   "F",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, recorder, err := performPermissionWebDAVRequest(t, user, tc.method, "/public/outside-webdav.txt", "", tc.headers)
			if status != http.StatusForbidden {
				t.Errorf("canonical WebDAV %s status: got %d, want %d (err: %v, body: %q)", tc.method, status, http.StatusForbidden, err, recorder.Body.String())
			}
			assertNoPermissionWebDAVOriginalHeaders(t, recorder.Header())
			if strings.Contains(recorder.Body.String(), "outside-webdav-secret") {
				t.Errorf("canonical WebDAV %s leaked target bytes %q", tc.method, recorder.Body.String())
			}
		})
	}
	if _, err := os.Stat(filepath.Join(sourcePath, "public", "copied-outside.txt")); !os.IsNotExist(err) {
		t.Errorf("canonical WebDAV COPY created destination: %v", err)
	}
}

func TestPermissionWebDAVSecurity_SymlinkTargetDenialDoesNotExposeTargetState(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
	user := permissionWebDAVUser(t, sourcePath, true, true)
	user.Username = "permission-webdav-symlink-target-state-user"
	savePermissionWebDAVUser(t, user)

	canonicalTarget := filepath.Join(sourcePath, "public", "canonical-denied-target.txt")
	if err := os.WriteFile(canonicalTarget, []byte("canonical target"), 0o644); err != nil {
		t.Fatal(err)
	}
	outsideTarget := filepath.Join(t.TempDir(), "outside-target.txt")
	if err := os.WriteFile(outsideTarget, []byte("outside target"), 0o644); err != nil {
		t.Fatal(err)
	}
	for linkPath, targetPath := range map[string]string{
		filepath.Join(sourcePath, "public", "canonical-denied-link.txt"): canonicalTarget,
		filepath.Join(sourcePath, "public", "outside-link.txt"):          outsideTarget,
		filepath.Join(sourcePath, "public", "broken-link.txt"):           filepath.Join(sourcePath, "public", "missing-target.txt"),
	} {
		if err := os.Symlink(targetPath, linkPath); err != nil {
			t.Skipf("WebDAV symlink target-state assertions unavailable: %v", err)
		}
	}
	if err := store.Access.DenyUser(sourcePath, "/public/canonical-denied-target.txt", user.Username); err != nil {
		t.Fatal(err)
	}

	methods := []struct {
		method  string
		headers map[string]string
	}{
		{method: http.MethodGet},
		{method: http.MethodHead},
		{method: "PROPFIND", headers: map[string]string{"Depth": "0"}},
		{method: http.MethodOptions},
	}
	for _, link := range []string{"/public/canonical-denied-link.txt", "/public/outside-link.txt", "/public/broken-link.txt"} {
		for _, tc := range methods {
			t.Run(tc.method+" "+link, func(t *testing.T) {
				status, recorder, err := performPermissionWebDAVRequest(t, user, tc.method, link, "", tc.headers)
				if status != http.StatusForbidden {
					t.Errorf("symlink target denial status: got %d, want %d (err: %v, body: %q)", status, http.StatusForbidden, err, recorder.Body.String())
				}
				assertNoPermissionWebDAVOriginalHeaders(t, recorder.Header())
			})
		}
	}

	for _, tc := range methods {
		t.Run(tc.method+" ordinary missing path", func(t *testing.T) {
			status, _, err := performPermissionWebDAVRequest(t, user, tc.method, "/public/ordinary-missing.txt", "", tc.headers)
			want := http.StatusNotFound
			if tc.method == http.MethodOptions {
				want = http.StatusOK
			}
			if status != want {
				t.Errorf("ordinary missing status: got %d, want %d (err: %v)", status, want, err)
			}
		})
	}
}

func TestPermissionWebDAVSecurity_COPYTokenPermissionIntersection(t *testing.T) {
	for _, tc := range []struct {
		name               string
		tokenBrowse        bool
		tokenDownload      bool
		tokenCreate        bool
		tokenModify        bool
		tokenDelete        bool
		revokeUserBrowse   bool
		revokeUserDownload bool
		destinationExists  bool
		overwrite          bool
	}{
		{name: "COPY token cannot exceed Browse", tokenDownload: true, tokenCreate: true, tokenModify: true, tokenDelete: true},
		{name: "COPY token loses revoked account Browse", tokenBrowse: true, tokenDownload: true, tokenCreate: true, tokenModify: true, tokenDelete: true, revokeUserBrowse: true},
		{name: "COPY token cannot exceed Download", tokenBrowse: true, tokenCreate: true, tokenModify: true, tokenDelete: true},
		{name: "COPY token loses revoked account Download", tokenBrowse: true, tokenDownload: true, tokenCreate: true, tokenModify: true, tokenDelete: true, revokeUserDownload: true},
		{name: "COPY new target requires token Create", tokenBrowse: true, tokenDownload: true, tokenModify: true, tokenDelete: true},
		{name: "COPY existing target requires token Modify", tokenBrowse: true, tokenDownload: true, tokenCreate: true, tokenDelete: true, destinationExists: true},
		{name: "COPY overwrite requires token Delete", tokenBrowse: true, tokenDownload: true, tokenModify: true, destinationExists: true, overwrite: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
			configurePermissionWebDAVAuth(t)
			user := permissionWebDAVUser(t, sourcePath, true, true)
			user.Username = "permission-webdav-copy-token-" + strings.ReplaceAll(tc.name, " ", "-")
			user.Permissions.Create = true
			user.Permissions.Modify = true
			user.Permissions.Delete = true
			savePermissionWebDAVUser(t, user)
			destinationPath := filepath.Join(sourcePath, "public", "copied-token.txt")
			if tc.destinationExists {
				if err := os.WriteFile(destinationPath, []byte("token destination must survive"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			token := issuePermissionReadAPIToken(t, user, "permission-webdav-copy-token", users.Permissions{
				Browse:   tc.tokenBrowse,
				Download: tc.tokenDownload,
				Create:   tc.tokenCreate,
				Modify:   tc.tokenModify,
				Delete:   tc.tokenDelete,
			})
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

			req := httptest.NewRequest("COPY", "/dav/source1/public/readme.txt", nil)
			req.SetBasicAuth("ignored", token)
			req.Header.Set("Destination", "http://example.com/dav/source1/public/copied-token.txt")
			if tc.overwrite {
				req.Header.Set("Overwrite", "T")
			} else {
				req.Header.Set("Overwrite", "F")
			}
			recorder := httptest.NewRecorder()
			permissionWebDAVRouter().ServeHTTP(recorder, req)
			if recorder.Code != http.StatusForbidden {
				t.Errorf("WebDAV COPY token status: got %d, want %d (body: %q)", recorder.Code, http.StatusForbidden, recorder.Body.String())
			}
			content, err := os.ReadFile(destinationPath)
			if tc.destinationExists {
				if err != nil {
					t.Fatalf("denied token COPY removed destination: %v", err)
				}
				if got := string(content); got != "token destination must survive" {
					t.Errorf("denied token COPY changed destination: %q", got)
				}
			} else if !os.IsNotExist(err) {
				t.Errorf("denied token COPY created destination: %v", err)
			}
		})
	}
}

func TestPermissionWebDAVSecurity_OverwriteDenialPreservesDestination(t *testing.T) {
	for _, tc := range []struct {
		name          string
		method        string
		source        string
		create        bool
		modify        bool
		delete        bool
		wantStatus    int
		prepareSource bool
	}{
		{
			name:       "COPY without Create or Modify",
			method:     "COPY",
			source:     "/public/readme.txt",
			delete:     true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:          "MOVE without Modify",
			method:        "MOVE",
			source:        "/public/move-source.txt",
			create:        true,
			delete:        true,
			wantStatus:    http.StatusForbidden,
			prepareSource: true,
		},
		{
			name:       "MOVE with missing source",
			method:     "MOVE",
			source:     "/public/missing-source.txt",
			create:     true,
			modify:     true,
			delete:     true,
			wantStatus: http.StatusNotFound,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
			destinationPath := filepath.Join(sourcePath, "public", "overwrite-destination.txt")
			if err := os.WriteFile(destinationPath, []byte("destination must survive"), 0o644); err != nil {
				t.Fatal(err)
			}
			if tc.prepareSource {
				if err := os.WriteFile(filepath.Join(sourcePath, "public", "move-source.txt"), []byte("move source"), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			user := permissionWebDAVUser(t, sourcePath, true, true)
			user.Permissions.Create = tc.create
			user.Permissions.Modify = tc.modify
			user.Permissions.Delete = tc.delete
			status, recorder, err := performPermissionWebDAVRequest(t, user, tc.method, tc.source, "", map[string]string{
				"Destination": "http://example.com/dav/source1/public/overwrite-destination.txt",
				"Overwrite":   "T",
			})
			if status != tc.wantStatus {
				t.Errorf("WebDAV %s status: got %d, want %d (err: %v, body: %q)", tc.method, status, tc.wantStatus, err, recorder.Body.String())
			}
			content, readErr := os.ReadFile(destinationPath)
			if readErr != nil {
				t.Fatalf("destination was removed after denied %s: %v", tc.method, readErr)
			}
			if got := string(content); got != "destination must survive" {
				t.Errorf("destination changed after denied %s: %q", tc.method, got)
			}
		})
	}
}

func TestPermissionWebDAVSecurity_SymlinkEntryOperationsPreserveTargets(t *testing.T) {
	t.Run("DELETE removes the link", func(t *testing.T) {
		sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
		targetPath := filepath.Join(sourcePath, "public", "readme.txt")
		linkPath := filepath.Join(sourcePath, "public", "delete-link.txt")
		if err := os.Symlink(targetPath, linkPath); err != nil {
			t.Skipf("WebDAV symlink entry assertions unavailable: %v", err)
		}
		user := permissionWebDAVUser(t, sourcePath, true, true)
		user.Permissions.Delete = true

		status, recorder, err := performPermissionWebDAVRequest(t, user, http.MethodDelete, "/public/delete-link.txt", "", nil)
		if status != http.StatusNoContent {
			t.Fatalf("WebDAV DELETE symlink status: got %d, want %d (err: %v, body: %q)", status, http.StatusNoContent, err, recorder.Body.String())
		}
		if _, lstatErr := os.Lstat(linkPath); !os.IsNotExist(lstatErr) {
			t.Errorf("DELETE did not remove the symlink entry: %v", lstatErr)
		}
		content, err := os.ReadFile(targetPath)
		if err != nil {
			t.Fatalf("DELETE removed the symlink target: %v", err)
		}
		if got := string(content); got != "public content" {
			t.Errorf("DELETE changed the symlink target: %q", got)
		}
	})

	t.Run("MOVE moves the link", func(t *testing.T) {
		sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
		targetPath := filepath.Join(sourcePath, "public", "readme.txt")
		linkPath := filepath.Join(sourcePath, "public", "move-link.txt")
		movedPath := filepath.Join(sourcePath, "public", "moved-link.txt")
		if err := os.Symlink(targetPath, linkPath); err != nil {
			t.Skipf("WebDAV symlink entry assertions unavailable: %v", err)
		}
		user := permissionWebDAVUser(t, sourcePath, true, true)
		user.Permissions.Create = true
		user.Permissions.Modify = true

		status, recorder, err := performPermissionWebDAVRequest(t, user, "MOVE", "/public/move-link.txt", "", map[string]string{
			"Destination": "http://example.com/dav/source1/public/moved-link.txt",
			"Overwrite":   "F",
		})
		if status != http.StatusCreated {
			t.Fatalf("WebDAV MOVE symlink status: got %d, want %d (err: %v, body: %q)", status, http.StatusCreated, err, recorder.Body.String())
		}
		if _, lstatErr := os.Lstat(linkPath); !os.IsNotExist(lstatErr) {
			t.Errorf("MOVE left the old symlink entry: %v", lstatErr)
		}
		info, err := os.Lstat(movedPath)
		if err != nil {
			t.Fatalf("MOVE did not create the destination entry: %v", err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			t.Errorf("MOVE replaced the symlink with mode %v", info.Mode())
		}
		content, err := os.ReadFile(targetPath)
		if err != nil {
			t.Fatalf("MOVE removed the symlink target: %v", err)
		}
		if got := string(content); got != "public content" {
			t.Errorf("MOVE changed the symlink target: %q", got)
		}
	})

	t.Run("COPY overwrite replaces the link only", func(t *testing.T) {
		sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
		targetPath := filepath.Join(sourcePath, "public", "overwrite-target.txt")
		linkPath := filepath.Join(sourcePath, "public", "overwrite-link.txt")
		if err := os.WriteFile(targetPath, []byte("target must survive"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(targetPath, linkPath); err != nil {
			t.Skipf("WebDAV symlink entry assertions unavailable: %v", err)
		}
		user := permissionWebDAVUser(t, sourcePath, true, true)
		user.Permissions.Create = true
		user.Permissions.Modify = true
		user.Permissions.Delete = true

		status, recorder, err := performPermissionWebDAVRequest(t, user, "COPY", "/public/readme.txt", "", map[string]string{
			"Destination": "http://example.com/dav/source1/public/overwrite-link.txt",
			"Overwrite":   "T",
		})
		if status != http.StatusNoContent {
			t.Fatalf("WebDAV COPY symlink overwrite status: got %d, want %d (err: %v, body: %q)", status, http.StatusNoContent, err, recorder.Body.String())
		}
		content, err := os.ReadFile(targetPath)
		if err != nil {
			t.Fatalf("COPY overwrite removed the symlink target: %v", err)
		}
		if got := string(content); got != "target must survive" {
			t.Errorf("COPY overwrite changed the symlink target: %q", got)
		}
		info, err := os.Lstat(linkPath)
		if err != nil {
			t.Fatalf("COPY overwrite did not create destination: %v", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			t.Error("COPY overwrite left the destination as a symlink")
		}
		copied, err := os.ReadFile(linkPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(copied); got != "public content" {
			t.Errorf("COPY overwrite content: got %q", got)
		}
	})
}

func TestPermissionWebDAVSecurity_WritePermissionMatrix(t *testing.T) {
	for _, tc := range []struct {
		name              string
		method            string
		create            bool
		modify            bool
		delete            bool
		destinationExists bool
		wantStatus        int
		wantContent       string
	}{
		{name: "COPY new target accepts Create", method: "COPY", create: true, wantStatus: http.StatusCreated, wantContent: "public content"},
		{name: "COPY new target rejects Modify", method: "COPY", modify: true, wantStatus: http.StatusForbidden},
		{name: "COPY overwrite accepts Modify and Delete", method: "COPY", modify: true, delete: true, destinationExists: true, wantStatus: http.StatusNoContent, wantContent: "public content"},
		{name: "COPY overwrite rejects Create without Modify", method: "COPY", create: true, delete: true, destinationExists: true, wantStatus: http.StatusForbidden},
		{name: "PUT new target accepts Create", method: http.MethodPut, create: true, wantStatus: http.StatusCreated, wantContent: "put content"},
		{name: "PUT new target rejects Modify", method: http.MethodPut, modify: true, wantStatus: http.StatusForbidden},
		{name: "PUT overwrite accepts Modify and Delete", method: http.MethodPut, modify: true, delete: true, destinationExists: true, wantStatus: http.StatusCreated, wantContent: "put content"},
		{name: "PUT overwrite rejects Create without Modify", method: http.MethodPut, create: true, delete: true, destinationExists: true, wantStatus: http.StatusForbidden},
		{name: "PUT overwrite rejects missing Delete", method: http.MethodPut, modify: true, destinationExists: true, wantStatus: http.StatusForbidden},
		{name: "MOVE new target requires Create with source Modify", method: "MOVE", create: true, modify: true, wantStatus: http.StatusCreated, wantContent: "move content"},
		{name: "MOVE new target rejects source Modify without Create", method: "MOVE", modify: true, wantStatus: http.StatusForbidden},
		{name: "MOVE overwrite accepts Modify and Delete", method: "MOVE", modify: true, delete: true, destinationExists: true, wantStatus: http.StatusNoContent, wantContent: "move content"},
		{name: "MOVE overwrite rejects missing Delete", method: "MOVE", modify: true, destinationExists: true, wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
			user := permissionWebDAVUser(t, sourcePath, true, true)
			user.Permissions.Create = tc.create
			user.Permissions.Modify = tc.modify
			user.Permissions.Delete = tc.delete

			destinationPath := filepath.Join(sourcePath, "public", "permission-matrix-destination.txt")
			if tc.destinationExists {
				if err := os.WriteFile(destinationPath, []byte("destination must survive"), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			requestPath := "/public/permission-matrix-destination.txt"
			body := "put content"
			var headers map[string]string
			if tc.method == "COPY" || tc.method == "MOVE" {
				requestPath = "/public/readme.txt"
				if tc.method == "MOVE" {
					requestPath = "/public/permission-matrix-source.txt"
					if err := os.WriteFile(filepath.Join(sourcePath, "public", "permission-matrix-source.txt"), []byte("move content"), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				headers = map[string]string{
					"Destination": "http://example.com/dav/source1/public/permission-matrix-destination.txt",
					"Overwrite":   map[bool]string{true: "T", false: "F"}[tc.destinationExists],
				}
				body = ""
			}

			status, recorder, err := performPermissionWebDAVRequest(t, user, tc.method, requestPath, body, headers)
			if status != tc.wantStatus {
				t.Errorf("WebDAV %s status: got %d, want %d (err: %v, body: %q)", tc.method, status, tc.wantStatus, err, recorder.Body.String())
			}

			content, readErr := os.ReadFile(destinationPath)
			if tc.wantStatus == http.StatusForbidden {
				if tc.destinationExists {
					if readErr != nil {
						t.Fatalf("denied %s removed destination: %v", tc.method, readErr)
					}
					if got := string(content); got != "destination must survive" {
						t.Errorf("denied %s changed destination: %q", tc.method, got)
					}
				} else if !os.IsNotExist(readErr) {
					t.Errorf("denied %s created destination: %v", tc.method, readErr)
				}
				if tc.method == "MOVE" {
					if source, sourceErr := os.ReadFile(filepath.Join(sourcePath, "public", "permission-matrix-source.txt")); sourceErr != nil || string(source) != "move content" {
						t.Errorf("denied MOVE changed source: content=%q err=%v", source, sourceErr)
					}
				}
				return
			}
			if readErr != nil {
				t.Fatalf("authorized %s did not create destination: %v", tc.method, readErr)
			}
			if got := string(content); got != tc.wantContent {
				t.Errorf("authorized %s content: got %q, want %q", tc.method, got, tc.wantContent)
			}
		})
	}

	for _, tc := range []struct {
		name       string
		create     bool
		modify     bool
		wantStatus int
	}{
		{name: "MKCOL new target accepts Create", create: true, wantStatus: http.StatusCreated},
		{name: "MKCOL new target rejects Modify", modify: true, wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
			user := permissionWebDAVUser(t, sourcePath, true, true)
			user.Permissions.Create = tc.create
			user.Permissions.Modify = tc.modify
			status, recorder, err := performPermissionWebDAVRequest(t, user, "MKCOL", "/public/permission-matrix-directory", "", nil)
			if status != tc.wantStatus {
				t.Errorf("WebDAV MKCOL status: got %d, want %d (err: %v, body: %q)", status, tc.wantStatus, err, recorder.Body.String())
			}
			info, statErr := os.Stat(filepath.Join(sourcePath, "public", "permission-matrix-directory"))
			if tc.wantStatus == http.StatusCreated {
				if statErr != nil || !info.IsDir() {
					t.Errorf("authorized MKCOL did not create directory: info=%v err=%v", info, statErr)
				}
			} else if !os.IsNotExist(statErr) {
				t.Errorf("denied MKCOL created directory: %v", statErr)
			}
		})
	}
}

func TestPermissionWebDAVSecurity_ScopedVirtualRootIsImmutable(t *testing.T) {
	for _, tc := range []struct {
		name        string
		method      string
		requestPath string
		destination string
	}{
		{name: "DELETE scope root", method: http.MethodDelete, requestPath: "/"},
		{name: "MOVE scope root source", method: "MOVE", requestPath: "/", destination: "http://example.com/dav/source1/moved-root"},
		{name: "COPY overwrite scope root destination", method: "COPY", requestPath: "/readme.txt", destination: "http://example.com/dav/source1/"},
		{name: "MOVE overwrite scope root destination", method: "MOVE", requestPath: "/readme.txt", destination: "http://example.com/dav/source1/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
			user := permissionWebDAVUser(t, sourcePath, true, true)
			user.Scopes[0].Scope = "/public"
			user.Permissions.Create = true
			user.Permissions.Modify = true
			user.Permissions.Delete = true
			headers := map[string]string{}
			if tc.destination != "" {
				headers["Destination"] = tc.destination
				headers["Overwrite"] = "T"
			}

			status, recorder, err := performPermissionWebDAVRequest(t, user, tc.method, tc.requestPath, "", headers)
			if status != http.StatusForbidden {
				t.Errorf("scoped WebDAV %s status: got %d, want %d (err: %v, body: %q)", tc.method, status, http.StatusForbidden, err, recorder.Body.String())
			}
			content, readErr := os.ReadFile(filepath.Join(sourcePath, "public", "readme.txt"))
			if readErr != nil {
				t.Fatalf("scoped root operation removed content: %v", readErr)
			}
			if got := string(content); got != "public content" {
				t.Errorf("scoped root operation changed content: %q", got)
			}
		})
	}
}

func TestPermissionWebDAVSecurity_LockAndPropertyPermissionMatrix(t *testing.T) {
	for _, tc := range []struct {
		name       string
		method     string
		path       string
		browse     bool
		create     bool
		modify     bool
		headers    map[string]string
		wantAbsent string
	}{
		{name: "LOCK existing requires Browse", method: "LOCK", path: "/public/readme.txt", modify: true},
		{name: "LOCK existing requires Modify", method: "LOCK", path: "/public/readme.txt", browse: true},
		{name: "LOCK missing requires Create", method: "LOCK", path: "/public/missing-lock.txt", browse: true, modify: true, wantAbsent: "missing-lock.txt"},
		{name: "UNLOCK requires Browse", method: "UNLOCK", path: "/public/readme.txt", modify: true, headers: map[string]string{"Lock-Token": "<missing-token>"}},
		{name: "UNLOCK existing requires Modify", method: "UNLOCK", path: "/public/readme.txt", browse: true, headers: map[string]string{"Lock-Token": "<missing-token>"}},
		{name: "PROPPATCH requires Browse", method: "PROPPATCH", path: "/public/readme.txt", modify: true},
		{name: "PROPPATCH requires Modify", method: "PROPPATCH", path: "/public/readme.txt", browse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
			user := permissionWebDAVUser(t, sourcePath, tc.browse, true)
			user.Permissions.Create = tc.create
			user.Permissions.Modify = tc.modify
			status, recorder, err := performPermissionWebDAVRequest(t, user, tc.method, tc.path, "", tc.headers)
			if status != http.StatusForbidden {
				t.Errorf("WebDAV %s status: got %d, want %d (err: %v, body: %q)", tc.method, status, http.StatusForbidden, err, recorder.Body.String())
			}
			if tc.wantAbsent != "" {
				if _, statErr := os.Stat(filepath.Join(sourcePath, "public", tc.wantAbsent)); !os.IsNotExist(statErr) {
					t.Errorf("denied LOCK created resource: %v", statErr)
				}
			}
		})
	}
}

func TestPermissionWebDAVSecurity_LockLifecycleUsesCreateAndModify(t *testing.T) {
	lockBody := `<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner><D:href>permission-test</D:href></D:owner></D:lockinfo>`

	t.Run("existing resource uses Modify and can be unlocked", func(t *testing.T) {
		sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
		user := permissionWebDAVUser(t, sourcePath, true, true)
		user.Permissions.Modify = true
		status, recorder, err := performPermissionWebDAVRequest(t, user, "LOCK", "/public/readme.txt", lockBody, nil)
		if status != http.StatusOK {
			t.Fatalf("LOCK existing status: got %d, want %d (err: %v, body: %q)", status, http.StatusOK, err, recorder.Body.String())
		}
		lockToken := recorder.Header().Get("Lock-Token")
		if lockToken == "" {
			t.Fatal("LOCK existing did not return Lock-Token")
		}
		user.Permissions.Delete = true
		status, recorder, err = performPermissionWebDAVRequest(t, user, http.MethodPut, "/public/readme.txt", "locked update", map[string]string{"If": "(" + lockToken + ")"})
		if status != http.StatusCreated {
			t.Fatalf("PUT with matching lock token: got %d, want %d (err: %v, body: %q)", status, http.StatusCreated, err, recorder.Body.String())
		}
		status, recorder, err = performPermissionWebDAVRequest(t, user, "UNLOCK", "/public/readme.txt", "", map[string]string{"Lock-Token": lockToken})
		if status != http.StatusNoContent {
			t.Errorf("UNLOCK existing status: got %d, want %d (err: %v, body: %q)", status, http.StatusNoContent, err, recorder.Body.String())
		}
	})

	t.Run("missing resource uses Create", func(t *testing.T) {
		sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
		user := permissionWebDAVUser(t, sourcePath, true, true)
		user.Permissions.Create = true
		status, recorder, err := performPermissionWebDAVRequest(t, user, "LOCK", "/public/new-lock-resource.txt", lockBody, nil)
		if status != http.StatusCreated {
			t.Fatalf("LOCK missing status: got %d, want %d (err: %v, body: %q)", status, http.StatusCreated, err, recorder.Body.String())
		}
		if _, statErr := os.Stat(filepath.Join(sourcePath, "public", "new-lock-resource.txt")); statErr != nil {
			t.Errorf("LOCK with Create did not create resource: %v", statErr)
		}
	})
}

func TestPermissionWebDAVSecurity_BrokenAndOutsideSymlinkEntries(t *testing.T) {
	t.Run("DELETE removes a broken link", func(t *testing.T) {
		sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
		linkPath := filepath.Join(sourcePath, "public", "broken-delete-link.txt")
		if err := os.Symlink(filepath.Join(sourcePath, "missing-target.txt"), linkPath); err != nil {
			t.Skipf("WebDAV symlink entry assertions unavailable: %v", err)
		}
		user := permissionWebDAVUser(t, sourcePath, true, true)
		user.Permissions.Delete = true
		status, recorder, err := performPermissionWebDAVRequest(t, user, http.MethodDelete, "/public/broken-delete-link.txt", "", nil)
		if status != http.StatusNoContent {
			t.Fatalf("DELETE broken link status: got %d, want %d (err: %v, body: %q)", status, http.StatusNoContent, err, recorder.Body.String())
		}
		if _, err := os.Lstat(linkPath); !os.IsNotExist(err) {
			t.Errorf("DELETE did not remove broken link: %v", err)
		}
	})

	t.Run("MOVE moves an outside link without touching its target", func(t *testing.T) {
		sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
		outsidePath := filepath.Join(t.TempDir(), "outside-move-target.txt")
		if err := os.WriteFile(outsidePath, []byte("outside target must survive"), 0o644); err != nil {
			t.Fatal(err)
		}
		linkPath := filepath.Join(sourcePath, "public", "outside-move-link.txt")
		movedPath := filepath.Join(sourcePath, "public", "outside-moved-link.txt")
		if err := os.Symlink(outsidePath, linkPath); err != nil {
			t.Skipf("WebDAV symlink entry assertions unavailable: %v", err)
		}
		user := permissionWebDAVUser(t, sourcePath, true, true)
		user.Permissions.Create = true
		user.Permissions.Modify = true
		status, recorder, err := performPermissionWebDAVRequest(t, user, "MOVE", "/public/outside-move-link.txt", "", map[string]string{
			"Destination": "http://example.com/dav/source1/public/outside-moved-link.txt",
			"Overwrite":   "F",
		})
		if status != http.StatusCreated {
			t.Fatalf("MOVE outside link status: got %d, want %d (err: %v, body: %q)", status, http.StatusCreated, err, recorder.Body.String())
		}
		if info, err := os.Lstat(movedPath); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Errorf("MOVE did not preserve symlink entry: info=%v err=%v", info, err)
		}
		if content, err := os.ReadFile(outsidePath); err != nil || string(content) != "outside target must survive" {
			t.Errorf("MOVE changed outside target: content=%q err=%v", content, err)
		}
	})

	t.Run("COPY overwrite replaces an outside link without touching its target", func(t *testing.T) {
		sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
		outsidePath := filepath.Join(t.TempDir(), "outside-copy-target.txt")
		if err := os.WriteFile(outsidePath, []byte("outside target must survive"), 0o644); err != nil {
			t.Fatal(err)
		}
		linkPath := filepath.Join(sourcePath, "public", "outside-copy-link.txt")
		if err := os.Symlink(outsidePath, linkPath); err != nil {
			t.Skipf("WebDAV symlink entry assertions unavailable: %v", err)
		}
		user := permissionWebDAVUser(t, sourcePath, true, true)
		user.Permissions.Modify = true
		user.Permissions.Delete = true
		status, recorder, err := performPermissionWebDAVRequest(t, user, "COPY", "/public/readme.txt", "", map[string]string{
			"Destination": "http://example.com/dav/source1/public/outside-copy-link.txt",
			"Overwrite":   "T",
		})
		if status != http.StatusNoContent {
			t.Fatalf("COPY outside link status: got %d, want %d (err: %v, body: %q)", status, http.StatusNoContent, err, recorder.Body.String())
		}
		if content, err := os.ReadFile(outsidePath); err != nil || string(content) != "outside target must survive" {
			t.Errorf("COPY changed outside target: content=%q err=%v", content, err)
		}
		if info, err := os.Lstat(linkPath); err != nil || info.Mode()&os.ModeSymlink != 0 {
			t.Errorf("COPY did not replace link entry: info=%v err=%v", info, err)
		}
	})
}

func TestPermissionWebDAVSecurity_RoutedMissingPathDoesNotExposePhysicalPath(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
	configurePermissionWebDAVAuth(t)
	user := permissionWebDAVUser(t, sourcePath, true, true)
	user.Username = "permission-webdav-missing-path-user"
	savePermissionWebDAVUser(t, user)
	token := issuePermissionReadAPIToken(t, user, "permission-webdav-missing-path", users.Permissions{Browse: true, Download: true})

	for _, method := range []string{http.MethodGet, http.MethodHead, "PROPFIND"} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/dav/source1/public/does-not-exist.txt", nil)
			req.SetBasicAuth("ignored", token)
			if method == "PROPFIND" {
				req.Header.Set("Depth", "0")
			}
			recorder := httptest.NewRecorder()
			permissionWebDAVRouter().ServeHTTP(recorder, req)
			if recorder.Code != http.StatusNotFound {
				t.Errorf("routed missing %s status: got %d, want %d (body: %q)", method, recorder.Code, http.StatusNotFound, recorder.Body.String())
			}
			responseText := recorder.Body.String()
			for name, values := range recorder.Header() {
				responseText += name + "=" + strings.Join(values, ",")
			}
			for _, physicalPath := range []string{sourcePath, filepath.ToSlash(sourcePath), strings.ReplaceAll(sourcePath, `\`, `\\`)} {
				if physicalPath != "" && strings.Contains(responseText, physicalPath) {
					t.Errorf("routed missing %s exposed physical path %q in %q", method, physicalPath, responseText)
				}
			}
		})
	}
}

type permissionWebDAVReadTrapFS struct {
	webdav.FileSystem
}

func (permissionWebDAVReadTrapFS) OpenFile(context.Context, string, int, os.FileMode) (webdav.File, error) {
	panic("authenticated WebDAV reads must not use webdav.Dir.OpenFile")
}

func (permissionWebDAVReadTrapFS) Stat(context.Context, string) (os.FileInfo, error) {
	panic("authenticated WebDAV reads must not use webdav.Dir.Stat")
}

func TestPermissionWebDAVSecurity_ReadsUseStableAuthenticatedHandles(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
	user := permissionWebDAVUser(t, sourcePath, true, true)
	fs := &filteredFileSystem{
		fs:     permissionWebDAVReadTrapFS{},
		source: "source1",
		user:   user,
	}
	file, err := fs.OpenFile(context.Background(), "/public/readme.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	content, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read stable WebDAV handle: readErr=%v closeErr=%v", readErr, closeErr)
	}
	if got := string(content); got != "public content" {
		t.Errorf("stable WebDAV handle content: got %q", got)
	}
	info, err := fs.Stat(context.Background(), "/public/readme.txt")
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != int64(len("public content")) {
		t.Errorf("stable WebDAV Stat size: got %d, want %d", info.Size(), len("public content"))
	}
}

type permissionWebDAVLateCreateFS struct {
	webdav.FileSystem
	realPath string
	content  string
	once     sync.Once
}

func (fs *permissionWebDAVLateCreateFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	var createErr error
	fs.once.Do(func() {
		createErr = os.WriteFile(fs.realPath, []byte(fs.content), 0o644)
	})
	if createErr != nil {
		return nil, createErr
	}
	return fs.FileSystem.OpenFile(ctx, name, flag, perm)
}

type permissionWebDAVOverwriteRenameFS struct {
	webdav.FileSystem
	root string
}

func (fs permissionWebDAVOverwriteRenameFS) Rename(_ context.Context, oldName, newName string) error {
	oldPath := filepath.Join(fs.root, filepath.FromSlash(strings.TrimPrefix(oldName, "/")))
	newPath := filepath.Join(fs.root, filepath.FromSlash(strings.TrimPrefix(newName, "/")))
	if err := os.RemoveAll(newPath); err != nil {
		return err
	}
	return os.Rename(oldPath, newPath)
}

type permissionWebDAVBlockingReader struct {
	reader  *strings.Reader
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *permissionWebDAVBlockingReader) Read(p []byte) (int, error) {
	r.once.Do(func() {
		close(r.started)
		<-r.release
	})
	return r.reader.Read(p)
}

func TestPermissionWebDAVSecurity_WriteTargetStateChangesUseCurrentPermissions(t *testing.T) {
	t.Run("late destination cannot turn Create into overwrite", func(t *testing.T) {
		sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
		destinationPath := filepath.Join(sourcePath, "public", "late-put.txt")
		user := permissionWebDAVUser(t, sourcePath, true, true)
		user.Permissions.Create = true
		lateFS := &permissionWebDAVLateCreateFS{
			FileSystem: webdav.Dir(sourcePath),
			realPath:   destinationPath,
			content:    "late destination must survive",
		}
		fs := &filteredFileSystem{fs: lateFS, source: "source1", user: user}

		file, err := fs.OpenFile(context.Background(), "/public/late-put.txt", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
		if err == nil {
			_ = file.Close()
			t.Error("Create-only WebDAV open overwrote a destination that appeared after authorization")
		}
		content, readErr := os.ReadFile(destinationPath)
		if readErr != nil {
			t.Fatalf("read late destination: %v", readErr)
		}
		if got := string(content); got != "late destination must survive" {
			t.Errorf("late destination was changed: %q", got)
		}
	})

	t.Run("removed destination cannot turn Modify into create", func(t *testing.T) {
		sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
		destinationPath := filepath.Join(sourcePath, "public", "removed-copy.txt")
		if err := os.WriteFile(destinationPath, []byte("destination"), 0o644); err != nil {
			t.Fatal(err)
		}
		user := permissionWebDAVUser(t, sourcePath, true, true)
		user.Permissions.Modify = true
		user.Permissions.Delete = true

		originalCheckPermissions := files.CheckPermissionsFunc
		var removeOnce sync.Once
		files.CheckPermissionsFunc = func(opts utils.FileOptions, accessStorage *access.Storage, currentUser *users.User) (string, string, error) {
			removeOnce.Do(func() {
				if err := os.Remove(destinationPath); err != nil {
					t.Errorf("remove destination during WebDAV state change: %v", err)
				}
			})
			return originalCheckPermissions(opts, accessStorage, currentUser)
		}
		t.Cleanup(func() { files.CheckPermissionsFunc = originalCheckPermissions })

		status, recorder, err := performPermissionWebDAVRequest(t, user, "COPY", "/public/readme.txt", "", map[string]string{
			"Destination": "http://example.com/dav/source1/public/removed-copy.txt",
			"Overwrite":   "T",
		})
		if status != http.StatusForbidden {
			t.Errorf("COPY after destination removal: got %d, want %d (err: %v, body: %q)", status, http.StatusForbidden, err, recorder.Body.String())
		}
		if _, statErr := os.Stat(destinationPath); !os.IsNotExist(statErr) {
			t.Errorf("Modify-only COPY recreated a destination without Create: %v", statErr)
		}
	})

	t.Run("truncating an existing target rechecks Delete", func(t *testing.T) {
		sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
		destinationPath := filepath.Join(sourcePath, "public", "truncate-target.txt")
		if err := os.WriteFile(destinationPath, []byte("target must survive"), 0o644); err != nil {
			t.Fatal(err)
		}
		user := permissionWebDAVUser(t, sourcePath, true, true)
		user.Permissions.Modify = true
		fs := &filteredFileSystem{fs: webdav.Dir(sourcePath), source: "source1", user: user}

		file, err := fs.OpenFile(context.Background(), "/public/truncate-target.txt", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
		if err == nil {
			_ = file.Close()
			t.Error("WebDAV truncate succeeded without Delete")
		}
		content, readErr := os.ReadFile(destinationPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if got := string(content); got != "target must survive" {
			t.Errorf("target changed after denied truncate: %q", got)
		}
	})

	t.Run("renaming over an existing target rechecks Delete", func(t *testing.T) {
		sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
		sourceFile := filepath.Join(sourcePath, "public", "rename-source.txt")
		destinationPath := filepath.Join(sourcePath, "public", "rename-target.txt")
		if err := os.WriteFile(sourceFile, []byte("source"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destinationPath, []byte("target must survive"), 0o644); err != nil {
			t.Fatal(err)
		}
		user := permissionWebDAVUser(t, sourcePath, true, true)
		user.Permissions.Modify = true
		fs := &filteredFileSystem{
			fs: permissionWebDAVOverwriteRenameFS{
				FileSystem: webdav.Dir(sourcePath),
				root:       sourcePath,
			},
			source: "source1",
			user:   user,
		}

		err := fs.Rename(context.Background(), "/public/rename-source.txt", "/public/rename-target.txt")
		if err == nil {
			t.Error("WebDAV rename overwrote a destination without Delete")
		}
		content, readErr := os.ReadFile(destinationPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if got := string(content); got != "target must survive" {
			t.Errorf("target changed after denied rename: %q", got)
		}
	})

	t.Run("LOCK body delay cannot turn Create into Modify", func(t *testing.T) {
		sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
		destinationPath := filepath.Join(sourcePath, "public", "late-lock.txt")
		user := permissionWebDAVUser(t, sourcePath, true, true)
		user.Permissions.Create = true
		body := &permissionWebDAVBlockingReader{
			reader:  strings.NewReader(`<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner><D:href>permission-test</D:href></D:owner></D:lockinfo>`),
			started: make(chan struct{}),
			release: make(chan struct{}),
		}
		req := httptest.NewRequest("LOCK", "/dav/source1/public/late-lock.txt", body)
		req.SetPathValue("source", "source1")
		req.SetPathValue("path", "/public/late-lock.txt")
		recorder := httptest.NewRecorder()
		type handlerResult struct {
			status int
			err    error
		}
		result := make(chan handlerResult, 1)
		go func() {
			returned, err := webDAVHandler(recorder, req, &requestContext{user: user})
			result <- handlerResult{status: permissionHandlerStatus(returned, recorder), err: err}
		}()

		<-body.started
		if err := os.WriteFile(destinationPath, []byte("late lock target"), 0o644); err != nil {
			t.Fatal(err)
		}
		close(body.release)
		select {
		case got := <-result:
			if got.status >= 200 && got.status < 300 {
				t.Errorf("LOCK used stale Create permission after target appeared: status=%d err=%v", got.status, got.err)
			}
			if token := recorder.Header().Get("Lock-Token"); token != "" {
				t.Errorf("denied late LOCK returned token %q", token)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for delayed LOCK")
		}
	})
}

const permissionWebDAVSecurityLockBody = `<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner><D:href>permission-test</D:href></D:owner></D:lockinfo>`

func TestPermissionWebDAVSecurity_LockTokenMustMatchAuthorizedPath(t *testing.T) {
	t.Run("UNLOCK rejects a token from another path", func(t *testing.T) {
		sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
		user := permissionWebDAVUser(t, sourcePath, true, true)
		user.Permissions.Modify = true

		status, recorder, err := performPermissionWebDAVRequest(t, user, "LOCK", "/public/readme.txt", permissionWebDAVSecurityLockBody, nil)
		if status != http.StatusOK {
			t.Fatalf("create source lock: got %d, want %d (err: %v, body: %q)", status, http.StatusOK, err, recorder.Body.String())
		}
		lockToken := recorder.Header().Get("Lock-Token")
		if lockToken == "" {
			t.Fatal("source LOCK did not return a token")
		}

		user.Permissions.Modify = false
		user.Permissions.Create = true
		status, recorder, err = performPermissionWebDAVRequest(t, user, "UNLOCK", "/public/other-missing.txt", "", map[string]string{"Lock-Token": lockToken})
		if status != http.StatusForbidden {
			t.Errorf("mismatched UNLOCK: got %d, want %d (err: %v, body: %q)", status, http.StatusForbidden, err, recorder.Body.String())
		}

		user.Permissions.Modify = true
		user.Permissions.Delete = true
		status, recorder, err = performPermissionWebDAVRequest(t, user, http.MethodPut, "/public/readme.txt", "lock must survive", nil)
		if status != webdav.StatusLocked {
			t.Errorf("mismatched UNLOCK removed source lock: PUT got %d, want %d (err: %v, body: %q)", status, webdav.StatusLocked, err, recorder.Body.String())
		}
	})

	t.Run("LOCK refresh rejects a token from another path", func(t *testing.T) {
		sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
		user := permissionWebDAVUser(t, sourcePath, true, true)
		user.Permissions.Modify = true

		status, recorder, err := performPermissionWebDAVRequest(t, user, "LOCK", "/public/readme.txt", permissionWebDAVSecurityLockBody, nil)
		if status != http.StatusOK {
			t.Fatalf("create source lock: got %d, want %d (err: %v, body: %q)", status, http.StatusOK, err, recorder.Body.String())
		}
		lockToken := recorder.Header().Get("Lock-Token")
		if lockToken == "" {
			t.Fatal("source LOCK did not return a token")
		}

		user.Permissions.Modify = false
		user.Permissions.Create = true
		status, recorder, err = performPermissionWebDAVRequest(t, user, "LOCK", "/public/other-missing.txt", "", map[string]string{"If": "(" + lockToken + ")"})
		if status != http.StatusPreconditionFailed {
			t.Errorf("mismatched LOCK refresh: got %d, want %d (err: %v, body: %q)", status, http.StatusPreconditionFailed, err, recorder.Body.String())
		}
		if body := recorder.Body.String(); strings.Contains(body, "/public/readme.txt") || strings.Contains(body, "permission-test") {
			t.Errorf("mismatched LOCK refresh leaked source lock metadata %q", body)
		}

		user.Permissions.Modify = true
		user.Permissions.Delete = true
		status, recorder, err = performPermissionWebDAVRequest(t, user, http.MethodPut, "/public/readme.txt", "lock must survive", nil)
		if status != webdav.StatusLocked {
			t.Errorf("mismatched LOCK refresh changed source lock: PUT got %d, want %d (err: %v, body: %q)", status, webdav.StatusLocked, err, recorder.Body.String())
		}
	})
}

func TestPermissionWebDAVSecurity_LockNamespaceUsesAuthenticatedIdentity(t *testing.T) {
	t.Run("different scopes do not share relative lock names", func(t *testing.T) {
		sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
		for scope, content := range map[string]string{
			"scope-a": "scope a content",
			"scope-b": "scope b content",
		} {
			directory := filepath.Join(sourcePath, scope)
			if err := os.MkdirAll(directory, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "same.txt"), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}

		userA := permissionWebDAVUser(t, sourcePath, true, true)
		userA.Username = "permission-webdav-scope-a"
		userA.Scopes[0].Scope = "/scope-a"
		userA.Permissions.Modify = true
		status, recorder, err := performPermissionWebDAVRequest(t, userA, "LOCK", "/same.txt", permissionWebDAVSecurityLockBody, nil)
		if status != http.StatusOK {
			t.Fatalf("LOCK scope A: got %d, want %d (err: %v, body: %q)", status, http.StatusOK, err, recorder.Body.String())
		}

		userB := permissionWebDAVUser(t, sourcePath, true, true)
		userB.Username = "permission-webdav-scope-b"
		userB.Scopes[0].Scope = "/scope-b"
		userB.Permissions.Modify = true
		userB.Permissions.Delete = true
		status, recorder, err = performPermissionWebDAVRequest(t, userB, http.MethodPut, "/same.txt", "scope b updated", nil)
		if status != http.StatusCreated {
			t.Errorf("scope B PUT collided with scope A lock: got %d, want %d (err: %v, body: %q)", status, http.StatusCreated, err, recorder.Body.String())
		}
		if content, readErr := os.ReadFile(filepath.Join(sourcePath, "scope-a", "same.txt")); readErr != nil || string(content) != "scope a content" {
			t.Errorf("scope A content changed: content=%q err=%v", content, readErr)
		}
		if content, readErr := os.ReadFile(filepath.Join(sourcePath, "scope-b", "same.txt")); readErr != nil || string(content) != "scope b updated" {
			t.Errorf("scope B content was not updated: content=%q err=%v", content, readErr)
		}
	})

	t.Run("case aliases of one file share a lock", func(t *testing.T) {
		sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
		canonicalPath := filepath.Join(sourcePath, "public", "readme.txt")
		aliasPath := filepath.Join(sourcePath, "PUBLIC", "README.TXT")
		canonicalInfo, err := os.Stat(canonicalPath)
		if err != nil {
			t.Fatal(err)
		}
		aliasInfo, err := os.Stat(aliasPath)
		if err != nil || !os.SameFile(canonicalInfo, aliasInfo) {
			t.Skip("filesystem does not provide case aliases")
		}

		user := permissionWebDAVUser(t, sourcePath, true, true)
		user.Permissions.Modify = true
		user.Permissions.Delete = true
		status, recorder, err := performPermissionWebDAVRequest(t, user, "LOCK", "/public/readme.txt", permissionWebDAVSecurityLockBody, nil)
		if status != http.StatusOK {
			t.Fatalf("LOCK canonical path: got %d, want %d (err: %v, body: %q)", status, http.StatusOK, err, recorder.Body.String())
		}

		status, recorder, err = performPermissionWebDAVRequest(t, user, http.MethodPut, "/PUBLIC/README.TXT", "must remain locked", nil)
		if status != webdav.StatusLocked {
			t.Errorf("case-alias PUT bypassed lock: got %d, want %d (err: %v, body: %q)", status, webdav.StatusLocked, err, recorder.Body.String())
		}
		if content, readErr := os.ReadFile(canonicalPath); readErr != nil || string(content) != "public content" {
			t.Errorf("locked content changed: content=%q err=%v", content, readErr)
		}
	})

	t.Run("directory aliases share a depth lock with the canonical target", func(t *testing.T) {
		sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
		canonicalDirectory := filepath.Join(sourcePath, "public", "canonical-lock-directory")
		if err := os.MkdirAll(canonicalDirectory, 0o755); err != nil {
			t.Fatal(err)
		}
		aliasDirectory := filepath.Join(sourcePath, "public", "lock-directory-alias")
		if err := os.Symlink(canonicalDirectory, aliasDirectory); err != nil {
			t.Skipf("directory alias lock assertions unavailable: %v", err)
		}

		user := permissionWebDAVUser(t, sourcePath, true, true)
		user.Permissions.Create = true
		user.Permissions.Modify = true
		status, recorder, err := performPermissionWebDAVRequest(t, user, "LOCK", "/public/lock-directory-alias", permissionWebDAVSecurityLockBody, nil)
		if status != http.StatusOK {
			t.Fatalf("LOCK directory alias: got %d, want %d (err: %v, body: %q)", status, http.StatusOK, err, recorder.Body.String())
		}

		status, recorder, err = performPermissionWebDAVRequest(t, user, http.MethodPut, "/public/canonical-lock-directory/blocked.txt", "must remain locked", nil)
		if status != webdav.StatusLocked {
			t.Errorf("canonical child PUT bypassed alias depth lock: got %d, want %d (err: %v, body: %q)", status, webdav.StatusLocked, err, recorder.Body.String())
		}
		if _, statErr := os.Stat(filepath.Join(canonicalDirectory, "blocked.txt")); !os.IsNotExist(statErr) {
			t.Errorf("alias depth lock allowed canonical child creation: %v", statErr)
		}
	})
}

func TestPermissionWebDAVSecurity_LockIdentityIncludesSource(t *testing.T) {
	source1Path, source2Path := setupPermissionWebDAVSecurityEnv(t)
	const name = "same-lock-name.txt"
	for _, sourcePath := range []string{source1Path, source2Path} {
		if err := os.WriteFile(filepath.Join(sourcePath, name), []byte(sourcePath), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	user := permissionWebDAVUser(t, source1Path, true, true)
	user.Scopes = append(user.Scopes, users.SourceScope{Name: source2Path, Scope: "/"})

	first, err := resolveAuthenticatedWebDAVLockName(user, "source1", "/"+name)
	if err != nil {
		t.Fatalf("resolve source1 lock identity: %v", err)
	}
	second, err := resolveAuthenticatedWebDAVLockName(user, "source2", "/"+name)
	if err != nil {
		t.Fatalf("resolve source2 lock identity: %v", err)
	}
	if first == second {
		t.Fatalf("different sources produced the same lock identity %q", first)
	}
}

func TestPermissionWebDAVSecurity_LockConfirmationRejectsAnotherSourceToken(t *testing.T) {
	source1Path, source2Path := setupPermissionWebDAVSecurityEnv(t)
	user := permissionWebDAVUser(t, source1Path, true, true)
	user.Scopes = append(user.Scopes, users.SourceScope{Name: source2Path, Scope: "/"})
	user.Permissions.Modify = true
	user.Permissions.Delete = true

	request := func(source, method, requestPath, body string, headers map[string]string) (int, *httptest.ResponseRecorder, error) {
		req := httptest.NewRequest(method, "/dav/"+source+requestPath, strings.NewReader(body))
		req.SetPathValue("source", source)
		req.SetPathValue("path", requestPath)
		for name, value := range headers {
			req.Header.Set(name, value)
		}
		recorder := httptest.NewRecorder()
		returned, err := webDAVHandler(recorder, req, &requestContext{user: user})
		return permissionHandlerStatus(returned, recorder), recorder, err
	}

	lock := func(source, requestPath string) string {
		t.Helper()
		status, recorder, err := request(source, "LOCK", requestPath, permissionWebDAVSecurityLockBody, nil)
		if status != http.StatusOK {
			t.Fatalf("LOCK %s%s: got %d, want %d (err: %v, body: %q)", source, requestPath, status, http.StatusOK, err, recorder.Body.String())
		}
		token := recorder.Header().Get("Lock-Token")
		if token == "" {
			t.Fatalf("LOCK %s%s did not return a token", source, requestPath)
		}
		return token
	}

	source1Token := lock("source1", "/public/readme.txt")
	source2Token := lock("source2", "/shared/document.txt")
	_, source1Raw, err := decodeAuthenticatedWebDAVLockToken(strings.Trim(source1Token, "<>"))
	if err != nil {
		t.Fatal(err)
	}
	_, source2Raw, err := decodeAuthenticatedWebDAVLockToken(strings.Trim(source2Token, "<>"))
	if err != nil {
		t.Fatal(err)
	}
	if source1Raw != source2Raw {
		t.Fatalf("test did not create the required cross-source raw token collision: source1=%q source2=%q", source1Raw, source2Raw)
	}

	status, recorder, err := request("source2", http.MethodPut, "/shared/document.txt", "must not cross source locks", map[string]string{
		"If": "(" + source1Token + ")",
	})
	if status >= 200 && status < 300 {
		t.Fatalf("source1 lock token confirmed source2 lock: got %d (err: %v, body: %q)", status, err, recorder.Body.String())
	}
	content, readErr := os.ReadFile(filepath.Join(source2Path, "shared", "document.txt"))
	if readErr != nil || string(content) != "shared content" {
		t.Fatalf("cross-source lock confirmation changed source2: content=%q err=%v", content, readErr)
	}

	status, recorder, err = request("source2", http.MethodPut, "/shared/document.txt", "matching source2 lock", map[string]string{
		"If": "(" + source2Token + ")",
	})
	if status < 200 || status >= 300 {
		t.Fatalf("matching source2 lock token was rejected: got %d (err: %v, body: %q)", status, err, recorder.Body.String())
	}
}

type permissionWebDAVLateRenameTargetFS struct {
	webdav.FileSystem
	root string
}

func (fs permissionWebDAVLateRenameTargetFS) Rename(ctx context.Context, oldName, newName string) error {
	newPath := filepath.Join(fs.root, filepath.FromSlash(strings.TrimPrefix(newName, "/")))
	if err := os.WriteFile(newPath, []byte("late destination must survive"), 0o644); err != nil {
		return err
	}
	return fs.FileSystem.Rename(ctx, oldName, newName)
}

func (fs permissionWebDAVLateRenameTargetFS) RenameNoReplace(_ context.Context, oldName, newName string) error {
	oldPath := filepath.Join(fs.root, filepath.FromSlash(strings.TrimPrefix(oldName, "/")))
	newPath := filepath.Join(fs.root, filepath.FromSlash(strings.TrimPrefix(newName, "/")))
	if err := os.WriteFile(newPath, []byte("late destination must survive"), 0o644); err != nil {
		return err
	}
	return renameWebDAVNoReplace(oldPath, newPath)
}

func TestPermissionWebDAVSecurity_MOVELateDestinationRequiresDelete(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
	sourceFile := filepath.Join(sourcePath, "public", "late-move-source.txt")
	destinationFile := filepath.Join(sourcePath, "public", "late-move-destination.txt")
	if err := os.WriteFile(sourceFile, []byte("source must survive"), 0o644); err != nil {
		t.Fatal(err)
	}
	user := permissionWebDAVUser(t, sourcePath, true, true)
	user.Permissions.Create = true
	user.Permissions.Modify = true
	fs := &filteredFileSystem{
		fs: permissionWebDAVLateRenameTargetFS{
			FileSystem: webdav.Dir(sourcePath),
			root:       sourcePath,
		},
		source: "source1",
		user:   user,
	}

	err := fs.Rename(context.Background(), "/public/late-move-source.txt", "/public/late-move-destination.txt")
	if err == nil {
		t.Error("MOVE overwrote a destination that appeared after authorization without Delete")
	}
	if content, readErr := os.ReadFile(sourceFile); readErr != nil || string(content) != "source must survive" {
		t.Errorf("denied MOVE changed source: content=%q err=%v", content, readErr)
	}
	if content, readErr := os.ReadFile(destinationFile); readErr != nil || string(content) != "late destination must survive" {
		t.Errorf("denied MOVE changed late destination: content=%q err=%v", content, readErr)
	}
}
