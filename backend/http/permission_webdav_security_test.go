package http

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/database/users"
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
			assertNoOriginalHeaders(t, recorder.Header())
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
			assertNoOriginalHeaders(t, recorder.Header())
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
				assertNoOriginalHeaders(t, recorder.Header())
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
			assertNoOriginalHeaders(t, recorder.Header())
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
			assertNoOriginalHeaders(t, recorder.Header())
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
	configurePermissionReadAuth(t)
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
			savePermissionReadUser(t, user)

			tokenPermissions := users.Permissions{Download: tc.tokenDownload}
			setFutureReadPermission(t, &tokenPermissions, "Browse", tc.tokenBrowse)
			token := issuePermissionReadAPIToken(t, user, "permission-webdav-token-"+suffix, tokenPermissions)
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
			assertNoOriginalHeaders(t, recorder.Header())
			if strings.Contains(recorder.Body.String(), "public content") {
				t.Errorf("unauthorized WebDAV token leaked original bytes %q", recorder.Body.String())
			}
		})
	}
}

func TestPermissionWebDAVSecurity_TokenPROPFINDUsesBrowsePermission(t *testing.T) {
	sourcePath, _ := setupPermissionWebDAVSecurityEnv(t)
	configurePermissionReadAuth(t)
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
			savePermissionReadUser(t, user)
			tokenPermissions := users.Permissions{Browse: tc.tokenBrowse, Download: tc.tokenDownload}
			token := issuePermissionReadAPIToken(t, user, "permission-webdav-propfind-token-"+suffix, tokenPermissions)

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
	configurePermissionReadAuth(t)

	user := permissionWebDAVUser(t, sourcePath, true, true)
	user.Username = "permission-webdav-routed-head-user"
	savePermissionReadUser(t, user)
	token := issuePermissionReadAPIToken(t, user, "permission-webdav-routed-head-token", users.Permissions{Download: true})

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
			assertNoOriginalHeaders(t, response.Header)
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

	t.Run("existing write permission conjunction still rejects PUT", func(t *testing.T) {
		user := permissionWebDAVUser(t, sourcePath, false, true)
		user.Permissions.Create = true
		user.Permissions.Delete = true
		status, _, err := performPermissionWebDAVRequest(t, user, http.MethodPut, "/public/missing-modify.txt", "must not be written", nil)
		if status != http.StatusForbidden {
			t.Errorf("missing Modify PUT status: expected %d, got %d (err: %v)", http.StatusForbidden, status, err)
		}
		if _, statErr := os.Stat(filepath.Join(sourcePath, "public", "missing-modify.txt")); statErr == nil {
			t.Error("WebDAV PUT wrote a file without the existing write permission conjunction")
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
