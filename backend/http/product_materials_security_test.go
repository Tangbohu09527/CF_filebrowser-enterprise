package http

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func productSecurityRoute(t *testing.T, token string, req productRequest) (*httptest.ResponseRecorder, *auditStoreStub) {
	t.Helper()
	events := newAuditStoreStub()
	handler := newCoreFileAuditRouter(events)
	response := coreFileAuditRequest(t, handler, token, http.MethodPost, "/api/resources/products", nil, coreFileAuditJSONBody(t, req), nil)
	return response, events
}

func productSecurityAllow(t *testing.T, username string) {
	t.Helper()
	previous := config.Server.ProductMaterialsUsers
	config.Server.ProductMaterialsUsers = []string{username}
	t.Cleanup(func() { config.Server.ProductMaterialsUsers = previous })
}

func productSecurityInput(t *testing.T, source string, u *users.User, name string) productRequest {
	t.Helper()
	productTestZip(t, filepath.Join(source, "public", name), map[string][]byte{"main/中文 原图 (1).jpg": []byte("first immutable image bytes"), "detail/详情.png": []byte("second immutable image bytes")})
	req := productRequest{Action: "inspect", Source: "source1", Path: "/public/" + name}
	status, data, err := productTestRequest(t, u, req)
	requireArchivePermissionStatus(t, status, err, http.StatusOK)
	var result struct {
		SHA256  string          `json:"sha256"`
		Members []productMember `json:"manifest"`
	}
	if err = json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	req.Action = "import"
	req.SHA256 = result.SHA256
	req.Members = result.Members
	req.Destination = "/public/products"
	req.Brand = "品牌"
	req.Product = "小米"
	req.Specification = "500g"
	req.Version = "v1"
	for i := range req.Members {
		req.Members[i].Category = "main"
		req.Members[i].Evidence = "explicit test classification"
	}
	return req
}

func TestProductMaterialsSecurityRealRouteAndAudit(t *testing.T) {
	source := setupResourcePutTestEnv(t)
	configurePermissionReadAuth(t)
	perms := users.Permissions{Api: true, Browse: true, Download: true, Create: true}
	u := archivePermissionUser(source, "product-real-route", perms)
	savePermissionReadUser(t, u)
	productSecurityAllow(t, u.Username)
	token := issuePermissionReadAPIToken(t, u, "product-route-token", perms)
	req := productSecurityInput(t, source, u, "真实 原包.zip")
	inspect := req
	inspect.Action = "inspect"
	response, events := productSecurityRoute(t, token, inspect)
	requireCoreFileAuditStatus(t, response, http.StatusOK)
	event := requireCoreFileAuditReadEvent(t, events)
	requireCoreFileAuditEvent(t, event, auditdb.ActionFileBrowse, auditdb.ResultSuccess, http.StatusOK, "source1", req.Path)
	requireCoreFileAuditAPIToken(t, event, u, perms, token)
	response, events = productSecurityRoute(t, token, req)
	requireCoreFileAuditStatus(t, response, http.StatusOK)
	event = requireCoreFileAuditWriteEvent(t, events)
	destination := path.Join(req.Destination, req.Brand, req.Product, req.Specification, req.Version)
	requireCoreFileAuditEvent(t, event, auditdb.ActionArchiveExtract, auditdb.ResultSuccess, http.StatusOK, "source1", destination)
	requireCoreFileAuditAPIToken(t, event, u, perms, token)
	export := productRequest{Action: "export", Source: "source1", Path: destination, Destination: "/public/exports", Name: "商品 中文 (1).zip", Categories: []string{"main"}}
	response, events = productSecurityRoute(t, token, export)
	requireCoreFileAuditStatus(t, response, http.StatusOK)
	event = requireCoreFileAuditWriteEvent(t, events)
	requireCoreFileAuditEvent(t, event, auditdb.ActionArchiveCreate, auditdb.ResultSuccess, http.StatusOK, "source1", "/public/exports/商品 中文 (1).zip")
}

func TestProductMaterialsSecurityTokenIntersectionAndCurrentScope(t *testing.T) {
	source := setupResourcePutTestEnv(t)
	configurePermissionReadAuth(t)
	perms := users.Permissions{Api: true, Browse: true, Download: true, Create: true}
	u := archivePermissionUser(source, "product-token-user", perms)
	savePermissionReadUser(t, u)
	productSecurityAllow(t, u.Username)
	req := productSecurityInput(t, source, u, "input.zip")
	readPerms := perms
	readPerms.Create = false
	restricted := issuePermissionReadAPIToken(t, u, "read-no-create", readPerms)
	response, _ := productSecurityRoute(t, restricted, req)
	requireCoreFileAuditStatus(t, response, http.StatusForbidden)
	if _, err := os.Stat(filepath.Join(source, "public", "products")); !os.IsNotExist(err) {
		t.Fatalf("denied token wrote destination: %v", err)
	}
	full := issuePermissionReadAPIToken(t, u, "original-scope", perms)
	if err := os.Mkdir(filepath.Join(source, "other"), 0755); err != nil {
		t.Fatal(err)
	}
	u.Scopes = []users.SourceScope{{Name: source, Scope: "/other"}}
	if err := store.Users.Update(u, true, "Scopes"); err != nil {
		t.Fatal(err)
	}
	inspect := req
	inspect.Action = "inspect"
	response, _ = productSecurityRoute(t, full, inspect)
	if response.Code == http.StatusOK {
		t.Fatalf("stale token bypassed current scope: %s", response.Body.String())
	}
	u.Scopes = []users.SourceScope{{Name: source, Scope: "/"}}
	if err := store.Users.Update(u, true, "Scopes"); err != nil {
		t.Fatal(err)
	}
	u.Permissions.Download = false
	if err := store.Users.Update(u, true, "Permissions"); err != nil {
		t.Fatal(err)
	}
	response, _ = productSecurityRoute(t, full, inspect)
	requireCoreFileAuditStatus(t, response, http.StatusForbidden)
}

func TestProductMaterialsSecurityUnknownDirectoryAndPendingResume(t *testing.T) {
	source := setupResourcePutTestEnv(t)
	u := archivePermissionUser(source, "product-resume", users.Permissions{Api: true, Browse: true, Download: true, Create: true})
	req := productSecurityInput(t, source, u, "input.zip")
	destination := path.Join(req.Destination, req.Brand, req.Product, req.Specification, req.Version)
	local := filepath.Join(source, filepath.FromSlash(strings.TrimPrefix(destination, "/")))
	if err := os.MkdirAll(local, 0755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(local, "employee-note.txt")
	if err := os.WriteFile(sentinel, []byte("employee original"), 0644); err != nil {
		t.Fatal(err)
	}
	status, _, err := productTestRequest(t, u, req)
	requireArchivePermissionStatus(t, status, err, http.StatusConflict)
	names, err := os.ReadDir(local)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0].Name() != "employee-note.txt" {
		t.Fatal("unknown version was merged")
	}
	req.Version = "new-version"
	status, data, err := productTestRequest(t, u, req)
	requireArchivePermissionStatus(t, status, err, http.StatusOK)
	var manifest productManifest
	if err = json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	// Simulate a stopped publication in isolated test files: intent and original
	// remain, one member and completion marker are absent. No production paths.
	versionRoot := filepath.Join(source, filepath.FromSlash(strings.TrimPrefix(manifest.Path, "/")))
	if err = os.Remove(filepath.Join(versionRoot, productManifestName)); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(source, filepath.FromSlash(strings.TrimPrefix(manifest.Members[0].StoredPath, "/")))
	if err = os.Remove(missing); err != nil {
		t.Fatal(err)
	}
	productLocks = sync.Map{} // A fresh process has no in-memory version reservation.
	status, resumed, err := productTestRequest(t, u, req)
	requireArchivePermissionStatus(t, status, err, http.StatusOK)
	if !bytes.Equal(data, resumed) {
		t.Fatal("pending resume manifest changed")
	}
	for _, member := range manifest.Members {
		localFile := filepath.Join(source, filepath.FromSlash(strings.TrimPrefix(member.StoredPath, "/")))
		digest, size, err := productFileHash(localFile, productMemberLimit)
		if err != nil || digest != member.SHA256 || size != member.Size {
			t.Fatalf("resumed member mismatch %s: %v", member.Path, err)
		}
	}
}

func TestProductMaterialsSecurityZIPDeclaredBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
		size  uint64
	}{{"too-many", productMemberCount + 1, 1}, {"oversized-member", 1, uint64(productMemberLimit) + 1}} {
		t.Run(tc.name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "bounded.zip")
			f, err := os.Create(filename)
			if err != nil {
				t.Fatal(err)
			}
			writer := zip.NewWriter(f)
			for i := 0; i < tc.count; i++ {
				header := &zip.FileHeader{Name: strings.Repeat("a", i+1) + ".jpg", Method: zip.Store, UncompressedSize64: tc.size, CompressedSize64: tc.size}
				header.SetMode(0644)
				entry, err := writer.CreateRaw(header)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = entry.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
			}
			if err = writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = inspectProductZip(filename); err == nil {
				t.Fatal("declared ZIP bound bypassed")
			}
		})
	}
}

func TestProductMaterialsSecurityDefaultOffAndWrongUser(t *testing.T) {
	source := setupResourcePutTestEnv(t)
	configurePermissionReadAuth(t)
	perms := users.Permissions{Api: true, Browse: true, Download: true, Create: true}
	u := archivePermissionUser(source, "not-product-operator", perms)
	savePermissionReadUser(t, u)
	token := issuePermissionReadAPIToken(t, u, "product-default-off", perms)
	req := productSecurityInput(t, source, u, "restricted.zip")
	req.Action = "inspect"
	for _, allowed := range [][]string{nil, {"some-other-operator"}} {
		previous := config.Server.ProductMaterialsUsers
		config.Server.ProductMaterialsUsers = allowed
		response, _ := productSecurityRoute(t, token, req)
		config.Server.ProductMaterialsUsers = previous
		requireCoreFileAuditStatus(t, response, http.StatusForbidden)
	}
}
