package http

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func productTestZip(t *testing.T, filename string, entries map[string][]byte) {
	t.Helper()
	f, e := os.Create(filename)
	if e != nil {
		t.Fatal(e)
	}
	z := zip.NewWriter(f)
	for name, data := range entries {
		w, createErr := z.Create(name)
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, e = w.Write(data); e != nil {
			t.Fatal(e)
		}
	}
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
}
func productTestRequest(t *testing.T, u *users.User, req productRequest) (int, []byte, error) {
	t.Helper()
	previousUsers := config.Server.ProductMaterialsUsers
	config.Server.ProductMaterialsUsers = []string{u.Username}
	defer func() { config.Server.ProductMaterialsUsers = previousUsers }()
	b, e := json.Marshal(req)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/resources/products", bytes.NewReader(b))
	w := httptest.NewRecorder()
	status, e := productMaterialsHandler(w, r, &requestContext{user: u})
	return permissionHandlerStatus(status, w), w.Body.Bytes(), e
}
func TestProductMaterialsFullHTTPWorkflow(t *testing.T) {
	source := setupResourcePutTestEnv(t)
	u := archivePermissionUser(source, "product-normal-user", users.Permissions{Api: true, Browse: true, Download: true, Create: true})
	archive := filepath.Join(source, "public", "中文 产品 (1).zip")
	original := map[string][]byte{"主图/原图 (1).jpg": []byte("main product actual bytes"), "详情/详情 二.png": []byte("detail actual bytes")}
	productTestZip(t, archive, original)
	req := productRequest{Action: "inspect", Source: "source1", Path: "/public/中文 产品 (1).zip"}
	status, data, e := productTestRequest(t, u, req)
	requireArchivePermissionStatus(t, status, e, http.StatusOK)
	var inspected struct {
		SHA256   string          `json:"sha256"`
		Manifest []productMember `json:"manifest"`
	}
	if e = json.Unmarshal(data, &inspected); e != nil {
		t.Fatal(e)
	}
	if len(inspected.Manifest) != 2 {
		t.Fatalf("manifest: %s", data)
	}
	req.Action = "import"
	req.SHA256 = inspected.SHA256
	req.Destination = "/public/商品资料"
	req.Brand = "品牌"
	req.Product = "米脂小米"
	req.Specification = "500g"
	req.Version = "20261018"
	req.Members = inspected.Manifest
	for i := range req.Members {
		req.Members[i].Category = "detail"
		if strings.HasPrefix(req.Members[i].Path, "主图") {
			req.Members[i].Category = "main"
		}
		req.Members[i].Evidence = "explicit user category and verified image content"
	}
	status, data, e = productTestRequest(t, u, req)
	requireArchivePermissionStatus(t, status, e, http.StatusOK)
	var manifest productManifest
	if e = json.Unmarshal(data, &manifest); e != nil {
		t.Fatal(e)
	}
	if manifest.State != "complete" {
		t.Fatal(string(data))
	}
	for _, m := range manifest.Members {
		stored, readErr := os.ReadFile(filepath.Join(source, filepath.FromSlash(strings.TrimPrefix(m.StoredPath, "/"))))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(stored, original[m.Path]) {
			t.Fatal("member bytes changed")
		}
	}
	// Identical retry is idempotent; it never creates a second version.
	status, again, e := productTestRequest(t, u, req)
	requireArchivePermissionStatus(t, status, e, http.StatusOK)
	if !bytes.Equal(data, again) {
		t.Fatal("idempotent response changed")
	}
	export := productRequest{Action: "export", Source: "source1", Path: manifest.Path, Destination: "/public/exports", Name: "中文 主图和详情 (1).zip", Categories: []string{"main", "detail"}}
	status, data, e = productTestRequest(t, u, export)
	requireArchivePermissionStatus(t, status, e, http.StatusOK)
	status, duplicate, duplicateErr := productTestRequest(t, u, export)
	requireArchivePermissionStatus(t, status, duplicateErr, http.StatusOK)
	if !bytes.Equal(data, duplicate) {
		t.Fatal("repeated frozen export changed ZIP descriptor")
	}
	var result struct {
		Path     string          `json:"path"`
		SHA256   string          `json:"sha256"`
		Manifest []productMember `json:"manifest"`
	}
	if e = json.Unmarshal(data, &result); e != nil {
		t.Fatal(e)
	}
	exported := filepath.Join(source, filepath.FromSlash(strings.TrimPrefix(result.Path, "/")))
	h, _, e := productFileHash(exported, productArchiveLimit)
	if e != nil || h != result.SHA256 {
		t.Fatal("export digest mismatch", e)
	}
	members, e := inspectProductZip(exported)
	if e != nil || len(members) != 2 {
		t.Fatal("export incomplete", e)
	}
	originalHash, _, e := productFileHash(archive, productArchiveLimit)
	if e != nil || originalHash != inspected.SHA256 {
		t.Fatal("original changed")
	}
	// Employee modification is detected, not silently overwritten or exported.
	target := filepath.Join(source, filepath.FromSlash(strings.TrimPrefix(manifest.Members[0].StoredPath, "/")))
	if e = os.WriteFile(target, []byte("employee edited"), 0644); e != nil {
		t.Fatal(e)
	}
	export.Name = "changed.zip"
	status, _, e = productTestRequest(t, u, export)
	if status != http.StatusConflict || e == nil {
		t.Fatalf("changed export allowed: %d %v", status, e)
	}
	status, _, e = productTestRequest(t, u, req)
	if status == http.StatusOK || e == nil {
		t.Fatal("retry overwrote employee change")
	}
}
func TestProductMaterialsRejectsUnsafeZIPBeforePublish(t *testing.T) {
	cases := []struct {
		name  string
		entry string
		mode  fs.FileMode
		data  []byte
	}{
		{"parent", "../escape.jpg", 0644, []byte("x")}, {"absolute", "/absolute.jpg", 0644, []byte("x")},
		{"drive", "C:/drive.jpg", 0644, []byte("x")}, {"backslash", "folder\\file.jpg", 0644, []byte("x")},
		{"link", "image.jpg", fs.ModeSymlink | 0777, []byte("/elsewhere")}, {"fifo", "pipe", fs.ModeNamedPipe | 0644, []byte{}},
		{"expansion", "bomb.txt", 0644, bytes.Repeat([]byte{0}, 2<<20)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, e := os.CreateTemp(t.TempDir(), "test-*.zip")
			if e != nil {
				t.Fatal(e)
			}
			z := zip.NewWriter(f)
			header := &zip.FileHeader{Name: tc.entry, Method: zip.Deflate}
			header.SetMode(tc.mode)
			w, e := z.CreateHeader(header)
			if e != nil {
				t.Fatal(e)
			}
			_, _ = w.Write(tc.data)
			_ = z.Close()
			_ = f.Close()
			if _, e = inspectProductZip(f.Name()); e == nil {
				t.Fatal("unsafe ZIP accepted")
			}
		})
	}
	t.Run("duplicate", func(t *testing.T) {
		f, _ := os.CreateTemp(t.TempDir(), "dup*.zip")
		z := zip.NewWriter(f)
		for _, n := range []string{"A.jpg", "a.jpg"} {
			w, _ := z.Create(n)
			_, _ = io.WriteString(w, "x")
		}
		_ = z.Close()
		_ = f.Close()
		if _, e := inspectProductZip(f.Name()); e == nil {
			t.Fatal("case collision accepted")
		}
	})
}
func TestProductMaterialsRequiresCurrentPermissionsAndScope(t *testing.T) {
	source := setupResourcePutTestEnv(t)
	archive := filepath.Join(source, "public", "input.zip")
	productTestZip(t, archive, map[string][]byte{"image.jpg": []byte("bytes")})
	readonly := archivePermissionUser(source, "readonly-product", users.Permissions{Browse: true, Download: true})
	status, _, e := productTestRequest(t, readonly, productRequest{Action: "import", Source: "source1", Path: "/public/input.zip"})
	requireArchivePermissionStatus(t, status, e, http.StatusForbidden)
	denied := archivePermissionUser(source, "denied-product", users.Permissions{Browse: true, Download: true, Create: true})
	savePermissionReadUser(t, denied)
	if e = store.Access.DenyUser(source, "/public/input.zip", denied.Username); e != nil {
		t.Fatal(e)
	}
	status, _, e = productTestRequest(t, denied, productRequest{Action: "inspect", Source: "source1", Path: "/public/input.zip"})
	requireArchivePermissionStatus(t, status, e, http.StatusForbidden)
	status, _, e = productTestRequest(t, readonly, productRequest{Action: "inspect", Source: "ungranted-source", Path: "/public/input.zip"})
	if status == http.StatusOK || e == nil {
		t.Fatal("wrong source allowed")
	}
}
func TestProductMaterialsPublicationNeverReplaces(t *testing.T) {
	source := setupResourcePutTestEnv(t)
	u := archivePermissionUser(source, "publish-product", users.Permissions{Browse: true, Download: true, Create: true})
	old := filepath.Join(source, "public", "same.dat")
	if e := os.WriteFile(old, []byte("employee"), 0644); e != nil {
		t.Fatal(e)
	}
	temp := filepath.Join(t.TempDir(), "derived.dat")
	if e := os.WriteFile(temp, []byte("new bytes"), 0644); e != nil {
		t.Fatal(e)
	}
	digest := sha256.Sum256([]byte("new bytes"))
	e := productPublishLocal(&requestContext{user: u}, "source1", "/public/same.dat", temp, hex.EncodeToString(digest[:]))
	if e == nil {
		t.Fatal("conflicting file replaced")
	}
	b, _ := os.ReadFile(old)
	if string(b) != "employee" {
		t.Fatal("employee file changed")
	}
}
