package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

// Production uses /wechat-acceptance, not the source root. Keep the public
// request paths relative to that scope throughout the real authenticated route.
func TestProductMaterialsNonRootScopeCompletesAndExports(t *testing.T) {
	source := setupResourcePutTestEnv(t)
	configurePermissionReadAuth(t)
	perms := users.Permissions{Api: true, Browse: true, Download: true, Create: true}
	user := archivePermissionUser(source, "product-non-root", perms)
	user.Scopes = []users.SourceScope{{Name: source, Scope: "/public"}}
	savePermissionReadUser(t, user)
	productSecurityAllow(t, user.Username)
	token := issuePermissionReadAPIToken(t, user, "non-root-product", perms)
	filename := filepath.Join(source, "public", "完整商品 (1).zip")
	productTestZip(t, filename, map[string][]byte{"主图/中文 (1).jpg": []byte("independent image bytes")})
	request := productRequest{Action: "inspect", Source: "source1", Path: "/完整商品 (1).zip"}
	response, _ := productSecurityRoute(t, token, request)
	requireCoreFileAuditStatus(t, response, http.StatusOK)
	var inspected struct {
		SHA256   string          `json:"sha256"`
		Manifest []productMember `json:"manifest"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &inspected); err != nil {
		t.Fatal(err)
	}
	request.Action, request.SHA256, request.Destination = "import", inspected.SHA256, "/products"
	request.Brand, request.Product, request.Specification, request.Version = "品牌", "小米", "1kg", "v1"
	request.Members = inspected.Manifest
	request.Members[0].Category, request.Members[0].Evidence = "main", "explicit actual image fixture evidence"
	response, _ = productSecurityRoute(t, token, request)
	requireCoreFileAuditStatus(t, response, http.StatusOK)
	var imported productManifest
	if err := json.Unmarshal(response.Body.Bytes(), &imported); err != nil {
		t.Fatal(err)
	}
	if imported.State != "complete" || imported.Path != "/products/品牌/小米/1kg/v1" {
		t.Fatal("non-root completion mismatch")
	}
	complete := filepath.Join(source, "public", "products", "品牌", "小米", "1kg", "v1", productManifestName)
	if _, err := os.Stat(complete); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(source, "products")); !os.IsNotExist(err) {
		t.Fatal("wrote outside user scope")
	}
	// Task54's exact failure boundary: all bytes and pending intent exist but
	// the completion marker does not. A new process resumes the same version.
	if err := os.Remove(complete); err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(filepath.Dir(complete), "product-materials.pending.json")
	pendingBefore, err := os.ReadFile(pending)
	if err != nil {
		t.Fatal(err)
	}
	productLocks = sync.Map{}
	response, _ = productSecurityRoute(t, token, request)
	requireCoreFileAuditStatus(t, response, http.StatusOK)
	pendingAfter, err := os.ReadFile(pending)
	if err != nil || string(pendingBefore) != string(pendingAfter) {
		t.Fatal("resume changed frozen pending intent", err)
	}
	var resumed productManifest
	if err = json.Unmarshal(response.Body.Bytes(), &resumed); err != nil || resumed.Path != imported.Path || resumed.State != "complete" {
		t.Fatal("pending version did not complete in place", err)
	}
	export := productRequest{Action: "export", Source: "source1", Path: imported.Path, Destination: "/exports", Name: "原图 (1).zip", Categories: []string{"main"}}
	response, _ = productSecurityRoute(t, token, export)
	requireCoreFileAuditStatus(t, response, http.StatusOK)
	if hash, _, err := productFileHash(filename, productArchiveLimit); err != nil || hash != inspected.SHA256 {
		t.Fatal("original changed", err)
	}
}

// A deterministic scheduling point in the real HTTP request models a concurrent
// administrative revoke after the archive has already been published. No product
// hook or permission bypass is added to the implementation.
type productPermissionChangeContext struct {
	context.Context
	published string
	change    func()
	changed   bool
}

func (c *productPermissionChangeContext) Err() error {
	if !c.changed {
		if _, err := os.Stat(c.published); err == nil {
			c.changed = true
			c.change()
		}
	}
	return c.Context.Err()
}

func TestProductMaterialsNonRootScopeRejectsMidRequestRevocation(t *testing.T) {
	for _, mode := range []string{"scope", "download", "token"} {
		t.Run(mode, func(t *testing.T) {
			source := setupResourcePutTestEnv(t)
			configurePermissionReadAuth(t)
			perms := users.Permissions{Api: true, Browse: true, Download: true, Create: true}
			user := archivePermissionUser(source, "product-revoke-"+mode, perms)
			user.Scopes = []users.SourceScope{{Name: source, Scope: "/public"}}
			savePermissionReadUser(t, user)
			productSecurityAllow(t, user.Username)
			token := issuePermissionReadAPIToken(t, user, "revoke-product", perms)
			filename := filepath.Join(source, "public", "input.zip")
			productTestZip(t, filename, map[string][]byte{"a.jpg": []byte("immutable input bytes")})
			req := productRequest{Action: "inspect", Source: "source1", Path: "/input.zip"}
			response, _ := productSecurityRoute(t, token, req)
			requireCoreFileAuditStatus(t, response, http.StatusOK)
			var inspected struct {
				SHA256   string          `json:"sha256"`
				Manifest []productMember `json:"manifest"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &inspected); err != nil {
				t.Fatal(err)
			}
			req.Action, req.SHA256, req.Destination = "import", inspected.SHA256, "/products"
			req.Brand, req.Product, req.Specification, req.Version = "brand", "product", "1kg", "v1"
			req.Members = inspected.Manifest
			req.Members[0].Category, req.Members[0].Evidence = "main", "verified isolated content"
			version := filepath.Join(source, "public", "products", "brand", "product", "1kg", "v1")
			if err := os.Mkdir(filepath.Join(source, "other"), 0755); err != nil {
				t.Fatal(err)
			}
			ctx := &productPermissionChangeContext{Context: context.Background(), published: filepath.Join(version, "original", "input.zip")}
			ctx.change = func() {
				var err error
				switch mode {
				case "scope":
					user.Scopes = []users.SourceScope{{Name: source, Scope: "/other"}}
					err = store.Users.Update(user, true, "Scopes")
				case "download":
					user.Permissions.Download = false
					err = store.Users.Update(user, true, "Permissions")
				case "token":
					err = auth.RevokeApiToken(store.Access, token)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			request := httptest.NewRequest(http.MethodPost, "/api/resources/products", coreFileAuditJSONBody(t, req)).WithContext(ctx)
			request.Header.Set("Authorization", "Bearer "+token)
			response = httptest.NewRecorder()
			newCoreFileAuditRouter(newAuditStoreStub()).ServeHTTP(response, request)
			if !ctx.changed || response.Code == http.StatusOK {
				t.Fatalf("mid-request revocation ignored: changed=%v status=%d", ctx.changed, response.Code)
			}
			if _, err := os.Stat(filepath.Join(version, productManifestName)); !os.IsNotExist(err) {
				t.Fatal("revoked import marked complete", err)
			}
			if hash, _, err := productFileHash(filename, productArchiveLimit); err != nil || hash != inspected.SHA256 {
				t.Fatal("original changed", err)
			}
		})
	}
}
