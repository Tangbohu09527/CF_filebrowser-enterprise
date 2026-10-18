package http

import (
	"encoding/json"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func TestProductMaterialsOrganizeRecoveryAndRestart(t *testing.T) {
	source := setupResourcePutTestEnv(t)
	configurePermissionReadAuth(t)
	perms := users.Permissions{Api: true, Browse: true, Download: true, Create: true, Modify: true, Delete: true}
	u := archivePermissionUser(source, "organize-user", perms)
	savePermissionReadUser(t, u)
	productSecurityAllow(t, u.Username)
	token := issuePermissionReadAPIToken(t, u, "organize-token", perms)
	local := func(p string) string { return filepath.Join(source, filepath.FromSlash(p[1:])) }
	original := []byte("original immutable product image")
	if e := os.WriteFile(local("/public/original (1).jpg"), original, 0644); e != nil {
		t.Fatal(e)
	}
	hash, _, _ := productFileHash(local("/public/original (1).jpg"), 1024)
	call := func(operation, id, selected, destination, expected string, extra func(*productRequest)) productOperationResult {
		t.Helper()
		req := productRequest{Action: "organize", Operation: operation, OperationID: id, Source: "source1", Path: selected, Destination: destination, ExpectedSHA256: expected, RecoveryRoot: "/public/recovery"}
		if extra != nil {
			extra(&req)
		}
		r, _ := productSecurityRoute(t, token, req)
		requireCoreFileAuditStatus(t, r, http.StatusOK)
		var out productOperationResult
		if e := json.Unmarshal(r.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
		if out.State != "complete" || !out.Recoverable {
			t.Fatal(r.Body.String())
		}
		return out
	}
	call("copy", "copy-1", "/public/original (1).jpg", "/public/copy.jpg", hash, nil)
	if b, e := os.ReadFile(local("/public/original (1).jpg")); e != nil || string(b) != string(original) {
		t.Fatal("copy modified original")
	}
	moved := call("move", "move-1", "/public/copy.jpg", "/public/moved.jpg", hash, nil)
	// Process-local locks can disappear; persisted receipt and immutable backup suffice.
	productLocks = sync.Map{}
	call("move", "move-1", "/public/copy.jpg", "/public/moved.jpg", hash, nil)
	call("restore", "restore-1", "/public/copy.jpg", "", hash, func(req *productRequest) { req.RecoveryPath = moved.RecoveryPath })
	call("rename", "rename-1", "/public/moved.jpg", "/public/renamed 中文 (1).jpg", hash, nil)
	deleted := call("delete", "delete-1", "/public/renamed 中文 (1).jpg", "", hash, nil)
	if _, e := os.Stat(local("/public/renamed 中文 (1).jpg")); !os.IsNotExist(e) {
		t.Fatal("delete left original visible")
	}
	call("restore", "restore-2", "/public/renamed 中文 (1).jpg", "", hash, func(req *productRequest) { req.RecoveryPath = deleted.RecoveryPath })
	replacement := []byte("approved replacement")
	if e := os.WriteFile(local("/public/replacement.jpg"), replacement, 0644); e != nil {
		t.Fatal(e)
	}
	newHash, _, _ := productFileHash(local("/public/replacement.jpg"), 1024)
	replaced := call("replace", "replace-1", "/public/copy.jpg", "", hash, func(req *productRequest) { req.ReplacementPath = "/public/replacement.jpg"; req.SHA256 = newHash })
	// Simulate failure after output publication but before the completion marker.
	if e := os.Remove(local(path.Join(replaced.RecoveryPath, "complete.json"))); e != nil {
		t.Fatal(e)
	}
	productLocks = sync.Map{}
	call("replace", "replace-1", "/public/copy.jpg", "", hash, func(req *productRequest) { req.ReplacementPath = "/public/replacement.jpg"; req.SHA256 = newHash })
	if b, e := os.ReadFile(local(path.Join(replaced.RecoveryPath, "before.bin"))); e != nil || string(b) != string(original) {
		t.Fatal("before-image unavailable")
	}
	if b, e := os.ReadFile(local("/public/copy.jpg")); e != nil || string(b) != string(replacement) {
		t.Fatal("replace failed")
	}
}
func TestProductMaterialsOrganizeConflictsDoNotCapture(t *testing.T) {
	source := setupResourcePutTestEnv(t)
	u := archivePermissionUser(source, "organize-conflict", users.Permissions{Api: true, Browse: true, Download: true, Create: true, Modify: true, Delete: true})
	src := filepath.Join(source, "public", "first.jpg")
	dst := filepath.Join(source, "public", "second.jpg")
	if writeErr := os.WriteFile(src, []byte("first"), 0644); writeErr != nil {
		t.Fatal(writeErr)
	}
	if writeErr := os.WriteFile(dst, []byte("second"), 0644); writeErr != nil {
		t.Fatal(writeErr)
	}
	hash, _, _ := productFileHash(src, 1024)
	req := productRequest{Action: "organize", Operation: "move", OperationID: "conflict", Source: "source1", Path: "/public/first.jpg", Destination: "/public/second.jpg", ExpectedSHA256: hash, RecoveryRoot: "/public/recovery"}
	status, _, e := productTestRequest(t, u, req)
	requireArchivePermissionStatus(t, status, e, http.StatusConflict)
	if b, _ := os.ReadFile(src); string(b) != "first" {
		t.Fatal("conflict captured source")
	}
	if b, _ := os.ReadFile(dst); string(b) != "second" {
		t.Fatal("conflict replaced destination")
	}
	req.Destination = "/public/new.jpg"
	req.ExpectedSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	status, _, e = productTestRequest(t, u, req)
	requireArchivePermissionStatus(t, status, e, http.StatusConflict)
	if _, e = os.Stat(filepath.Join(source, "public", "recovery")); !os.IsNotExist(e) {
		t.Fatal("wrong digest wrote recovery")
	}
}
func TestProductMaterialsOrganizePendingRecoveryAndPermission(t *testing.T) {
	source := setupResourcePutTestEnv(t)
	configurePermissionReadAuth(t)
	perms := users.Permissions{Api: true, Browse: true, Download: true, Create: true, Modify: true, Delete: true}
	u := archivePermissionUser(source, "organize-pending", perms)
	savePermissionReadUser(t, u)
	productSecurityAllow(t, u.Username)
	token := issuePermissionReadAPIToken(t, u, "pending-token", perms)
	src := filepath.Join(source, "public", "first.jpg")
	if writeErr := os.WriteFile(src, []byte("first"), 0644); writeErr != nil {
		t.Fatal(writeErr)
	}
	hash, _, _ := productFileHash(src, 1024)
	req := productRequest{Action: "organize", Operation: "delete", OperationID: "pending-1", Source: "source1", Path: "/public/first.jpg", ExpectedSHA256: hash, RecoveryRoot: "/public/recovery"}
	r, _ := productSecurityRoute(t, token, req)
	requireCoreFileAuditStatus(t, r, http.StatusOK)
	receipt := filepath.Join(source, "public", "recovery", "pending-1", "complete.json")
	os.Remove(receipt)
	productLocks = sync.Map{}
	r, _ = productSecurityRoute(t, token, req)
	requireCoreFileAuditStatus(t, r, http.StatusOK)
	// Token still has old authority; current account revocation must win on retry.
	u.Permissions.Delete = false
	savePermissionReadUser(t, u)
	r, _ = productSecurityRoute(t, token, req)
	if r.Code != http.StatusForbidden && r.Code != http.StatusUnauthorized {
		t.Fatalf("revocation accepted: %d", r.Code)
	}
	// A different allowed user must not claim another actor's recovery.
	another := archivePermissionUser(source, "organize-other", perms)
	savePermissionReadUser(t, another)
	config.Server.ProductMaterialsUsers = append(config.Server.ProductMaterialsUsers, another.Username)
	otherToken := issuePermissionReadAPIToken(t, another, "other-token", perms)
	req.Operation = "restore"
	req.OperationID = "restore-stolen"
	req.RecoveryPath = "/public/recovery/pending-1"
	r, _ = productSecurityRoute(t, otherToken, req)
	requireCoreFileAuditStatus(t, r, http.StatusForbidden)
}

func TestProductMaterialsOrganizeConcurrentEditRetained(t *testing.T) {
	source := setupResourcePutTestEnv(t)
	u := archivePermissionUser(source, "organize-concurrent", users.Permissions{Api: true, Browse: true, Download: true, Create: true, Modify: true, Delete: true})
	src := filepath.Join(source, "public", "first.jpg")
	if err := os.WriteFile(src, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}
	hash, _, _ := productFileHash(src, 1024)
	req := productRequest{Action: "organize", Operation: "move", OperationID: "concurrent", Source: "source1", Path: "/public/first.jpg", Destination: "/public/new.jpg", ExpectedSHA256: hash, RecoveryRoot: "/public/recovery"}
	prior := authenticatedReadSnapshotCompleteHook
	authenticatedReadSnapshotCompleteHook = func() {
		authenticatedReadSnapshotCompleteHook = nil
		if err := os.WriteFile(src, []byte("employee current edit"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { authenticatedReadSnapshotCompleteHook = prior }()
	status, _, err := productTestRequest(t, u, req)
	requireArchivePermissionStatus(t, status, err, http.StatusConflict)
	if actual, _ := os.ReadFile(src); string(actual) != "employee current edit" {
		t.Fatal("employee change lost")
	}
	if _, err = os.Stat(filepath.Join(source, "public", "new.jpg")); !os.IsNotExist(err) {
		t.Fatal("conflicting operation published output")
	}
}
