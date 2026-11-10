package http

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/fileutils"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	dbshare "github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/filebrowser/backend/trash"
)

func callTrash(t *testing.T, user *users.User, handler handleFunc, method, url, id string, body any) (int, string) {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, url, bytes.NewReader(data))
	r.SetPathValue("id", id)
	w := httptest.NewRecorder()
	status, err := handler(w, r, &requestContext{user: user})
	if status == 0 {
		status = w.Code
	}
	if err != nil {
		return status, err.Error()
	}
	return status, w.Body.String()
}

func createTrashFixture(t *testing.T) (string, *users.User, string) {
	t.Helper()
	source := setupResourcePutTestEnv(t)
	if err := os.WriteFile(filepath.Join(source, "public", "sample.txt"), []byte("synthetic archive bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	user := saveAPITokenTestUser(t, "trash-ordinary-user", source, users.Permissions{Delete: true, Create: true, Browse: true})
	return source, user, "trash-http-operation-0001"
}

func TestTrashHTTPPermissionOwnershipScopeAndNoOverwrite(t *testing.T) {
	source, user, id := createTrashFixture(t)
	request := trashRequest{Source: "source1", Path: "/public/sample.txt", OperationID: id}
	user.Permissions.Delete = false
	status, _ := callTrash(t, user, trashPostHandler, http.MethodPost, "/api/trash", "", request)
	if status != http.StatusForbidden {
		t.Fatalf("missing Delete: %d", status)
	}
	user.Permissions.Delete = true
	status, body := callTrash(t, user, trashPostHandler, http.MethodPost, "/api/trash", "", request)
	if status != http.StatusOK {
		t.Fatalf("trash %d: %s", status, body)
	}
	var item trash.Item
	if err := json.Unmarshal([]byte(body), &item); err != nil {
		t.Fatal(err)
	}
	if item.State != "trashed" || item.OriginalPath != "/public/sample.txt" || item.Source != "source1" || item.SHA256 == "" {
		t.Fatalf("contract mismatch: %+v", item)
	}
	if strings.Contains(body, source) {
		t.Fatal("filesystem Source key leaked")
	}
	// A different ordinary identity with the same path permissions cannot claim it.
	other := *user
	other.ID = 72
	other.Username = "other-user"
	status, _ = callTrash(t, &other, trashGetHandler, http.MethodGet, "/api/trash/"+id+"?source=source1", id, nil)
	if status != http.StatusForbidden {
		t.Fatalf("foreign item: %d", status)
	}
	status, body = callTrash(t, &other, trashListHandler, http.MethodGet, "/api/trash?source=source1", "", nil)
	if status != http.StatusOK || !strings.Contains(body, "\"total\":0") {
		t.Fatalf("foreign list: %d %s", status, body)
	}
	// Narrowed scopes and ACL revocation apply to old operation IDs immediately.
	user.Scopes[0].Scope = "/elsewhere"
	status, _ = callTrash(t, user, trashGetHandler, http.MethodGet, "/api/trash/"+id+"?source=source1", id, nil)
	if status != http.StatusForbidden {
		t.Fatalf("scope revocation: %d", status)
	}
	user.Scopes[0].Scope = "/public"
	status, body = callTrash(t, user, trashGetHandler, http.MethodGet, "/api/trash/"+id+"?source=source1", id, nil)
	if status != http.StatusOK || !strings.Contains(body, "\"path\":\"/sample.txt\"") {
		t.Fatalf("scoped path: %d %s", status, body)
	}
	if err := store.Access.DenyUser(source, "/public/sample.txt", user.Username); err != nil {
		t.Fatal(err)
	}
	status, _ = callTrash(t, user, trashGetHandler, http.MethodGet, "/api/trash/"+id+"?source=source1", id, nil)
	if status != http.StatusForbidden {
		t.Fatalf("ACL revocation: %d", status)
	}
	if _, err := store.Access.RemoveDenyUser(source, "/public/sample.txt", user.Username); err != nil {
		t.Fatal(err)
	}
	user.Permissions.Create = false
	user.Permissions.Modify = true
	restore := trashRequest{Source: "source1", Path: "/sample.txt", RestoreOperationID: "restore-http-operation-0001"}
	status, _ = callTrash(t, user, trashRestoreHandler, http.MethodPost, "/api/trash/"+id+"/restore", id, restore)
	if status != http.StatusForbidden {
		t.Fatalf("Modify must not grant Create: %d", status)
	}
	user.Permissions.Create = true
	if err := os.WriteFile(filepath.Join(source, "public", "sample.txt"), []byte("new occupant"), 0644); err != nil {
		t.Fatal(err)
	}
	status, _ = callTrash(t, user, trashRestoreHandler, http.MethodPost, "/api/trash/"+id+"/restore", id, restore)
	if status != http.StatusConflict {
		t.Fatalf("overwrite restore: %d", status)
	}
	status, body = callTrash(t, user, trashGetHandler, http.MethodGet, "/api/trash/"+id+"?source=source1&restore_operation_id="+restore.RestoreOperationID, id, nil)
	if status != http.StatusOK || !strings.Contains(body, "\"restore_attempt\":") || !strings.Contains(body, "\"error_code\":\"target_exists\"") {
		t.Fatalf("rejected restore journal: %d %s", status, body)
	}
	restore.Path = "/restored.txt"
	restore.RestoreOperationID = "restore-http-operation-0002"
	status, body = callTrash(t, user, trashRestoreHandler, http.MethodPost, "/api/trash/"+id+"/restore", id, restore)
	if status != http.StatusOK || !strings.Contains(body, "\"state\":\"restored\"") {
		t.Fatalf("restore %d: %s", status, body)
	}
	data, _ := os.ReadFile(filepath.Join(source, "public", "sample.txt"))
	if string(data) != "new occupant" {
		t.Fatal("original occupant changed")
	}
	data, _ = os.ReadFile(filepath.Join(source, "public", "restored.txt"))
	if string(data) != "synthetic archive bytes" {
		t.Fatal("restored bytes differ")
	}
}

func TestTrashHTTPReadOnlyInvalidPathsAndCurrentTargetACL(t *testing.T) {
	source, user, id := createTrashFixture(t)
	idx := indexing.GetIndex("source1")
	status, _ := callTrash(t, user, trashPostHandler, http.MethodPost, "/api/trash", "", trashRequest{Source: source, Path: "/public/sample.txt", OperationID: id})
	if status != http.StatusForbidden {
		t.Fatalf("physical Source path must not be a public identifier: %d", status)
	}
	idx.Config.ReadOnly = true
	status, _ = callTrash(t, user, trashPostHandler, http.MethodPost, "/api/trash", "", trashRequest{Source: "source1", Path: "/public/sample.txt", OperationID: id})
	if status != http.StatusForbidden {
		t.Fatalf("read-only trash: %d", status)
	}
	idx.Config.ReadOnly = false
	for _, filename := range []string{"/", "/public", "../public/sample.txt", "C:\\sample.txt", "/.filebrowser-trash/content"} {
		status, _ = callTrash(t, user, trashPostHandler, http.MethodPost, "/api/trash", "", trashRequest{Source: "source1", Path: filename, OperationID: id})
		if status == http.StatusOK {
			t.Fatalf("accepted %q", filename)
		}
	}
	status, _ = callTrash(t, user, trashPostHandler, http.MethodPost, "/api/trash", "", trashRequest{Source: "source1", Path: "/public/sample.txt", OperationID: id})
	if status != http.StatusOK {
		t.Fatalf("trash: %d", status)
	}
	idx.Config.ReadOnly = true
	status, _ = callTrash(t, user, trashRestoreHandler, http.MethodPost, "/api/trash/"+id+"/restore", id, trashRequest{Source: "source1", Path: "/public/restored.txt", RestoreOperationID: "restore-readonly-0001"})
	if status != http.StatusForbidden {
		t.Fatalf("read-only restore: %d", status)
	}
	idx.Config.ReadOnly = false
	if err := store.Access.DenyUser(source, "/public/restored.txt", user.Username); err != nil {
		t.Fatal(err)
	}
	status, _ = callTrash(t, user, trashRestoreHandler, http.MethodPost, "/api/trash/"+id+"/restore", id, trashRequest{Source: "source1", Path: "/public/restored.txt", RestoreOperationID: "restore-target-acl-0001"})
	if status != http.StatusForbidden {
		t.Fatalf("target ACL: %d", status)
	}
}

func TestTrashAPITokenIntersectionAndPermissionRevocation(t *testing.T) {
	source, _, id := createTrashFixture(t)
	previousAuth := settings.Config.Auth
	t.Cleanup(func() { settings.Config.Auth = previousAuth })
	settings.Config.Auth.Key = "synthetic-trash-token-test-signing-key"
	config.Auth.Key = settings.Config.Auth.Key
	config.Auth.Methods.NoAuth = false
	user := saveAPITokenTestUser(t, "trash-api-user", source, users.Permissions{Api: true, Delete: true, Create: true, Browse: true})
	narrow, _ := issuePermissionContractToken(t, user, "trash-without-delete", "create,browse")
	full, _ := issuePermissionContractToken(t, user, "trash-with-delete", "delete,create,browse")
	api := http.NewServeMux()
	registerTrashRoutes(api)
	requestBody := `{"source":"source1","path":"/public/sample.txt","operation_id":"` + id + `"}`
	call := func(token string) int {
		r := httptest.NewRequest(http.MethodPost, "/trash", strings.NewReader(requestBody))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		return w.Code
	}
	if status := call(narrow); status != http.StatusForbidden {
		t.Fatalf("token intersection: %d", status)
	}
	if status := call(full); status != http.StatusOK {
		t.Fatalf("full token: %d", status)
	}
	updateAPITokenTestUserPermissions(t, user, users.Permissions{Api: true, Create: true, Browse: true})
	if status := call(full); status != http.StatusForbidden {
		t.Fatalf("revoked Delete replay: %d", status)
	}
}

func TestTrashIsolationAcrossOrdinaryAPIsAndRecursiveOperations(t *testing.T) {
	source, user, id := createTrashFixture(t)
	user.Permissions.Download = true
	user.ShowHidden = true
	status, body := callTrash(t, user, trashPostHandler, http.MethodPost, "/api/trash", "", trashRequest{Source: "source1", Path: "/public/sample.txt", OperationID: id})
	if status != http.StatusOK {
		t.Fatalf("trash: %d %s", status, body)
	}
	for _, handler := range []handleFunc{resourceGetHandler, resourcePutHandler, resourceDeleteHandler} {
		status, _ = callTrash(t, user, handler, http.MethodGet, "/api/resources?source=source1&path=/.filebrowser-trash/"+id+"/content", "", nil)
		if status == http.StatusOK {
			t.Fatal("reserved item exposed or modified by ordinary resource API")
		}
	}
	status, body = callTrash(t, user, resourceGetHandler, http.MethodGet, "/api/resources?source=source1&path=/", "", nil)
	if status != http.StatusOK || strings.Contains(body, ".filebrowser-trash") {
		t.Fatalf("ordinary listing leaked: %d %s", status, body)
	}
	status, _ = callTrash(t, user, downloadHandler, http.MethodGet, "/api/resources/download?source=source1&file=/.filebrowser-trash/"+id+"/content", "", nil)
	if status == http.StatusOK {
		t.Fatal("reserved payload download allowed")
	}
	if _, err := safeExtractPath(source, ".filebrowser-trash/"+id+"/content"); err == nil {
		t.Fatal("extraction can overwrite reserved payload")
	}
	// Sharing a parent directory must not bypass reserved-entry filtering.
	var archive bytes.Buffer
	w := zip.NewWriter(&archive)
	if err := addFile("source1", "/", &requestContext{user: user, share: &dbshare.Link{}}, nil, w, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(archive.Bytes()), int64(archive.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range z.File {
		if strings.Contains(entry.Name, ".filebrowser-trash") {
			t.Fatal("share archive leaked trash")
		}
	}
	// A containing directory may be a parent Source of another configured Source.
	if err := fileutils.CopyFile(source, filepath.Join(t.TempDir(), "copied")); !os.IsPermission(err) {
		t.Fatalf("recursive copy: %v", err)
	}
	if err := fileutils.MoveFile(source, filepath.Join(t.TempDir(), "moved")); !os.IsPermission(err) {
		t.Fatalf("recursive move: %v", err)
	}
	if err := files.DeleteFiles("source1", source, true); !os.IsPermission(err) {
		t.Fatalf("recursive delete: %v", err)
	}
	ffs := &filteredFileSystem{source: "source1", user: user, userScope: "/"}
	if err := ffs.RemoveAll(context.Background(), "/"); !os.IsPermission(err) {
		t.Fatalf("WebDAV ancestor delete: %v", err)
	}
	if err := ffs.Rename(context.Background(), "/", "/moved"); !os.IsPermission(err) {
		t.Fatalf("WebDAV ancestor rename: %v", err)
	}
	idx := indexing.GetIndex("source1")
	if idx.IsViewable(true, "/.filebrowser-trash/", false, true) || !idx.ShouldSkip(true, "/.filebrowser-trash/", true, false, true) {
		t.Fatal("indexing did not exclude reserved storage")
	}
	if store.Access.Permitted(source, "/.filebrowser-trash/"+id+"/content", user.Username) || store.Access.PermittedFresh(source, "/.filebrowser-trash/", user.Username) {
		t.Fatal("Access permits reserved storage")
	}
	if err := utils.CheckUserStorageTree(filepath.Join(source, "public")); err != nil {
		t.Fatalf("normal sibling directory rejected: %v", err)
	}
}
