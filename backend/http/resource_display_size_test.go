package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
)

func resourceDisplayUser(t *testing.T, sourcePath string) (*users.User, string) {
	t.Helper()
	configurePermissionReadAuth(t)
	user := &users.User{
		Username:    "resource-display-user",
		Permissions: users.Permissions{Browse: true, Preview: true, Download: true},
		Scopes:      []users.SourceScope{{Name: sourcePath, Scope: "/"}},
	}
	savePermissionReadUser(t, user)
	return user, issuePermissionReadWebToken(t, user)
}

func resourceDisplayRequest(t *testing.T, user *users.User, token, path string) *iteminfo.ExtendedFileInfo {
	t.Helper()
	query := url.Values{"source": {"source1"}, "path": {path}}
	request := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
	recorder := httptest.NewRecorder()
	status, requestErr := resourceGetHandler(recorder, request, &requestContext{user: user, token: token})
	if requestErr != nil || permissionHandlerStatus(status, recorder) != http.StatusOK {
		t.Fatalf("resource display request failed: status=%d err=%v", status, requestErr)
	}
	var response iteminfo.ExtendedFileInfo
	if decodeErr := json.Unmarshal(recorder.Body.Bytes(), &response); decodeErr != nil {
		t.Fatalf("decode resource display response: %v", decodeErr)
	}
	return &response
}

func TestResourceDisplaySizesFollowSourceMode(t *testing.T) {
	for _, logical := range []bool{false, true} {
		name := "physical"
		if logical {
			name = "logical"
		}
		t.Run(name, func(t *testing.T) {
			sourcePath := setupResourcePutTestEnv(t)
			idx := indexing.GetIndex("source1")
			idx.Config.UseLogicalSize = logical
			fileSizes := map[string]int64{"zero.txt": 0, "one.txt": 1, "block.bin": 4096, "over-block.bin": 4097}
			for filename, size := range fileSizes {
				if writeErr := os.WriteFile(filepath.Join(sourcePath, "public", filename), bytes.Repeat([]byte("x"), int(size)), 0o644); writeErr != nil {
					t.Fatal(writeErr)
				}
			}
			if !logical {
				fileSizes["one.txt"], fileSizes["over-block.bin"] = 4096, 8192
			}
			user, token := resourceDisplayUser(t, sourcePath)
			response := resourceDisplayRequest(t, user, token, "/public/")
			if len(response.Files) != len(fileSizes) {
				t.Fatalf("directory files changed: files=%d", len(response.Files))
			}
			for _, child := range response.Files {
				expected, found := fileSizes[child.Name]
				if !found || child.Size != expected {
					t.Errorf("file %s display size=%d want=%d", child.Name, child.Size, expected)
				}
			}
			// File detail and preview safety metadata remain real byte sizes.
			if detail := resourceDisplayRequest(t, user, token, "/public/one.txt"); detail.Size != 1 {
				t.Errorf("file detail changed real byte size to %d", detail.Size)
			}
		})
	}
}

func TestResourceDisplaySizesKeepFreshFilteringAndPermissionChecks(t *testing.T) {
	for _, logical := range []bool{false, true} {
		name := "physical"
		if logical {
			name = "logical"
		}
		t.Run(name, func(t *testing.T) {
			sourcePath := setupResourcePutTestEnv(t)
			idx := indexing.GetIndex("source1")
			idx.Config.UseLogicalSize = logical
			for _, filename := range []string{"changed.txt", "deleted.txt", "replaced.txt"} {
				if writeErr := os.WriteFile(filepath.Join(sourcePath, "public", filename), []byte("x"), 0o644); writeErr != nil {
					t.Fatal(writeErr)
				}
			}
			user, token := resourceDisplayUser(t, sourcePath)
			listing, listingErr := files.FileInfoFaster(utils.FileOptions{Source: "source1", Path: "/public", Expand: true}, store.Access, user, store.Share)
			if listingErr != nil {
				t.Fatal(listingErr)
			}
			target, targetErr := resolveAuthenticatedReadTarget(user, "source1", "/public")
			if targetErr != nil {
				t.Fatal(targetErr)
			}
			if writeErr := os.WriteFile(filepath.Join(sourcePath, "public", "changed.txt"), bytes.Repeat([]byte("y"), 5000), 0o644); writeErr != nil {
				t.Fatal(writeErr)
			}
			for _, filename := range []string{"deleted.txt", "replaced.txt"} {
				if removeErr := os.Remove(filepath.Join(sourcePath, "public", filename)); removeErr != nil {
					t.Fatal(removeErr)
				}
			}
			if mkdirErr := os.Mkdir(filepath.Join(sourcePath, "public", "replaced.txt"), 0o755); mkdirErr != nil {
				t.Fatal(mkdirErr)
			}
			if filterErr := filterAuthenticatedDirectoryFileInfo(user, "source1", target, listing); filterErr != nil {
				t.Fatal(filterErr)
			}
			if len(listing.Files) != 1 || listing.Files[0].Name != "changed.txt" || listing.Files[0].Size != 5000 {
				t.Fatal("shared filtering retained deleted/type-changed children or changed the real file size")
			}
			expected := int64(8192)
			if logical {
				expected = 5000
			}
			response := resourceDisplayRequest(t, user, token, "/public")
			if len(response.Files) != 1 || response.Files[0].Size != expected {
				t.Fatal("resource listing did not apply display mode to the fresh file size")
			}
			revoked := *user
			revoked.Permissions.Browse = false
			if updateErr := store.Users.Update(&revoked, true, "Permissions"); updateErr != nil {
				t.Fatal(updateErr)
			}
			query := url.Values{"source": {"source1"}, "path": {"/public"}}
			request := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
			recorder := httptest.NewRecorder()
			status, requestErr := resourceGetHandler(recorder, request, &requestContext{user: user, token: token})
			if permissionHandlerStatus(status, recorder) != http.StatusForbidden || requestErr == nil || recorder.Body.Len() != 0 {
				t.Fatal("withdrawn Browse permission exposed resource display metadata")
			}
		})
	}
}

func TestResourceDisplayDoesNotExposeDeniedDirectoryAggregates(t *testing.T) {
	for _, logical := range []bool{false, true} {
		name := "physical"
		if logical {
			name = "logical"
		}
		t.Run(name, func(t *testing.T) {
			sourcePath := setupResourcePutTestEnv(t)
			idx := indexing.GetIndex("source1")
			idx.Config.UseLogicalSize = logical
			nestedPath := filepath.Join(sourcePath, "public", "nested")
			if mkdirErr := os.Mkdir(nestedPath, 0o755); mkdirErr != nil {
				t.Fatal(mkdirErr)
			}
			for relative, size := range map[string]int{
				"visible.txt": 1, "hidden.txt": 8193,
				"nested/visible.txt": 1, "nested/hidden.txt": 16385,
			} {
				if writeErr := os.WriteFile(filepath.Join(sourcePath, "public", filepath.FromSlash(relative)), bytes.Repeat([]byte("x"), size), 0o644); writeErr != nil {
					t.Fatal(writeErr)
				}
			}
			// The global index total contains a denied descendant even though
			// the caller may browse the parent directory itself.
			var nestedAggregate uint64 = 24576
			if logical {
				nestedAggregate = 16386
			}
			idx.SetFolderSize("/public/nested/", nestedAggregate)
			user, token := resourceDisplayUser(t, sourcePath)
			for _, deniedPath := range []string{"/public/hidden.txt", "/public/nested/hidden.txt"} {
				if denyErr := store.Access.DenyUser(sourcePath, deniedPath, user.Username); denyErr != nil {
					t.Fatal(denyErr)
				}
			}
			parentInfo, parentErr := os.Stat(filepath.Join(sourcePath, "public"))
			if parentErr != nil {
				t.Fatal(parentErr)
			}
			nestedInfo, nestedErr := os.Stat(nestedPath)
			if nestedErr != nil {
				t.Fatal(nestedErr)
			}
			response := resourceDisplayRequest(t, user, token, "/public")
			if len(response.Files) != 1 || response.Files[0].Name != "visible.txt" {
				t.Fatal("directory listing exposed denied direct children")
			}
			if response.Size != parentInfo.Size() {
				t.Fatal("directory listing exposed its unfiltered global aggregate")
			}
			if len(response.Folders) != 1 || response.Folders[0].Name != "nested" || response.Folders[0].Size != nestedInfo.Size() {
				t.Fatal("visible child directory exposed a denied descendant's aggregate size")
			}
			nested := resourceDisplayRequest(t, user, token, "/public/nested")
			if len(nested.Files) != 1 || nested.Files[0].Name != "visible.txt" || nested.Size != nestedInfo.Size() {
				t.Fatal("nested directory request exposed denied descendant metadata")
			}
		})
	}
}
