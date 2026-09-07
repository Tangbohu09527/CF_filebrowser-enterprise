package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
)

func resourceAggregateFixture(t *testing.T, logical bool) (string, *users.User, string) {
	t.Helper()
	source := setupResourcePutTestEnv(t)
	idx := indexing.GetIndex("source1")
	idx.Config.ResolvedRules = settings.ResolvedRulesConfig{NoRules: true}
	idx.Config.UseLogicalSize = logical
	for _, path := range []string{"nested", "empty"} {
		if mkdirErr := os.Mkdir(filepath.Join(source, "public", path), 0o755); mkdirErr != nil {
			t.Fatal(mkdirErr)
		}
	}
	for path, body := range map[string]string{"outer.txt": "12345678901234567", "nested/inner.txt": "12345"} {
		if writeErr := os.WriteFile(filepath.Join(source, "public", filepath.FromSlash(path)), []byte(body), 0o644); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	user, token := resourceDisplayUser(t, source)
	previous := resourceAggregateCollectedHook
	t.Cleanup(func() { resourceAggregateCollectedHook = previous })
	return source, user, token
}

func resourceAggregateInodeSize(t *testing.T, source string) int64 {
	t.Helper()
	info, statErr := os.Stat(filepath.Join(source, "public"))
	if statErr != nil {
		t.Fatal(statErr)
	}
	return info.Size()
}

func TestResourceAggregateListsFreshCompleteSubtrees(t *testing.T) {
	for _, logical := range []bool{false, true} {
		name := "physical"
		if logical {
			name = "logical"
		}
		t.Run(name, func(t *testing.T) {
			_, user, token := resourceAggregateFixture(t, logical)
			response := resourceDisplayRequest(t, user, token, "/public")
			want := int64(12288) // 4 KiB file + 4 KiB nested + 4 KiB empty directory.
			nested, empty := int64(4096), int64(4096)
			if logical {
				want, nested, empty = 22, 5, 0
			}
			if response.Size != want || len(response.Folders) != 2 {
				t.Fatalf("complete directory size=%d folders=%d want=%d/2", response.Size, len(response.Folders), want)
			}
			for _, folder := range response.Folders {
				if (folder.Name == "nested" && folder.Size != nested) || (folder.Name == "empty" && folder.Size != empty) {
					t.Fatalf("unexpected aggregate for %s: %d", folder.Name, folder.Size)
				}
			}
			if detail := resourceDisplayRequest(t, user, token, "/public/outer.txt"); detail.Size != 17 {
				t.Fatal("aggregate changed file-detail real bytes")
			}
		})
	}
}

func TestResourceAggregateFallbackOnCurrentDeniedDescendants(t *testing.T) {
	for _, group := range []bool{false, true} {
		name := "user"
		if group {
			name = "group"
		}
		t.Run(name, func(t *testing.T) {
			source, user, token := resourceAggregateFixture(t, true)
			inodeSize := resourceAggregateInodeSize(t, source)
			resourceAggregateCollectedHook = func() {
				var denyErr error
				if group {
					if groupErr := store.Access.AddUserToGroup("aggregate-team", user.Username); groupErr != nil {
						t.Fatal(groupErr)
					}
					denyErr = store.Access.DenyGroup(source, "/public/nested/inner.txt", "aggregate-team")
				} else {
					denyErr = store.Access.DenyUser(source, "/public/nested/inner.txt", user.Username)
				}
				if denyErr != nil {
					t.Fatal(denyErr)
				}
			}
			response := resourceDisplayRequest(t, user, token, "/public")
			if response.Size != inodeSize {
				t.Fatal("aggregate disclosed a descendant denied after collection")
			}
		})
	}
}

func TestResourceAggregateFreshBatchRejectsRevocationAfterPreparation(t *testing.T) {
	source, user, token := resourceAggregateFixture(t, true)
	target, resolveErr := resolveAuthenticatedReadTarget(user, "source1", "/public")
	if resolveErr != nil {
		t.Fatal(resolveErr)
	}
	walk, collectErr := collectAuthenticatedResourceAggregates(context.Background(), &requestContext{user: user, token: token}, target)
	if collectErr != nil || walk == nil {
		t.Fatalf("prepare complete aggregate: %v", collectErr)
	}
	if denyErr := store.Access.DenyUser(source, "/public/nested/inner.txt", user.Username); denyErr != nil {
		t.Fatal(denyErr)
	}
	info := &iteminfo.ExtendedFileInfo{FileInfo: iteminfo.FileInfo{ItemInfo: iteminfo.ItemInfo{Size: target.Info.Size()}}}
	walk.apply(user, target, info)
	if info.Size != target.Info.Size() {
		t.Fatal("final aggregate application used a stale descendant ACL")
	}
}

func TestResourceAggregateRejectsIdentityAndPermissionChanges(t *testing.T) {
	for _, mutation := range []string{"scope", "scope-identity", "browse", "api-token-browse", "api-token-revoke"} {
		t.Run(mutation, func(t *testing.T) {
			source, user, token := resourceAggregateFixture(t, true)
			requestPath := "/public"
			if mutation == "scope-identity" {
				user.Scopes = []users.SourceScope{{Name: source, Scope: "/public"}}
				if updateErr := store.Users.Update(user, true, "Scopes"); updateErr != nil {
					t.Fatal(updateErr)
				}
				requestPath = "/"
			}
			if mutation == "api-token-revoke" || mutation == "api-token-browse" {
				user.Permissions.Api = true
				if updateErr := store.Users.Update(user, true, "Permissions"); updateErr != nil {
					t.Fatal(updateErr)
				}
				token = issuePermissionReadAPIToken(t, user, "aggregate-token", user.Permissions)
			}
			collected := false
			resourceAggregateCollectedHook = func() {
				collected = true
				updated := *user
				switch mutation {
				case "scope":
					updated.Scopes = []users.SourceScope{{Name: source, Scope: "/public/nested"}}
					if updateErr := store.Users.Update(&updated, true, "Scopes"); updateErr != nil {
						t.Fatal(updateErr)
					}
				case "scope-identity":
					public := filepath.Join(source, "public")
					if renameErr := os.Rename(public, filepath.Join(source, "detached-scope")); renameErr != nil {
						t.Fatal(renameErr)
					}
					if mkdirErr := os.Mkdir(public, 0o755); mkdirErr != nil {
						t.Fatal(mkdirErr)
					}
				case "browse", "api-token-browse":
					updated.Permissions.Browse = false
					if updateErr := store.Users.Update(&updated, true, "Permissions"); updateErr != nil {
						t.Fatal(updateErr)
					}
				case "api-token-revoke":
					if revokeErr := store.Access.RevokeToken(token); revokeErr != nil {
						t.Fatal(revokeErr)
					}
				}
			}
			query := url.Values{"source": {"source1"}, "path": {requestPath}}
			request := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
			recorder := httptest.NewRecorder()
			status, requestErr := resourceGetHandler(recorder, request, &requestContext{user: user, token: token})
			if !collected {
				t.Fatal("request did not reach post-collection revocation")
			}
			if status != http.StatusForbidden || requestErr == nil || recorder.Body.Len() != 0 {
				t.Fatal("changed scope, Browse or token exposed a prepared aggregate")
			}
		})
	}
}

func TestResourceAggregateDiscardsChangedFilesystemAndRules(t *testing.T) {
	for _, mutation := range []string{"size", "delete", "file-to-directory", "directory-identity", "canonical-swap", "rules"} {
		t.Run(mutation, func(t *testing.T) {
			source, user, token := resourceAggregateFixture(t, true)
			inodeSize := resourceAggregateInodeSize(t, source)
			resourceAggregateCollectedHook = func() {
				path := filepath.Join(source, "public", "nested", "inner.txt")
				switch mutation {
				case "size":
					if writeErr := os.WriteFile(path, []byte("changed-content-size"), 0o644); writeErr != nil {
						t.Fatal(writeErr)
					}
				case "delete", "file-to-directory":
					if removeErr := os.Remove(path); removeErr != nil {
						t.Fatal(removeErr)
					}
					if mutation == "file-to-directory" {
						if mkdirErr := os.Mkdir(path, 0o755); mkdirErr != nil {
							t.Fatal(mkdirErr)
						}
					}
				case "directory-identity":
					nested := filepath.Dir(path)
					if renameErr := os.Rename(nested, filepath.Join(source, "detached")); renameErr != nil {
						t.Fatal(renameErr)
					}
					if mkdirErr := os.Mkdir(nested, 0o755); mkdirErr != nil {
						t.Fatal(mkdirErr)
					}
				case "canonical-swap":
					outside := filepath.Join(t.TempDir(), "private.txt")
					if writeErr := os.WriteFile(outside, []byte("outside canonical replacement"), 0o600); writeErr != nil {
						t.Fatal(writeErr)
					}
					if removeErr := os.Remove(path); removeErr != nil {
						t.Fatal(removeErr)
					}
					if linkErr := os.Symlink(outside, path); linkErr != nil {
						t.Fatal(linkErr)
					}
				case "rules":
					indexing.GetIndex("source1").Config.ResolvedRules = settings.ResolvedRulesConfig{
						FilePaths: map[string]settings.ConditionalRule{"/public/nested/inner.txt": {}},
					}
				}
			}
			response := resourceDisplayRequest(t, user, token, "/public")
			if response.Size != inodeSize {
				t.Fatal("aggregate retained a changed, removed or newly excluded contribution")
			}
		})
	}
}

func TestResourceAggregateBudgetsAndReadErrorsDiscardWholeResult(t *testing.T) {
	_, user, token := resourceAggregateFixture(t, true)
	target, resolveErr := resolveAuthenticatedReadTarget(user, "source1", "/public")
	if resolveErr != nil {
		t.Fatal(resolveErr)
	}
	for _, reason := range []string{"entries", "depth", "path-bytes", "deadline", "cancelled", "read-error"} {
		t.Run(reason, func(t *testing.T) {
			limits := resourceAggregateLimits{entries: 100, depth: 32, pathBytes: 4096, batch: 2, duration: time.Second}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch reason {
			case "entries":
				limits.entries = 3 // Shared across the parent, both child directories and files.
			case "depth":
				limits.depth = 1
			case "path-bytes":
				limits.pathBytes = 4
			case "deadline":
				limits.duration = time.Nanosecond
			case "cancelled":
				cancel()
			case "read-error":
				limits.readDir = func(*os.File, int) ([]os.FileInfo, error) { return nil, errors.New("injected bounded directory read failure") }
			}
			walk, collectErr := collectAuthenticatedResourceAggregatesWithLimits(ctx, &requestContext{user: user, token: token}, target, limits)
			if collectErr != nil || walk != nil {
				t.Fatalf("incomplete aggregate must be unavailable: result=%t err=%v", walk != nil, collectErr)
			}
		})
	}
}

func TestResourceAggregateHonorsRoutedAPITokenIntersection(t *testing.T) {
	_, user, _ := resourceAggregateFixture(t, true)
	user.Permissions.Api = true
	if updateErr := store.Users.Update(user, true, "Permissions"); updateErr != nil {
		t.Fatal(updateErr)
	}
	token := issuePermissionReadAPIToken(t, user, "aggregate-no-browse", users.Permissions{Download: true})
	collected := false
	resourceAggregateCollectedHook = func() { collected = true }
	query := url.Values{"source": {"source1"}, "path": {"/public"}}
	request := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	withUser(resourceGetHandler)(recorder, request)
	if recorder.Code != http.StatusForbidden || collected {
		t.Fatal("token without Browse reached aggregate collection")
	}
}

func TestResourceAggregateDoesNotRestoreHiddenDirectFileThroughTotals(t *testing.T) {
	source, user, token := resourceAggregateFixture(t, true)
	inodeSize := resourceAggregateInodeSize(t, source)
	resourceAggregateCollectedHook = func() {
		if denyErr := store.Access.DenyUser(source, "/public/outer.txt", user.Username); denyErr != nil {
			t.Fatal(denyErr)
		}
	}
	response := resourceDisplayRequest(t, user, token, "/public")
	if response.Size != inodeSize || len(response.Files) != 0 {
		t.Fatal("post-collection revocation leaked the direct file or its size")
	}
}

func TestResourceAggregateKeepsScannerHiddenEntrySemantics(t *testing.T) {
	source, user, token := resourceAggregateFixture(t, false)
	root := filepath.Join(source, "public", "scanner-folders")
	if mkdirErr := os.Mkdir(root, 0o755); mkdirErr != nil {
		t.Fatal(mkdirErr)
	}
	for _, name := range []string{"one", "two", "three", "four", ".hiddenDir"} {
		if mkdirErr := os.Mkdir(filepath.Join(root, name), 0o755); mkdirErr != nil {
			t.Fatal(mkdirErr)
		}
	}
	if writeErr := os.WriteFile(filepath.Join(root, ".hiddenDir", "nested.txt"), nil, 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	user.ShowHidden = true
	if updateErr := store.Users.Update(user, true, "ShowHidden"); updateErr != nil {
		t.Fatal(updateErr)
	}
	response := resourceDisplayRequest(t, user, token, "/public/scanner-folders")
	if len(response.Folders) != 5 {
		t.Fatal("aggregate changed the user's hidden-folder listing preference")
	}
	if response.Size != 4*4096 {
		t.Fatalf("scanner total must omit hidden directory contribution: got=%d want=%d", response.Size, 4*4096)
	}
}
