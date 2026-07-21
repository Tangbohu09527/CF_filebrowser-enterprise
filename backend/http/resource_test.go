package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	storm "github.com/asdine/storm/v3"
	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/fileutils"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/database/access"
	dbshare "github.com/gtsteffaniak/filebrowser/backend/database/share"
	dbsql "github.com/gtsteffaniak/filebrowser/backend/database/sql"
	"github.com/gtsteffaniak/filebrowser/backend/database/storage/bolt"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/filebrowser/backend/preview"
)

func TestResourcePutPermissions(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)

	tests := []struct {
		name     string
		path     string
		existing bool
		create   bool
		modify   bool
		status   int
		content  string
	}{
		{
			name:    "new file requires create permission",
			path:    "/public/no-permissions-new.txt",
			create:  false,
			modify:  false,
			status:  http.StatusForbidden,
			content: "created without permission",
		},
		{
			name:    "create permission allows a new file",
			path:    "/public/create-only-new.txt",
			create:  true,
			modify:  false,
			status:  http.StatusOK,
			content: "created with permission",
		},
		{
			name:     "existing file requires modify permission",
			path:     "/public/create-only-existing.txt",
			existing: true,
			create:   true,
			modify:   false,
			status:   http.StatusForbidden,
			content:  "overwritten without permission",
		},
		{
			name:     "modify permission allows overwriting an existing file",
			path:     "/public/modify-only-existing.txt",
			existing: true,
			create:   false,
			modify:   true,
			status:   http.StatusOK,
			content:  "overwritten with permission",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			realPath := filepath.Join(sourcePath, filepath.FromSlash(strings.TrimPrefix(tc.path, "/")))
			if tc.existing {
				if err := os.WriteFile(realPath, []byte("original content"), 0644); err != nil {
					t.Fatal(err)
				}
			}

			user := &users.User{
				Username: tc.name,
				Permissions: users.Permissions{
					Create: tc.create,
					Modify: tc.modify,
				},
				Scopes: []users.SourceScope{
					{Name: sourcePath, Scope: "/"},
				},
			}

			query := url.Values{
				"source": {"source1"},
				"path":   {tc.path},
			}
			req := httptest.NewRequest(http.MethodPut, "/api/resources?"+query.Encode(), strings.NewReader(tc.content))
			w := httptest.NewRecorder()

			status, err := resourcePutHandler(w, req, &requestContext{user: user})
			if status != tc.status {
				t.Errorf("status: expected %d, got %d (err: %v)", tc.status, status, err)
			}

			actualContent, readErr := os.ReadFile(realPath)
			if tc.status == http.StatusForbidden && !tc.existing {
				if readErr == nil {
					t.Errorf("file: expected not to exist, but was created with content %q", actualContent)
				} else if !os.IsNotExist(readErr) {
					t.Errorf("file: expected not to exist, got read error: %v", readErr)
				}
				return
			}

			if readErr != nil {
				t.Errorf("file: expected to exist, got read error: %v", readErr)
				return
			}
			expectedContent := tc.content
			if tc.status == http.StatusForbidden {
				expectedContent = "original content"
			}
			if string(actualContent) != expectedContent {
				t.Errorf("content: expected %q, got %q", expectedContent, actualContent)
			}
		})
	}
}

func TestResourcePostPermissions(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	if preview.GetService() == nil {
		if err := preview.StartPreviewGenerator(1, filepath.Join(filepath.Dir(sourcePath), "preview-cache")); err != nil {
			t.Fatal(err)
		}
	}

	const originalContent = "original content"
	tests := []struct {
		name            string
		path            string
		existing        bool
		override        bool
		create          bool
		modify          bool
		status          int
		content         string
		expectedExists  bool
		expectedContent string
	}{
		{
			name:            "create only creates a missing file",
			path:            "/public/create-only-new-post.txt",
			create:          true,
			status:          http.StatusOK,
			content:         "created with create permission",
			expectedExists:  true,
			expectedContent: "created with create permission",
		},
		{
			name:    "modify only cannot create a missing file",
			path:    "/public/modify-only-new-post.txt",
			modify:  true,
			status:  http.StatusForbidden,
			content: "must not be created with modify permission",
		},
		{
			name:            "create only cannot override an existing file",
			path:            "/public/create-only-existing-post.txt",
			existing:        true,
			override:        true,
			create:          true,
			status:          http.StatusForbidden,
			content:         "unauthorized overwrite",
			expectedExists:  true,
			expectedContent: originalContent,
		},
		{
			name:            "modify only overrides an existing file",
			path:            "/public/modify-only-existing-post.txt",
			existing:        true,
			override:        true,
			modify:          true,
			status:          http.StatusOK,
			content:         "overwritten with modify permission",
			expectedExists:  true,
			expectedContent: "overwritten with modify permission",
		},
		{
			name:            "existing file conflicts without override",
			path:            "/public/no-override-existing-post.txt",
			existing:        true,
			create:          true,
			modify:          true,
			status:          http.StatusConflict,
			content:         "must not replace original content",
			expectedExists:  true,
			expectedContent: originalContent,
		},
		{
			name:            "create only with override creates a missing file",
			path:            "/public/create-only-override-new-post.txt",
			override:        true,
			create:          true,
			status:          http.StatusOK,
			content:         "created with override and create permission",
			expectedExists:  true,
			expectedContent: "created with override and create permission",
		},
		{
			name:     "modify only with override cannot create a missing file",
			path:     "/public/modify-only-override-new-post.txt",
			override: true,
			modify:   true,
			status:   http.StatusForbidden,
			content:  "must not be created by override",
		},
		{
			name:    "no permissions cannot create a missing file",
			path:    "/public/no-permissions-new-post.txt",
			status:  http.StatusForbidden,
			content: "must not be created without permissions",
		},
		{
			name:            "no permissions cannot override an existing file",
			path:            "/public/no-permissions-existing-post.txt",
			existing:        true,
			override:        true,
			status:          http.StatusForbidden,
			content:         "must not overwrite without permissions",
			expectedExists:  true,
			expectedContent: originalContent,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			realPath := filepath.Join(sourcePath, filepath.FromSlash(strings.TrimPrefix(tc.path, "/")))
			if tc.existing {
				if err := os.WriteFile(realPath, []byte(originalContent), 0644); err != nil {
					t.Fatal(err)
				}
			}

			user := &users.User{
				Username: tc.name,
				Permissions: users.Permissions{
					Create: tc.create,
					Modify: tc.modify,
				},
				Scopes: []users.SourceScope{
					{Name: sourcePath, Scope: "/"},
				},
			}

			query := url.Values{
				"source": {"source1"},
				"path":   {tc.path},
			}
			if tc.override {
				query.Set("override", "true")
			}
			req := httptest.NewRequest(http.MethodPost, "/api/resources?"+query.Encode(), strings.NewReader(tc.content))
			w := httptest.NewRecorder()

			status, err := resourcePostHandler(w, req, &requestContext{user: user})
			if status != tc.status {
				t.Errorf("status: expected %d, got %d (err: %v)", tc.status, status, err)
			}

			info, statErr := os.Stat(realPath)
			if tc.expectedExists {
				if statErr != nil {
					t.Errorf("existence: expected file to exist, got stat error: %v", statErr)
				} else if info.IsDir() {
					t.Errorf("existence: expected a file, got a directory")
				}
			} else if statErr == nil {
				t.Errorf("existence: expected file not to exist")
			} else if !os.IsNotExist(statErr) {
				t.Errorf("existence: expected file not to exist, got stat error: %v", statErr)
			}

			actualContent, readErr := os.ReadFile(realPath)
			if !tc.expectedExists {
				if readErr == nil {
					t.Errorf("content: expected no file content, got %q", actualContent)
				} else if !os.IsNotExist(readErr) {
					t.Errorf("content: expected no file content, got read error: %v", readErr)
				}
				return
			}

			if readErr != nil {
				t.Errorf("content: expected %q, got read error: %v", tc.expectedContent, readErr)
				return
			}
			if string(actualContent) != tc.expectedContent {
				t.Errorf("content: expected %q, got %q", tc.expectedContent, actualContent)
			}
		})
	}
}

func TestPublicUploadReplacementPermissions(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	if preview.GetService() == nil {
		if err := preview.StartPreviewGenerator(1, filepath.Join(filepath.Dir(sourcePath), "public-upload-preview-cache")); err != nil {
			t.Fatal(err)
		}
	}

	owner := &users.User{
		Username: "public-upload-owner",
		Permissions: users.Permissions{
			Share:  true,
			Create: true,
			Modify: true,
		},
		Scopes: []users.SourceScope{
			{Name: sourcePath, Scope: "/"},
		},
	}
	if err := store.Users.Save(owner, false, false); err != nil {
		t.Fatalf("save share owner: %v", err)
	}

	publicAPI := http.NewServeMux()
	publicAPI.HandleFunc("POST /resources", withHashFile(publicUploadHandler))
	router := http.NewServeMux()
	router.Handle("/public/api/", http.StripPrefix("/public/api", publicAPI))

	const originalContent = "original public upload content"
	tests := []struct {
		name              string
		shareType         string
		allowCreate       bool
		allowReplacements bool
		existing          bool
		params            url.Values
		uploadContent     string
		expectedStatus    int
		expectedExists    bool
		expectedContent   string
	}{
		{
			name:              "replacement disabled conflicts when no replacement is requested",
			shareType:         "upload",
			allowCreate:       true,
			allowReplacements: false,
			existing:          true,
			uploadContent:     "content from a conflicting upload",
			expectedStatus:    http.StatusConflict,
			expectedExists:    true,
			expectedContent:   originalContent,
		},
		{
			name:              "replacement disabled rejects action override",
			shareType:         "upload",
			allowCreate:       true,
			allowReplacements: false,
			existing:          true,
			params: url.Values{
				"action": {"override"},
			},
			uploadContent:   "content from action override",
			expectedStatus:  http.StatusForbidden,
			expectedExists:  true,
			expectedContent: originalContent,
		},
		{
			name:              "replacement disabled rejects override true",
			shareType:         "upload",
			allowCreate:       true,
			allowReplacements: false,
			existing:          true,
			params: url.Values{
				"override": {"true"},
			},
			uploadContent:   "content from override true",
			expectedStatus:  http.StatusForbidden,
			expectedExists:  true,
			expectedContent: originalContent,
		},
		{
			name:              "replacement disabled rejects other action with override true",
			shareType:         "upload",
			allowCreate:       true,
			allowReplacements: false,
			existing:          true,
			params: url.Values{
				"action":   {"rename"},
				"override": {"true"},
			},
			uploadContent:   "content from another action and override true",
			expectedStatus:  http.StatusForbidden,
			expectedExists:  true,
			expectedContent: originalContent,
		},
		{
			name:              "replacement enabled replaces an existing file",
			shareType:         "upload",
			allowCreate:       true,
			allowReplacements: true,
			existing:          true,
			params: url.Values{
				"override": {"true"},
			},
			uploadContent:   "replacement enabled content",
			expectedStatus:  http.StatusOK,
			expectedExists:  true,
			expectedContent: "replacement enabled content",
		},
		{
			name:              "replacement disabled still permits creating a missing file",
			shareType:         "upload",
			allowCreate:       true,
			allowReplacements: false,
			uploadContent:     "new public upload content",
			expectedStatus:    http.StatusOK,
			expectedExists:    true,
			expectedContent:   "new public upload content",
		},
		{
			name:              "share without create permission rejects a missing file",
			shareType:         "normal",
			allowCreate:       false,
			allowReplacements: false,
			uploadContent:     "content that must not be created",
			expectedStatus:    http.StatusForbidden,
			expectedExists:    false,
			expectedContent:   "",
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filename := fmt.Sprintf("public-upload-permissions-%d.txt", i)
			realPath := filepath.Join(sourcePath, "public", filename)
			if tc.existing {
				if err := os.WriteFile(realPath, []byte(originalContent), 0644); err != nil {
					t.Fatalf("write original file: %v", err)
				}
			}

			hash := fmt.Sprintf("public-upload-permissions-%d", i)
			link := &dbshare.Link{
				Hash:                hash,
				UserID:              owner.ID,
				CapabilityVersion:   dbshare.CurrentCapabilityVersion,
				CreatorCapabilities: dbshare.CapabilitiesFromPermissions(owner.Permissions),
				CommonShare: dbshare.CommonShare{
					Source:            sourcePath,
					Path:              "/public",
					ShareType:         tc.shareType,
					AllowCreate:       tc.allowCreate,
					AllowReplacements: tc.allowReplacements,
				},
			}
			if err := store.Share.Save(link); err != nil {
				t.Fatalf("save test share: %v", err)
			}

			query := url.Values{
				"hash": {hash},
				"path": {"/" + filename},
			}
			for key, values := range tc.params {
				for _, value := range values {
					query.Add(key, value)
				}
			}
			req := httptest.NewRequest(http.MethodPost, "/public/api/resources?"+query.Encode(), strings.NewReader(tc.uploadContent))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)
			if w.Code != tc.expectedStatus {
				t.Errorf("status: expected %d, got %d", tc.expectedStatus, w.Code)
			}

			info, statErr := os.Stat(realPath)
			if tc.expectedExists {
				if statErr != nil {
					t.Errorf("existence: expected file to exist, got stat error: %v", statErr)
				} else if info.IsDir() {
					t.Errorf("existence: expected a file, got a directory")
				}
			} else if statErr == nil {
				t.Errorf("existence: expected file not to exist")
			} else if !os.IsNotExist(statErr) {
				t.Errorf("existence: expected file not to exist, got stat error: %v", statErr)
			}

			actualContent, readErr := os.ReadFile(realPath)
			if !tc.expectedExists {
				if readErr == nil {
					t.Errorf("content: expected no file content, got %q", actualContent)
				} else if !os.IsNotExist(readErr) {
					t.Errorf("content: expected no file content, got read error: %v", readErr)
				}
				return
			}
			if readErr != nil {
				t.Errorf("content: expected %q, got read error: %v", tc.expectedContent, readErr)
				return
			}
			if string(actualContent) != tc.expectedContent {
				t.Errorf("content: expected %q, got %q", tc.expectedContent, actualContent)
			}
		})
	}
}

func TestAPITokenPermissionScope(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)

	previousAuth := settings.Config.Auth
	testAuth := settings.Auth{Key: "api-token-permission-scope-test-key"}
	config.Auth = testAuth
	settings.Config.Auth = testAuth
	t.Cleanup(func() {
		settings.Config.Auth = previousAuth
	})

	if preview.GetService() == nil {
		if err := preview.StartPreviewGenerator(1, filepath.Join(filepath.Dir(sourcePath), "token-preview-cache")); err != nil {
			t.Fatal(err)
		}
	}

	api := http.NewServeMux()
	api.HandleFunc("POST /resources", withUser(resourcePostHandler))
	api.HandleFunc("PATCH /resources", withUser(resourcePatchHandler))
	router := http.NewServeMux()
	router.Handle("/api/", http.StripPrefix("/api", api))

	createTests := []struct {
		name                   string
		username               string
		path                   string
		content                string
		userPermissionsAtIssue users.Permissions
		tokenPermissions       users.Permissions
		userPermissionsAtUse   users.Permissions
		expectedStatus         int
	}{
		{
			name:     "token without create cannot use user create permission",
			username: "token-create-denied",
			path:     "/public/token-create-denied.txt",
			content:  "created through an over-privileged token",
			userPermissionsAtIssue: users.Permissions{
				Api:    true,
				Create: true,
				Modify: true,
			},
			tokenPermissions: users.Permissions{
				Modify: true,
			},
			userPermissionsAtUse: users.Permissions{
				Api:    true,
				Create: true,
				Modify: true,
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:     "token and user with create can create a file",
			username: "token-create-allowed",
			path:     "/public/token-create-allowed.txt",
			content:  "created through an allowed token",
			userPermissionsAtIssue: users.Permissions{
				Api:    true,
				Create: true,
				Modify: true,
			},
			tokenPermissions: users.Permissions{
				Create: true,
			},
			userPermissionsAtUse: users.Permissions{
				Api:    true,
				Create: true,
				Modify: true,
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:     "token create cannot exceed current user permission",
			username: "token-capped-by-user",
			path:     "/public/token-capped-by-user.txt",
			content:  "must not exceed current user permission",
			userPermissionsAtIssue: users.Permissions{
				Api:    true,
				Create: true,
			},
			tokenPermissions: users.Permissions{
				Create: true,
			},
			userPermissionsAtUse: users.Permissions{
				Api:    true,
				Create: false,
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:     "old narrow token cannot gain later user create permission",
			username: "token-later-user-grant",
			path:     "/public/token-later-user-grant.txt",
			content:  "created after user permission leaked into token",
			userPermissionsAtIssue: users.Permissions{
				Api:    true,
				Create: false,
				Modify: true,
			},
			tokenPermissions: users.Permissions{
				Modify: true,
			},
			userPermissionsAtUse: users.Permissions{
				Api:    true,
				Create: true,
				Modify: true,
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:     "token immediately loses revoked user create permission",
			username: "token-user-permission-revoked",
			path:     "/public/token-user-permission-revoked.txt",
			content:  "must not survive user permission revocation",
			userPermissionsAtIssue: users.Permissions{
				Api:    true,
				Create: true,
			},
			tokenPermissions: users.Permissions{
				Create: true,
			},
			userPermissionsAtUse: users.Permissions{
				Api:    true,
				Create: false,
			},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tc := range createTests {
		t.Run(tc.name, func(t *testing.T) {
			user := saveAPITokenTestUser(t, tc.username, sourcePath, tc.userPermissionsAtIssue)
			token := createAPITokenForTest(t, user, tc.username+"-token", tc.tokenPermissions)
			updateAPITokenTestUserPermissions(t, user, tc.userPermissionsAtUse)

			query := url.Values{
				"source": {"source1"},
				"path":   {tc.path},
			}
			req := httptest.NewRequest(http.MethodPost, "/api/resources?"+query.Encode(), strings.NewReader(tc.content))
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)
			if w.Code != tc.expectedStatus {
				t.Errorf("status: expected %d, got %d", tc.expectedStatus, w.Code)
			}

			realPath := filepath.Join(sourcePath, filepath.FromSlash(strings.TrimPrefix(tc.path, "/")))
			assertAPITokenFileState(t, realPath, w.Code == http.StatusOK, tc.content)
		})
	}

	modifyTests := []struct {
		name             string
		username         string
		fromPath         string
		toPath           string
		content          string
		userPermissions  users.Permissions
		tokenPermissions users.Permissions
		expectedStatus   int
	}{
		{
			name:     "token without modify cannot rename with user modify permission",
			username: "token-modify-denied",
			fromPath: "/public/token-modify-denied-source.txt",
			toPath:   "/public/token-modify-denied-destination.txt",
			content:  "renamed through an over-privileged token",
			userPermissions: users.Permissions{
				Api:    true,
				Create: true,
				Modify: true,
			},
			tokenPermissions: users.Permissions{
				Create: true,
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:     "token and user with modify can rename",
			username: "token-modify-allowed",
			fromPath: "/public/token-modify-allowed-source.txt",
			toPath:   "/public/token-modify-allowed-destination.txt",
			content:  "renamed through an allowed token",
			userPermissions: users.Permissions{
				Api:    true,
				Create: true,
				Modify: true,
			},
			tokenPermissions: users.Permissions{
				Modify: true,
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range modifyTests {
		t.Run(tc.name, func(t *testing.T) {
			user := saveAPITokenTestUser(t, tc.username, sourcePath, tc.userPermissions)
			token := createAPITokenForTest(t, user, tc.username+"-token", tc.tokenPermissions)

			realFromPath := filepath.Join(sourcePath, filepath.FromSlash(strings.TrimPrefix(tc.fromPath, "/")))
			realToPath := filepath.Join(sourcePath, filepath.FromSlash(strings.TrimPrefix(tc.toPath, "/")))
			if err := os.WriteFile(realFromPath, []byte(tc.content), 0644); err != nil {
				t.Fatal(err)
			}

			body, err := json.Marshal(MoveCopyRequest{
				Items: []MoveCopyItem{
					{
						FromSource: "source1",
						FromPath:   tc.fromPath,
						ToSource:   "source1",
						ToPath:     tc.toPath,
					},
				},
				Action: "rename",
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPatch, "/api/resources", strings.NewReader(string(body)))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)
			if w.Code != tc.expectedStatus {
				t.Errorf("status: expected %d, got %d", tc.expectedStatus, w.Code)
			}

			assertAPITokenRenameState(t, realFromPath, realToPath, tc.content, w.Code == http.StatusOK)
		})
	}

	t.Run("authentication intersects user and token permissions", func(t *testing.T) {
		userPermissions := users.Permissions{
			Api:    true,
			Create: true,
			Modify: true,
			Delete: true,
		}
		tokenPermissions := users.Permissions{
			Create: false,
			Modify: true,
			Delete: false,
		}
		user := saveAPITokenTestUser(t, "token-auth-intersection", sourcePath, userPermissions)
		token := createAPITokenForTest(t, user, "token-auth-intersection-token", tokenPermissions)

		var effectivePermissions users.Permissions
		probe := withUserHelper(func(_ http.ResponseWriter, _ *http.Request, d *requestContext) (int, error) {
			effectivePermissions = d.user.Permissions
			return http.StatusOK, nil
		})
		req := httptest.NewRequest(http.MethodGet, "/api/token-permission-probe", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		status, err := probe(w, req, &requestContext{})
		if err != nil {
			t.Errorf("authentication: unexpected error: %v", err)
		}
		if status != http.StatusOK {
			t.Errorf("authentication status: expected %d, got %d", http.StatusOK, status)
		}
		if effectivePermissions.Create {
			t.Errorf("effective create permission: expected false, got true")
		}
		if !effectivePermissions.Modify {
			t.Errorf("effective modify permission: expected true, got false")
		}
		if effectivePermissions.Delete {
			t.Errorf("effective delete permission: expected false, got true")
		}
	})
}

func saveAPITokenTestUser(t *testing.T, username, sourcePath string, permissions users.Permissions) *users.User {
	t.Helper()

	user := &users.User{
		Username:    username,
		Permissions: permissions,
		Scopes: []users.SourceScope{
			{Name: sourcePath, Scope: "/"},
		},
	}
	if err := store.Users.Save(user, false, false); err != nil {
		t.Fatal(err)
	}
	if user.ID == 0 {
		t.Fatal("saved API token test user has no ID")
	}
	return user
}

func createAPITokenForTest(t *testing.T, user *users.User, name string, permissions users.Permissions) string {
	t.Helper()

	permissionNames := make([]string, 0, 8)
	if permissions.Api {
		permissionNames = append(permissionNames, "api")
	}
	if permissions.Admin {
		permissionNames = append(permissionNames, "admin")
	}
	if permissions.Modify {
		permissionNames = append(permissionNames, "modify")
	}
	if permissions.Delete {
		permissionNames = append(permissionNames, "delete")
	}
	if permissions.Create {
		permissionNames = append(permissionNames, "create")
	}
	if permissions.Share {
		permissionNames = append(permissionNames, "share")
	}
	if permissions.Realtime {
		permissionNames = append(permissionNames, "realtime")
	}
	if permissions.Download {
		permissionNames = append(permissionNames, "download")
	}
	if len(permissionNames) == 0 {
		t.Fatal("API token test requires a non-minimal token")
	}

	query := url.Values{
		"name":        {name},
		"days":        {"1"},
		"permissions": {strings.Join(permissionNames, ",")},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/auth/token?"+query.Encode(), nil)
	w := httptest.NewRecorder()
	status, err := createApiTokenHandler(w, req, &requestContext{user: user})
	if err != nil || status != http.StatusOK {
		t.Fatalf("create API token: expected status %d, got %d (err: %v)", http.StatusOK, status, err)
	}

	var response HttpResponse
	if decodeErr := json.NewDecoder(w.Body).Decode(&response); decodeErr != nil {
		t.Fatalf("decode API token response: %v", decodeErr)
	}
	if response.Token == "" {
		t.Fatal("create API token returned an empty token")
	}

	storedUser, err := store.Users.Get(user.ID)
	if err != nil {
		t.Fatalf("load API token user: %v", err)
	}
	storedToken, ok := storedUser.Tokens[name]
	if !ok {
		t.Fatal("created API token was not stored on the user")
	}
	if storedToken.Permissions != permissions {
		t.Fatalf("stored API token permissions: expected %+v, got %+v", permissions, storedToken.Permissions)
	}

	return response.Token
}

func updateAPITokenTestUserPermissions(t *testing.T, user *users.User, permissions users.Permissions) {
	t.Helper()

	user.Permissions = permissions
	if err := store.Users.Update(user, true, "Permissions"); err != nil {
		t.Fatal(err)
	}
}

func assertAPITokenFileState(t *testing.T, realPath string, expectedExists bool, expectedContent string) {
	t.Helper()

	info, statErr := os.Stat(realPath)
	if expectedExists {
		if statErr != nil {
			t.Errorf("existence: expected file to exist, got stat error: %v", statErr)
		} else if info.IsDir() {
			t.Errorf("existence: expected a file, got a directory")
		}
	} else if statErr == nil {
		t.Errorf("existence: expected file not to exist")
	} else if !os.IsNotExist(statErr) {
		t.Errorf("existence: expected file not to exist, got stat error: %v", statErr)
	}

	actualContent, readErr := os.ReadFile(realPath)
	if !expectedExists {
		if readErr == nil {
			t.Errorf("content: expected no file content, got %q", actualContent)
		} else if !os.IsNotExist(readErr) {
			t.Errorf("content: expected no file content, got read error: %v", readErr)
		}
		return
	}
	if readErr != nil {
		t.Errorf("content: expected %q, got read error: %v", expectedContent, readErr)
		return
	}
	if string(actualContent) != expectedContent {
		t.Errorf("content: expected %q, got %q", expectedContent, actualContent)
	}
}

func assertAPITokenRenameState(t *testing.T, realFromPath, realToPath, expectedContent string, renamed bool) {
	t.Helper()

	if renamed {
		assertAPITokenFileState(t, realFromPath, false, "")
		assertAPITokenFileState(t, realToPath, true, expectedContent)
		return
	}
	assertAPITokenFileState(t, realFromPath, true, expectedContent)
	assertAPITokenFileState(t, realToPath, false, "")
}

func setupResourcePutTestEnv(t *testing.T) string {
	t.Helper()

	tempDir := t.TempDir()
	sourcePath := filepath.Join(tempDir, "source1")
	if err := os.MkdirAll(filepath.Join(sourcePath, "public"), 0755); err != nil {
		t.Fatal(err)
	}

	db, err := storm.Open(filepath.Join(tempDir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("close test database: %v", closeErr)
		}
	})

	previousStore := store
	previousConfig := config
	previousCacheDir := settings.Config.Server.CacheDir
	previousSourceMap := settings.Config.Server.SourceMap
	previousNameToSource := settings.Config.Server.NameToSource
	t.Cleanup(func() {
		store = previousStore
		config = previousConfig
		settings.Config.Server.CacheDir = previousCacheDir
		settings.Config.Server.SourceMap = previousSourceMap
		settings.Config.Server.NameToSource = previousNameToSource
		settings.InitializeUserResolvers()
	})

	store, err = bolt.NewStorage(db)
	if err != nil {
		t.Fatal(err)
	}
	store.Access.AllRules = make(access.SourceRuleMap)
	store.Access.Groups = make(access.GroupMap)

	source := &settings.Source{
		Path: sourcePath,
		Name: "source1",
		Config: settings.SourceConfig{
			ResolvedRules: settings.ResolvedRulesConfig{
				IndexingDisabled: true,
				NoRules:          true,
			},
		},
	}
	config = &settings.Settings{
		Server: settings.Server{
			CacheDir: tempDir,
			SourceMap: map[string]*settings.Source{
				sourcePath: source,
			},
			NameToSource: map[string]*settings.Source{
				"source1": source,
			},
		},
	}
	settings.Config.Server.CacheDir = tempDir
	settings.Config.Server.SourceMap = config.Server.SourceMap
	settings.Config.Server.NameToSource = config.Server.NameToSource
	settings.InitializeUserResolvers()

	previousFilePerm := fileutils.PermFile
	previousDirPerm := fileutils.PermDir
	fileutils.SetFsPermissions(0644, 0755)
	t.Cleanup(func() {
		fileutils.PermFile = previousFilePerm
		fileutils.PermDir = previousDirPerm
	})
	previousIndexDB := indexing.GetIndexDB()
	indexDB, _, err := dbsql.NewIndexDB("resource_put_permissions", "OFF", 1000, 32, false)
	if err != nil {
		t.Fatal(err)
	}
	indexing.SetIndexDBForTesting(indexDB)
	indexing.Initialize(source, false, false)
	t.Cleanup(func() {
		indexing.StopAllScanners()
		indexing.ClearTestIndices()
		indexing.SetIndexDBForTesting(previousIndexDB)
		if err := indexDB.Close(); err != nil {
			t.Errorf("close test index database: %v", err)
		}
	})

	return sourcePath
}
