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
	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	commonerrors "github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/access"
	"github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/storage/bolt"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
)

func setupPermissionWebDAVSecurityTestEnv(t *testing.T) (string, string) {
	t.Helper()

	tempDir := t.TempDir()
	source1Path := filepath.Join(tempDir, "source1")
	source2Path := filepath.Join(tempDir, "source2")
	for _, dir := range []string{
		filepath.Join(source1Path, "public"),
		filepath.Join(source2Path, "shared"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("create WebDAV permission test directory: %v", err)
		}
	}
	for path, content := range map[string]string{
		filepath.Join(source1Path, "public", "readme.txt"):   "public content",
		filepath.Join(source2Path, "shared", "document.txt"): "shared content",
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("create WebDAV permission test file: %v", err)
		}
	}

	db, err := storm.Open(filepath.Join(tempDir, "permission-webdav.db"))
	if err != nil {
		t.Fatalf("open WebDAV permission test database: %v", err)
	}
	testStore, err := bolt.NewStorage(db)
	if err != nil {
		_ = db.Close()
		t.Fatalf("create WebDAV permission test storage: %v", err)
	}
	testStore.Access.AllRules = make(access.SourceRuleMap)
	testStore.Access.Groups = make(access.GroupMap)

	previousConfig := config
	previousStore := store
	previousSettingsServer := settings.Config.Server
	previousCheckPermissions := files.CheckPermissionsFunc
	previousFileInfoFaster := files.FileInfoFasterFunc

	testServer := settings.Server{
		BaseURL:  "/",
		CacheDir: tempDir,
		SourceMap: map[string]*settings.Source{
			source1Path: {Path: source1Path, Name: "source1"},
			source2Path: {Path: source2Path, Name: "source2"},
		},
		NameToSource: map[string]*settings.Source{
			"source1": {Path: source1Path, Name: "source1"},
			"source2": {Path: source2Path, Name: "source2"},
		},
	}
	config = &settings.Settings{Server: testServer}
	store = testStore
	settings.Config.Server = testServer
	settings.InitializeUserResolvers()

	indexing.SetTestIndex("source1", source1Path)
	indexing.SetTestIndex("source2", source2Path)
	installPermissionWebDAVSecurityFilesystemMocks(source1Path, source2Path)

	t.Cleanup(func() {
		files.CheckPermissionsFunc = previousCheckPermissions
		files.FileInfoFasterFunc = previousFileInfoFaster
		indexing.ClearTestIndices()
		config = previousConfig
		store = previousStore
		settings.Config.Server = previousSettingsServer
		settings.InitializeUserResolvers()
		if err := db.Close(); err != nil {
			t.Errorf("close WebDAV permission test database: %v", err)
		}
	})

	return source1Path, source2Path
}

func installPermissionWebDAVSecurityFilesystemMocks(source1Path, source2Path string) {
	resolveSource := func(source string) (string, error) {
		switch source {
		case "source1":
			return source1Path, nil
		case "source2":
			return source2Path, nil
		default:
			return "", fmt.Errorf("unknown source %q", source)
		}
	}
	resolvePath := func(opts utils.FileOptions, user *users.User) (string, string, string, error) {
		sourcePath, err := resolveSource(opts.Source)
		if err != nil {
			return "", "", "", err
		}
		userScope, err := user.GetScopeForSourcePath(sourcePath)
		if err != nil {
			return "", "", "", commonerrors.ErrAccessDenied
		}
		safePath, err := utils.SanitizeUserPath(opts.Path)
		if err != nil {
			return "", "", "", commonerrors.ErrAccessDenied
		}
		indexPath := utils.JoinPathAsUnix(userScope, safePath)
		realPath := filepath.Join(sourcePath, filepath.FromSlash(strings.TrimPrefix(indexPath, "/")))
		return sourcePath, userScope, realPath, nil
	}

	files.CheckPermissionsFunc = func(opts utils.FileOptions, accessStorage *access.Storage, user *users.User) (string, string, error) {
		sourcePath, userScope, _, err := resolvePath(opts, user)
		if err != nil {
			return "", "", err
		}
		safePath, err := utils.SanitizeUserPath(opts.Path)
		if err != nil {
			return "", "", commonerrors.ErrAccessDenied
		}
		indexPath := utils.JoinPathAsUnix(userScope, safePath)
		if accessStorage != nil && !accessStorage.Permitted(sourcePath, indexPath, user.Username) {
			return "", "", commonerrors.ErrAccessDenied
		}
		return indexPath, userScope, nil
	}

	files.FileInfoFasterFunc = func(opts utils.FileOptions, accessStorage *access.Storage, user *users.User, _ *share.Storage) (*iteminfo.ExtendedFileInfo, error) {
		sourcePath, userScope, realPath, err := resolvePath(opts, user)
		if err != nil {
			return nil, err
		}
		safePath, err := utils.SanitizeUserPath(opts.Path)
		if err != nil {
			return nil, commonerrors.ErrAccessDenied
		}
		indexPath := utils.JoinPathAsUnix(userScope, safePath)
		if accessStorage != nil && !accessStorage.Permitted(sourcePath, indexPath, user.Username) {
			return nil, commonerrors.ErrAccessDenied
		}

		stat, err := os.Stat(realPath)
		if err != nil {
			return nil, err
		}
		itemType := "text/plain"
		if stat.IsDir() {
			itemType = "directory"
		}
		result := &iteminfo.ExtendedFileInfo{
			FileInfo: iteminfo.FileInfo{
				Path: opts.Path,
				ItemInfo: iteminfo.ItemInfo{
					Name:    stat.Name(),
					Size:    stat.Size(),
					ModTime: stat.ModTime(),
					Type:    itemType,
				},
			},
		}
		if !opts.Expand || !stat.IsDir() {
			return result, nil
		}

		entries, err := os.ReadDir(realPath)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			entryInfo, err := entry.Info()
			if err != nil {
				return nil, err
			}
			entryType := "text/plain"
			if entryInfo.IsDir() {
				entryType = "directory"
			}
			entryItem := iteminfo.ItemInfo{
				Name:    entryInfo.Name(),
				Size:    entryInfo.Size(),
				ModTime: entryInfo.ModTime(),
				Type:    entryType,
			}
			if entryInfo.IsDir() {
				result.Folders = append(result.Folders, entryItem)
			} else {
				result.Files = append(result.Files, iteminfo.ExtendedItemInfo{ItemInfo: entryItem})
			}
		}
		return result, nil
	}
}

func setFutureReadPermission(t *testing.T, permissions *users.Permissions, name string, value bool) {
	t.Helper()

	switch name {
	case "Browse":
		permissions.Browse = value
	default:
		t.Fatalf("unknown read permission %q", name)
	}
}

func assertNoPermissionWebDAVOriginalHeaders(t *testing.T, headers http.Header) {
	t.Helper()

	for _, name := range []string{
		"Accept-Ranges",
		"Content-Length",
		"Content-Range",
		"Content-Disposition",
		"ETag",
		"Last-Modified",
	} {
		if value := headers.Get(name); value != "" {
			t.Errorf("unauthorized WebDAV response leaked %s %q", name, value)
		}
	}
	if contentType := headers.Get("Content-Type"); strings.HasPrefix(strings.ToLower(contentType), "text/plain") {
		t.Errorf("unauthorized WebDAV response leaked original Content-Type %q", contentType)
	}
}

func configurePermissionWebDAVAuth(t *testing.T) {
	t.Helper()

	previousConfigAuth := config.Auth
	previousSettingsAuth := settings.Config.Auth
	testAuth := settings.Auth{Key: "permission-webdav-security-test-key"}
	config.Auth = testAuth
	settings.Config.Auth = testAuth
	t.Cleanup(func() {
		config.Auth = previousConfigAuth
		settings.Config.Auth = previousSettingsAuth
	})
}

func savePermissionWebDAVUser(t *testing.T, user *users.User) {
	t.Helper()

	user.Permissions.Api = true
	if err := store.Users.Save(user, false, false); err != nil {
		t.Fatalf("save WebDAV permission test user: %v", err)
	}
}

func issuePermissionWebDAVAPIToken(t *testing.T, user *users.User, name string, permissions users.Permissions) string {
	t.Helper()

	permissionNames := make([]string, 0, 2)
	if permissions.Browse {
		permissionNames = append(permissionNames, "browse")
	}
	if permissions.Download {
		permissionNames = append(permissionNames, "download")
	}
	if len(permissionNames) == 0 {
		t.Fatal("WebDAV permission test requires a non-minimal API token")
	}

	query := url.Values{
		"name":        {name},
		"days":        {"1"},
		"permissions": {strings.Join(permissionNames, ",")},
	}
	request := httptest.NewRequest(http.MethodPost, "/api/auth/token?"+query.Encode(), nil)
	response := httptest.NewRecorder()
	status, err := createApiTokenHandler(response, request, &requestContext{user: user})
	if err != nil || status != http.StatusOK {
		t.Fatalf("create WebDAV permission API token: status=%d err=%v", status, err)
	}

	var payload HttpResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode WebDAV permission API token: %v", err)
	}
	if payload.Token == "" {
		t.Fatal("WebDAV permission API token is empty")
	}
	return payload.Token
}
