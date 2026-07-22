package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/access"
	dbshare "github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
)

type permissionMediaSecurityHarness struct {
	sourcePath string
	audioPath  string
	videoPath  string
}

func newPermissionMediaSecurityHarness(t *testing.T) *permissionMediaSecurityHarness {
	t.Helper()

	sourcePath := setupResourcePutTestEnv(t)
	audioPath := filepath.Join(sourcePath, "public", "media-audio.mp3")
	videoPath := filepath.Join(sourcePath, "public", "media-video.mp4")
	if err := os.WriteFile(audioPath, permissionReadID3Audio("authorized media title"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(videoPath, []byte("permission-media-video"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourcePath, "public", "media-video.srt"), []byte("permission media subtitle"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourcePath, "public", "media-audio.lrc"), []byte("[00:01.00]permission media lyric\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	idx := indexing.GetIndex("source1")
	if idx == nil {
		t.Fatal("source1 index was not initialized")
	}
	idx.CreateMockData(1, 1)

	return &permissionMediaSecurityHarness{
		sourcePath: sourcePath,
		audioPath:  audioPath,
		videoPath:  videoPath,
	}
}

func (h *permissionMediaSecurityHarness) user(browse, previewAllowed, download bool) *users.User {
	return &users.User{
		Username: "permission-media-user",
		Permissions: users.Permissions{
			Browse:   browse,
			Preview:  previewAllowed,
			Download: download,
		},
		Scopes: []users.SourceScope{{Name: h.sourcePath, Scope: "/"}},
	}
}

func permissionMediaRequest(handler handleFunc, path string, query url.Values, user *users.User) (int, *httptest.ResponseRecorder, error) {
	req := httptest.NewRequest(http.MethodGet, path+"?"+query.Encode(), nil)
	recorder := httptest.NewRecorder()
	returned, err := handler(recorder, req, &requestContext{user: user})
	return permissionHandlerStatus(returned, recorder), recorder, err
}

func permissionMediaAPIRouter() *http.ServeMux {
	api := http.NewServeMux()
	api.HandleFunc("GET /media/metadata", withUser(metadataHandler))
	api.HandleFunc("GET /media/subtitles", withUser(subtitlesHandler))
	api.HandleFunc("GET /media/lyrics", withUser(lyricsHandler))
	router := http.NewServeMux()
	router.Handle("/api/", http.StripPrefix("/api", api))
	return router
}

func permissionMediaTokenRequest(router http.Handler, token, path string, query url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path+"?"+query.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func TestPermissionMediaSecurity_PermissionChecksPrecedeLookup(t *testing.T) {
	h := newPermissionMediaSecurityHarness(t)

	tests := []struct {
		name    string
		handler handleFunc
		path    string
		query   url.Values
		user    *users.User
	}{
		{
			name:    "metadata requires Browse",
			handler: metadataHandler,
			path:    "/api/media/metadata",
			query:   url.Values{"source": {"source1"}, "path": {"/public/media-audio.mp3"}},
			user:    h.user(false, true, true),
		},
		{
			name:    "album art requires Preview",
			handler: metadataHandler,
			path:    "/api/media/metadata",
			query:   url.Values{"source": {"source1"}, "path": {"/public/media-audio.mp3"}, "albumArt": {"true"}},
			user:    h.user(true, false, true),
		},
		{
			name:    "subtitles require Download",
			handler: subtitlesHandler,
			path:    "/api/media/subtitles",
			query: url.Values{
				"source": {"source1"}, "path": {"/public/media-video.mp4"},
				"name": {"media-video.srt"}, "embedded": {"false"},
			},
			user: h.user(true, true, false),
		},
		{
			name:    "lyrics require Download",
			handler: lyricsHandler,
			path:    "/api/media/lyrics",
			query:   url.Values{"source": {"source1"}, "path": {"/public/media-audio.mp3"}},
			user:    h.user(true, true, false),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := files.FileInfoFasterFunc
			calls := 0
			files.FileInfoFasterFunc = func(opts utils.FileOptions, accessStorage *access.Storage, user *users.User, shareStorage *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
				calls++
				return original(opts, accessStorage, user, shareStorage)
			}
			t.Cleanup(func() { files.FileInfoFasterFunc = original })

			status, recorder, err := permissionMediaRequest(test.handler, test.path, test.query, test.user)
			assertPermissionReadDenied(t, status, err, test.name)
			if calls != 0 {
				t.Errorf("permission denial performed %d FileInfo lookup(s), want 0", calls)
			}
			if recorder.Body.Len() != 0 {
				t.Errorf("permission denial emitted body %q", recorder.Body.Bytes())
			}
		})
	}
}

func TestPermissionMediaSecurity_BrowseOnlyOmitsDerivedMetadata(t *testing.T) {
	h := newPermissionMediaSecurityHarness(t)
	user := h.user(true, false, false)

	original := files.FileInfoFasterFunc
	var calls []utils.FileOptions
	files.FileInfoFasterFunc = func(opts utils.FileOptions, accessStorage *access.Storage, currentUser *users.User, shareStorage *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
		calls = append(calls, opts)
		return original(opts, accessStorage, currentUser, shareStorage)
	}
	t.Cleanup(func() { files.FileInfoFasterFunc = original })

	status, recorder, err := permissionMediaRequest(metadataHandler, "/api/media/metadata", url.Values{
		"source": {"source1"}, "path": {"/public/media-audio.mp3"},
	}, user)
	if status != http.StatusOK || err != nil {
		t.Fatalf("Browse-only metadata status: got %d, want %d (err: %v)", status, http.StatusOK, err)
	}
	var response iteminfo.ExtendedFileInfo
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Name != "media-audio.mp3" || response.Path != "/public/media-audio.mp3" {
		t.Errorf("Browse-only basic metadata = name %q path %q", response.Name, response.Path)
	}
	if response.Metadata != nil || len(response.Subtitles) != 0 {
		t.Errorf("Browse-only response exposed derived metadata: metadata=%+v subtitles=%+v", response.Metadata, response.Subtitles)
	}
	for _, opts := range calls {
		if opts.Metadata || opts.AlbumArt || opts.ReadPath != "" {
			t.Errorf("Browse-only request triggered a protected media read: %+v", opts)
		}
	}
}

func TestPermissionMediaSecurity_RevocationPreventsConversion(t *testing.T) {
	h := newPermissionMediaSecurityHarness(t)
	user := h.user(true, true, false)
	user.Username = "permission-media-revocation-user"
	savePermissionReadUser(t, user)

	original := files.FileInfoFasterFunc
	calls := 0
	converterCalls := 0
	files.FileInfoFasterFunc = func(opts utils.FileOptions, accessStorage *access.Storage, currentUser *users.User, shareStorage *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
		calls++
		if opts.Metadata || opts.AlbumArt || opts.ReadPath != "" {
			converterCalls++
		}
		response, err := original(opts, accessStorage, currentUser, shareStorage)
		if calls == 1 && err == nil {
			revoked := *user
			revoked.Permissions.Preview = false
			if updateErr := store.Users.Update(&revoked, true, "Permissions"); updateErr != nil {
				return nil, updateErr
			}
		}
		return response, err
	}
	t.Cleanup(func() { files.FileInfoFasterFunc = original })

	status, recorder, err := permissionMediaRequest(metadataHandler, "/api/media/metadata", url.Values{
		"source": {"source1"}, "path": {"/public/media-audio.mp3"},
	}, user)
	assertPermissionReadDenied(t, status, err, "revoked metadata conversion")
	if calls != 1 || converterCalls != 0 {
		t.Errorf("revoked conversion calls: total=%d converter=%d, want 1/0", calls, converterCalls)
	}
	if bytes.Contains(recorder.Body.Bytes(), []byte("authorized media title")) {
		t.Errorf("revoked metadata leaked response %q", recorder.Body.Bytes())
	}
}

func TestPermissionMediaSecurity_SnapshotCompletionRechecksBeforeConversion(t *testing.T) {
	h := newPermissionMediaSecurityHarness(t)
	user := h.user(true, true, false)
	user.Username = "permission-media-snapshot-revocation-user"
	savePermissionReadUser(t, user)

	previousSnapshotHook := authenticatedReadSnapshotCompleteHook
	hookCalls := 0
	authenticatedReadSnapshotCompleteHook = func() {
		hookCalls++
		updated := *user
		updated.Permissions.Preview = false
		if err := store.Users.Update(&updated, true, "Permissions"); err != nil {
			t.Errorf("revoke Preview after media snapshot: %v", err)
		}
	}
	t.Cleanup(func() { authenticatedReadSnapshotCompleteHook = previousSnapshotHook })

	original := files.FileInfoFasterFunc
	converterCalls := 0
	files.FileInfoFasterFunc = func(opts utils.FileOptions, accessStorage *access.Storage, currentUser *users.User, shareStorage *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
		if opts.Metadata || opts.AlbumArt || opts.ReadPath != "" {
			converterCalls++
		}
		return original(opts, accessStorage, currentUser, shareStorage)
	}
	t.Cleanup(func() { files.FileInfoFasterFunc = original })

	status, recorder, err := permissionMediaRequest(metadataHandler, "/api/media/metadata", url.Values{
		"source": {"source1"}, "path": {"/public/media-audio.mp3"},
	}, user)
	assertPermissionReadDenied(t, status, err, "snapshot-complete metadata revocation")
	if hookCalls != 1 || converterCalls != 0 {
		t.Errorf("snapshot-complete revocation calls: hook=%d converter=%d, want 1/0", hookCalls, converterCalls)
	}
	if bytes.Contains(recorder.Body.Bytes(), []byte("authorized media title")) {
		t.Errorf("snapshot-complete revocation leaked metadata %q", recorder.Body.Bytes())
	}
}

func TestPermissionMediaSecurity_MetadataUsesStableSnapshot(t *testing.T) {
	h := newPermissionMediaSecurityHarness(t)
	replacementPath := h.audioPath + ".replacement"
	backupPath := h.audioPath + ".original"
	replacementTitle := "replacement media secret"
	if err := os.WriteFile(replacementPath, permissionReadID3Audio(replacementTitle), 0o644); err != nil {
		t.Fatal(err)
	}

	original := files.FileInfoFasterFunc
	conversionCalls := 0
	var readPath string
	files.FileInfoFasterFunc = func(opts utils.FileOptions, accessStorage *access.Storage, currentUser *users.User, shareStorage *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
		if !opts.Metadata {
			return original(opts, accessStorage, currentUser, shareStorage)
		}
		conversionCalls++
		readPath = opts.ReadPath
		if err := os.Rename(h.audioPath, backupPath); err != nil {
			return nil, err
		}
		if err := os.Rename(replacementPath, h.audioPath); err != nil {
			_ = os.Rename(backupPath, h.audioPath)
			return nil, err
		}
		response, readErr := original(opts, accessStorage, currentUser, shareStorage)
		restoreErr := os.Rename(h.audioPath, replacementPath)
		if restoreErr == nil {
			restoreErr = os.Rename(backupPath, h.audioPath)
		}
		if readErr != nil {
			return response, readErr
		}
		return response, restoreErr
	}
	t.Cleanup(func() { files.FileInfoFasterFunc = original })

	status, recorder, err := permissionMediaRequest(metadataHandler, "/api/media/metadata", url.Values{
		"source": {"source1"}, "path": {"/public/media-audio.mp3"},
	}, h.user(true, true, false))
	if status != http.StatusOK || err != nil {
		t.Fatalf("stable metadata status: got %d, want %d (err: %v)", status, http.StatusOK, err)
	}
	if conversionCalls != 1 || readPath == "" || strings.EqualFold(readPath, h.audioPath) {
		t.Errorf("metadata conversion did not use one request snapshot: calls=%d readPath=%q", conversionCalls, readPath)
	}
	var response iteminfo.ExtendedFileInfo
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Metadata == nil || response.Metadata.Title != "authorized media title" {
		t.Errorf("stable metadata title = %+v", response.Metadata)
	}
	if bytes.Contains(recorder.Body.Bytes(), []byte(replacementTitle)) {
		t.Errorf("stable metadata leaked replacement title %q", replacementTitle)
	}
}

func TestPermissionMediaSecurity_DirectoryMetadataIsolatesCanonicalTargets(t *testing.T) {
	h := newPermissionMediaSecurityHarness(t)
	directoryPath := filepath.Join(h.sourcePath, "public", "media-directory")
	aclDirectory := filepath.Join(h.sourcePath, "public", "media-acl-targets")
	privateDirectory := filepath.Join(h.sourcePath, "private")
	for _, path := range []string{directoryPath, aclDirectory, privateDirectory} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	allowedTitle := "allowed directory media title"
	outsideTitle := "outside media title"
	scopeTitle := "scope media title"
	aclTitle := "acl media title"
	allowedPath := filepath.Join(directoryPath, "allowed.mp3")
	outsidePath := filepath.Join(t.TempDir(), "outside.mp3")
	scopePath := filepath.Join(privateDirectory, "private.mp3")
	aclPath := filepath.Join(aclDirectory, "denied.mp3")
	for path, title := range map[string]string{
		allowedPath: allowedTitle,
		outsidePath: outsideTitle,
		scopePath:   scopeTitle,
		aclPath:     aclTitle,
	} {
		if err := os.WriteFile(path, permissionReadID3Audio(title), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	createPermissionReadSymlink(t, outsidePath, filepath.Join(directoryPath, "outside-link.mp3"))
	createPermissionReadSymlink(t, scopePath, filepath.Join(directoryPath, "scope-link.mp3"))
	createPermissionReadSymlink(t, aclPath, filepath.Join(directoryPath, "acl-link.mp3"))
	indexing.GetIndex("source1").CreateMockData(1, 1)

	user := h.user(true, true, false)
	user.Username = "permission-media-directory-user"
	user.Scopes[0].Scope = "/public"
	savePermissionReadUser(t, user)
	if err := store.Access.DenyUser(h.sourcePath, "/public/media-acl-targets/denied.mp3", user.Username); err != nil {
		t.Fatal(err)
	}

	original := files.FileInfoFasterFunc
	var mediaReads []utils.FileOptions
	files.FileInfoFasterFunc = func(opts utils.FileOptions, accessStorage *access.Storage, currentUser *users.User, shareStorage *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
		if opts.Metadata {
			mediaReads = append(mediaReads, opts)
		}
		return original(opts, accessStorage, currentUser, shareStorage)
	}
	t.Cleanup(func() { files.FileInfoFasterFunc = original })

	status, recorder, err := permissionMediaRequest(metadataHandler, "/api/media/metadata", url.Values{
		"source": {"source1"}, "path": {"/media-directory"},
	}, user)
	if status != http.StatusOK || err != nil {
		t.Fatalf("directory metadata status: got %d, want %d (err: %v)", status, http.StatusOK, err)
	}
	var response iteminfo.ExtendedFileInfo
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	titles := make(map[string]string)
	for _, child := range response.Files {
		if child.Metadata != nil {
			titles[child.Name] = child.Metadata.Title
		}
	}
	if titles["allowed.mp3"] != allowedTitle {
		t.Errorf("allowed child title = %q, want %q; all=%v", titles["allowed.mp3"], allowedTitle, titles)
	}
	if len(mediaReads) != 1 || mediaReads[0].ReadPath == "" {
		t.Errorf("directory protected reads = %+v, want one snapshot read", mediaReads)
	}
	for name, secret := range map[string]string{
		"outside-link.mp3": outsideTitle,
		"scope-link.mp3":   scopeTitle,
		"acl-link.mp3":     aclTitle,
	} {
		if titles[name] != "" || bytes.Contains(recorder.Body.Bytes(), []byte(secret)) {
			t.Errorf("unauthorized child %s leaked metadata %q", name, titles[name])
		}
	}
}

func TestPermissionMediaSecurity_DirectoryTargetsRetainLogicalAliases(t *testing.T) {
	targets := []authenticatedReadTarget{
		{LogicalPath: "/public/media/first-alias.mp3", CanonicalPath: "/public/targets/shared.mp3"},
		{LogicalPath: "/public/media/second-alias.mp3", CanonicalPath: "/public/other/shared.mp3"},
	}

	byName := authenticatedMediaTargetsByLogicalName(targets)
	for index, name := range []string{"first-alias.mp3", "second-alias.mp3"} {
		target, ok := byName[name]
		if !ok {
			t.Errorf("logical media alias %q was lost: %+v", name, byName)
			continue
		}
		if target.LogicalPath != targets[index].LogicalPath {
			t.Errorf("logical media alias %q resolved to %+v, want %+v", name, target, targets[index])
		}
	}
}

func TestPermissionMediaSecurity_LogicalAliasListingsEnforceChildACL(t *testing.T) {
	h := newPermissionMediaSecurityHarness(t)
	canonicalDirectory := filepath.Join(h.sourcePath, "public", "media-logical-target")
	aliasDirectory := filepath.Join(h.sourcePath, "public", "media-logical-alias")
	if err := os.MkdirAll(canonicalDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"allowed.mp3", "denied.mp3"} {
		if err := os.WriteFile(filepath.Join(canonicalDirectory, name), permissionReadID3Audio(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	createPermissionReadSymlink(t, canonicalDirectory, aliasDirectory)
	indexing.GetIndex("source1").CreateMockData(1, 1)

	user := h.user(true, false, false)
	user.Username = "permission-media-logical-listing-user"
	savePermissionReadUser(t, user)
	if err := store.Access.DenyUser(h.sourcePath, "/public/media-logical-alias/denied.mp3", user.Username); err != nil {
		t.Fatal(err)
	}

	status, recorder, err := permissionMediaRequest(metadataHandler, "/api/media/metadata", url.Values{
		"source": {"source1"}, "path": {"/public/media-logical-alias"},
	}, user)
	if status != http.StatusOK || err != nil {
		t.Fatalf("logical alias listing status: got %d, want %d (err: %v)", status, http.StatusOK, err)
	}
	var response iteminfo.ExtendedFileInfo
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Name != "media-logical-alias" {
		t.Errorf("logical alias directory name = %q, want %q", response.Name, "media-logical-alias")
	}
	for _, child := range response.Files {
		if child.Name == "denied.mp3" {
			t.Errorf("logical child ACL leaked denied media item: %+v", child)
		}
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte("allowed.mp3")) {
		t.Errorf("logical alias listing omitted allowed child: %q", recorder.Body.Bytes())
	}
}

func TestPermissionMediaSecurity_LogicalAliasesPreserveNamesAndSidecars(t *testing.T) {
	h := newPermissionMediaSecurityHarness(t)
	canonicalAudio := filepath.Join(h.sourcePath, "public", "canonical-track.mp3")
	canonicalVideo := filepath.Join(h.sourcePath, "public", "canonical-video.mp4")
	if err := os.WriteFile(canonicalAudio, permissionReadID3Audio("logical alias title"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(canonicalVideo, []byte("logical alias video"), 0o644); err != nil {
		t.Fatal(err)
	}
	createPermissionReadSymlink(t, canonicalAudio, filepath.Join(h.sourcePath, "public", "alias-track.mp3"))
	createPermissionReadSymlink(t, canonicalVideo, filepath.Join(h.sourcePath, "public", "alias-video.mp4"))
	if err := os.WriteFile(filepath.Join(h.sourcePath, "public", "alias-track.lrc"), []byte("[00:01.00]logical alias lyric\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.sourcePath, "public", "alias-video.srt"), []byte("logical alias subtitle"), 0o644); err != nil {
		t.Fatal(err)
	}
	indexing.GetIndex("source1").CreateMockData(1, 1)

	user := h.user(true, true, true)
	user.Username = "permission-media-logical-sidecar-user"
	savePermissionReadUser(t, user)

	status, metadataRecorder, err := permissionMediaRequest(metadataHandler, "/api/media/metadata", url.Values{
		"source": {"source1"}, "path": {"/public/alias-track.mp3"},
	}, user)
	if status != http.StatusOK || err != nil {
		t.Fatalf("logical alias metadata status: got %d, want %d (err: %v)", status, http.StatusOK, err)
	}
	var metadata iteminfo.ExtendedFileInfo
	if unmarshalErr := json.Unmarshal(metadataRecorder.Body.Bytes(), &metadata); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if metadata.Name != "alias-track.mp3" {
		t.Errorf("logical audio alias name = %q, want %q", metadata.Name, "alias-track.mp3")
	}
	if metadata.Metadata == nil || !metadata.Metadata.HasLyrics {
		t.Errorf("authorized logical lyrics sidecar was not reflected in metadata: %+v", metadata.Metadata)
	}

	status, lyricsRecorder, err := permissionMediaRequest(lyricsHandler, "/api/media/lyrics", url.Values{
		"source": {"source1"}, "path": {"/public/alias-track.mp3"},
	}, user)
	if status != http.StatusOK || err != nil || !bytes.Contains(lyricsRecorder.Body.Bytes(), []byte("logical alias lyric")) {
		t.Errorf("logical alias lyrics response: status=%d err=%v body=%q", status, err, lyricsRecorder.Body.Bytes())
	}

	status, subtitleRecorder, err := permissionMediaRequest(subtitlesHandler, "/api/media/subtitles", url.Values{
		"source": {"source1"}, "path": {"/public/alias-video.mp4"},
		"name": {"alias-video.srt"}, "embedded": {"false"},
	}, user)
	if status != http.StatusOK || err != nil || !bytes.Contains(subtitleRecorder.Body.Bytes(), []byte("logical alias subtitle")) {
		t.Errorf("logical alias subtitle response: status=%d err=%v body=%q", status, err, subtitleRecorder.Body.Bytes())
	}
}

func TestPermissionMediaSecurity_TokenPermissionIntersection(t *testing.T) {
	t.Run("full token cannot exceed its permission snapshot", func(t *testing.T) {
		h := newPermissionMediaSecurityHarness(t)
		configurePermissionReadAuth(t)
		user := h.user(true, true, true)
		user.Permissions.Api = true
		user.Username = "permission-media-full-token-user"
		savePermissionReadUser(t, user)
		token := issuePermissionReadAPIToken(t, user, "permission-media-full-token", users.Permissions{
			Api:    true,
			Browse: true,
		})
		router := permissionMediaAPIRouter()

		metadata := permissionMediaTokenRequest(router, token, "/api/media/metadata", url.Values{
			"source": {"source1"}, "path": {"/public/media-audio.mp3"},
		})
		if metadata.Code != http.StatusOK {
			t.Fatalf("full-token base metadata status: got %d, want %d", metadata.Code, http.StatusOK)
		}
		var response iteminfo.ExtendedFileInfo
		if err := json.Unmarshal(metadata.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Metadata != nil {
			t.Errorf("full token exceeded missing Preview permission: %+v", response.Metadata)
		}

		lyrics := permissionMediaTokenRequest(router, token, "/api/media/lyrics", url.Values{
			"source": {"source1"}, "path": {"/public/media-audio.mp3"},
		})
		assertPermissionReadDenied(t, lyrics.Code, nil, "full token missing Download")
	})

	t.Run("minimal token follows current user revocation", func(t *testing.T) {
		h := newPermissionMediaSecurityHarness(t)
		configurePermissionReadAuth(t)
		user := h.user(true, true, true)
		user.Permissions.Api = true
		user.Username = "permission-media-minimal-token-user"
		savePermissionReadUser(t, user)
		const tokenName = "permission-media-minimal-token"
		token, tokenMetadata, err := auth.MakeSignedTokenAPI(user, tokenName, time.Hour, users.Permissions{}, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Users.AddApiToken(user.ID, tokenName, token, tokenMetadata); err != nil {
			t.Fatal(err)
		}
		if err := store.Access.AddApiToken(token, user.ID); err != nil {
			t.Fatal(err)
		}
		router := permissionMediaAPIRouter()

		allowed := permissionMediaTokenRequest(router, token, "/api/media/metadata", url.Values{
			"source": {"source1"}, "path": {"/public/media-audio.mp3"},
		})
		if allowed.Code != http.StatusOK || !bytes.Contains(allowed.Body.Bytes(), []byte("authorized media title")) {
			t.Fatalf("minimal-token current permission response: status=%d body=%q", allowed.Code, allowed.Body.Bytes())
		}

		revoked := *user
		revoked.Permissions.Preview = false
		revoked.Permissions.Download = false
		if err := store.Users.Update(&revoked, true, "Permissions"); err != nil {
			t.Fatal(err)
		}
		metadata := permissionMediaTokenRequest(router, token, "/api/media/metadata", url.Values{
			"source": {"source1"}, "path": {"/public/media-audio.mp3"},
		})
		if metadata.Code != http.StatusOK || bytes.Contains(metadata.Body.Bytes(), []byte("authorized media title")) {
			t.Errorf("minimal token retained revoked Preview: status=%d body=%q", metadata.Code, metadata.Body.Bytes())
		}
		lyrics := permissionMediaTokenRequest(router, token, "/api/media/lyrics", url.Values{
			"source": {"source1"}, "path": {"/public/media-audio.mp3"},
		})
		assertPermissionReadDenied(t, lyrics.Code, nil, "minimal token revoked Download")
	})
}

func TestPermissionMediaSecurity_MainTargetCanonicalBoundaries(t *testing.T) {
	h := newPermissionMediaSecurityHarness(t)
	directoryPath := filepath.Join(h.sourcePath, "public", "media-main-boundaries")
	aclDirectory := filepath.Join(h.sourcePath, "public", "media-main-acl")
	privateDirectory := filepath.Join(h.sourcePath, "private")
	for _, path := range []string{directoryPath, aclDirectory, privateDirectory} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	outsidePath := filepath.Join(t.TempDir(), "outside.mp3")
	scopePath := filepath.Join(privateDirectory, "scope.mp3")
	aclPath := filepath.Join(aclDirectory, "denied.mp3")
	for path, title := range map[string]string{
		outsidePath: "outside main media secret",
		scopePath:   "scope main media secret",
		aclPath:     "acl main media secret",
	} {
		if err := os.WriteFile(path, permissionReadID3Audio(title), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	createPermissionReadSymlink(t, outsidePath, filepath.Join(directoryPath, "outside.mp3"))
	createPermissionReadSymlink(t, scopePath, filepath.Join(directoryPath, "scope.mp3"))
	createPermissionReadSymlink(t, aclPath, filepath.Join(directoryPath, "acl.mp3"))
	indexing.GetIndex("source1").CreateMockData(1, 1)

	user := h.user(true, true, true)
	user.Username = "permission-media-main-boundary-user"
	user.Scopes[0].Scope = "/public"
	savePermissionReadUser(t, user)
	if err := store.Access.DenyUser(h.sourcePath, "/public/media-main-acl/denied.mp3", user.Username); err != nil {
		t.Fatal(err)
	}

	for _, handlerTest := range []struct {
		name    string
		handler handleFunc
		path    string
		query   func(string) url.Values
	}{
		{
			name:    "metadata",
			handler: metadataHandler,
			path:    "/api/media/metadata",
			query: func(name string) url.Values {
				return url.Values{"source": {"source1"}, "path": {"/media-main-boundaries/" + name}}
			},
		},
		{
			name:    "lyrics",
			handler: lyricsHandler,
			path:    "/api/media/lyrics",
			query: func(name string) url.Values {
				return url.Values{"source": {"source1"}, "path": {"/media-main-boundaries/" + name}}
			},
		},
	} {
		t.Run(handlerTest.name, func(t *testing.T) {
			for _, name := range []string{"outside.mp3", "scope.mp3", "acl.mp3"} {
				t.Run(name, func(t *testing.T) {
					original := files.FileInfoFasterFunc
					calls := 0
					files.FileInfoFasterFunc = func(opts utils.FileOptions, accessStorage *access.Storage, currentUser *users.User, shareStorage *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
						calls++
						return original(opts, accessStorage, currentUser, shareStorage)
					}
					t.Cleanup(func() { files.FileInfoFasterFunc = original })

					status, recorder, err := permissionMediaRequest(handlerTest.handler, handlerTest.path, handlerTest.query(name), user)
					assertPermissionReadDenied(t, status, err, handlerTest.name+" canonical boundary")
					if calls != 0 {
						t.Errorf("canonical denial performed %d FileInfo lookup(s), want 0", calls)
					}
					for _, secret := range []string{"outside main media secret", "scope main media secret", "acl main media secret"} {
						if bytes.Contains(recorder.Body.Bytes(), []byte(secret)) {
							t.Errorf("canonical denial leaked %q in %q", secret, recorder.Body.Bytes())
						}
					}
				})
			}
		})
	}
}
