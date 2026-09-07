package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/events"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
	"github.com/gtsteffaniak/go-cache/cache"
)

func resetPermissionDuplicateResultsCache(t *testing.T) {
	t.Helper()
	previous := duplicateResultsCache
	duplicateResultsCache = cache.NewCache[duplicateResponse](15 * time.Second)
	t.Cleanup(func() {
		duplicateResultsCache = previous
	})
}

func permissionDuplicateMarkerResponse(size int64, paths ...string) duplicateResponse {
	files := make([]*indexing.SearchResult, 0, len(paths))
	for _, path := range paths {
		files = append(files, &indexing.SearchResult{Path: path, Source: "source1", Size: size, Type: "text/plain"})
	}
	return duplicateResponse{Groups: []duplicateGroup{{Size: size, Count: len(files), Files: files}}}
}

func permissionToolsAPIRouter() *http.ServeMux {
	api := http.NewServeMux()
	api.HandleFunc("GET /tools/duplicateFinder", withUser(duplicatesHandler))
	api.HandleFunc("GET /tools/fileWatcher", withUser(fileWatchHandler))
	router := http.NewServeMux()
	router.Handle("/api/", http.StripPrefix("/api", api))
	return router
}

type permissionFileWatchRecorder struct {
	mu      sync.Mutex
	header  http.Header
	status  int
	body    strings.Builder
	writes  chan string
	onWrite func(string)
}

func newPermissionFileWatchRecorder() *permissionFileWatchRecorder {
	return &permissionFileWatchRecorder{
		header: make(http.Header),
		writes: make(chan string, 32),
	}
}

func (r *permissionFileWatchRecorder) Header() http.Header {
	return r.header
}

func (r *permissionFileWatchRecorder) WriteHeader(status int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status == 0 {
		r.status = status
	}
}

func (r *permissionFileWatchRecorder) Write(p []byte) (int, error) {
	message := string(p)
	r.mu.Lock()
	if r.status == 0 {
		r.status = http.StatusOK
	}
	_, _ = r.body.Write(p)
	onWrite := r.onWrite
	r.mu.Unlock()
	if onWrite != nil {
		onWrite(message)
	}
	r.writes <- message
	return len(p), nil
}

func (r *permissionFileWatchRecorder) Flush() {}

func (r *permissionFileWatchRecorder) BodyString() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body.String()
}

func waitForPermissionFileWatchWrite(t *testing.T, recorder *permissionFileWatchRecorder, contains string) string {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case message := <-recorder.writes:
			if strings.Contains(message, contains) {
				return message
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for file watcher output containing %q; body=%q", contains, recorder.BodyString())
		}
	}
}

func TestPermissionReadSecurity_ToolEndpointsRequireReadPermissions(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)

	for _, tc := range []struct {
		name     string
		browse   bool
		download bool
		admin    bool
	}{
		{name: "duplicate finder requires Browse", browse: false, download: true},
		{name: "duplicate finder requires Download for checksums", browse: true, download: false},
		{name: "admin does not bypass duplicate Browse", browse: false, download: true, admin: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetPermissionDuplicateResultsCache(t)
			user := h.user(t, tc.browse, true, tc.download)
			user.Permissions.Admin = tc.admin
			query := url.Values{
				"source":    {"source1"},
				"scope":     {"/public"},
				"minSizeMb": {"0"},
			}
			req := httptest.NewRequest(http.MethodGet, "/api/tools/duplicateFinder?"+query.Encode(), nil)
			recorder := httptest.NewRecorder()

			returned, err := duplicatesHandler(recorder, req, &requestContext{user: user})
			if got := permissionHandlerStatus(returned, recorder); got != http.StatusForbidden {
				t.Errorf("duplicate finder status: got %d, want %d (err: %v)", got, http.StatusForbidden, err)
			}
			if recorder.Body.Len() != 0 {
				t.Errorf("denied duplicate finder emitted body %q", recorder.Body.String())
			}
		})
	}

	t.Run("file watcher requires Browse before latency shortcut", func(t *testing.T) {
		user := h.user(t, false, true, true)
		req := httptest.NewRequest(http.MethodGet, "/api/tools/fileWatcher?latencyCheck=true", nil)
		recorder := httptest.NewRecorder()

		returned, err := fileWatchHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusForbidden {
			t.Errorf("latency check status: got %d, want %d (err: %v)", got, http.StatusForbidden, err)
		}
		if recorder.Body.Len() != 0 {
			t.Errorf("denied latency check emitted body %q", recorder.Body.String())
		}
	})

	t.Run("file watcher requires Browse before file lookup", func(t *testing.T) {
		user := h.user(t, false, true, true)
		query := url.Values{
			"source": {"source1"},
			"path":   {"/public/secret.txt"},
		}
		req := httptest.NewRequest(http.MethodGet, "/api/tools/fileWatcher?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := fileWatchHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusForbidden {
			t.Errorf("file watcher status: got %d, want %d (err: %v)", got, http.StatusForbidden, err)
		}
		assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "Browse=false file watcher")
	})

	t.Run("file watcher requires Download", func(t *testing.T) {
		user := h.user(t, true, true, false)
		query := url.Values{"source": {"source1"}, "path": {"/public/secret.txt"}}
		req := httptest.NewRequest(http.MethodGet, "/api/tools/fileWatcher?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := fileWatchHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusForbidden {
			t.Errorf("file watcher Download status: got %d, want %d (err: %v)", got, http.StatusForbidden, err)
		}
		assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "Download=false file watcher")
	})

	t.Run("admin does not bypass file watcher Browse", func(t *testing.T) {
		user := h.user(t, false, true, true)
		user.Permissions.Admin = true
		query := url.Values{"source": {"source1"}, "path": {"/public/secret.txt"}}
		req := httptest.NewRequest(http.MethodGet, "/api/tools/fileWatcher?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := fileWatchHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusForbidden {
			t.Errorf("admin file watcher status: got %d, want %d (err: %v)", got, http.StatusForbidden, err)
		}
		assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "admin Browse=false file watcher")
	})

	t.Run("SSE file watcher requires Browse before headers or lookup", func(t *testing.T) {
		user := h.user(t, false, true, true)
		user.Permissions.Realtime = true
		query := url.Values{
			"source": {"source1"},
			"path":   {"/public/secret.txt"},
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req := httptest.NewRequest(http.MethodGet, "/api/tools/fileWatcher/sse?"+query.Encode(), nil).WithContext(ctx)
		recorder := httptest.NewRecorder()

		returned, err := fileWatchSSEHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusForbidden {
			t.Errorf("SSE file watcher status: got %d, want %d (err: %v)", got, http.StatusForbidden, err)
		}
		if contentType := recorder.Header().Get("Content-Type"); contentType != "" {
			t.Errorf("denied SSE file watcher emitted Content-Type %q", contentType)
		}
		assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "Browse=false SSE file watcher")
	})

	t.Run("admin does not bypass SSE Realtime", func(t *testing.T) {
		user := h.user(t, true, true, true)
		user.Permissions.Admin = true
		query := url.Values{"source": {"source1"}, "path": {"/public/secret.txt"}}
		req := httptest.NewRequest(http.MethodGet, "/api/tools/fileWatcher/sse?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()

		returned, err := fileWatchSSEHandler(recorder, req, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusForbidden {
			t.Errorf("admin SSE Realtime status: got %d, want %d (err: %v)", got, http.StatusForbidden, err)
		}
		if contentType := recorder.Header().Get("Content-Type"); contentType != "" {
			t.Errorf("denied SSE file watcher emitted Content-Type %q", contentType)
		}
		assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "admin Realtime=false SSE file watcher")
	})
}

func TestPermissionReadSecurity_DuplicateCacheDoesNotCrossUsersOrScopes(t *testing.T) {
	t.Run("different user", func(t *testing.T) {
		h := newPermissionReadSecurityHarness(t)
		resetPermissionDuplicateResultsCache(t)
		owner := h.user(t, true, true, true)
		owner.Username = "duplicate-cache-owner"
		savePermissionReadUser(t, owner)
		reader := h.user(t, true, true, true)
		reader.Username = "duplicate-cache-reader"
		savePermissionReadUser(t, reader)
		query := url.Values{"source": {"source1"}, "scope": {"/public"}, "minSizeMb": {"0"}}
		req := httptest.NewRequest(http.MethodGet, "/api/tools/duplicateFinder?"+query.Encode(), nil)
		ownerOpts, err := prepDuplicatesOptions(req, &requestContext{user: owner})
		if err != nil {
			t.Fatal(err)
		}
		readerOpts, err := prepDuplicatesOptions(req, &requestContext{user: reader})
		if err != nil {
			t.Fatal(err)
		}
		idx := indexing.GetIndex(ownerOpts.source)
		ownerKey := duplicateResultsCacheKey(idx, ownerOpts)
		readerKey := duplicateResultsCacheKey(idx, readerOpts)
		if ownerKey == readerKey {
			t.Fatal("duplicate cache key did not isolate users")
		}
		const markerSize = int64(987654320)
		duplicateResultsCache.Set(ownerKey, permissionDuplicateMarkerResponse(markerSize, "/secret.txt", "/preview.jpg"))

		recorder := httptest.NewRecorder()
		returned, handlerErr := duplicatesHandler(recorder, req, &requestContext{user: reader})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
			t.Fatalf("different-user duplicate status: got %d, want %d (err: %v)", got, http.StatusOK, handlerErr)
		}
		if strings.Contains(recorder.Body.String(), fmt.Sprintf("%d", markerSize)) {
			t.Errorf("duplicate cache crossed users: %s", recorder.Body.String())
		}
	})

	t.Run("different search scope", func(t *testing.T) {
		h := newPermissionReadSecurityHarness(t)
		resetPermissionDuplicateResultsCache(t)
		user := h.user(t, true, true, true)
		user.Username = "duplicate-cache-scope-user"
		savePermissionReadUser(t, user)
		publicQuery := url.Values{"source": {"source1"}, "scope": {"/public"}, "minSizeMb": {"0"}}
		rootQuery := url.Values{"source": {"source1"}, "scope": {"/"}, "minSizeMb": {"0"}}
		publicReq := httptest.NewRequest(http.MethodGet, "/api/tools/duplicateFinder?"+publicQuery.Encode(), nil)
		rootReq := httptest.NewRequest(http.MethodGet, "/api/tools/duplicateFinder?"+rootQuery.Encode(), nil)
		publicOpts, err := prepDuplicatesOptions(publicReq, &requestContext{user: user})
		if err != nil {
			t.Fatal(err)
		}
		rootOpts, err := prepDuplicatesOptions(rootReq, &requestContext{user: user})
		if err != nil {
			t.Fatal(err)
		}
		idx := indexing.GetIndex(publicOpts.source)
		publicKey := duplicateResultsCacheKey(idx, publicOpts)
		rootKey := duplicateResultsCacheKey(idx, rootOpts)
		if publicKey == rootKey {
			t.Fatal("duplicate cache key did not isolate search scopes")
		}
		const markerSize = int64(987654319)
		duplicateResultsCache.Set(publicKey, permissionDuplicateMarkerResponse(markerSize, "/secret.txt", "/preview.jpg"))

		recorder := httptest.NewRecorder()
		returned, handlerErr := duplicatesHandler(recorder, rootReq, &requestContext{user: user})
		if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
			t.Fatalf("different-scope duplicate status: got %d, want %d (err: %v)", got, http.StatusOK, handlerErr)
		}
		if strings.Contains(recorder.Body.String(), fmt.Sprintf("%d", markerSize)) {
			t.Errorf("duplicate cache crossed search scopes: %s", recorder.Body.String())
		}
	})
}

func TestPermissionReadSecurity_DuplicateScopeDefaultsToRoot(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	user := h.user(t, true, true, true)
	query := url.Values{"source": {"source1"}, "minSizeMb": {"0"}}
	req := httptest.NewRequest(http.MethodGet, "/api/tools/duplicateFinder?"+query.Encode(), nil)
	opts, err := prepDuplicatesOptions(req, &requestContext{user: user})
	if err != nil {
		t.Fatal(err)
	}
	idx := indexing.GetIndex(opts.source)
	want := idx.MakeIndexPath("/", true)
	if opts.searchScope != "/" || opts.combinedPath != want {
		t.Fatalf("default duplicate scope: search=%q combined=%q, want search=/ combined=%q", opts.searchScope, opts.combinedPath, want)
	}
}

func TestPermissionReadSecurity_DuplicateDeniedParentRetainsExplicitChildren(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	resetPermissionDuplicateResultsCache(t)
	user := h.user(t, true, true, true)
	user.Username = "duplicate-denied-parent-user"
	savePermissionReadUser(t, user)

	if err := store.Access.DenyUser(h.sourcePath, "/public", user.Username); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/public/secret.txt", "/public/preview.jpg"} {
		if err := store.Access.AllowUser(h.sourcePath, path, user.Username); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(h.sourcePath, "public", "denied.txt"), []byte("denied duplicate marker"), 0o644); err != nil {
		t.Fatal(err)
	}

	query := url.Values{"source": {"source1"}, "scope": {"/public"}, "minSizeMb": {"0"}}
	req := httptest.NewRequest(http.MethodGet, "/api/tools/duplicateFinder?"+query.Encode(), nil)
	opts, err := prepDuplicatesOptions(req, &requestContext{user: user})
	if err != nil {
		t.Fatal(err)
	}
	idx := indexing.GetIndex(opts.source)
	const markerSize = int64(987654322)
	duplicateResultsCache.Set(duplicateResultsCacheKey(idx, opts), permissionDuplicateMarkerResponse(
		markerSize,
		"/secret.txt",
		"/preview.jpg",
		"/denied.txt",
	))

	recorder := httptest.NewRecorder()
	returned, handlerErr := duplicatesHandler(recorder, req, &requestContext{user: user})
	if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
		t.Errorf("denied parent duplicate status: got %d, want %d (err: %v, body: %q)", got, http.StatusOK, handlerErr, recorder.Body.String())
	}
	for _, allowed := range []string{"secret.txt", "preview.jpg"} {
		if !strings.Contains(recorder.Body.String(), allowed) {
			t.Errorf("explicitly allowed duplicate %q was not returned: %s", allowed, recorder.Body.String())
		}
	}
	if strings.Contains(recorder.Body.String(), "denied.txt") {
		t.Errorf("inherited-denied duplicate was returned: %s", recorder.Body.String())
	}
}

func TestPermissionReadSecurity_DuplicateCurrentCacheRechecksACL(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	resetPermissionDuplicateResultsCache(t)
	user := h.user(t, true, true, true)
	user.Username = "duplicate-current-cache-user"
	savePermissionReadUser(t, user)
	query := url.Values{
		"source":    {"source1"},
		"scope":     {"/public"},
		"minSizeMb": {"0"},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/tools/duplicateFinder?"+query.Encode(), nil)
	opts, err := prepDuplicatesOptions(req, &requestContext{user: user})
	if err != nil {
		t.Fatal(err)
	}
	idx := indexing.GetIndex(opts.source)
	if idx == nil {
		t.Fatal("source1 index was not initialized")
	}
	cacheKey := duplicateResultsCacheKey(idx, opts)
	const markerSize = int64(987654321)
	duplicateResultsCache.Set(cacheKey, permissionDuplicateMarkerResponse(markerSize, "/secret.txt", "/preview.jpg"))

	first := httptest.NewRecorder()
	returned, handlerErr := duplicatesHandler(first, req, &requestContext{user: user})
	if got := permissionHandlerStatus(returned, first); got != http.StatusOK {
		t.Fatalf("initial duplicate cache status: got %d, want %d (err: %v)", got, http.StatusOK, handlerErr)
	}
	marker := fmt.Sprintf("%d", markerSize)
	if !strings.Contains(first.Body.String(), marker) {
		t.Fatalf("current duplicate cache was not exercised: %s", first.Body.String())
	}

	if err := store.Access.DenyUser(h.sourcePath, "/public/secret.txt", user.Username); err != nil {
		t.Fatalf("revoke cached duplicate path: %v", err)
	}
	second := httptest.NewRecorder()
	returned, handlerErr = duplicatesHandler(second, req, &requestContext{user: user})
	if got := permissionHandlerStatus(returned, second); got != http.StatusOK {
		t.Fatalf("revoked duplicate cache status: got %d, want %d (err: %v)", got, http.StatusOK, handlerErr)
	}
	if strings.Contains(second.Body.String(), marker) || strings.Contains(second.Body.String(), "secret.txt") {
		t.Errorf("current duplicate cache was not re-filtered after ACL revocation: %s", second.Body.String())
	}
}

func TestPermissionReadSecurity_DuplicateCacheHitDoesNotWaitForSearchLock(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	resetPermissionDuplicateResultsCache(t)
	user := h.user(t, true, true, true)
	query := url.Values{
		"source":    {"source1"},
		"scope":     {"/public"},
		"minSizeMb": {"0"},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/tools/duplicateFinder?"+query.Encode(), nil)
	opts, err := prepDuplicatesOptions(req, &requestContext{user: user})
	if err != nil {
		t.Fatal(err)
	}
	idx := indexing.GetIndex(opts.source)
	cacheKey := duplicateResultsCacheKey(idx, opts)
	const markerSize = int64(987654318)
	duplicateResultsCache.Set(cacheKey, permissionDuplicateMarkerResponse(markerSize, "/secret.txt", "/preview.jpg"))

	duplicateSearchMutex.Lock()
	defer duplicateSearchMutex.Unlock()
	recorder := httptest.NewRecorder()
	returned, handlerErr := duplicatesHandler(recorder, req, &requestContext{user: user})
	if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK {
		t.Errorf("cached duplicate search waited for search lock: got %d, want %d (err: %v)", got, http.StatusOK, handlerErr)
	}
	if !strings.Contains(recorder.Body.String(), fmt.Sprintf("%d", markerSize)) {
		t.Errorf("cached duplicate response was not served while search lock was held: %s", recorder.Body.String())
	}
}

func TestPermissionReadSecurity_DuplicatesFromRealIndexSizeModes(t *testing.T) {
	for _, logical := range []bool{false, true} {
		t.Run(fmt.Sprintf("useLogicalSize=%t", logical), func(t *testing.T) {
			sourcePath := setupResourcePutTestEnv(t)
			resetPermissionDuplicateResultsCache(t)
			idx := indexing.GetIndex("source1")
			if idx == nil {
				t.Fatal("test source index is unavailable")
			}
			// Enable only the synchronous real-directory refresh; the test helper
			// initialized this source without starting background scanners.
			idx.Config.ResolvedRules.IndexingDisabled = false
			idx.Config.UseLogicalSize = false
			content := bytes.Repeat([]byte{0}, 1126*1024)
			if len(content)%4096 == 0 {
				t.Fatal("duplicate fixture must not be aligned to a 4 KiB block")
			}
			names := []string{"duplicate-size-a.bin", "duplicate-size-b.bin"}
			var allocatedSize int64
			for _, name := range names {
				realPath := filepath.Join(sourcePath, "public", name)
				if writeErr := os.WriteFile(realPath, content, 0o644); writeErr != nil {
					t.Fatal(writeErr)
				}
				info, statErr := os.Stat(realPath)
				if statErr != nil {
					t.Fatal(statErr)
				}
				// Read the actual platform scanner size, rather than rounding the
				// fixture length or constructing synthetic index metadata.
				physical, physicalErr := idx.GetFsInfoCore("/public/"+name, indexing.Options{})
				if physicalErr != nil {
					t.Fatal(physicalErr)
				}
				t.Logf("fixture=%s logical_bytes=%d scanner_allocated_bytes=%d", name, info.Size(), physical.Size)
				if info.Size() != int64(len(content)) || physical.Size == info.Size() {
					t.Fatal("fixture must expose distinct actual logical and scanner allocated sizes")
				}
				if allocatedSize != 0 && allocatedSize != physical.Size {
					t.Fatal("identical duplicate fixtures have different allocated sizes")
				}
				allocatedSize = physical.Size
			}
			idx.Config.UseLogicalSize = logical
			if refreshErr := idx.RefreshDirectory("/public/", true); refreshErr != nil {
				t.Fatal(refreshErr)
			}
			wantSize := allocatedSize
			if logical {
				wantSize = int64(len(content))
			}
			indexed, indexErr := indexing.GetIndexDB().GetFilesForMultipleSizes("source1", []int64{wantSize}, "/")
			if indexErr != nil {
				t.Fatal(indexErr)
			}
			if len(indexed[wantSize]) != len(names) {
				t.Fatalf("real index has %d duplicate candidates at size %d, want %d", len(indexed[wantSize]), wantSize, len(names))
			}
			user := &users.User{
				Username:    "duplicate-real-index-user",
				Permissions: users.Permissions{Browse: true, Download: true},
				Scopes:      []users.SourceScope{{Name: sourcePath, Scope: "/"}},
			}
			savePermissionReadUser(t, user)
			query := url.Values{"source": {"source1"}, "scope": {"/"}, "minSizeMb": {"1"}}
			request := httptest.NewRequest(http.MethodGet, "/api/tools/duplicateFinder?"+query.Encode(), nil)
			recorder := httptest.NewRecorder()
			returned, handlerErr := duplicatesHandler(recorder, request, &requestContext{user: user})
			if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK || handlerErr != nil {
				t.Fatalf("real-index duplicate status=%d, want 200 (err: %v)", got, handlerErr)
			}
			var response duplicateResponse
			if decodeErr := json.Unmarshal(recorder.Body.Bytes(), &response); decodeErr != nil {
				t.Fatal(decodeErr)
			}
			if response.Incomplete || len(response.Groups) != 1 {
				t.Fatalf("real-index duplicate groups=%d incomplete=%t, want one complete group", len(response.Groups), response.Incomplete)
			}
			group := response.Groups[0]
			if group.Size != wantSize || group.Count != len(names) || len(group.Files) != len(names) {
				t.Fatalf("duplicate group size=%d count=%d files=%d, want size=%d count=2 files=2", group.Size, group.Count, len(group.Files), wantSize)
			}
			wantPaths := map[string]bool{"/public/duplicate-size-a.bin": true, "/public/duplicate-size-b.bin": true}
			for _, file := range group.Files {
				if file == nil || file.Source != "source1" || file.Size != wantSize || !wantPaths[file.Path] {
					t.Fatal("duplicate response changed source, indexed size, or expected file identity")
				}
				delete(wantPaths, file.Path)
			}
			if len(wantPaths) != 0 {
				t.Fatal("duplicate response omitted an indexed fixture")
			}

			// A different logical length can occupy the same physical bucket and
			// have the same sampled zero bytes. It must not be called a duplicate.
			if writeErr := os.WriteFile(filepath.Join(sourcePath, "public", names[1]), append(content, 0), 0o644); writeErr != nil {
				t.Fatal(writeErr)
			}
			if refreshErr := idx.RefreshDirectory("/public/", true); refreshErr != nil {
				t.Fatal(refreshErr)
			}
			changed, changedErr := idx.GetFsInfoCore("/public/"+names[1], indexing.Options{})
			if changedErr != nil {
				t.Fatal(changedErr)
			}
			changedSize := wantSize
			if logical {
				changedSize++
			}
			if changed.Size != changedSize {
				t.Fatalf("changed fixture scanner size=%d, want %d", changed.Size, changedSize)
			}
			if !logical {
				// Prove the persisted scanner bucket still contains both candidates;
				// SQL separating their sizes must not make this rejection pass.
				reindexed, reindexErr := indexing.GetIndexDB().GetFilesForMultipleSizes("source1", []int64{wantSize}, "/")
				if reindexErr != nil {
					t.Fatal(reindexErr)
				}
				if len(reindexed[wantSize]) != len(names) {
					t.Fatalf("different-length real index has %d candidates in allocation bucket %d, want 2", len(reindexed[wantSize]), wantSize)
				}
				for _, candidate := range reindexed[wantSize] {
					if candidate == nil || candidate.Size != wantSize {
						t.Fatal("different-length candidate left the original allocation bucket")
					}
				}
			}
			resetPermissionDuplicateResultsCache(t)
			recorder = httptest.NewRecorder()
			returned, handlerErr = duplicatesHandler(recorder, request, &requestContext{user: user})
			if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK || handlerErr != nil {
				t.Fatalf("different-length duplicate status=%d, want 200 (err: %v)", got, handlerErr)
			}
			response = duplicateResponse{}
			if decodeErr := json.Unmarshal(recorder.Body.Bytes(), &response); decodeErr != nil {
				t.Fatal(decodeErr)
			}
			if response.Incomplete || len(response.Groups) != 0 {
				t.Fatalf("different logical lengths returned groups=%d incomplete=%t, want no duplicate groups", len(response.Groups), response.Incomplete)
			}
		})
	}
}

type permissionDuplicateSizeInfo struct {
	os.FileInfo
	logicalSize int64
	stat        any
}

func (info permissionDuplicateSizeInfo) Size() int64 { return info.logicalSize }
func (info permissionDuplicateSizeInfo) Sys() any    { return info.stat }

func TestPermissionReadSecurity_DuplicateSizeRejectsInvalidStat(t *testing.T) {
	realPath := filepath.Join(t.TempDir(), "duplicate-size.bin")
	if writeErr := os.WriteFile(realPath, []byte("duplicate-size"), 0o644); writeErr != nil {
		t.Fatal(writeErr)
	}
	info, statErr := os.Stat(realPath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	negative := permissionDuplicateSizeInfo{FileInfo: info, logicalSize: -1, stat: info.Sys()}
	for _, logical := range []bool{false, true} {
		if _, ok := duplicateIndexedFileSize(negative, logical); ok {
			t.Fatalf("negative logical size was accepted in logical=%t mode", logical)
		}
		if _, ok := duplicateIndexedFileSize(nil, logical); ok {
			t.Fatalf("missing file info was accepted in logical=%t mode", logical)
		}
	}
	if runtime.GOOS == "windows" {
		overflow := permissionDuplicateSizeInfo{FileInfo: info, logicalSize: math.MaxInt64, stat: info.Sys()}
		if _, ok := duplicateIndexedFileSize(overflow, false); ok {
			t.Fatal("overflowing Windows allocation rounding was accepted")
		}
		return
	}
	unknown := permissionDuplicateSizeInfo{FileInfo: info, logicalSize: info.Size(), stat: struct{}{}}
	if _, ok := duplicateIndexedFileSize(unknown, false); ok {
		t.Fatal("unknown Unix allocation metadata was accepted")
	}
	// Clone the real platform stat type without importing a Unix-only type
	// into this existing cross-platform test file.
	original := reflect.ValueOf(info.Sys())
	if original.Kind() != reflect.Pointer || original.IsNil() || original.Elem().Kind() != reflect.Struct {
		t.Fatal("Unix fixture did not expose a stat structure")
	}
	for _, blocks := range []int64{-1, math.MaxInt64/512 + 1} {
		copied := reflect.New(original.Elem().Type())
		copied.Elem().Set(original.Elem())
		blockField := copied.Elem().FieldByName("Blocks")
		if !blockField.IsValid() || blockField.Kind() != reflect.Int64 || !blockField.CanSet() {
			t.Fatal("Unix fixture did not expose a signed allocation block count")
		}
		blockField.SetInt(blocks)
		invalid := permissionDuplicateSizeInfo{FileInfo: info, logicalSize: info.Size(), stat: copied.Interface()}
		if _, ok := duplicateIndexedFileSize(invalid, false); ok {
			t.Fatalf("invalid Unix allocation block count %d was accepted", blocks)
		}
	}
}

func TestPermissionReadSecurity_DuplicateChecksumRechecksACL(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	user := h.user(t, true, true, true)
	user.Username = "duplicate-checksum-recheck-user"
	savePermissionReadUser(t, user)
	const content = "same duplicate content long enough for both checksum candidates"
	paths := []string{"duplicate-recheck-a.txt", "duplicate-recheck-b.txt"}
	files := make([]*iteminfo.FileInfo, 0, len(paths))
	for _, name := range paths {
		realPath := filepath.Join(h.sourcePath, "public", name)
		if err := os.WriteFile(realPath, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(realPath)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, &iteminfo.FileInfo{
			Path: "/public/" + name,
			ItemInfo: iteminfo.ItemInfo{
				Name:    name,
				Size:    info.Size(),
				ModTime: info.ModTime(),
				Type:    "text/plain",
			},
		})
	}
	opts := &duplicatesOptions{
		source:       "source1",
		combinedPath: "/public/",
		user:         user,
	}
	filtered := filterFilesByPermission(files, opts)
	if len(filtered) != 2 {
		t.Fatalf("initial duplicate permission filter returned %d files", len(filtered))
	}
	if err := store.Access.DenyUser(h.sourcePath, "/public/duplicate-recheck-a.txt", user.Username); err != nil {
		t.Fatal(err)
	}
	stats := &duplicateProcessingStats{startTime: time.Now(), uniqueChecksums: make(map[string]bool)}
	groups := groupFilesByChecksum(filtered, opts, int64(len(content)), stats)
	if len(groups) != 0 {
		t.Errorf("duplicate checksum continued after ACL revocation: %+v", groups)
	}
}

func TestPermissionReadSecurity_DuplicateFilteringPreservesLogicalAliases(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	canonicalPath := filepath.Join(h.sourcePath, "public", "duplicate-canonical.txt")
	if err := os.WriteFile(canonicalPath, []byte("duplicate logical alias content"), 0o644); err != nil {
		t.Fatal(err)
	}
	aliases := []string{"duplicate-alias-a.txt", "duplicate-alias-b.txt"}
	for _, name := range aliases {
		createPermissionReadSymlink(t, canonicalPath, filepath.Join(h.sourcePath, "public", name))
	}
	info, err := os.Stat(canonicalPath)
	if err != nil {
		t.Fatal(err)
	}
	indexed := make([]*iteminfo.FileInfo, 0, len(aliases))
	for _, name := range aliases {
		indexed = append(indexed, &iteminfo.FileInfo{
			Path: "/public/" + name,
			ItemInfo: iteminfo.ItemInfo{
				Name: name, Size: info.Size(), ModTime: info.ModTime(), Type: "text/plain",
			},
		})
	}
	user := h.user(t, true, true, true)
	filtered := filterFilesByPermission(indexed, &duplicatesOptions{
		source: "source1", combinedPath: "/public/", user: user,
	})
	if len(filtered) != len(aliases) {
		t.Fatalf("logical duplicate aliases after filtering = %d, want %d", len(filtered), len(aliases))
	}
	for i, file := range filtered {
		want := "/public/" + aliases[i]
		if file.Path != want {
			t.Errorf("duplicate alias path = %q, want %q", file.Path, want)
		}
	}
}

func TestPermissionReadSecurity_FileWatcherPreservesLogicalAliasName(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	aliasPath := filepath.Join(h.sourcePath, "public", "watch-alias.txt")
	createPermissionReadSymlink(t, h.secretPath, aliasPath)
	user := h.user(t, true, true, true)
	query := url.Values{"source": {"source1"}, "path": {"/public/watch-alias.txt"}}
	request := httptest.NewRequest(http.MethodGet, "/api/tools/fileWatcher?"+query.Encode(), nil)
	recorder := httptest.NewRecorder()
	returned, err := fileWatchHandler(recorder, request, &requestContext{user: user})
	if got := permissionHandlerStatus(returned, recorder); got != http.StatusOK || err != nil {
		t.Fatalf("logical alias file watcher status: got %d, want %d (err: %v)", got, http.StatusOK, err)
	}
	var response fileWatchResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Metadata == nil || response.Metadata.Name != "watch-alias.txt" {
		t.Errorf("logical alias file watcher metadata = %+v", response.Metadata)
	}
}

func TestPermissionReadSecurity_FileWatcherDoesNotBroadcastAcrossTokens(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	configurePermissionReadAuth(t)
	user := h.user(t, true, true, true)
	user.Username = "permission-filewatch-token-isolation"
	user.Permissions.Api = true
	user.Permissions.Realtime = true
	savePermissionReadUser(t, user)
	token := issuePermissionReadAPIToken(t, user, "permission-filewatch-token-isolation", users.Permissions{
		Api:      true,
		Browse:   true,
		Download: true,
		Realtime: true,
	})

	// A low-privilege token can legitimately hold Realtime without Browse or Download
	// and therefore have a generic event connection for this username.
	lowPrivilegeEvents := events.Register(user.Username, nil)
	t.Cleanup(func() {
		events.Unregister(user.Username, lowPrivilegeEvents)
	})

	ctx, cancel := context.WithCancel(context.Background())
	query := url.Values{
		"source":   {"source1"},
		"path":     {"/public/secret.txt"},
		"interval": {"30"},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/tools/fileWatcher/sse?"+query.Encode(), nil).WithContext(ctx)
	recorder := newPermissionFileWatchRecorder()
	done := make(chan struct{})
	go func() {
		_, _ = fileWatchSSEHandler(recorder, req, &requestContext{user: user, token: token})
		close(done)
	}()

	waitForPermissionFileWatchWrite(t, recorder, permissionReadSecret)
	var leaked string
	select {
	case message := <-lowPrivilegeEvents:
		if message.EventType == "fileWatch" && strings.Contains(message.Message, permissionReadSecret) {
			leaked = message.Message
		}
	case <-time.After(200 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("file watcher did not stop after request cancellation")
	}

	if leaked != "" {
		t.Errorf("high-privilege watcher broadcast original content to another token: %s", leaked)
	}
	if !filepath.IsAbs(h.secretPath) {
		t.Fatalf("test fixture path is not absolute: %q", h.secretPath)
	}
}

func TestPermissionReadSecurity_FileWatcherRechecksTokenAfterAck(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	configurePermissionReadAuth(t)
	user := h.user(t, true, true, true)
	user.Username = "permission-filewatch-ack-revoke"
	user.Permissions.Api = true
	user.Permissions.Realtime = true
	savePermissionReadUser(t, user)
	token := issuePermissionReadAPIToken(t, user, "permission-filewatch-ack-revoke", users.Permissions{
		Api:      true,
		Browse:   true,
		Download: true,
		Realtime: true,
	})
	query := url.Values{
		"source":   {"source1"},
		"path":     {"/public/secret.txt"},
		"interval": {"30"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/tools/fileWatcher/sse?"+query.Encode(), nil).WithContext(ctx)
	recorder := newPermissionFileWatchRecorder()
	var once sync.Once
	recorder.onWrite = func(message string) {
		if strings.Contains(message, "connected") {
			once.Do(func() {
				if err := auth.RevokeApiToken(store.Access, token); err != nil {
					t.Errorf("revoke file watcher token after ack: %v", err)
				}
			})
		}
	}
	done := make(chan struct{})
	go func() {
		_, _ = fileWatchSSEHandler(recorder, req, &requestContext{user: user, token: token})
		close(done)
	}()

	waitForPermissionFileWatchWrite(t, recorder, "connected")
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cancel()
		<-done
	}
	if strings.Contains(recorder.BodyString(), permissionReadSecret) {
		t.Errorf("file watcher leaked content after token revocation during ack: %s", recorder.BodyString())
	}
}

func TestPermissionReadSecurity_FileWatcherRechecksTokenAfterContentWrite(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	configurePermissionReadAuth(t)
	user := h.user(t, true, true, true)
	user.Username = "permission-filewatch-content-write-revoke"
	user.Permissions.Api = true
	user.Permissions.Realtime = true
	savePermissionReadUser(t, user)
	token := issuePermissionReadAPIToken(t, user, "permission-filewatch-content-write-revoke", users.Permissions{
		Api:      true,
		Browse:   true,
		Download: true,
		Realtime: true,
	})
	query := url.Values{
		"source":   {"source1"},
		"path":     {"/public/secret.txt"},
		"interval": {"30"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/tools/fileWatcher/sse?"+query.Encode(), nil).WithContext(ctx)
	recorder := newPermissionFileWatchRecorder()
	var once sync.Once
	recorder.onWrite = func(message string) {
		if strings.Contains(message, permissionReadSecret) {
			once.Do(func() {
				if err := auth.RevokeApiToken(store.Access, token); err != nil {
					t.Errorf("revoke file watcher token during content write: %v", err)
				}
			})
		}
	}
	done := make(chan struct{})
	go func() {
		_, _ = fileWatchSSEHandler(recorder, req, &requestContext{user: user, token: token})
		close(done)
	}()

	waitForPermissionFileWatchWrite(t, recorder, permissionReadSecret)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("file watcher remained active after token revocation during content write")
	}
}

func TestPermissionReadSecurity_FileWatcherStopsAfterAuthorizationRevocation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		revoke func(*testing.T, *permissionReadSecurityHarness, *users.User, string)
	}{
		{
			name: "Token",
			revoke: func(t *testing.T, _ *permissionReadSecurityHarness, _ *users.User, token string) {
				if err := auth.RevokeApiToken(store.Access, token); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "account Browse",
			revoke: func(t *testing.T, _ *permissionReadSecurityHarness, user *users.User, _ string) {
				updated := *user
				updated.Permissions.Browse = false
				if err := store.Users.Update(&updated, true, "Permissions"); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "path ACL",
			revoke: func(t *testing.T, h *permissionReadSecurityHarness, user *users.User, _ string) {
				if err := store.Access.DenyUser(h.sourcePath, "/public/secret.txt", user.Username); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newPermissionReadSecurityHarness(t)
			configurePermissionReadAuth(t)
			user := h.user(t, true, true, true)
			user.Username = "permission-filewatch-periodic-" + strings.ReplaceAll(tc.name, " ", "-")
			user.Permissions.Api = true
			user.Permissions.Realtime = true
			savePermissionReadUser(t, user)
			token := issuePermissionReadAPIToken(t, user, "permission-filewatch-periodic", users.Permissions{
				Api:      true,
				Browse:   true,
				Download: true,
				Realtime: true,
			})
			query := url.Values{
				"source":   {"source1"},
				"path":     {"/public/secret.txt"},
				"interval": {"1"},
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req := httptest.NewRequest(http.MethodGet, "/api/tools/fileWatcher/sse?"+query.Encode(), nil).WithContext(ctx)
			recorder := newPermissionFileWatchRecorder()
			done := make(chan struct{})
			go func() {
				_, _ = fileWatchSSEHandler(recorder, req, &requestContext{user: user, token: token})
				close(done)
			}()

			waitForPermissionFileWatchWrite(t, recorder, permissionReadSecret)
			initialEvents := strings.Count(recorder.BodyString(), permissionReadSecret)
			tc.revoke(t, h, user, token)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				cancel()
				<-done
				t.Fatal("file watcher remained active after authorization revocation")
			}
			if got := strings.Count(recorder.BodyString(), permissionReadSecret); got != initialEvents {
				t.Errorf("file watcher sent content after authorization revocation: before=%d after=%d body=%q", initialEvents, got, recorder.BodyString())
			}
		})
	}
}

func TestPermissionReadSecurity_FileWatcherRejectsRawTraversal(t *testing.T) {
	h := newPermissionReadSecurityHarness(t)
	user := h.user(t, true, true, true)
	user.Permissions.Realtime = true
	query := url.Values{"source": {"source1"}, "path": {"/public/../private/secret.txt"}}
	for _, tc := range []struct {
		name   string
		invoke func(*httptest.ResponseRecorder, *http.Request) (int, error)
	}{
		{name: "GET", invoke: func(w *httptest.ResponseRecorder, r *http.Request) (int, error) {
			return fileWatchHandler(w, r, &requestContext{user: user})
		}},
		{name: "SSE", invoke: func(w *httptest.ResponseRecorder, r *http.Request) (int, error) {
			return fileWatchSSEHandler(w, r, &requestContext{user: user})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/tools/fileWatcher?"+query.Encode(), nil)
			recorder := httptest.NewRecorder()
			returned, err := tc.invoke(recorder, req)
			if got := permissionHandlerStatus(returned, recorder); got != http.StatusBadRequest {
				t.Errorf("file watcher traversal status: got %d, want %d (err: %v)", got, http.StatusBadRequest, err)
			}
			if recorder.Header().Get("Content-Type") != "" {
				t.Errorf("file watcher traversal emitted Content-Type %q", recorder.Header().Get("Content-Type"))
			}
		})
	}
}

func TestPermissionReadSecurity_ToolTokenPermissionIntersection(t *testing.T) {
	for _, tc := range []struct {
		name             string
		endpoint         string
		tokenBrowse      bool
		tokenDownload    bool
		revokeUserBrowse bool
	}{
		{
			name:          "duplicate token cannot exceed Browse",
			endpoint:      "/api/tools/duplicateFinder?source=source1&scope=/public&minSizeMb=0",
			tokenBrowse:   false,
			tokenDownload: true,
		},
		{
			name:          "duplicate token cannot exceed Download",
			endpoint:      "/api/tools/duplicateFinder?source=source1&scope=/public&minSizeMb=0",
			tokenBrowse:   true,
			tokenDownload: false,
		},
		{
			name:             "duplicate token loses revoked account Browse",
			endpoint:         "/api/tools/duplicateFinder?source=source1&scope=/public&minSizeMb=0",
			tokenBrowse:      true,
			tokenDownload:    true,
			revokeUserBrowse: true,
		},
		{
			name:          "file watcher token cannot exceed Browse",
			endpoint:      "/api/tools/fileWatcher?source=source1&path=/public/secret.txt",
			tokenBrowse:   false,
			tokenDownload: true,
		},
		{
			name:             "file watcher token loses revoked account Browse",
			endpoint:         "/api/tools/fileWatcher?source=source1&path=/public/secret.txt",
			tokenBrowse:      true,
			tokenDownload:    true,
			revokeUserBrowse: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newPermissionReadSecurityHarness(t)
			resetPermissionDuplicateResultsCache(t)
			configurePermissionReadAuth(t)
			user := h.user(t, true, true, true)
			user.Username = "permission-tools-token-" + strings.ReplaceAll(tc.name, " ", "-")
			user.Permissions.Api = true
			savePermissionReadUser(t, user)
			token := issuePermissionReadAPIToken(t, user, "permission-tools-token", users.Permissions{
				Api:      true,
				Browse:   tc.tokenBrowse,
				Preview:  true,
				Download: tc.tokenDownload,
			})
			if tc.revokeUserBrowse {
				user.Permissions.Browse = false
				if err := store.Users.Update(user, true, "Permissions"); err != nil {
					t.Fatal(err)
				}
			}

			req := httptest.NewRequest(http.MethodGet, tc.endpoint, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			recorder := httptest.NewRecorder()
			permissionToolsAPIRouter().ServeHTTP(recorder, req)
			if recorder.Code != http.StatusForbidden {
				t.Errorf("tool token status: got %d, want %d (body: %q)", recorder.Code, http.StatusForbidden, recorder.Body.String())
			}
			assertNoPermissionReadBytes(t, recorder.Body.Bytes(), "tool token response")
		})
	}
}
