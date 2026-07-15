package http

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	dbshare "github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/preview"
)

func TestChunkUploadSecurityFailures(t *testing.T) {
	h := newChunkUploadSecurityHarness(t)

	t.Run("uploads to one target do not share a temporary path", func(t *testing.T) {
		indexPath := "/public/shared-temp-path.bin"
		finalPath := h.realPath(indexPath)
		firstBody := []byte("FIRST-UP")

		first := h.authenticatedChunk(indexPath, 0, 64, bytes.NewReader(firstBody), false)
		firstTemps := snapshotChunkTemps(t, finalPath)
		logChunkTemps(t, "after first upload", firstTemps)
		if first.Code != http.StatusOK {
			t.Fatalf("first upload status: expected %d, got %d; body=%s", http.StatusOK, first.Code, first.Body.String())
		}
		if len(firstTemps) != 1 {
			t.Fatalf("first upload temporary files: expected 1, got %d", len(firstTemps))
		}

		second := h.authenticatedChunk(indexPath, 0, 96, strings.NewReader("SECONDUP"), false)
		afterSecond := snapshotChunkTemps(t, finalPath)
		logChunkTemps(t, "after second upload", afterSecond)
		t.Logf("responses: first=%d second=%d", first.Code, second.Code)

		if second.Code < http.StatusBadRequest && len(afterSecond) == 1 && afterSecond[0].path == firstTemps[0].path {
			t.Errorf("two accepted uploads reused temporary path %q", afterSecond[0].path)
		}
		if current, ok := findChunkTemp(afterSecond, firstTemps[0].path); ok && !bytes.Equal(current.data, firstBody) {
			t.Errorf("second upload changed the first upload temporary file: before=%q after=%q", firstBody, current.data)
		}
	})

	t.Run("incorrect offset is rejected", func(t *testing.T) {
		indexPath := "/public/incorrect-offset.bin"
		finalPath := h.realPath(indexPath)
		initial := []byte("ABCD")

		first := h.authenticatedChunk(indexPath, 0, 32, bytes.NewReader(initial), false)
		if first.Code != http.StatusOK {
			t.Fatalf("initial chunk status: expected %d, got %d; body=%s", http.StatusOK, first.Code, first.Body.String())
		}
		second := h.authenticatedChunk(indexPath, 1, 32, strings.NewReader("xy"), false)
		temps := snapshotChunkTemps(t, finalPath)
		logChunkTemps(t, "after incorrect offset", temps)
		t.Logf("responses: initial=%d incorrect-offset=%d", first.Code, second.Code)

		if second.Code < http.StatusBadRequest {
			t.Errorf("incorrect offset was accepted with status %d", second.Code)
		}
		if len(temps) != 1 {
			t.Fatalf("temporary files: expected 1, got %d", len(temps))
		}
		if !bytes.Equal(temps[0].data, initial) {
			t.Errorf("incorrect offset modified disk content: expected %q, got %q", initial, temps[0].data)
		}
	})

	t.Run("duplicate offset does not overwrite a completed chunk", func(t *testing.T) {
		indexPath := "/public/duplicate-offset.bin"
		finalPath := h.realPath(indexPath)
		initial := []byte("ORIGINAL")

		first := h.authenticatedChunk(indexPath, 0, 32, bytes.NewReader(initial), false)
		if first.Code != http.StatusOK {
			t.Fatalf("initial chunk status: expected %d, got %d; body=%s", http.StatusOK, first.Code, first.Body.String())
		}
		duplicate := h.authenticatedChunk(indexPath, 0, 32, strings.NewReader("REPLACED"), false)
		temps := snapshotChunkTemps(t, finalPath)
		logChunkTemps(t, "after duplicate offset", temps)
		t.Logf("responses: initial=%d duplicate=%d", first.Code, duplicate.Code)

		if duplicate.Code < http.StatusBadRequest {
			t.Errorf("duplicate offset was accepted with status %d", duplicate.Code)
		}
		if len(temps) != 1 {
			t.Fatalf("temporary files: expected 1, got %d", len(temps))
		}
		if !bytes.Equal(temps[0].data, initial) {
			t.Errorf("duplicate offset overwrote disk content: expected %q, got %q", initial, temps[0].data)
		}
	})

	t.Run("jumped offset cannot create a hole", func(t *testing.T) {
		indexPath := "/public/jumped-offset.bin"
		finalPath := h.realPath(indexPath)

		jumped := h.authenticatedChunk(indexPath, 8, 32, strings.NewReader("TAIL"), false)
		temps := snapshotChunkTemps(t, finalPath)
		logChunkTemps(t, "after jumped offset", temps)
		t.Logf("response: jumped-offset=%d", jumped.Code)

		if jumped.Code < http.StatusBadRequest {
			t.Errorf("jumped offset was accepted with status %d", jumped.Code)
		}
		for _, temp := range temps {
			if len(temp.data) >= 8 && allZero(temp.data[:8]) {
				t.Errorf("jumped offset created an eight-byte hole in %q: bytes=%v", temp.path, temp.data)
			}
		}
	})

	t.Run("declared total size must match committed file size", func(t *testing.T) {
		indexPath := "/public/size-mismatch.bin"
		finalPath := h.realPath(indexPath)
		body := []byte("123456")

		response := h.authenticatedChunk(indexPath, 0, 5, bytes.NewReader(body), false)
		temps := snapshotChunkTemps(t, finalPath)
		logChunkTemps(t, "after size mismatch", temps)
		finalData, readErr := os.ReadFile(finalPath)
		if readErr == nil {
			t.Logf("disk final path=%q declared-size=5 actual-size=%d bytes=%q", finalPath, len(finalData), finalData)
		} else {
			t.Logf("disk final path=%q read-error=%v", finalPath, readErr)
		}
		t.Logf("response: size-mismatch=%d", response.Code)

		if response.Code < http.StatusBadRequest {
			t.Errorf("size-mismatched upload was accepted with status %d", response.Code)
		}
		if readErr == nil {
			t.Errorf("size-mismatched upload was committed: declared=5 actual=%d", len(finalData))
		} else if !os.IsNotExist(readErr) {
			t.Fatalf("read final file: %v", readErr)
		}
	})

	t.Run("concurrent uploads to one target cannot pollute each other", func(t *testing.T) {
		indexPath := "/public/concurrent-pollution.bin"
		finalPath := h.realPath(indexPath)
		arrived := make(chan struct{}, 2)
		release := make(chan struct{})
		firstWritten := make(chan struct{})

		firstBody := &coordinatedChunkReader{
			reader:  strings.NewReader("AAAA"),
			arrived: arrived,
			release: release,
			signal:  firstWritten,
		}
		secondBody := &coordinatedChunkReader{
			reader:  strings.NewReader("BB"),
			arrived: arrived,
			release: release,
			wait:    firstWritten,
		}

		responses := make(chan *httptest.ResponseRecorder, 2)
		var requests sync.WaitGroup
		requests.Add(2)
		go func() {
			defer requests.Done()
			responses <- h.authenticatedChunk(indexPath, 0, 32, firstBody, false)
		}()
		go func() {
			defer requests.Done()
			responses <- h.authenticatedChunk(indexPath, 0, 32, secondBody, false)
		}()

		arrivalCount := waitForChunkReaders(arrived, 2, time.Second)
		close(release)
		requests.Wait()
		close(responses)

		codes := make([]int, 0, 2)
		for response := range responses {
			codes = append(codes, response.Code)
		}
		temps := snapshotChunkTemps(t, finalPath)
		logChunkTemps(t, "after concurrent uploads", temps)
		t.Logf("concurrent readers opened=%d response-statuses=%v", arrivalCount, codes)

		bothAccepted := len(codes) == 2 && codes[0] < http.StatusBadRequest && codes[1] < http.StatusBadRequest
		if bothAccepted && len(temps) == 1 {
			t.Errorf("both concurrent uploads were accepted into one temporary file %q", temps[0].path)
		}
		for _, temp := range temps {
			if bytes.Equal(temp.data, []byte("BBAA")) {
				t.Errorf("concurrent upload content was mixed on disk in %q: %q", temp.path, temp.data)
			}
		}
	})

	t.Run("stale non-final upload is removed", func(t *testing.T) {
		indexPath := "/public/stale-non-final.bin"
		finalPath := h.realPath(indexPath)

		response := h.authenticatedChunk(indexPath, 0, 64, strings.NewReader("PARTIAL"), false)
		if response.Code != http.StatusOK {
			t.Fatalf("non-final chunk status: expected %d, got %d; body=%s", http.StatusOK, response.Code, response.Body.String())
		}
		temps := snapshotChunkTemps(t, finalPath)
		if len(temps) != 1 {
			t.Fatalf("temporary files: expected 1, got %d", len(temps))
		}
		staleTime := time.Now().Add(-72 * time.Hour)
		if err := os.Chtimes(temps[0].path, staleTime, staleTime); err != nil {
			t.Fatalf("age temporary file: %v", err)
		}

		trigger := h.authenticatedChunk("/public/stale-cleanup-trigger.bin", 0, 64, strings.NewReader("NEXT"), false)
		if trigger.Code != http.StatusOK {
			t.Fatalf("cleanup trigger status: expected %d, got %d; body=%s", http.StatusOK, trigger.Code, trigger.Body.String())
		}
		afterTrigger := snapshotChunkTemps(t, finalPath)
		logChunkTemps(t, "after later upload activity", afterTrigger)
		if len(afterTrigger) != 0 {
			age := time.Since(afterTrigger[0].modTime).Round(time.Second)
			t.Errorf("stale non-final temporary file remains on disk after later upload activity: path=%q age=%s", afterTrigger[0].path, age)
		}
	})

	t.Run("move failure removes completed temporary file", func(t *testing.T) {
		indexPath := "/public/move-failure"
		finalPath := h.realPath(indexPath)
		if err := os.Mkdir(finalPath, 0755); err != nil {
			t.Fatalf("create conflicting destination directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(finalPath, "sentinel"), []byte("keep"), 0644); err != nil {
			t.Fatalf("populate conflicting destination directory: %v", err)
		}

		response := h.authenticatedChunk(indexPath, 0, 4, strings.NewReader("DATA"), true)
		temps := snapshotChunkTemps(t, finalPath)
		logChunkTemps(t, "after MoveResource failure", temps)
		t.Logf("response: move-failure=%d body=%s", response.Code, response.Body.String())

		if response.Code != http.StatusInternalServerError {
			t.Errorf("MoveResource failure status: expected %d, got %d", http.StatusInternalServerError, response.Code)
		}
		if len(temps) != 0 {
			t.Errorf("MoveResource failure retained %d completed temporary file(s)", len(temps))
		}
	})

	t.Run("authenticated and share uploads do not share a temporary file", func(t *testing.T) {
		indexPath := "/public/cross-entry.bin"
		finalPath := h.realPath(indexPath)
		authenticatedBody := []byte("NORMAL")

		authenticated := h.authenticatedChunk(indexPath, 0, 64, bytes.NewReader(authenticatedBody), false)
		if authenticated.Code != http.StatusOK {
			t.Fatalf("authenticated chunk status: expected %d, got %d; body=%s", http.StatusOK, authenticated.Code, authenticated.Body.String())
		}
		authenticatedTemps := snapshotChunkTemps(t, finalPath)
		if len(authenticatedTemps) != 1 {
			t.Fatalf("authenticated temporary files: expected 1, got %d", len(authenticatedTemps))
		}
		logChunkTemps(t, "after authenticated upload", authenticatedTemps)

		shared := h.sharedChunk("/cross-entry.bin", 0, 96, strings.NewReader("SHARED"), false)
		afterShare := snapshotChunkTemps(t, finalPath)
		logChunkTemps(t, "after share upload", afterShare)
		t.Logf("responses: authenticated=%d share=%d", authenticated.Code, shared.Code)

		if shared.Code < http.StatusBadRequest && len(afterShare) == 1 && afterShare[0].path == authenticatedTemps[0].path {
			t.Errorf("authenticated and share uploads reused temporary path %q", afterShare[0].path)
		}
		if current, ok := findChunkTemp(afterShare, authenticatedTemps[0].path); ok && !bytes.Equal(current.data, authenticatedBody) {
			t.Errorf("share upload changed authenticated upload temporary content: before=%q after=%q", authenticatedBody, current.data)
		}
	})
}

type chunkUploadSecurityHarness struct {
	sourcePath string
	shareHash  string
	router     http.Handler
}

func newChunkUploadSecurityHarness(t *testing.T) *chunkUploadSecurityHarness {
	t.Helper()

	sourcePath := setupResourcePutTestEnv(t)
	if preview.GetService() == nil {
		if err := preview.StartPreviewGenerator(1, filepath.Join(filepath.Dir(sourcePath), "chunk-upload-security-preview")); err != nil {
			t.Fatalf("start preview service: %v", err)
		}
	}

	user := &users.User{
		Username: "chunk-upload-security-user",
		Permissions: users.Permissions{
			Create: true,
			Modify: true,
		},
		Scopes: []users.SourceScope{
			{Name: sourcePath, Scope: "/"},
		},
	}
	if err := store.Users.Save(user, false, false); err != nil {
		t.Fatalf("save ordinary upload user: %v", err)
	}
	if user.ID != 1 {
		t.Fatalf("ordinary upload user ID: expected 1 for no-auth routing, got %d", user.ID)
	}
	config.Auth.Methods.NoAuth = true

	const shareHash = "chunk-upload-security-share"
	link := &dbshare.Link{
		Hash:   shareHash,
		UserID: user.ID,
		CommonShare: dbshare.CommonShare{
			Source:            sourcePath,
			Path:              "/public",
			ShareType:         "upload",
			AllowCreate:       true,
			AllowReplacements: true,
		},
	}
	if err := store.Share.Save(link); err != nil {
		t.Fatalf("save upload share: %v", err)
	}

	api := http.NewServeMux()
	api.HandleFunc("POST /resources", withUser(resourcePostHandler))
	publicAPI := http.NewServeMux()
	publicAPI.HandleFunc("POST /resources", withHashFile(publicUploadHandler))
	root := http.NewServeMux()
	root.Handle("/api/", http.StripPrefix("/api", api))
	root.Handle("/public/api/", http.StripPrefix("/public/api", publicAPI))

	return &chunkUploadSecurityHarness{
		sourcePath: sourcePath,
		shareHash:  shareHash,
		router:     root,
	}
}

func (h *chunkUploadSecurityHarness) realPath(indexPath string) string {
	return filepath.Join(h.sourcePath, filepath.FromSlash(strings.TrimPrefix(indexPath, "/")))
}

func (h *chunkUploadSecurityHarness) authenticatedChunk(indexPath string, offset, total int64, body io.Reader, override bool) *httptest.ResponseRecorder {
	query := url.Values{
		"source": {"source1"},
		"path":   {indexPath},
	}
	if override {
		query.Set("override", "true")
	}
	return h.serveChunk("/api/resources?"+query.Encode(), offset, total, body)
}

func (h *chunkUploadSecurityHarness) sharedChunk(indexPath string, offset, total int64, body io.Reader, override bool) *httptest.ResponseRecorder {
	query := url.Values{
		"hash": {h.shareHash},
		"path": {indexPath},
	}
	if override {
		query.Set("override", "true")
	}
	return h.serveChunk("/public/api/resources?"+query.Encode(), offset, total, body)
}

func (h *chunkUploadSecurityHarness) serveChunk(target string, offset, total int64, body io.Reader) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, target, body)
	request.Header.Set("X-File-Chunk-Offset", strconv.FormatInt(offset, 10))
	request.Header.Set("X-File-Total-Size", strconv.FormatInt(total, 10))
	response := httptest.NewRecorder()
	h.router.ServeHTTP(response, request)
	return response
}

type chunkTempSnapshot struct {
	path    string
	data    []byte
	modTime time.Time
}

func snapshotChunkTemps(t *testing.T, finalPath string) []chunkTempSnapshot {
	t.Helper()

	matches, err := filepath.Glob(finalPath + ".*.uploading.tmp")
	if err != nil {
		t.Fatalf("glob chunk temporary files for %q: %v", finalPath, err)
	}
	snapshots := make([]chunkTempSnapshot, 0, len(matches))
	for _, match := range matches {
		data, readErr := os.ReadFile(match)
		if readErr != nil {
			t.Fatalf("read chunk temporary file %q: %v", match, readErr)
		}
		info, statErr := os.Stat(match)
		if statErr != nil {
			t.Fatalf("stat chunk temporary file %q: %v", match, statErr)
		}
		snapshots = append(snapshots, chunkTempSnapshot{
			path:    match,
			data:    data,
			modTime: info.ModTime(),
		})
	}
	return snapshots
}

func logChunkTemps(t *testing.T, label string, snapshots []chunkTempSnapshot) {
	t.Helper()

	if len(snapshots) == 0 {
		t.Logf("%s: no .uploading.tmp files", label)
		return
	}
	for _, snapshot := range snapshots {
		t.Logf("%s: disk temp path=%q size=%d modtime=%s bytes=%q raw=%v", label, snapshot.path, len(snapshot.data), snapshot.modTime.Format(time.RFC3339Nano), snapshot.data, snapshot.data)
	}
}

func findChunkTemp(snapshots []chunkTempSnapshot, path string) (chunkTempSnapshot, bool) {
	for _, snapshot := range snapshots {
		if snapshot.path == path {
			return snapshot, true
		}
	}
	return chunkTempSnapshot{}, false
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

type coordinatedChunkReader struct {
	reader  *strings.Reader
	arrived chan<- struct{}
	release <-chan struct{}
	wait    <-chan struct{}
	signal  chan struct{}
	started bool
	once    sync.Once
}

func (r *coordinatedChunkReader) Read(buffer []byte) (int, error) {
	if !r.started {
		r.started = true
		r.arrived <- struct{}{}
		<-r.release
		if r.wait != nil {
			select {
			case <-r.wait:
			case <-time.After(time.Second):
			}
		}
	}

	n, err := r.reader.Read(buffer)
	if err == io.EOF && r.signal != nil {
		r.once.Do(func() { close(r.signal) })
	}
	return n, err
}

func waitForChunkReaders(arrived <-chan struct{}, count int, timeout time.Duration) int {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	received := 0
	for received < count {
		select {
		case <-arrived:
			received++
		case <-timer.C:
			return received
		}
	}
	return received
}
