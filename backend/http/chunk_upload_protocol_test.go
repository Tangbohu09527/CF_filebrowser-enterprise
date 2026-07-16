package http

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestChunkUploadAuthenticationKeyUsesPersistedSettings(t *testing.T) {
	setupResourcePutTestEnv(t)

	if _, err := chunkUploadAuthenticationKey(); err == nil {
		t.Fatal("missing chunk upload authentication key was accepted")
	}

	config.Auth.Key = "configured-chunk-upload-test-key"
	key, err := chunkUploadAuthenticationKey()
	if err != nil {
		t.Fatalf("read configured chunk upload authentication key: %v", err)
	}
	if string(key) != config.Auth.Key {
		t.Fatalf("configured chunk upload authentication key: expected %q, got %q", config.Auth.Key, key)
	}

	persisted := *config
	persisted.Auth.Key = "persisted-chunk-upload-test-key"
	if err := store.Settings.Save(&persisted); err != nil {
		t.Fatalf("persist chunk upload authentication key: %v", err)
	}
	config.Auth.Key = "different-process-config-key"

	key, err = chunkUploadAuthenticationKey()
	if err != nil {
		t.Fatalf("read persisted chunk upload authentication key: %v", err)
	}
	if string(key) != persisted.Auth.Key {
		t.Fatalf("persisted chunk upload authentication key: expected %q, got %q", persisted.Auth.Key, key)
	}
}

func TestChunkUploadProtocolValidation(t *testing.T) {
	h := newChunkUploadSecurityHarness(t)

	t.Run("valid chunks append and commit at the declared size", func(t *testing.T) {
		indexPath := "/public/valid-resume.bin"
		first := h.authenticatedChunk(indexPath, 0, 8, strings.NewReader("ABCD"), false)
		if first.Code != http.StatusOK {
			t.Fatalf("first chunk status: expected %d, got %d; body=%s", http.StatusOK, first.Code, first.Body.String())
		}
		second := h.authenticatedChunk(indexPath, 4, 8, strings.NewReader("EFGH"), false)
		if second.Code != http.StatusOK {
			t.Fatalf("second chunk status: expected %d, got %d; body=%s", http.StatusOK, second.Code, second.Body.String())
		}

		finalPath := h.realPath(indexPath)
		data, err := os.ReadFile(finalPath)
		if err != nil {
			t.Fatalf("read committed file: %v", err)
		}
		if !bytes.Equal(data, []byte("ABCDEFGH")) {
			t.Fatalf("committed content: expected %q, got %q", "ABCDEFGH", data)
		}
		if temps := snapshotChunkTemps(t, finalPath); len(temps) != 0 {
			t.Fatalf("completed upload retained %d temporary file(s)", len(temps))
		}
	})

	t.Run("total size cannot change during a session", func(t *testing.T) {
		indexPath := "/public/changed-total.bin"
		finalPath := h.realPath(indexPath)
		first := h.authenticatedChunk(indexPath, 0, 8, strings.NewReader("ABCD"), false)
		if first.Code != http.StatusOK {
			t.Fatalf("first chunk status: expected %d, got %d; body=%s", http.StatusOK, first.Code, first.Body.String())
		}
		changed := h.authenticatedChunk(indexPath, 4, 9, strings.NewReader("EFGH"), false)
		if changed.Code != http.StatusConflict {
			t.Fatalf("changed total status: expected %d, got %d; body=%s", http.StatusConflict, changed.Code, changed.Body.String())
		}

		temps := snapshotChunkTemps(t, finalPath)
		if len(temps) != 1 || !bytes.Equal(temps[0].data, []byte("ABCD")) {
			t.Fatalf("changed total modified the active upload: temps=%v", temps)
		}
		if _, err := os.Stat(finalPath); !os.IsNotExist(err) {
			t.Fatalf("changed total committed a final file: stat error=%v", err)
		}
	})

	t.Run("oversized continuation is rolled back", func(t *testing.T) {
		indexPath := "/public/oversized-continuation.bin"
		finalPath := h.realPath(indexPath)
		first := h.authenticatedChunk(indexPath, 0, 6, strings.NewReader("ABCD"), false)
		if first.Code != http.StatusOK {
			t.Fatalf("first chunk status: expected %d, got %d; body=%s", http.StatusOK, first.Code, first.Body.String())
		}
		unknownLengthBody := io.MultiReader(strings.NewReader("XYZ"))
		oversized := h.authenticatedChunk(indexPath, 4, 6, unknownLengthBody, false)
		if oversized.Code != http.StatusBadRequest {
			t.Fatalf("oversized chunk status: expected %d, got %d; body=%s", http.StatusBadRequest, oversized.Code, oversized.Body.String())
		}

		temps := snapshotChunkTemps(t, finalPath)
		if len(temps) != 1 || !bytes.Equal(temps[0].data, []byte("ABCD")) {
			t.Fatalf("oversized chunk changed the accepted prefix: temps=%v", temps)
		}
		if _, err := os.Stat(finalPath); !os.IsNotExist(err) {
			t.Fatalf("oversized chunk committed a final file: stat error=%v", err)
		}
	})

	t.Run("zero byte file commits but empty non-final chunk is rejected", func(t *testing.T) {
		zeroPath := "/public/zero-byte.bin"
		zero := h.authenticatedChunk(zeroPath, 0, 0, bytes.NewReader(nil), false)
		if zero.Code != http.StatusOK {
			t.Fatalf("zero-byte upload status: expected %d, got %d; body=%s", http.StatusOK, zero.Code, zero.Body.String())
		}
		info, err := os.Stat(h.realPath(zeroPath))
		if err != nil {
			t.Fatalf("stat zero-byte file: %v", err)
		}
		if info.Size() != 0 {
			t.Fatalf("zero-byte file size: expected 0, got %d", info.Size())
		}

		emptyPath := "/public/empty-non-final.bin"
		empty := h.authenticatedChunk(emptyPath, 0, 4, bytes.NewReader(nil), false)
		if empty.Code != http.StatusBadRequest {
			t.Fatalf("empty non-final chunk status: expected %d, got %d; body=%s", http.StatusBadRequest, empty.Code, empty.Body.String())
		}
		if temps := snapshotChunkTemps(t, h.realPath(emptyPath)); len(temps) != 0 {
			t.Fatalf("empty non-final chunk retained %d temporary file(s)", len(temps))
		}
	})

	t.Run("share upload preserves chunk validation status", func(t *testing.T) {
		indexPath := "/share-oversized.bin"
		response := h.sharedChunk(indexPath, 0, 1, strings.NewReader("XX"), false)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("share oversized chunk status: expected %d, got %d; body=%s", http.StatusBadRequest, response.Code, response.Body.String())
		}

		finalPath := h.realPath("/public" + indexPath)
		if _, err := os.Stat(finalPath); !os.IsNotExist(err) {
			t.Fatalf("share oversized chunk committed a final file: stat error=%v", err)
		}
		if temps := snapshotChunkTemps(t, finalPath); len(temps) != 0 {
			t.Fatalf("share oversized chunk retained %d temporary file(s)", len(temps))
		}
	})

	t.Run("target appearing during final chunk is not overwritten", func(t *testing.T) {
		indexPath := "/public/final-commit-race.bin"
		finalPath := h.realPath(indexPath)
		arrived := make(chan struct{}, 1)
		release := make(chan struct{})
		body := &coordinatedChunkReader{
			reader:  strings.NewReader("CHUNKED"),
			arrived: arrived,
			release: release,
		}

		var requests sync.WaitGroup
		requests.Add(1)
		responses := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			defer requests.Done()
			responses <- h.authenticatedChunk(indexPath, 0, 7, body, false)
		}()
		if received := waitForChunkReaders(arrived, 1, time.Second); received != 1 {
			close(release)
			requests.Wait()
			t.Fatalf("chunk reader did not start")
		}
		if err := os.WriteFile(finalPath, []byte("RACE"), 0644); err != nil {
			close(release)
			requests.Wait()
			t.Fatalf("create racing target: %v", err)
		}
		close(release)
		requests.Wait()
		response := <-responses
		if response.Code != http.StatusConflict {
			t.Fatalf("final commit race status: expected %d, got %d; body=%s", http.StatusConflict, response.Code, response.Body.String())
		}
		data, err := os.ReadFile(finalPath)
		if err != nil {
			t.Fatalf("read racing target: %v", err)
		}
		if !bytes.Equal(data, []byte("RACE")) {
			t.Fatalf("racing target was overwritten: got %q", data)
		}
		if temps := snapshotChunkTemps(t, finalPath); len(temps) != 0 {
			t.Fatalf("rejected final commit retained %d temporary file(s)", len(temps))
		}
	})

	t.Run("windows target matching is case insensitive", func(t *testing.T) {
		if runtime.GOOS != "windows" {
			t.Skip("Windows filesystem behavior")
		}

		upperPath := "/public/Case-Target.bin"
		lowerPath := "/public/case-target.bin"
		first := h.authenticatedChunk(upperPath, 0, 8, strings.NewReader("ABCD"), false)
		if first.Code != http.StatusOK {
			t.Fatalf("first chunk status: expected %d, got %d; body=%s", http.StatusOK, first.Code, first.Body.String())
		}
		duplicate := h.authenticatedChunk(lowerPath, 0, 8, strings.NewReader("WXYZ"), false)
		if duplicate.Code != http.StatusConflict {
			t.Fatalf("case-variant duplicate status: expected %d, got %d; body=%s", http.StatusConflict, duplicate.Code, duplicate.Body.String())
		}

		temps := snapshotChunkTemps(t, h.realPath(upperPath))
		if len(temps) != 1 || !bytes.Equal(temps[0].data, []byte("ABCD")) {
			t.Fatalf("case-variant duplicate changed the active upload: temps=%v", temps)
		}
	})

	t.Run("stale cleanup ignores unauthenticated temporary names", func(t *testing.T) {
		targetPath := h.realPath("/public/forged-temp.bin")
		forgedPath := targetPath + chunkUploadTempMarker + strings.Repeat("A", chunkUploadTempTokenLen) + chunkUploadTempSuffix
		if err := os.WriteFile(forgedPath, []byte("USER FILE"), 0644); err != nil {
			t.Fatalf("create forged temporary name: %v", err)
		}
		staleTime := time.Now().Add(-72 * time.Hour)
		if err := os.Chtimes(forgedPath, staleTime, staleTime); err != nil {
			t.Fatalf("age forged temporary name: %v", err)
		}

		trigger := h.authenticatedChunk("/public/forged-cleanup-trigger.bin", 0, 4, strings.NewReader("NEXT"), false)
		if trigger.Code != http.StatusOK {
			t.Fatalf("cleanup trigger status: expected %d, got %d; body=%s", http.StatusOK, trigger.Code, trigger.Body.String())
		}
		data, err := os.ReadFile(forgedPath)
		if err != nil {
			t.Fatalf("forged temporary name was removed: %v", err)
		}
		if !bytes.Equal(data, []byte("USER FILE")) {
			t.Fatalf("forged temporary name content changed: got %q", data)
		}
	})
}
