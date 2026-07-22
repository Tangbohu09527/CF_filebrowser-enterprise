package filebridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const transferTestToken = "header.payload.signature"

func TestTransferMkdirDryRunAndApply(t *testing.T) {
	t.Run("dry-run does not post", func(t *testing.T) {
		var getCalls atomic.Int32
		var postCalls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path != "/api/resources" {
				t.Errorf("unexpected request path: %s", request.URL.Path)
				http.NotFound(writer, request)
				return
			}
			switch request.Method {
			case http.MethodGet:
				getCalls.Add(1)
				writer.WriteHeader(http.StatusNotFound)
			case http.MethodPost:
				postCalls.Add(1)
				writer.WriteHeader(http.StatusNoContent)
			default:
				t.Errorf("unexpected request method: %s", request.Method)
				writer.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		defer server.Close()

		runner := transferTestRunner(t, server.URL, nil, nil)
		response := runner.Run(context.Background(), "mkdir", transferTestInput("/write/new-directory"), false)

		if !response.OK {
			t.Fatalf("mkdir dry-run failed: %+v", response.Error)
		}
		if !response.DryRun {
			t.Fatal("mkdir without --apply was not reported as a dry-run")
		}
		result, ok := response.Result.(WriteResult)
		if !ok {
			t.Fatalf("unexpected result type: %T", response.Result)
		}
		if result.Applied || result.Verified || result.AlreadyDone {
			t.Fatalf("dry-run reported an applied write: %+v", result)
		}
		if got := getCalls.Load(); got != 1 {
			t.Fatalf("dry-run stat calls = %d, want 1", got)
		}
		if got := postCalls.Load(); got != 0 {
			t.Fatalf("dry-run POST calls = %d, want 0", got)
		}
	})

	t.Run("apply posts and verifies", func(t *testing.T) {
		var created atomic.Bool
		var getCalls atomic.Int32
		var postCalls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path != "/api/resources" {
				t.Errorf("unexpected request path: %s", request.URL.Path)
				http.NotFound(writer, request)
				return
			}
			if request.URL.Query().Get("source") != "docs" || request.URL.Query().Get("path") != "/write/new-directory" {
				t.Errorf("unexpected mkdir query: %s", request.URL.RawQuery)
			}
			switch request.Method {
			case http.MethodGet:
				getCalls.Add(1)
				if !created.Load() {
					writer.WriteHeader(http.StatusNotFound)
					return
				}
				transferTestWriteJSON(t, writer, map[string]any{
					"name": "new-directory", "type": "directory", "size": int64(0),
				})
			case http.MethodPost:
				postCalls.Add(1)
				if request.URL.Query().Get("isDir") != "true" {
					t.Errorf("mkdir POST omitted isDir=true: %s", request.URL.RawQuery)
				}
				created.Store(true)
				writer.WriteHeader(http.StatusNoContent)
			default:
				t.Errorf("unexpected request method: %s", request.Method)
				writer.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		defer server.Close()

		runner := transferTestRunner(t, server.URL, nil, nil)
		response := runner.Run(context.Background(), "mkdir", transferTestInput("/write/new-directory"), true)

		if !response.OK {
			t.Fatalf("mkdir --apply failed: %+v", response.Error)
		}
		if response.DryRun {
			t.Fatal("mkdir --apply was reported as a dry-run")
		}
		result, ok := response.Result.(WriteResult)
		if !ok {
			t.Fatalf("unexpected result type: %T", response.Result)
		}
		if !result.Applied || !result.Verified || result.AlreadyDone {
			t.Fatalf("mkdir --apply result was not verified: %+v", result)
		}
		if got := postCalls.Load(); got != 1 {
			t.Fatalf("mkdir --apply POST calls = %d, want 1", got)
		}
		if got := getCalls.Load(); got != 2 {
			t.Fatalf("mkdir --apply stat calls = %d, want 2", got)
		}
	})
}

func TestTransferUploadNewPreflight(t *testing.T) {
	localRoot := t.TempDir()
	localFile := filepath.Join(localRoot, "new.txt")
	if err := os.WriteFile(localFile, []byte("new upload"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("dry-run does not post", func(t *testing.T) {
		var getCalls atomic.Int32
		var postCalls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.Method {
			case http.MethodGet:
				getCalls.Add(1)
				writer.WriteHeader(http.StatusNotFound)
			case http.MethodPost:
				postCalls.Add(1)
				writer.WriteHeader(http.StatusNoContent)
			default:
				writer.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		defer server.Close()

		runner := transferTestRunner(t, server.URL, []string{localRoot}, nil)
		input := transferTestInput("/write/new.txt")
		input.LocalFile = localFile
		response := runner.Run(context.Background(), "upload-new", input, false)

		if !response.OK {
			t.Fatalf("upload-new dry-run failed: %+v", response.Error)
		}
		if !response.DryRun {
			t.Fatal("upload-new without --apply was not reported as a dry-run")
		}
		if got := getCalls.Load(); got != 1 {
			t.Fatalf("upload-new dry-run stat calls = %d, want 1", got)
		}
		if got := postCalls.Load(); got != 0 {
			t.Fatalf("upload-new dry-run POST calls = %d, want 0", got)
		}
	})

	t.Run("existing target is rejected", func(t *testing.T) {
		var getCalls atomic.Int32
		var postCalls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.Method {
			case http.MethodGet:
				getCalls.Add(1)
				transferTestWriteJSON(t, writer, map[string]any{
					"name": "existing.txt", "type": "text", "size": int64(8),
				})
			case http.MethodPost:
				postCalls.Add(1)
				writer.WriteHeader(http.StatusNoContent)
			default:
				writer.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		defer server.Close()

		runner := transferTestRunner(t, server.URL, []string{localRoot}, nil)
		input := transferTestInput("/write/existing.txt")
		input.LocalFile = localFile
		transferTestSetApproval(&input, []byte("new upload"))
		response := runner.Run(context.Background(), "upload-new", input, true)

		transferTestRequireError(t, response, "target_exists")
		if got := getCalls.Load(); got != 1 {
			t.Fatalf("existing-target stat calls = %d, want 1", got)
		}
		if got := postCalls.Load(); got != 0 {
			t.Fatalf("existing-target POST calls = %d, want 0", got)
		}
	})
}

func TestTransferUploadNewApplyUsesOneNonOverrideChunkAndVerifies(t *testing.T) {
	localRoot := t.TempDir()
	payload := []byte("supplier material\n")
	localFile := filepath.Join(localRoot, "supplier.txt")
	if err := os.WriteFile(localFile, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	digestBytes := sha256.Sum256(payload)
	digest := hex.EncodeToString(digestBytes[:])

	var preflightCalls atomic.Int32
	var postCalls atomic.Int32
	var headCalls atomic.Int32
	var statCalls atomic.Int32
	var checksumCalls atomic.Int32
	var sequenceMu sync.Mutex
	var sequence []string
	record := func(value string) {
		sequenceMu.Lock()
		sequence = append(sequence, value)
		sequenceMu.Unlock()
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/api/resources" && request.Method == http.MethodGet:
			if request.URL.Query().Get("source") != "docs" || request.URL.Query().Get("path") != "/write/supplier.txt" {
				t.Errorf("unexpected stat query: %s", request.URL.RawQuery)
			}
			if request.URL.Query().Get("checksum") == "sha256" {
				checksumCalls.Add(1)
				record("checksum")
				transferTestWriteJSON(t, writer, map[string]any{
					"name": "supplier.txt", "type": "text", "size": int64(len(payload)),
					"checksums": map[string]string{"sha256": digest},
				})
				return
			}
			if postCalls.Load() == 0 {
				preflightCalls.Add(1)
				record("preflight")
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			statCalls.Add(1)
			record("stat")
			transferTestWriteJSON(t, writer, map[string]any{
				"name": "supplier.txt", "type": "text", "size": int64(len(payload)),
			})
		case request.URL.Path == "/api/resources" && request.Method == http.MethodPost:
			postCalls.Add(1)
			record("post")
			query := request.URL.Query()
			if query.Get("source") != "docs" || query.Get("path") != "/write/supplier.txt" {
				t.Errorf("unexpected upload query: %s", request.URL.RawQuery)
			}
			for _, key := range []string{"override", "overwrite", "action"} {
				if _, present := query[key]; present {
					t.Errorf("upload unexpectedly supplied %s: %s", key, request.URL.RawQuery)
				}
			}
			if got := request.Header.Get("X-File-Chunk-Offset"); got != "0" {
				t.Errorf("X-File-Chunk-Offset = %q, want 0", got)
			}
			if got := request.Header.Get("X-File-Total-Size"); got != strconv.Itoa(len(payload)) {
				t.Errorf("X-File-Total-Size = %q, want %d", got, len(payload))
			}
			if got := request.Header.Get("Content-Type"); got != "application/octet-stream" {
				t.Errorf("Content-Type = %q, want application/octet-stream", got)
			}
			if request.ContentLength != int64(len(payload)) {
				t.Errorf("Content-Length = %d, want %d", request.ContentLength, len(payload))
			}
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Errorf("read upload body: %v", err)
			} else if string(body) != string(payload) {
				t.Errorf("upload body = %q, want %q", body, payload)
			}
			writer.WriteHeader(http.StatusNoContent)
		case request.URL.Path == "/api/resources/download" && request.Method == http.MethodHead:
			headCalls.Add(1)
			record("head")
			if request.URL.Query().Get("source") != "docs" || request.URL.Query().Get("file") != "/write/supplier.txt" {
				t.Errorf("unexpected verification HEAD query: %s", request.URL.RawQuery)
			}
			writer.Header().Set("Content-Length", strconv.Itoa(len(payload)))
			writer.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", request.Method, request.URL.String())
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	runner := transferTestRunner(t, server.URL, []string{localRoot}, nil)
	input := transferTestInput("/write/supplier.txt")
	input.LocalFile = localFile
	transferTestSetApproval(&input, payload)
	response := runner.Run(context.Background(), "upload-new", input, true)

	if !response.OK {
		t.Fatalf("upload-new --apply failed: %+v", response.Error)
	}
	result, ok := response.Result.(WriteResult)
	if !ok {
		t.Fatalf("unexpected result type: %T", response.Result)
	}
	if !result.Applied || !result.Verified || result.Bytes != int64(len(payload)) || result.SHA256 != digest {
		t.Fatalf("upload result was not fully verified: %+v", result)
	}
	if got := postCalls.Load(); got != 1 {
		t.Fatalf("upload POST calls = %d, want one single chunk", got)
	}
	if got := preflightCalls.Load(); got != 1 {
		t.Fatalf("preflight stat calls = %d, want 1", got)
	}
	if got := headCalls.Load(); got != 1 {
		t.Fatalf("verification HEAD calls = %d, want 1", got)
	}
	if got := statCalls.Load(); got != 1 {
		t.Fatalf("post-upload stat calls = %d, want 1", got)
	}
	if got := checksumCalls.Load(); got != 1 {
		t.Fatalf("post-upload checksum calls = %d, want 1", got)
	}
	sequenceMu.Lock()
	gotSequence := strings.Join(sequence, ",")
	sequenceMu.Unlock()
	if want := "preflight,post,head,stat,checksum"; gotSequence != want {
		t.Fatalf("request sequence = %q, want %q", gotSequence, want)
	}
}

func TestTransferUploadNewDetectsLocalFileChange(t *testing.T) {
	localRoot := t.TempDir()
	localFile := filepath.Join(localRoot, "changing.txt")
	original := []byte("original upload bytes")
	if err := os.WriteFile(localFile, original, 0o600); err != nil {
		t.Fatal(err)
	}

	var postCalls atomic.Int32
	var verificationCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/resources":
			writer.WriteHeader(http.StatusNotFound)
		case request.Method == http.MethodPost && request.URL.Path == "/api/resources":
			postCalls.Add(1)
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Errorf("read upload body: %v", err)
			} else if string(body) != string(original) {
				t.Errorf("upload body = %q, want original bytes", body)
			}
			if err := os.WriteFile(localFile, append(append([]byte(nil), original...), []byte(" changed")...), 0o600); err != nil {
				t.Errorf("change local file during upload: %v", err)
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodHead && request.URL.Path == "/api/resources/download":
			verificationCalls.Add(1)
			writer.WriteHeader(http.StatusOK)
		default:
			verificationCalls.Add(1)
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	runner := transferTestRunner(t, server.URL, []string{localRoot}, nil)
	input := transferTestInput("/write/changing.txt")
	input.LocalFile = localFile
	transferTestSetApproval(&input, original)
	response := runner.Run(context.Background(), "upload-new", input, true)

	transferTestRequireError(t, response, "local_file_changed")
	if got := postCalls.Load(); got != 1 {
		t.Fatalf("upload POST calls = %d, want 1", got)
	}
	if got := verificationCalls.Load(); got != 0 {
		t.Fatalf("verification calls after local change = %d, want 0", got)
	}
}

func TestTransferUploadNewBindsApplyToDryRunContent(t *testing.T) {
	localRoot := t.TempDir()
	localFile := filepath.Join(localRoot, "approved.txt")
	approved := []byte("approved content")
	if err := os.WriteFile(localFile, approved, 0o600); err != nil {
		t.Fatal(err)
	}

	var requests atomic.Int32
	var postCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method == http.MethodPost {
			postCalls.Add(1)
		}
		writer.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	runner := transferTestRunner(t, server.URL, []string{localRoot}, nil)
	input := transferTestInput("/write/approved.txt")
	input.LocalFile = localFile
	dryRun := runner.Run(context.Background(), "upload-new", input, false)
	if !dryRun.OK {
		t.Fatalf("dry-run failed: %+v", dryRun.Error)
	}
	plan := dryRun.Result.(WriteResult)
	if plan.SHA256 == "" || plan.Bytes != int64(len(approved)) {
		t.Fatalf("dry-run omitted approval material: %+v", plan)
	}

	if err := os.WriteFile(localFile, []byte("unapproved replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	input.ExpectedBytes = &plan.Bytes
	input.ExpectedSHA256 = plan.SHA256
	apply := runner.Run(context.Background(), "upload-new", input, true)
	transferTestRequireError(t, apply, "approval_mismatch")
	if got := postCalls.Load(); got != 0 {
		t.Fatalf("approval mismatch sent %d POST requests, want 0", got)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("apply mismatch sent an HTTP request; total requests = %d, want only dry-run preflight", got)
	}
}

func TestTransferUploadNewDryRunIncludesZeroBytes(t *testing.T) {
	localRoot := t.TempDir()
	localFile := filepath.Join(localRoot, "empty.txt")
	if err := os.WriteFile(localFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	runner := transferTestRunner(t, server.URL, []string{localRoot}, nil)
	input := transferTestInput("/write/empty.txt")
	input.LocalFile = localFile
	response := runner.Run(context.Background(), "upload-new", input, false)
	if !response.OK {
		t.Fatalf("empty-file dry-run failed: %+v", response.Error)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"bytes":0`) {
		t.Fatalf("zero-byte approval material was omitted: %s", encoded)
	}
}

func TestTransferDownloadEnforcesMaximumSize(t *testing.T) {
	outputRoot := t.TempDir()
	payload := []byte("12345")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/api/resources/download" {
			t.Errorf("unexpected request: %s %s", request.Method, request.URL.String())
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.WriteHeader(http.StatusOK)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = writer.Write(payload)
	}))
	defer server.Close()

	runner := transferTestRunner(t, server.URL, nil, []string{outputRoot})
	runner.config.MaxDownloadBytes = int64(len(payload) - 1)
	outputFile := filepath.Join(outputRoot, "too-large.bin")
	input := transferTestInput("/read/too-large.bin")
	input.OutputFile = outputFile
	response := runner.Run(context.Background(), "download", input, false)

	transferTestRequireError(t, response, "download_too_large")
	if _, err := os.Lstat(outputFile); !os.IsNotExist(err) {
		t.Fatalf("oversized download created output file: %v", err)
	}
	transferTestRequireNoTemporaryFiles(t, outputRoot)
}

func TestTransferDownloadNeverOverwritesTarget(t *testing.T) {
	t.Run("existing target is rejected before request", func(t *testing.T) {
		outputRoot := t.TempDir()
		target := filepath.Join(outputRoot, "existing.bin")
		const existing = "keep this content"
		if err := os.WriteFile(target, []byte(existing), 0o600); err != nil {
			t.Fatal(err)
		}
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			requests.Add(1)
			_, _ = io.WriteString(writer, "replacement")
		}))
		defer server.Close()

		runner := transferTestRunner(t, server.URL, nil, []string{outputRoot})
		input := transferTestInput("/read/existing.bin")
		input.OutputFile = target
		response := runner.Run(context.Background(), "download", input, false)

		transferTestRequireError(t, response, "local_target_exists")
		if got := requests.Load(); got != 0 {
			t.Fatalf("existing output caused %d HTTP requests, want 0", got)
		}
		content, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != existing {
			t.Fatalf("existing output was overwritten: %q", content)
		}
	})

	t.Run("target appearing at publish is not overwritten", func(t *testing.T) {
		outputRoot := t.TempDir()
		target := filepath.Join(outputRoot, "raced.bin")
		reader := &transferPublishRaceReader{
			target: target, existing: []byte("racing writer"), payload: []byte("download bytes"),
		}
		written, _, err := writeAtomicNoReplace(reader, int64(len(reader.payload)), target, 1024)
		if written != int64(len(reader.payload)) {
			t.Fatalf("bytes written = %d, want %d", written, len(reader.payload))
		}
		transferTestRequireBridgeError(t, err, "local_target_exists")
		content, readErr := os.ReadFile(target)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(content) != string(reader.existing) {
			t.Fatalf("racing target was overwritten: %q", content)
		}
		transferTestRequireNoTemporaryFiles(t, outputRoot)
	})
}

func TestTransferTemporaryFileIsCleanedAfterWriteFailure(t *testing.T) {
	outputRoot := t.TempDir()
	target := filepath.Join(outputRoot, "failed.bin")
	reader := &transferFailingReader{payload: []byte("partial bytes")}

	written, _, err := writeAtomicNoReplace(reader, -1, target, 1024)
	if written != int64(len(reader.payload)) {
		t.Fatalf("bytes written before failure = %d, want %d", written, len(reader.payload))
	}
	transferTestRequireBridgeError(t, err, "download_failed")
	if _, statErr := os.Lstat(target); !os.IsNotExist(statErr) {
		t.Fatalf("failed download created output file: %v", statErr)
	}
	transferTestRequireNoTemporaryFiles(t, outputRoot)
}

func TestTransferLocalReadWriteRootsAreIsolated(t *testing.T) {
	base := t.TempDir()
	readRoot := filepath.Join(base, "read")
	writeRoot := filepath.Join(base, "write")
	outsideRoot := filepath.Join(base, "outside")
	for _, directory := range []string{readRoot, writeRoot, outsideRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	readFile := filepath.Join(readRoot, "input.txt")
	writeFile := filepath.Join(writeRoot, "not-an-input.txt")
	for filename, content := range map[string]string{readFile: "allowed input", writeFile: "write-root input"} {
		if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

	}

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	runner := transferTestRunner(t, server.URL, []string{readRoot}, []string{writeRoot})

	resolvedRead, err := runner.config.authorizeLocalRead(readFile)
	if err != nil {
		t.Fatalf("allowed local read was rejected: %v", err)
	}
	if filepath.Base(resolvedRead) != filepath.Base(readFile) {
		t.Fatalf("resolved local read = %q, want %q", resolvedRead, readFile)
	}
	_, err = runner.config.authorizeLocalRead(writeFile)
	transferTestRequireBridgeError(t, err, "local_path_denied")

	allowedOutput := filepath.Join(writeRoot, "output.bin")
	resolvedWrite, err := runner.config.authorizeLocalWrite(allowedOutput)
	if err != nil {
		t.Fatalf("allowed local write was rejected: %v", err)
	}
	if filepath.Base(resolvedWrite) != filepath.Base(allowedOutput) {
		t.Fatalf("resolved local write = %q, want %q", resolvedWrite, allowedOutput)
	}
	_, err = runner.config.authorizeLocalWrite(filepath.Join(readRoot, "wrong-output.bin"))
	transferTestRequireBridgeError(t, err, "local_path_denied")
	_, err = runner.config.authorizeLocalWrite(filepath.Join(outsideRoot, "outside.bin"))
	transferTestRequireBridgeError(t, err, "local_path_denied")

	uploadInput := transferTestInput("/write/not-an-input.txt")
	uploadInput.LocalFile = writeFile
	transferTestSetApproval(&uploadInput, []byte("write-root input"))
	uploadResponse := runner.Run(context.Background(), "upload-new", uploadInput, true)
	transferTestRequireError(t, uploadResponse, "local_path_denied")

	downloadInput := transferTestInput("/read/wrong-output.bin")
	downloadInput.OutputFile = filepath.Join(readRoot, "wrong-output.bin")
	downloadResponse := runner.Run(context.Background(), "download", downloadInput, false)
	transferTestRequireError(t, downloadResponse, "local_path_denied")

	if got := requests.Load(); got != 0 {
		t.Fatalf("locally denied paths caused %d HTTP requests, want 0", got)
	}
}

type transferFailingReader struct {
	payload []byte
	sent    bool
}

func (reader *transferFailingReader) Read(buffer []byte) (int, error) {
	if reader.sent {
		return 0, errors.New("injected read failure")
	}
	reader.sent = true
	return copy(buffer, reader.payload), nil
}

type transferPublishRaceReader struct {
	target   string
	existing []byte
	payload  []byte
	offset   int
	created  bool
}

func (reader *transferPublishRaceReader) Read(buffer []byte) (int, error) {
	if !reader.created {
		if err := os.WriteFile(reader.target, reader.existing, 0o600); err != nil {
			return 0, err
		}
		reader.created = true
	}
	if reader.offset == len(reader.payload) {
		return 0, io.EOF
	}
	written := copy(buffer, reader.payload[reader.offset:])
	reader.offset += written
	return written, nil
}

func transferTestRunner(t *testing.T, serverURL string, localReadRoots, localWriteRoots []string) *Runner {
	t.Helper()
	config := &Config{
		BaseURL: serverURL,
		AllowedSources: map[string]SourcePolicy{
			"docs": {ReadRoots: []string{"/read"}, WriteRoots: []string{"/write"}},
		},
		LocalReadRoots:       localReadRoots,
		LocalWriteRoots:      localWriteRoots,
		TimeoutSeconds:       5,
		MaxDownloadBytes:     1 << 20,
		MaxInlineBytes:       1 << 20,
		MaxChecksumBytes:     1 << 20,
		MaxUploadBytes:       1 << 20,
		SearchDefaultLimit:   10,
		SearchMaxLimit:       100,
		MaxRetries:           1,
		RetryDelayMillis:     1,
		MaxRetryDelaySeconds: 1,
	}
	if err := config.applyDefaultsAndValidate(true); err != nil {
		t.Fatalf("validate test config: %v", err)
	}
	client := NewClient(config, transferTestToken)
	return NewRunner(config, client, &AuditLogger{writer: io.Discard})
}

func transferTestInput(resourcePath string) Input {
	return Input{
		SchemaVersion: SchemaVersion,
		RequestID:     "req-transfer-test",
		OperationID:   "op-transfer-test",
		Source:        "docs",
		Path:          resourcePath,
	}
}

func transferTestSetApproval(input *Input, payload []byte) {
	digest := sha256.Sum256(payload)
	size := int64(len(payload))
	input.ExpectedBytes = &size
	input.ExpectedSHA256 = hex.EncodeToString(digest[:])
}

func transferTestWriteJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Errorf("encode server response: %v", err)
	}
}

func transferTestRequireError(t *testing.T, response Response, code string) {
	t.Helper()
	if response.OK || response.Error == nil {
		t.Fatalf("response unexpectedly succeeded: %+v", response)
	}
	if response.Error.Code != code {
		t.Fatalf("error code = %q, want %q (response: %+v)", response.Error.Code, code, response)
	}
}

func transferTestRequireBridgeError(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error, got nil", code)
	}
	var bridgeErr *BridgeError
	if !asBridgeError(err, &bridgeErr) {
		t.Fatalf("error type = %T, want *BridgeError: %v", err, err)
	}
	if bridgeErr.Code != code {
		t.Fatalf("error code = %q, want %q", bridgeErr.Code, code)
	}
}

func transferTestRequireNoTemporaryFiles(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".filebrowser-agentctl-") {
			t.Errorf("temporary file was not cleaned up: %s", entry.Name())
		}
	}
}
