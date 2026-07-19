package filebridge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

type Runner struct {
	config *Config
	client *Client
	audit  *AuditLogger
}

const maxSearchQueryBytes = 4096

func NewRunner(config *Config, client *Client, audit *AuditLogger) *Runner {
	return &Runner{config: config, client: client, audit: audit}
}

func (r *Runner) Run(ctx context.Context, command string, input Input, apply bool) Response {
	requestID, requestErr := normalizeIdentifier(input.RequestID, "req")
	operationID, operationErr := normalizeIdentifier(input.OperationID, "op")
	dryRun := isWriteCommand(command) && !apply
	response := Response{
		SchemaVersion: SchemaVersion,
		Command:       command,
		RequestID:     requestID,
		OperationID:   operationID,
		DryRun:        dryRun,
	}
	started := time.Now()
	var result any
	var bytesProcessed int64
	var err error
	validateErr := validateCommandInput(command, input)
	if validateErr == nil {
		validateErr = validateApprovalInput(command, input, apply)
	}

	switch {
	case requestErr != nil:
		err = requestErr
	case operationErr != nil:
		err = operationErr
	case input.SchemaVersion != "" && input.SchemaVersion != SchemaVersion:
		err = bridgeError("unsupported_schema", "schema_version is not supported")
	case validateErr != nil:
		err = validateErr
	default:
		result, bytesProcessed, err = r.execute(ctx, command, input, apply, requestID)
	}

	resultCode := "ok"
	httpStatus := 0
	if err != nil {
		response.Error = errorResponse(err)
		resultCode = response.Error.Code
		httpStatus = response.Error.HTTPStatus
	} else {
		response.OK = true
		response.Result = result
	}
	auditErr := r.audit.Log(AuditEvent{
		OperationID: operationID,
		RequestID:   requestID,
		Command:     command,
		Source:      input.Source,
		Path:        input.Path,
		Result:      resultCode,
		HTTPStatus:  httpStatus,
		DurationMS:  time.Since(started).Milliseconds(),
		Bytes:       bytesProcessed,
		DryRun:      dryRun,
	})
	if auditErr != nil && response.OK {
		response.OK = false
		response.Result = nil
		response.Error = errorResponse(auditErr)
	}
	return response
}

func (r *Runner) execute(ctx context.Context, command string, input Input, apply bool, requestID string) (any, int64, error) {
	switch command {
	case "ping":
		result, err := r.client.ping(ctx, requestID)
		return result, 0, err
	case "whoami", "capabilities":
		result, err := r.client.capabilities(ctx, requestID)
		return result, 0, err
	case "sources":
		result, err := r.client.sources(ctx, requestID)
		return result, 0, err
	case "list":
		result, err := r.list(ctx, requestID, input)
		return result, 0, err
	case "search":
		result, err := r.search(ctx, requestID, input)
		return result, 0, err
	case "stat":
		result, err := r.stat(ctx, requestID, input, "")
		return result, 0, err
	case "checksum":
		result, err := r.checksum(ctx, requestID, input)
		return result, 0, err
	case "read":
		result, bytesRead, err := r.read(ctx, requestID, input)
		return result, bytesRead, err
	case "download":
		result, bytesRead, err := r.download(ctx, requestID, input)
		return result, bytesRead, err
	case "mkdir":
		result, err := r.mkdir(ctx, requestID, input, apply)
		return result, 0, err
	case "upload-new":
		result, bytesWritten, err := r.uploadNew(ctx, requestID, input, apply)
		return result, bytesWritten, err
	default:
		return nil, 0, bridgeError("unsupported_command", "command is not supported")
	}
}

func (r *Runner) list(ctx context.Context, requestID string, input Input) (ListResult, error) {
	if err := requireString(input.Source, "source"); err != nil {
		return ListResult{}, err
	}
	resourcePath, err := r.config.authorizeRemote(input.Source, input.Path, readAccess)
	if err != nil {
		return ListResult{}, err
	}
	resource, err := r.client.getResource(ctx, requestID, input.Source, resourcePath, "")
	if err != nil {
		return ListResult{}, err
	}
	if resource.Type != "directory" {
		return ListResult{}, bridgeError("not_a_directory", "list path is not a directory")
	}
	result := ListResult{
		Source:  input.Source,
		Path:    resourcePath,
		Files:   make([]Item, 0, len(resource.Files)),
		Folders: make([]Item, 0, len(resource.Folders)),
	}
	for _, file := range resource.Files {
		item, err := r.childItem(input.Source, resourcePath, file, false)
		if err != nil {
			return ListResult{}, err
		}
		result.Files = append(result.Files, item)
	}
	for _, folder := range resource.Folders {
		item, err := r.childItem(input.Source, resourcePath, folder, true)
		if err != nil {
			return ListResult{}, err
		}
		result.Folders = append(result.Folders, item)
	}
	sort.Slice(result.Files, func(i, j int) bool { return result.Files[i].Name < result.Files[j].Name })
	sort.Slice(result.Folders, func(i, j int) bool { return result.Folders[i].Name < result.Folders[j].Name })
	return result, nil
}

func (r *Runner) childItem(source, parent string, wire wireItem, directory bool) (Item, error) {
	itemPath, err := joinRemote(parent, wire.Name)
	if err != nil {
		return Item{}, bridgeError("invalid_server_response", "FileBrowser returned an unsafe item path")
	}
	if _, err := r.config.authorizeRemote(source, itemPath, readAccess); err != nil {
		return Item{}, bridgeError("invalid_server_response", "FileBrowser returned an item outside the local allowlist")
	}
	return itemFromWire(source, itemPath, wire, directory), nil
}

func (r *Runner) search(ctx context.Context, requestID string, input Input) (SearchResult, error) {
	if err := requireString(input.Source, "source"); err != nil {
		return SearchResult{}, err
	}
	if strings.TrimSpace(input.Query) == "" {
		return SearchResult{}, bridgeError("invalid_input", "query is required")
	}
	if len(input.Query) > maxSearchQueryBytes {
		return SearchResult{}, bridgeError("invalid_input", "query exceeds 4096 bytes")
	}
	scope, err := r.config.authorizeRemote(input.Source, input.Path, readAccess)
	if err != nil {
		return SearchResult{}, err
	}
	limit := input.Limit
	if limit == 0 {
		limit = r.config.SearchDefaultLimit
	}
	if limit < 1 || limit > r.config.SearchMaxLimit {
		return SearchResult{}, bridgeError("invalid_limit", fmt.Sprintf("limit must be between 1 and %d", r.config.SearchMaxLimit))
	}
	wireResults, err := r.client.search(ctx, requestID, input.Source, scope, input.Query)
	if err != nil {
		return SearchResult{}, err
	}
	result := SearchResult{
		Source: input.Source, Scope: scope, Query: input.Query, Limit: limit,
		Truncated: len(wireResults) > limit, Items: make([]Item, 0, min(limit, len(wireResults))),
	}
	for _, wire := range wireResults {
		if len(result.Items) == limit {
			break
		}
		if wire.Source != "" && wire.Source != input.Source {
			return SearchResult{}, bridgeError("invalid_server_response", "search returned an unexpected source")
		}
		itemPath, err := searchResultPath(scope, wire.Path)
		if err != nil {
			return SearchResult{}, bridgeError("invalid_server_response", "search returned an unsafe path")
		}
		if _, err := r.config.authorizeRemote(input.Source, itemPath, readAccess); err != nil {
			return SearchResult{}, bridgeError("invalid_server_response", "search returned a path outside the local allowlist")
		}
		result.Items = append(result.Items, Item{
			Name: path.Base(itemPath), Path: itemPath, Source: input.Source,
			Size: wire.Size, Modified: wire.Modified, Type: wire.Type,
			IsDir: wire.Type == "directory", HasPreview: wire.HasPreview,
		})
	}
	return result, nil
}

func searchResultPath(scope, value string) (string, error) {
	if value == "" || strings.ContainsAny(value, "\\\x00\r\n") {
		return "", fmt.Errorf("unsafe search path")
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return "", fmt.Errorf("unsafe search path")
		}
	}
	return normalizeRemotePath(path.Join(scope, strings.TrimPrefix(value, "/")))
}

func (r *Runner) stat(ctx context.Context, requestID string, input Input, checksum string) (StatResult, error) {
	if err := requireString(input.Source, "source"); err != nil {
		return StatResult{}, err
	}
	resourcePath, err := r.config.authorizeRemote(input.Source, input.Path, readAccess)
	if err != nil {
		return StatResult{}, err
	}
	resource, err := r.client.getResource(ctx, requestID, input.Source, resourcePath, checksum)
	if err != nil {
		return StatResult{}, err
	}
	return statResult(input.Source, resourcePath, resource), nil
}

func (r *Runner) checksum(ctx context.Context, requestID string, input Input) (StatResult, error) {
	algorithm := input.Algorithm
	if algorithm == "" {
		algorithm = "sha256"
	}
	if algorithm != "sha256" && algorithm != "sha512" {
		return StatResult{}, bridgeError("invalid_algorithm", "algorithm must be sha256 or sha512")
	}
	metadata, err := r.stat(ctx, requestID, input, "")
	if err != nil {
		return StatResult{}, err
	}
	if metadata.Item.IsDir {
		return StatResult{}, bridgeError("not_a_file", "checksum path must be a file")
	}
	if metadata.Item.Size > r.config.MaxChecksumBytes {
		return StatResult{}, bridgeError("checksum_too_large", "file exceeds max_checksum_bytes")
	}
	return r.stat(ctx, requestID, input, algorithm)
}

func (r *Runner) read(ctx context.Context, requestID string, input Input) (ReadResult, int64, error) {
	if err := requireString(input.Source, "source"); err != nil {
		return ReadResult{}, 0, err
	}
	resourcePath, err := r.config.authorizeRemote(input.Source, input.Path, readAccess)
	if err != nil {
		return ReadResult{}, 0, err
	}
	response, err := r.client.downloadResponse(ctx, requestID, http.MethodGet, input.Source, resourcePath)
	if err != nil {
		return ReadResult{}, 0, err
	}
	defer response.Body.Close()
	limit := r.config.MaxInlineBytes
	if response.ContentLength > limit {
		return ReadResult{}, 0, bridgeError("download_too_large", "file exceeds max_inline_bytes")
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return ReadResult{}, 0, bridgeError("download_failed", "could not read complete response body")
	}
	if int64(len(content)) > limit {
		return ReadResult{}, int64(len(content)), bridgeError("download_too_large", "file exceeds max_inline_bytes")
	}
	if response.ContentLength >= 0 && response.ContentLength != int64(len(content)) {
		return ReadResult{}, int64(len(content)), bridgeError("download_incomplete", "response ended before declared content length")
	}
	digest := sha256.Sum256(content)
	encoding := "base64"
	encoded := base64.StdEncoding.EncodeToString(content)
	if utf8.Valid(content) && !strings.ContainsRune(string(content), '\x00') {
		encoding = "utf-8"
		encoded = string(content)
	}
	return ReadResult{
		Source: input.Source, Path: resourcePath, Bytes: int64(len(content)), SHA256: hex.EncodeToString(digest[:]),
		ContentType: response.Header.Get("Content-Type"), Encoding: encoding, Content: encoded, Untrusted: true,
	}, int64(len(content)), nil
}

func (r *Runner) download(ctx context.Context, requestID string, input Input) (DownloadResult, int64, error) {
	if err := requireString(input.Source, "source"); err != nil {
		return DownloadResult{}, 0, err
	}
	if err := requireString(input.OutputFile, "output_file"); err != nil {
		return DownloadResult{}, 0, err
	}
	resourcePath, err := r.config.authorizeRemote(input.Source, input.Path, readAccess)
	if err != nil {
		return DownloadResult{}, 0, err
	}
	outputFile, err := r.config.authorizeLocalWrite(input.OutputFile)
	if err != nil {
		return DownloadResult{}, 0, err
	}
	response, err := r.client.downloadResponse(ctx, requestID, http.MethodGet, input.Source, resourcePath)
	if err != nil {
		return DownloadResult{}, 0, err
	}
	defer response.Body.Close()
	if response.ContentLength > r.config.MaxDownloadBytes {
		return DownloadResult{}, 0, bridgeError("download_too_large", "file exceeds max_download_bytes")
	}
	bytesWritten, digest, err := writeAtomicNoReplace(response.Body, response.ContentLength, outputFile, r.config.MaxDownloadBytes)
	if err != nil {
		return DownloadResult{}, bytesWritten, err
	}
	return DownloadResult{
		Source: input.Source, Path: resourcePath, OutputFile: outputFile,
		Bytes: bytesWritten, SHA256: digest,
	}, bytesWritten, nil
}

func writeAtomicNoReplace(reader io.Reader, declaredSize int64, target string, maxBytes int64) (int64, string, error) {
	temporary, err := os.CreateTemp(filepath.Dir(target), ".filebrowser-agentctl-*")
	if err != nil {
		return 0, "", bridgeError("local_write_failed", "could not create temporary output file")
	}
	temporaryName := temporary.Name()
	published := false
	defer func() {
		_ = temporary.Close()
		if !published {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return 0, "", bridgeError("local_write_failed", "could not restrict temporary output file")
	}
	digest := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, digest), io.LimitReader(reader, maxBytes+1))
	if copyErr != nil {
		return written, "", bridgeError("download_failed", "could not write complete response body")
	}
	if written > maxBytes {
		return written, "", bridgeError("download_too_large", "file exceeds max_download_bytes")
	}
	if declaredSize >= 0 && written != declaredSize {
		return written, "", bridgeError("download_incomplete", "response size did not match Content-Length")
	}
	if err := temporary.Sync(); err != nil {
		return written, "", bridgeError("local_write_failed", "could not sync temporary output file")
	}
	if err := temporary.Close(); err != nil {
		return written, "", bridgeError("local_write_failed", "could not close temporary output file")
	}
	if err := os.Link(temporaryName, target); err != nil {
		if _, statErr := os.Lstat(target); statErr == nil {
			return written, "", bridgeError("local_target_exists", "output_file appeared before atomic publish")
		}
		return written, "", bridgeError("atomic_publish_failed", "filesystem does not support safe no-overwrite publish")
	}
	published = true
	if err := os.Remove(temporaryName); err != nil {
		return written, "", bridgeError("local_write_failed", "download was published but temporary link cleanup failed")
	}
	return written, hex.EncodeToString(digest.Sum(nil)), nil
}

func (r *Runner) mkdir(ctx context.Context, requestID string, input Input, apply bool) (WriteResult, error) {
	if err := requireString(input.Source, "source"); err != nil {
		return WriteResult{}, err
	}
	resourcePath, err := r.config.authorizeRemote(input.Source, input.Path, writeAccess)
	if err != nil {
		return WriteResult{}, err
	}
	planned := WriteResult{Action: "mkdir", Source: input.Source, Path: resourcePath, Applied: false}
	existing, statErr := r.client.getResource(ctx, requestID, input.Source, resourcePath, "")
	if statErr == nil {
		if existing.Type != "directory" {
			return WriteResult{}, bridgeError("target_exists", "mkdir target exists and is not a directory")
		}
		planned.AlreadyDone = true
		planned.Verified = true
		return planned, nil
	}
	if !isErrorCode(statErr, "not_found") {
		return WriteResult{}, statErr
	}
	if !apply {
		return planned, nil
	}
	if err := r.client.createDirectory(ctx, requestID, input.Source, resourcePath); err != nil {
		if isErrorCode(err, "conflict") {
			if resource, verifyErr := r.client.getResource(ctx, requestID, input.Source, resourcePath, ""); verifyErr == nil && resource.Type == "directory" {
				planned.Applied = true
				planned.AlreadyDone = true
				planned.Verified = true
				return planned, nil
			}
		}
		return WriteResult{}, err
	}
	resource, err := r.retryResourceStat(ctx, requestID, input.Source, resourcePath)
	if err != nil || resource.Type != "directory" {
		return WriteResult{}, bridgeError("verification_failed", "directory creation could not be verified")
	}
	planned.Applied = true
	planned.Verified = true
	return planned, nil
}

func (r *Runner) uploadNew(ctx context.Context, requestID string, input Input, apply bool) (WriteResult, int64, error) {
	if err := requireString(input.Source, "source"); err != nil {
		return WriteResult{}, 0, err
	}
	if err := requireString(input.LocalFile, "local_file"); err != nil {
		return WriteResult{}, 0, err
	}
	resourcePath, err := r.config.authorizeRemote(input.Source, input.Path, writeAccess)
	if err != nil {
		return WriteResult{}, 0, err
	}
	localFile, err := r.config.authorizeLocalRead(input.LocalFile)
	if err != nil {
		return WriteResult{}, 0, err
	}
	snapshot, digest, err := snapshotAndHash(localFile, r.config.MaxUploadBytes)
	if err != nil {
		return WriteResult{}, 0, err
	}
	if apply && (*input.ExpectedBytes != snapshot.Size() || input.ExpectedSHA256 != digest) {
		return WriteResult{}, 0, bridgeError("approval_mismatch", "local_file does not match the approved dry-run bytes and SHA-256")
	}
	if _, statErr := r.client.getResource(ctx, requestID, input.Source, resourcePath, ""); statErr == nil {
		return WriteResult{}, 0, bridgeError("target_exists", "upload-new target already exists")
	} else if !isErrorCode(statErr, "not_found") {
		return WriteResult{}, 0, statErr
	}
	result := WriteResult{
		Action: "upload-new", Source: input.Source, Path: resourcePath,
		Applied: false, Bytes: snapshot.Size(), SHA256: digest,
	}
	if !apply {
		return result, 0, nil
	}
	file, err := os.Open(localFile)
	if err != nil {
		return WriteResult{}, 0, bridgeError("local_file_changed", "local_file changed before upload")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !sameSnapshot(snapshot, openedInfo) {
		return WriteResult{}, 0, bridgeError("local_file_changed", "local_file changed before upload")
	}
	uploadDigest := sha256.New()
	counter := &byteCounter{}
	body := io.TeeReader(file, io.MultiWriter(uploadDigest, counter))
	if err := r.client.uploadNew(ctx, requestID, input.Source, resourcePath, body, snapshot.Size()); err != nil {
		if isErrorCode(err, "conflict") {
			return WriteResult{}, counter.n, bridgeError("target_exists", "upload-new target exists or appeared during upload")
		}
		if isErrorCode(err, "timeout") || isErrorCode(err, "connection_failed") || isErrorCode(err, "server_error") {
			return WriteResult{}, counter.n, bridgeError("upload_outcome_unknown", "upload outcome is unknown; stat the target before retrying")
		}
		return WriteResult{}, counter.n, err
	}
	afterInfo, statErr := os.Stat(localFile)
	uploadHash := hex.EncodeToString(uploadDigest.Sum(nil))
	if statErr != nil || !sameSnapshot(snapshot, afterInfo) || counter.n != snapshot.Size() || uploadHash != digest {
		return WriteResult{}, counter.n, bridgeError("local_file_changed", "local_file changed during upload; remote target may exist")
	}
	if err := r.verifyUpload(ctx, requestID, input.Source, resourcePath, snapshot.Size(), digest); err != nil {
		return WriteResult{}, counter.n, err
	}
	result.Applied = true
	result.Verified = true
	return result, counter.n, nil
}

type byteCounter struct{ n int64 }

func (c *byteCounter) Write(value []byte) (int, error) {
	c.n += int64(len(value))
	return len(value), nil
}

func snapshotAndHash(filename string, maxBytes int64) (os.FileInfo, string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, "", bridgeError("local_file_unavailable", "cannot open local_file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, "", bridgeError("local_file_unavailable", "local_file must be a regular file")
	}
	if info.Size() > maxBytes {
		return nil, "", bridgeError("upload_too_large", "local_file exceeds max_upload_bytes")
	}
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, maxBytes+1))
	if err != nil || written != info.Size() {
		return nil, "", bridgeError("local_file_changed", "local_file changed while preparing upload")
	}
	return info, hex.EncodeToString(digest.Sum(nil)), nil
}

func sameSnapshot(before, after os.FileInfo) bool {
	return after != nil && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime()) && os.SameFile(before, after)
}

func (r *Runner) verifyUpload(ctx context.Context, requestID, source, resourcePath string, size int64, digest string) error {
	head, err := r.client.downloadResponse(ctx, requestID, http.MethodHead, source, resourcePath)
	if err != nil {
		return bridgeError("verification_failed", "uploaded file could not be verified by download metadata")
	}
	_ = head.Body.Close()
	if head.ContentLength >= 0 && head.ContentLength != size {
		return bridgeError("verification_failed", "uploaded file size does not match")
	}
	resource, err := r.retryResourceStat(ctx, requestID, source, resourcePath)
	if err != nil || resource.Type == "directory" || resource.Size != size {
		return bridgeError("verification_failed", "uploaded file stat does not match")
	}
	if size <= r.config.MaxChecksumBytes {
		resource, err = r.client.getResource(ctx, requestID, source, resourcePath, "sha256")
		if err != nil || resource.Checksums["sha256"] != digest {
			return bridgeError("verification_failed", "uploaded file checksum does not match")
		}
	}
	return nil
}

func (r *Runner) retryResourceStat(ctx context.Context, requestID, source, resourcePath string) (wireResource, error) {
	var lastErr error
	for attempt := 0; attempt <= r.config.MaxRetries+2; attempt++ {
		resource, err := r.client.getResource(ctx, requestID, source, resourcePath, "")
		if err == nil {
			return resource, nil
		}
		lastErr = err
		if !isErrorCode(err, "not_found") || attempt == r.config.MaxRetries+2 {
			break
		}
		timer := time.NewTimer(r.config.retryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return wireResource{}, ctx.Err()
		case <-timer.C:
		}
	}
	return wireResource{}, lastErr
}

func itemFromWire(source, resourcePath string, wire wireItem, directory bool) Item {
	itemType := wire.Type
	if directory {
		itemType = "directory"
	}
	return Item{
		Name: wire.Name, Path: resourcePath, Source: source, Size: wire.Size,
		Modified: wire.Modified, Type: itemType, IsDir: directory || wire.Type == "directory",
		Hidden: wire.Hidden, HasPreview: wire.HasPreview,
	}
}

func statResult(source, resourcePath string, resource wireResource) StatResult {
	name := resource.Name
	if name == "" {
		name = path.Base(resourcePath)
	}
	return StatResult{
		Item: Item{
			Name: name, Path: resourcePath, Source: source, Size: resource.Size,
			Modified: resource.Modified, Type: resource.Type, IsDir: resource.Type == "directory",
			Hidden: resource.Hidden, HasPreview: resource.HasPreview,
		},
		Checksums: resource.Checksums,
	}
}

func normalizeIdentifier(value, prefix string) (string, error) {
	if value == "" {
		buffer := make([]byte, 12)
		if _, err := rand.Read(buffer); err != nil {
			return prefix + "-unavailable", bridgeError("identifier_failed", "could not generate request identifiers")
		}
		return prefix + "-" + hex.EncodeToString(buffer), nil
	}
	if len(value) > 128 {
		return value, bridgeError("invalid_identifier", prefix+" identifier is too long")
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("._:-", char)) {
			return value, bridgeError("invalid_identifier", prefix+" identifier contains unsupported characters")
		}
	}
	return value, nil
}

func isWriteCommand(command string) bool {
	return command == "mkdir" || command == "upload-new"
}

func validateCommandInput(command string, input Input) error {
	used := map[string]bool{
		"source":          input.Source != "",
		"path":            input.Path != "",
		"query":           input.Query != "",
		"limit":           input.Limit != 0,
		"algorithm":       input.Algorithm != "",
		"output_file":     input.OutputFile != "",
		"local_file":      input.LocalFile != "",
		"expected_bytes":  input.ExpectedBytes != nil,
		"expected_sha256": input.ExpectedSHA256 != "",
	}
	allowed := map[string]bool{}
	switch command {
	case "list", "stat", "read", "mkdir":
		allowed["source"], allowed["path"] = true, true
	case "search":
		allowed["source"], allowed["path"], allowed["query"], allowed["limit"] = true, true, true, true
	case "checksum":
		allowed["source"], allowed["path"], allowed["algorithm"] = true, true, true
	case "download":
		allowed["source"], allowed["path"], allowed["output_file"] = true, true, true
	case "upload-new":
		allowed["source"], allowed["path"], allowed["local_file"] = true, true, true
		allowed["expected_bytes"], allowed["expected_sha256"] = true, true
	case "ping", "whoami", "capabilities", "sources":
		// These commands accept only common request metadata.
	default:
		return bridgeError("unsupported_command", "command is not supported")
	}
	for field, present := range used {
		if present && !allowed[field] {
			return bridgeError("invalid_input", "input contains a field that is not allowed for this command")
		}
	}
	return nil
}

func validateApprovalInput(command string, input Input, apply bool) error {
	if apply && isWriteCommand(command) && input.OperationID == "" {
		return bridgeError("invalid_input", "operation_id is required with --apply")
	}
	if command != "upload-new" {
		return nil
	}
	if !apply {
		if input.ExpectedBytes != nil || input.ExpectedSHA256 != "" {
			return bridgeError("invalid_input", "expected_bytes and expected_sha256 are accepted only with --apply")
		}
		return nil
	}
	if input.ExpectedBytes == nil || *input.ExpectedBytes < 0 || len(input.ExpectedSHA256) != sha256.Size*2 {
		return bridgeError("invalid_input", "upload-new --apply requires non-negative expected_bytes and a lowercase SHA-256")
	}
	for _, char := range input.ExpectedSHA256 {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return bridgeError("invalid_input", "upload-new --apply requires non-negative expected_bytes and a lowercase SHA-256")
		}
	}
	return nil
}
