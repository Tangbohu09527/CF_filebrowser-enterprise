package http

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	commonerrors "github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

// fileWatchResponse represents the response from file watch
type fileWatchResponse struct {
	Contents string             `json:"contents,omitempty"` // Text content for text files
	IsText   bool               `json:"isText"`             // Whether the file is a text file
	Metadata *fileWatchMetadata `json:"metadata,omitempty"` // File metadata for non-text files
}

// fileWatchMetadata contains file information for non-text files
type fileWatchMetadata struct {
	Name     string    `json:"name"`     // File name
	Size     int64     `json:"size"`     // File size in bytes (for directories, total size of all files)
	Type     string    `json:"type"`     // MIME type
	Modified time.Time `json:"modified"` // Modification time
}

func isTextFileSample(reader io.ReadSeeker) (bool, error) {
	const sampleSize = 8192
	sample := make([]byte, sampleSize)
	n, err := io.ReadFull(reader, sample)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return false, err
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	sample = sample[:n]
	if len(sample) == 0 {
		return true, nil
	}
	nullCount := 0
	for _, b := range sample {
		if b == 0 {
			nullCount++
		}
	}
	if float64(nullCount)/float64(len(sample)) > 0.05 {
		return false, nil
	}
	for len(sample) > 0 {
		lastRune, size := utf8.DecodeLastRune(sample)
		if lastRune != utf8.RuneError || size != 1 {
			break
		}
		sample = sample[:len(sample)-1]
	}
	return len(sample) == 0 || utf8.Valid(sample), nil
}

// readLastNLines reads the last N lines from an already-authorized file handle.
func readLastNLines(file io.ReadSeeker, fileSize int64, n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("number of lines must be positive")
	}
	if fileSize == 0 {
		return "", nil
	}

	// For small files, just read everything
	// For larger files, read from the end
	const maxReadSize = 1024 * 1024 // 1MB
	var lines []string

	if fileSize <= maxReadSize {
		// Read entire file for small files
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return "", err
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return "", err
		}
	} else {
		// For large files, read from the end
		// Read the last chunk (up to 1MB) and count newlines
		readSize := maxReadSize
		if fileSize < int64(readSize) {
			readSize = int(fileSize)
		}

		if _, err := file.Seek(-int64(readSize), io.SeekEnd); err != nil {
			return "", err
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return "", err
		}
	}

	// Return only the last N lines
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}

	// Truncate lines that exceed 250 characters
	const maxLineLength = 250
	for i, line := range lines {
		if len(line) > maxLineLength {
			lines[i] = line[:maxLineLength] + "..."
		}
	}

	return strings.Join(lines, "\n"), nil
}

// fileWatchHandler handles file watching requests
// @Summary Watch a file
// @Description Returns the last N lines of a file
// @Tags Tools
// @Accept json
// @Produce json
// @Param path query string true "Path to the file"
// @Param source query string true "Source name"
// @Param lines query int false "Number of lines to read (default: 10, max: 50)"
// @Param latencyCheck query bool false "Return minimal response for latency checking"
// @Success 200 {object} fileWatchResponse
// @Failure 400 {object} map[string]string "Invalid request"
// @Failure 403 {object} map[string]string "Permission denied"
// @Failure 404 {object} map[string]string "File not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/tools/fileWatcher [get]
func fileWatchHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if d == nil || d.user == nil || !d.user.Permissions.Browse || !d.user.Permissions.Download {
		return http.StatusForbidden, fmt.Errorf("browse and download permissions are required for file watching")
	}
	if _, err := currentFileWatchUser(d, false); err != nil {
		return http.StatusForbidden, err
	}
	// Check for latency check request - return immediately with minimal response
	if r.URL.Query().Get("latencyCheck") != "" {
		return http.StatusOK, nil
	}

	path := r.URL.Query().Get("path")
	source := r.URL.Query().Get("source")
	linesStr := r.URL.Query().Get("lines")

	if path == "" || source == "" {
		return http.StatusBadRequest, fmt.Errorf("path and source are required")
	}
	var err error
	path, err = sanitizeAuthenticatedReadPath(path)
	if err != nil {
		return http.StatusBadRequest, err
	}

	// Parse lines parameter
	lines := 10 // default
	if linesStr != "" {
		var parsedLines int
		parsedLines, err = strconv.Atoi(linesStr)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid lines parameter: %v", err)
		}
		if parsedLines < 1 || parsedLines > 50 {
			return http.StatusBadRequest, fmt.Errorf("lines must be between 1 and 50")
		}
		lines = parsedLines
	}

	isText, contents, metadata, err := readCurrentFileWatchTarget(d, source, path, lines, false)
	if err != nil {
		return errToStatus(err), err
	}
	response := fileWatchResponse{IsText: isText, Contents: contents, Metadata: metadata}

	w.Header().Set("Content-Type", "application/json")
	return http.StatusOK, json.NewEncoder(w).Encode(response)
}

// fileWatchSSEEvent represents the SSE event payload for file watch updates
type fileWatchSSEEvent struct {
	Contents string             `json:"contents,omitempty"` // Text content for text files
	IsText   bool               `json:"isText"`             // Whether the file is a text file
	Metadata *fileWatchMetadata `json:"metadata,omitempty"` // File metadata for non-text files
}

// fileWatchSSEHandler handles Server-Sent Events for file watching
// @Summary Watch a file via SSE
// @Description Establishes an SSE connection to receive periodic file updates
// @Tags Tools
// @Param path query string true "Path to the file"
// @Param source query string true "Source name"
// @Param lines query int false "Number of lines to read (default: 10, max: 50)"
// @Param interval query int false "Update interval in seconds (1, 2, 5, 10, 15, or 30, requires realtime permission for SSE)"
// @Success 200 "SSE stream"
// @Failure 400 {object} map[string]string "Invalid request"
// @Failure 403 {object} map[string]string "Permission denied"
// @Failure 404 {object} map[string]string "File not found"
// @Router /api/tools/fileWatcher/sse [get]
func fileWatchSSEHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if d == nil || d.user == nil || !d.user.Permissions.Browse || !d.user.Permissions.Download {
		return http.StatusForbidden, fmt.Errorf("browse and download permissions are required for file watching")
	}
	if !d.user.Permissions.Realtime {
		return http.StatusForbidden, fmt.Errorf("realtime permission required for SSE file watching")
	}

	path := r.URL.Query().Get("path")
	source := r.URL.Query().Get("source")
	linesStr := r.URL.Query().Get("lines")
	intervalStr := r.URL.Query().Get("interval")

	var err error
	if path == "" || source == "" {
		return http.StatusBadRequest, fmt.Errorf("path and source are required")
	}

	cleanPath, err := sanitizeAuthenticatedReadPath(path)
	if err != nil {
		return http.StatusBadRequest, err
	}
	path = cleanPath

	// Parse lines parameter
	lines := 10 // default
	if linesStr != "" {
		var parsedLines int
		parsedLines, err = strconv.Atoi(linesStr)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid lines parameter: %v", err)
		}
		if parsedLines < 1 || parsedLines > 50 {
			return http.StatusBadRequest, fmt.Errorf("lines must be between 1 and 50")
		}
		lines = parsedLines
	}

	// Parse interval parameter (valid intervals: 1, 2, 5, 10, 15, 30 seconds)
	interval := time.Second * 1 // default
	if intervalStr != "" {
		var parsedInterval int
		parsedInterval, err = strconv.Atoi(intervalStr)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid interval parameter: %v", err)
		}
		validIntervals := map[int]bool{1: true, 2: true, 5: true, 10: true, 15: true, 30: true}
		if !validIntervals[parsedInterval] {
			return http.StatusBadRequest, fmt.Errorf("interval must be one of: 1, 2, 5, 10, 15, 30 seconds")
		}
		interval = time.Duration(parsedInterval) * time.Second
	}

	_, err = authorizeCurrentFileWatchTarget(d, source, path, true)
	if err != nil {
		return errToStatus(err), err
	}

	// Set up SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		return http.StatusInternalServerError, fmt.Errorf("streaming not supported")
	}

	msgr := messenger{flusher: flusher, writer: w}
	clientGone := r.Context().Done()

	// Initial ack
	statusMsg, _ := json.Marshal(map[string]interface{}{"status": "connected"})
	setFileWatchWriteDeadline(msgr)
	if err := msgr.sendEvent("fileWatch", string(statusMsg)); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("error sending initial message: %v", err)
	}

	if err := sendFileWatchTarget(msgr, d, source, path, lines); err != nil {
		return http.StatusOK, nil
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Main loop: listen for events from events system (like general SSE handler)
	// Use server context if available, otherwise use request context
	serverCtx := r.Context()
	if d.ctx != nil {
		serverCtx = d.ctx
	}

	for {
		select {
		case <-serverCtx.Done():
			return http.StatusOK, nil

		case <-clientGone:
			return http.StatusOK, nil

		case <-ticker.C:
			if sendErr := sendFileWatchTarget(msgr, d, source, path, lines); sendErr != nil {
				return http.StatusOK, nil
			}
		}
	}
}

func currentFileWatchUser(d *requestContext, requireRealtime bool) (*users.User, error) {
	if d == nil || d.user == nil {
		return nil, commonerrors.ErrAccessDenied
	}
	current, err := currentAuthenticatedReadUser(d.user, d.token)
	if err != nil {
		return nil, err
	}
	if !current.Permissions.Browse || !current.Permissions.Download || (requireRealtime && !current.Permissions.Realtime) {
		return nil, commonerrors.ErrAccessDenied
	}
	return current, nil
}

func authorizeCurrentFileWatchTarget(d *requestContext, source, path string, requireRealtime bool) (authenticatedReadTarget, error) {
	current, err := currentFileWatchUser(d, requireRealtime)
	if err != nil {
		return authenticatedReadTarget{}, err
	}
	return resolveAuthenticatedReadTarget(current, source, path)
}

func setFileWatchWriteDeadline(msgr messenger) {
	responseWriter, ok := msgr.writer.(http.ResponseWriter)
	if !ok {
		return
	}
	_ = http.NewResponseController(responseWriter).SetWriteDeadline(time.Now().Add(15 * time.Second))
}

func readFileWatchTarget(target authenticatedReadTarget, lines int) (bool, string, *fileWatchMetadata, error) {
	info := target.Info
	mimeType := "application/octet-stream"
	if reducedInfo, exists := target.Index.GetReducedMetadata(target.CanonicalPath, false); exists && reducedInfo.Type != "" {
		mimeType = reducedInfo.Type
	}
	if info.IsDir() {
		return false, "", &fileWatchMetadata{
			Name:     authenticatedReadTargetName(target, info.Name()),
			Size:     0,
			Type:     "directory",
			Modified: info.ModTime(),
		}, nil
	}
	file, opened, err := openAuthenticatedReadTarget(target)
	if err != nil {
		return false, "", nil, err
	}
	defer file.Close()
	isText, err := isTextFileSample(file)
	if err != nil {
		return false, "", nil, err
	}
	metadata := &fileWatchMetadata{
		Name:     authenticatedReadTargetName(target, opened.Name()),
		Size:     opened.Size(),
		Type:     mimeType,
		Modified: opened.ModTime(),
	}
	if !isText {
		return false, "", metadata, nil
	}
	contents, err := readLastNLines(file, opened.Size(), lines)
	if err != nil {
		return false, "", nil, err
	}
	return true, contents, metadata, nil
}

func readCurrentFileWatchTarget(d *requestContext, source, path string, lines int, requireRealtime bool) (bool, string, *fileWatchMetadata, error) {
	target, err := authorizeCurrentFileWatchTarget(d, source, path, requireRealtime)
	if err != nil {
		return false, "", nil, err
	}
	isText, contents, metadata, err := readFileWatchTarget(target, lines)
	if err != nil {
		return false, "", nil, err
	}
	currentTarget, err := authorizeCurrentFileWatchTarget(d, source, path, requireRealtime)
	if err != nil || !sameAuthenticatedReadTarget(target, currentTarget) {
		return false, "", nil, commonerrors.ErrAccessDenied
	}
	return isText, contents, metadata, nil
}

func sendFileWatchTarget(msgr messenger, d *requestContext, source, path string, lines int) error {
	isText, contents, metadata, err := readCurrentFileWatchTarget(d, source, path, lines, true)
	if err != nil {
		return err
	}
	sseEvent := fileWatchSSEEvent{IsText: isText, Contents: contents, Metadata: metadata}

	// Serialize and send only to this request's SSE stream.
	eventJSON, err := json.Marshal(sseEvent)
	if err != nil {
		return err
	}
	setFileWatchWriteDeadline(msgr)
	if err := msgr.sendEvent("fileWatch", string(eventJSON)); err != nil {
		return fmt.Errorf("error sending event: %v", err)
	}
	if _, err := authorizeCurrentFileWatchTarget(d, source, path, true); err != nil {
		return err
	}
	return nil
}
