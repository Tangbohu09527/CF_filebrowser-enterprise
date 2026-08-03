package http

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/fileutils"
	commonerrors "github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	"github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/go-cache/cache"
	"github.com/gtsteffaniak/go-logger/logger"
	"golang.org/x/time/rate"
)

// archiveMultiRequestIdle is how long without another Range/HEAD on the same archiveToken before
// the spooled file is removed (abandoned chunked download). Each chunk request extends this window.
const archiveMultiRequestIdle = 5 * time.Minute

const archiveSpoolActiveCacheTTL = 24 * time.Hour

var archiveSpoolAfterFunc = time.AfterFunc
var archiveSpoolRemoveFile = settings.RemoveDownloadArchiveSpool
var archiveSpoolTokenFunc = randomArchiveToken

type archiveSpoolSession struct {
	tmpPath          string
	spoolInfo        os.FileInfo
	originalFileName string
	userID           uint
	username         string
	source           string
	sourcePath       string
	requestFileList  []string
	memberPaths      []string
	memberTargets    []authenticatedReadTarget
	shareHash        string
	shareLink        *share.Link
	archiveExtension string
	shareTargets     []publicShareTarget
	shareMembers     []publicShareArchiveEntry
	lifecycle        *archiveSpoolLifecycle
}

type archiveSpoolLifecycle struct {
	mu            sync.Mutex
	timer         *time.Timer
	generation    uint64
	active        int
	removePending bool
	removed       bool
}

type archiveMemberTracker struct {
	paths   []string
	targets []authenticatedReadTarget
}

type authenticatedArchiveMember struct {
	indexPath   string
	archivePath string
	target      authenticatedReadTarget
	root        bool
}

var errAuthenticatedArchiveReadPermissions = fmt.Errorf("authenticated archive read permissions are required: %w", commonerrors.ErrAccessDenied)

func (t *archiveMemberTracker) add(path string, target authenticatedReadTarget) {
	if t != nil {
		t.paths = append(t.paths, path)
		t.targets = append(t.targets, target)
	}
}

func currentAuthenticatedArchiveUser(d *requestContext) (*users.User, error) {
	if d == nil || d.user == nil {
		return nil, errAuthenticatedArchiveReadPermissions
	}
	current, err := currentAuthenticatedReadUser(d.user, d.token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errAuthenticatedArchiveReadPermissions, err)
	}
	if !current.Permissions.Browse || !current.Permissions.Download {
		return nil, errAuthenticatedArchiveReadPermissions
	}
	return current, nil
}

func resolveCurrentAuthenticatedArchiveTarget(d *requestContext, source, indexPath string) (authenticatedReadTarget, error) {
	current, err := currentAuthenticatedArchiveUser(d)
	if err != nil {
		return authenticatedReadTarget{}, err
	}
	return resolveAuthenticatedReadIndexTarget(current, source, indexPath)
}

func reauthorizeAuthenticatedArchiveRoot(d *requestContext, source, indexPath string, checked authenticatedReadTarget) error {
	current, err := resolveCurrentAuthenticatedArchiveTarget(d, source, indexPath)
	if err != nil {
		return fmt.Errorf("%w: archive root authorization changed", errAuthenticatedArchiveReadPermissions)
	}
	if current.CanonicalPath != checked.CanonicalPath || !publicShareSameRealPath(current.RealPath, checked.RealPath) ||
		current.Info == nil || checked.Info == nil || current.Info.IsDir() != checked.Info.IsDir() {
		return errAuthenticatedArchiveReadPermissions
	}
	return nil
}

func reauthorizeAuthenticatedArchiveMember(d *requestContext, source string, member authenticatedArchiveMember) error {
	current, err := resolveCurrentAuthenticatedArchiveTarget(d, source, member.indexPath)
	if err != nil || !sameAuthenticatedReadTarget(member.target, current) {
		return errAuthenticatedArchiveReadPermissions
	}
	return nil
}

func reauthorizeAuthenticatedArchiveMembers(d *requestContext, source string, paths []string, targets []authenticatedReadTarget) error {
	if len(paths) != len(targets) {
		return errAuthenticatedArchiveReadPermissions
	}
	for i, memberPath := range paths {
		member := authenticatedArchiveMember{indexPath: memberPath, target: targets[i]}
		if err := reauthorizeAuthenticatedArchiveMember(d, source, member); err != nil {
			return err
		}
	}
	return nil
}

func copyAuthenticatedArchiveMember(d *requestContext, source string, member authenticatedArchiveMember, destination io.Writer, file *os.File) error {
	buffer := make([]byte, 1024*1024)
	for {
		if err := reauthorizeAuthenticatedArchiveMember(d, source, member); err != nil {
			return err
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			if err := reauthorizeAuthenticatedArchiveMember(d, source, member); err != nil {
				return err
			}
			written, writeErr := destination.Write(buffer[:n])
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			return reauthorizeAuthenticatedArchiveMember(d, source, member)
		}
		if readErr != nil {
			return normalizeAuthenticatedReadError(readErr)
		}
	}
}

func walkAuthenticatedArchiveMembers(
	d *requestContext,
	source string,
	indexPath string,
	flatten bool,
	visit func(authenticatedArchiveMember) error,
) error {
	return walkAuthenticatedArchiveMembersWithPolicy(d, source, indexPath, flatten, false, visit)
}

func walkAuthenticatedArchiveMembersWithPolicy(
	d *requestContext,
	source string,
	indexPath string,
	flatten bool,
	failOnDenied bool,
	visit func(authenticatedArchiveMember) error,
) error {
	root, err := resolveCurrentAuthenticatedArchiveTarget(d, source, indexPath)
	if err != nil {
		return err
	}
	if root.Info == nil {
		return commonerrors.ErrAccessDenied
	}
	if failOnDenied && authenticatedReadPathContainsSymlink(root.SourcePath, root.LogicalPath) {
		return fmt.Errorf("archive delete source %q traverses a symlink: %w", indexPath, commonerrors.ErrAccessDenied)
	}

	baseName := authenticatedReadTargetName(root, filepath.Base(root.RealPath))
	if !root.Info.IsDir() {
		return visit(authenticatedArchiveMember{
			indexPath:   indexPath,
			archivePath: baseName,
			target:      root,
		})
	}
	if err := visit(authenticatedArchiveMember{indexPath: indexPath, target: root, root: true}); err != nil {
		return err
	}

	return filepath.Walk(root.RealPath, func(filePath string, fileInfo os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return normalizeAuthenticatedReadError(walkErr)
		}
		relPath, err := filepath.Rel(root.RealPath, filePath)
		if err != nil {
			return fmt.Errorf("archive member path is unavailable")
		}
		if relPath == "." {
			return nil
		}
		if reauthorizeErr := reauthorizeAuthenticatedArchiveRoot(d, source, indexPath, root); reauthorizeErr != nil {
			return reauthorizeErr
		}

		relPath = filepath.ToSlash(relPath)
		memberPath := filepath.ToSlash(utils.JoinPathAsUnix(indexPath, relPath))
		memberTarget, err := resolveCurrentAuthenticatedArchiveTarget(d, source, memberPath)
		if err != nil {
			if errors.Is(err, errAuthenticatedArchiveReadPermissions) {
				return err
			}
			if errors.Is(err, commonerrors.ErrAccessDenied) {
				if failOnDenied {
					return fmt.Errorf("archive delete source member %q is not accessible: %w", memberPath, commonerrors.ErrAccessDenied)
				}
				if fileInfo.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			return err
		}

		// filepath.Walk does not descend through directory symlinks; preserve that behavior.
		if fileInfo.Mode()&os.ModeSymlink != 0 && memberTarget.Info.IsDir() {
			return nil
		}
		archivePath := relPath
		if !flatten {
			archivePath = filepath.ToSlash(filepath.Join(baseName, relPath))
		}
		return visit(authenticatedArchiveMember{
			indexPath:   memberPath,
			archivePath: archivePath,
			target:      memberTarget,
		})
	})
}

func snapshotArchiveDeleteSources(d *requestContext, source string, paths []string) (*archiveMemberTracker, error) {
	tracker := &archiveMemberTracker{}
	for _, indexPath := range paths {
		err := walkAuthenticatedArchiveMembersWithPolicy(d, source, indexPath, false, true, func(member authenticatedArchiveMember) error {
			if member.target.Info == nil {
				return commonerrors.ErrAccessDenied
			}
			tracker.add(member.indexPath, member.target)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return tracker, nil
}

func sameArchiveMemberTrackers(original, current *archiveMemberTracker) bool {
	if original == nil || current == nil || len(original.paths) != len(current.paths) || len(original.targets) != len(current.targets) {
		return false
	}
	for i := range original.paths {
		if original.paths[i] != current.paths[i] || !sameArchiveTargetSnapshot(original.targets[i], current.targets[i]) {
			return false
		}
	}
	return true
}

func sameArchiveTargetSnapshot(original, current authenticatedReadTarget) bool {
	return sameAuthenticatedReadTarget(original, current) &&
		original.Info.Size() == current.Info.Size() &&
		original.Info.Mode() == current.Info.Mode() &&
		original.Info.ModTime().Equal(current.Info.ModTime())
}

// archiveSpoolCache maps archiveToken to the scoped read session used to build the spool.
var archiveSpoolCache = cache.NewCache[archiveSpoolSession](archiveMultiRequestIdle)

func randomArchiveToken() (string, error) {
	return utils.RandomHex(16)
}

func stopArchiveSpoolTimerLocked(lifecycle *archiveSpoolLifecycle) {
	if lifecycle.timer != nil {
		lifecycle.timer.Stop()
		lifecycle.timer = nil
	}
}

func removeArchiveSpoolFile(tmpPath string, spoolInfo os.FileInfo) {
	if err := archiveSpoolRemoveFile(tmpPath, spoolInfo); err != nil && !os.IsNotExist(err) {
		logger.Debugf("archive spool remove %s: %v", tmpPath, err)
	}
}

func expireArchiveSpool(token string, session archiveSpoolSession, generation uint64) {
	lifecycle := session.lifecycle
	if lifecycle == nil {
		return
	}

	lifecycle.mu.Lock()
	if lifecycle.generation != generation || lifecycle.active != 0 || lifecycle.removePending || lifecycle.removed {
		lifecycle.mu.Unlock()
		return
	}
	current, ok := archiveSpoolCache.Get(token)
	if ok && (current.lifecycle != lifecycle || current.tmpPath != session.tmpPath) {
		lifecycle.mu.Unlock()
		return
	}
	lifecycle.timer = nil
	lifecycle.removePending = true
	lifecycle.removed = true
	if ok {
		archiveSpoolCache.Delete(token)
	}
	lifecycle.mu.Unlock()

	removeArchiveSpoolFile(session.tmpPath, session.spoolInfo)
}

func scheduleArchiveSpoolIdleCleanupLocked(token string, session archiveSpoolSession) {
	lifecycle := session.lifecycle
	stopArchiveSpoolTimerLocked(lifecycle)
	lifecycle.generation++
	generation := lifecycle.generation
	archiveSpoolCache.SetWithExp(token, session, archiveMultiRequestIdle)
	lifecycle.timer = archiveSpoolAfterFunc(archiveMultiRequestIdle, func() {
		expireArchiveSpool(token, session, generation)
	})
}

func invalidatePublicShareArchiveToken(token, shareHash string) {
	if token == "" || shareHash == "" {
		return
	}
	session, ok := archiveSpoolCache.Get(token)
	if !ok || session.shareHash != shareHash {
		return
	}
	removeSpooledArchiveNow(token, session.tmpPath)
}

// rescheduleArchiveSpoolIdleCleanup is retained for focused lifecycle tests and cleanup callers.
func rescheduleArchiveSpoolIdleCleanup(token, tmpPath string) {
	session, ok := archiveSpoolCache.Get(token)
	if !ok || session.tmpPath != tmpPath {
		return
	}
	if session.lifecycle == nil {
		session.lifecycle = &archiveSpoolLifecycle{}
	}
	lifecycle := session.lifecycle
	lifecycle.mu.Lock()
	if !lifecycle.removePending && !lifecycle.removed && lifecycle.active == 0 {
		scheduleArchiveSpoolIdleCleanupLocked(token, session)
	}
	lifecycle.mu.Unlock()
}

func acquireArchiveSpool(token string, session archiveSpoolSession) (archiveSpoolSession, bool) {
	if session.lifecycle == nil {
		session.lifecycle = &archiveSpoolLifecycle{}
	}
	lifecycle := session.lifecycle
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()

	current, ok := archiveSpoolCache.Get(token)
	if !ok || current.tmpPath != session.tmpPath {
		return archiveSpoolSession{}, false
	}
	if current.lifecycle != nil && current.lifecycle != lifecycle {
		return archiveSpoolSession{}, false
	}
	if lifecycle.removePending || lifecycle.removed {
		return archiveSpoolSession{}, false
	}
	if current.lifecycle == nil {
		current.lifecycle = lifecycle
	}
	stopArchiveSpoolTimerLocked(lifecycle)
	lifecycle.generation++
	lifecycle.active++
	archiveSpoolCache.SetWithExp(token, current, archiveSpoolActiveCacheTTL)
	return current, true
}

func releaseArchiveSpool(token string, session archiveSpoolSession, remove bool) {
	lifecycle := session.lifecycle
	if lifecycle == nil {
		if remove {
			archiveSpoolCache.Delete(token)
			removeArchiveSpoolFile(session.tmpPath, session.spoolInfo)
		} else {
			rescheduleArchiveSpoolIdleCleanup(token, session.tmpPath)
		}
		return
	}

	deleteFile := false
	lifecycle.mu.Lock()
	if lifecycle.active > 0 {
		lifecycle.active--
	}
	if remove && !lifecycle.removePending {
		lifecycle.removePending = true
		lifecycle.generation++
		stopArchiveSpoolTimerLocked(lifecycle)
		archiveSpoolCache.Delete(token)
	}
	if lifecycle.active == 0 {
		if lifecycle.removePending {
			if !lifecycle.removed {
				lifecycle.removed = true
				deleteFile = true
			}
		} else {
			current, ok := archiveSpoolCache.Get(token)
			if ok && current.lifecycle == lifecycle && current.tmpPath == session.tmpPath {
				scheduleArchiveSpoolIdleCleanupLocked(token, session)
			} else {
				lifecycle.removePending = true
				lifecycle.generation++
				stopArchiveSpoolTimerLocked(lifecycle)
				lifecycle.removed = true
				deleteFile = true
			}
		}
	}
	lifecycle.mu.Unlock()

	if deleteFile {
		removeArchiveSpoolFile(session.tmpPath, session.spoolInfo)
	}
}

// removeSpooledArchiveNow revokes token state immediately and deletes after active readers close.
func removeSpooledArchiveNow(token, tmpPath string) {
	session, ok := archiveSpoolCache.Get(token)
	if !ok {
		removeArchiveSpoolFile(tmpPath, nil)
		return
	}
	if session.tmpPath != tmpPath {
		return
	}
	if session.lifecycle == nil {
		archiveSpoolCache.Delete(token)
		removeArchiveSpoolFile(tmpPath, session.spoolInfo)
		return
	}

	lifecycle := session.lifecycle
	deleteFile := false
	lifecycle.mu.Lock()
	if !lifecycle.removePending {
		lifecycle.removePending = true
		lifecycle.generation++
		stopArchiveSpoolTimerLocked(lifecycle)
		archiveSpoolCache.Delete(token)
	}
	if lifecycle.active == 0 && !lifecycle.removed {
		lifecycle.removed = true
		deleteFile = true
	}
	lifecycle.mu.Unlock()

	if deleteFile {
		removeArchiveSpoolFile(tmpPath, session.spoolInfo)
	}
}

// archiveGetDeliversThroughEOF reports whether this GET serves through the last byte (full body or Range that ends at size-1).
func archiveGetDeliversThroughEOF(r *http.Request, size int64) bool {
	if r.Method != http.MethodGet || size <= 0 {
		return false
	}
	rg := r.Header.Get("Range")
	if rg == "" {
		return true
	}
	const prefix = "bytes="
	if !strings.HasPrefix(rg, prefix) {
		return false
	}
	rg = strings.TrimSpace(rg[len(prefix):])
	if i := strings.IndexByte(rg, ','); i >= 0 {
		rg = rg[:i]
	}
	dash := strings.IndexByte(rg, '-')
	if dash < 0 {
		return false
	}
	startStr := strings.TrimSpace(rg[:dash])
	endStr := strings.TrimSpace(rg[dash+1:])
	if endStr == "" {
		// "bytes=N-": suffix through EOF
		return true
	}
	if startStr == "" && endStr != "" {
		// "bytes=-N": last-N suffix includes EOF when size > 0
		return true
	}
	end, err := strconv.ParseInt(endStr, 10, 64)
	if err != nil {
		return false
	}
	return end >= size-1
}

// archiveAttachmentStem is the filename stem (no extension) for Content-Disposition on multi-item /
// directory downloads. It prefers the client file path so names match the UI (e.g. "Desktop.zip"); the
// old filepath.Dir(realPath)+Base trick can yield "/" at filesystem root or the wrong parent if index metadata lags.
func archiveAttachmentStem(fileList []string, realPath string) string {
	if len(fileList) == 0 {
		return "download"
	}
	first := filepath.ToSlash(strings.TrimSuffix(strings.TrimSpace(fileList[0]), "/"))
	var stem string
	if len(fileList) == 1 {
		stem = path.Base(first)
	} else {
		stem = path.Base(path.Dir(first))
	}
	if stem == "" || stem == "." || stem == "/" {
		if len(fileList) == 1 {
			stem = filepath.Base(realPath)
		} else {
			stem = filepath.Base(filepath.Dir(realPath))
		}
	}
	if stem == "" || stem == "." || stem == "/" {
		return "download"
	}
	return stem
}

// serveArchiveWithServeContent sends a built archive using ServeContent (Range-capable).
// For share links with MaxBandwidth > 0, outbound data is throttled via newThrottledReadSeeker (same limit as single-file download).
func serveArchiveWithServeContent(w http.ResponseWriter, r *http.Request, d *requestContext, rs io.ReadSeeker, fi os.FileInfo, originalFileName string) (int, error) {
	setContentDisposition(w, r, originalFileName)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "private")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	reader := rs
	if d.share != nil && d.share.MaxBandwidth > 0 {
		limit := rate.Limit(d.share.MaxBandwidth * 1024)
		burst := d.share.MaxBandwidth * 1024
		reader = newThrottledReadSeeker(rs, limit, burst, r.Context())
	}
	http.ServeContent(w, r, originalFileName, fi.ModTime(), reader)
	return 0, nil
}

// archiveCreateHandler creates an archive on the server at the given destination.
// POST /resources/archive — server-side only; does not return archive data.
//
// @Summary Create an archive on the server
// @Description Creates a zip or tar.gz archive on the server from the given paths (files and/or directories). Server-side only; no archive bytes are returned. All items must be from the same source. Folders are walked recursively; access-denied paths are silently skipped. Requires create permission. Archive size is checked against server.maxArchiveSizeGB limit if configured.
// @Description
// @Description **Request body parameters:**
// @Description - **fromSource** (string, required): Source name where the paths to archive live. Example: `"default"`
// @Description - **toSource** (string, optional): Source name where the archive file will be written. Defaults to fromSource if omitted. Example: `"backups"`
// @Description - **paths** (array of strings, required): Paths of files or directories to add to the archive (relative to fromSource). Directories are walked; access-denied entries are skipped. Example: `["/docs/file.txt", "/photos"]`
// @Description - **destination** (string, required): Full path where the archive file will be created (on toSource). Must end with .zip or .tar.gz (or format is inferred). Example: `"/backups/my-archive.zip"`
// @Description - **format** (string, optional): Archive format. One of: `"zip"`, `"tar.gz"`. Default inferred from destination extension. Example: `"zip"`
// @Description - **compression** (integer, optional): Gzip compression level for tar.gz only (0–9). 0 = default. Ignored for zip. Example: `6`
// @Description - **deleteAfter** (boolean, optional): If true, delete source files/directories after successful creation. Requires delete permission. Example: `true`
// @Tags Resources
// @Accept json
// @Produce json
// @Param body body archiveCreateRequest true "Request body: fromSource, toSource (optional), paths, destination, format (optional), compression (optional)"
// @Success 200 {object} map[string]string "Created; returns {\"path\": \"<destination path>\"}"
// @Failure 400 {object} map[string]string "Invalid request (e.g. missing required field, invalid path)"
// @Failure 403 {object} map[string]string "Forbidden (create permission or access denied)"
// @Failure 404 {object} map[string]string "Source not found"
// @Failure 413 {object} map[string]string "Request Entity Too Large (archive size exceeds maxArchiveSizeGB limit)"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/resources/archive [post]
func archiveCreateHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (status int, returnErr error) {
	if d.share != nil {
		return http.StatusForbidden, fmt.Errorf("archive create not allowed for shares")
	}
	currentUser, authErr := currentAuthenticatedArchiveUser(d)
	if authErr != nil {
		return errToStatus(authErr), authErr
	}

	var req archiveCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return http.StatusBadRequest, fmt.Errorf("invalid JSON body: %v", err)
	}
	if req.FromSource == "" || len(req.Paths) == 0 || req.Destination == "" {
		return http.StatusBadRequest, fmt.Errorf("fromSource, paths, and destination are required")
	}
	if req.DeleteAfter && !currentUser.Permissions.Delete {
		return http.StatusForbidden, fmt.Errorf("user is not allowed to delete archive sources")
	}

	destClean, err := sanitizeAuthenticatedReadPath(req.Destination)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("invalid destination path: %v", err)
	}
	req.Destination = destClean
	pathsClean := make([]string, 0, len(req.Paths))
	for _, p := range req.Paths {
		var clean string
		clean, err = sanitizeAuthenticatedReadPath(p)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid path %q: %v", p, err)
		}
		pathsClean = append(pathsClean, clean)
	}
	req.Paths = pathsClean

	destSource := req.ToSource
	if destSource == "" {
		destSource = req.FromSource
	}

	idx := indexing.GetIndex(req.FromSource)
	if idx == nil {
		return http.StatusNotFound, fmt.Errorf("source %s not found", req.FromSource)
	}
	userScope, err := currentUser.GetScopeForSourceName(req.FromSource)
	if err != nil {
		return http.StatusForbidden, err
	}

	// Resolve destination on ToSource (or Source if not set)
	if indexing.GetIndex(destSource) == nil {
		return http.StatusNotFound, fmt.Errorf("source %s not found", destSource)
	}
	destinationTarget, err := resolveAuthenticatedWriteTarget(currentUser, destSource, req.Destination)
	if err != nil {
		return errToStatus(err), fmt.Errorf("destination path is unavailable: %w", err)
	}
	if permissionErr := requireArchiveDestinationPermission(currentUser.Permissions, destinationTarget); permissionErr != nil {
		return archiveWritePreflightStatus(permissionErr), permissionErr
	}

	format := strings.ToLower(strings.TrimSpace(req.Format))
	if format == "" {
		destLower := strings.ToLower(req.Destination)
		if strings.HasSuffix(destLower, ".tar.gz") {
			format = "tar.gz"
		} else if strings.HasSuffix(destLower, ".zip") || filepath.Ext(req.Destination) == ".zip" {
			format = "zip"
		} else {
			format = "zip"
		}
	}
	if format != "zip" && format != "tar.gz" {
		return http.StatusBadRequest, fmt.Errorf("format must be zip or tar.gz")
	}

	compression := req.Compression
	if compression < 0 || compression > 9 {
		compression = 0
	}

	// Build full paths for items (same source)
	itemPaths := make([]string, 0, len(req.Paths))
	itemTargets := make([]authenticatedReadTarget, 0, len(req.Paths))
	if _, authErr := currentAuthenticatedArchiveUser(d); authErr != nil {
		return errToStatus(authErr), authErr
	}
	for _, it := range req.Paths {
		full := utils.JoinPathAsUnix(userScope, it)
		sourceTarget, authErr := resolveCurrentAuthenticatedArchiveTarget(d, req.FromSource, full)
		if authErr != nil {
			if errors.Is(authErr, errAuthenticatedArchiveReadPermissions) {
				return errToStatus(authErr), authErr
			}
			if errors.Is(authErr, commonerrors.ErrAccessDenied) {
				continue
			}
			return errToStatus(authErr), authErr
		}
		itemPaths = append(itemPaths, full)
		itemTargets = append(itemTargets, sourceTarget)
	}
	if len(itemPaths) == 0 {
		return http.StatusBadRequest, fmt.Errorf("no paths accessible; add at least one path you have access to")
	}

	// Check archive size limit if configured
	if config.Server.MaxArchiveSizeGB > 0 {
		var estimatedSize int64
		estimatedSize, err = computeArchiveSize(req.FromSource, itemPaths, d)
		if err != nil {
			return errToStatus(err), fmt.Errorf("failed to compute archive size: %w", err)
		}
		maxSizeBytes := config.Server.MaxArchiveSizeGB * 1024 * 1024 * 1024
		if estimatedSize > maxSizeBytes {
			return http.StatusRequestEntityTooLarge, fmt.Errorf("archive size would exceed the maximum allowed size (maxArchiveSize: %d GB)", config.Server.MaxArchiveSizeGB)
		}
	}
	if req.DeleteAfter {
		if _, err = snapshotArchiveDeleteSources(d, req.FromSource, itemPaths); err != nil {
			return errToStatus(err), err
		}
	}

	auditEnabled := AuditRecorderFromRequest(r) != nil
	auditItemCount := int64(len(req.Paths))
	auditAccessibleCount := int64(len(itemPaths))
	auditDeniedCount := auditItemCount - auditAccessibleCount
	auditBytes := int64(0)
	if auditEnabled {
		overwrite := destinationTarget.Info != nil
		metadata := resourceWriteAuditMetadata(auditdb.MethodPOST, auditItemCount)
		metadata.Bytes = &auditBytes
		metadata.Overwrite = &overwrite
		if auditErr := prepareResourceWriteAudit(r, auditdb.ActionArchiveCreate, destSource,
			destinationTarget.LogicalPath, destinationTarget.CanonicalPath, "", "", "", metadata); auditErr != nil {
			return http.StatusServiceUnavailable, ErrAuditUnavailable
		}
		if auditErr := reserveResourceWriteAudit(r); auditErr != nil {
			return http.StatusServiceUnavailable, ErrAuditUnavailable
		}
		defer func() {
			successCount := int64(0)
			failedCount := int64(0)
			deniedCount := auditDeniedCount
			switch {
			case status >= http.StatusOK && status < http.StatusBadRequest:
				successCount = auditAccessibleCount
			case status == http.StatusUnauthorized || status == http.StatusForbidden:
				deniedCount += auditAccessibleCount
			default:
				failedCount = auditAccessibleCount
			}
			outcome := resourceWriteAuditOutcomeMetadata(auditItemCount, successCount, failedCount, deniedCount)
			outcome.Bytes = &auditBytes
			_ = mergeResourceWriteAuditMetadata(r, outcome)
		}()
	}

	tempFile, err := os.CreateTemp("", "filebrowser-server-archive-*")
	if err != nil {
		return http.StatusInternalServerError, err
	}
	tempPath := tempFile.Name()
	tempClosed := false
	defer func() {
		if !tempClosed {
			_ = tempFile.Close()
		}
		_ = os.Remove(tempPath)
	}()

	var (
		createErr            error
		archivedDeleteSource *archiveMemberTracker
	)
	if req.DeleteAfter {
		archivedDeleteSource = &archiveMemberTracker{}
	}
	if format == "zip" {
		createErr = createZipTracked(d, req.FromSource, tempFile, archivedDeleteSource, itemPaths...)
	} else {
		createErr = createTarGzWithLevelTracked(d, req.FromSource, tempFile, compression, archivedDeleteSource, itemPaths...)
	}
	if createErr != nil {
		return errToStatus(createErr), createErr
	}
	if err = tempFile.Sync(); err != nil {
		return http.StatusInternalServerError, err
	}
	if auditEnabled {
		if archiveInfo, statErr := tempFile.Stat(); statErr == nil {
			auditBytes = archiveInfo.Size()
		}
	}
	if err = tempFile.Close(); err != nil {
		return http.StatusInternalServerError, err
	}
	tempClosed = true

	currentUser, authErr = currentAuthenticatedArchiveUser(d)
	if authErr != nil {
		return errToStatus(authErr), authErr
	}
	if req.DeleteAfter && !currentUser.Permissions.Delete {
		return http.StatusForbidden, fmt.Errorf("user is not allowed to delete archive sources")
	}
	if req.DeleteAfter {
		currentDeleteSources, snapshotErr := snapshotArchiveDeleteSources(d, req.FromSource, itemPaths)
		if snapshotErr != nil {
			return errToStatus(snapshotErr), snapshotErr
		}
		if !sameArchiveMemberTrackers(archivedDeleteSource, currentDeleteSources) {
			return http.StatusConflict, fmt.Errorf("archive sources changed during creation")
		}
		for i, full := range itemPaths {
			currentTarget, targetErr := resolveCurrentAuthenticatedArchiveTarget(d, req.FromSource, full)
			if targetErr != nil {
				return errToStatus(targetErr), targetErr
			}
			if !sameAuthenticatedReadTarget(itemTargets[i], currentTarget) {
				return http.StatusConflict, fmt.Errorf("archive source changed before delete")
			}
			itemTargets[i] = currentTarget
		}
	}
	currentDestinationTarget, err := resolveAuthenticatedWriteTarget(currentUser, destSource, req.Destination)
	if err != nil {
		return errToStatus(err), fmt.Errorf("destination path is unavailable: %w", err)
	}
	if permissionErr := requireArchiveDestinationPermission(currentUser.Permissions, currentDestinationTarget); permissionErr != nil {
		return archiveWritePreflightStatus(permissionErr), permissionErr
	}
	if !sameResourceAuditWriteTarget(destinationTarget, currentDestinationTarget) {
		return http.StatusConflict, fmt.Errorf("archive destination changed during creation")
	}
	destinationTarget = currentDestinationTarget
	completedArchive, err := os.Open(tempPath)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	writeErr := files.WriteFileWithPreCommit(destSource, destinationTarget.CanonicalPath,
		destinationTarget.RealPath, completedArchive, func() error {
			latestUser, latestAuthErr := currentAuthenticatedArchiveUser(d)
			if latestAuthErr != nil {
				return latestAuthErr
			}
			latestTarget, latestTargetErr := resolveAuthenticatedWriteTarget(latestUser, destSource, req.Destination)
			if latestTargetErr != nil {
				return latestTargetErr
			}
			if permissionErr := requireArchiveDestinationPermission(latestUser.Permissions, latestTarget); permissionErr != nil {
				return permissionErr
			}
			if !sameResourceAuditWriteTarget(destinationTarget, latestTarget) {
				return errResourceAuditTargetChanged
			}
			return nil
		})
	closeErr := completedArchive.Close()
	if writeErr != nil {
		if errors.Is(writeErr, errResourceAuditTargetChanged) {
			return http.StatusConflict, errResourceAuditTargetChanged
		}
		return errToStatus(writeErr), writeErr
	}
	if closeErr != nil {
		return http.StatusInternalServerError, closeErr
	}

	if req.DeleteAfter {
		currentUser, authErr = currentAuthenticatedArchiveUser(d)
		if authErr != nil {
			return errToStatus(authErr), authErr
		}
		if !currentUser.Permissions.Delete {
			return http.StatusForbidden, fmt.Errorf("user is not allowed to delete archive sources")
		}
		currentDeleteSources, snapshotErr := snapshotArchiveDeleteSources(d, req.FromSource, itemPaths)
		if snapshotErr != nil {
			return errToStatus(snapshotErr), snapshotErr
		}
		if !sameArchiveMemberTrackers(archivedDeleteSource, currentDeleteSources) {
			return http.StatusConflict, fmt.Errorf("archive sources changed before delete")
		}
		type itemToDelete struct {
			realPath string
			isDir    bool
		}
		var toDelete []itemToDelete
		for _, target := range itemTargets {
			toDelete = append(toDelete, itemToDelete{realPath: target.RealPath, isDir: target.Info.IsDir()})
		}
		for i := 0; i < len(toDelete); i++ {
			for j := i + 1; j < len(toDelete); j++ {
				if len(toDelete[j].realPath) > len(toDelete[i].realPath) {
					toDelete[i], toDelete[j] = toDelete[j], toDelete[i]
				}
			}
		}
		for _, item := range toDelete {
			if err := files.DeleteFiles(req.FromSource, item.realPath, item.isDir); err != nil {
				logger.Errorf("Failed to delete source after archive: %v", err)
			}
		}
	}

	return renderJSON(w, r, map[string]string{"path": req.Destination}, http.StatusOK)
}

// unarchiveHandler extracts an archive on the server. POST /resources/unarchive — server-side only.
//
// @Summary Extract an archive on the server
// @Description Extracts a zip or tar.gz archive on the server into the given destination directory. Server-side only; no extracted bytes are returned. Supports extracting to a different source via toSource. Requires create permission. Archive size is checked against server.maxArchiveSizeGB limit if configured.
// @Description
// @Description **Request body parameters:**
// @Description - **fromSource** (string, required): Source name where the archive file lives. Example: `"default"`
// @Description - **toSource** (string, optional): Source name where contents will be extracted. Defaults to fromSource if omitted. Example: `"restored"`
// @Description - **path** (string, required): Path to the archive file (on fromSource). Must be .zip, .tar.gz, or .tgz. Example: `"/downloads/data.zip"`
// @Description - **destination** (string, required): Directory path (on toSource) to extract into. Example: `"/projects/imported"`
// @Description - **deleteAfter** (boolean, optional): If true, delete the archive file after successful extraction. Default: false. Example: `true`
// @Tags Resources
// @Accept json
// @Produce json
// @Param body body unarchiveRequest true "Request body: fromSource, toSource (optional), path, destination, deleteAfter (optional)"
// @Success 200 {object} map[string]string "Extracted; returns {\"path\": \"<destination path>\", \"source\": \"<toSource>\"}"
// @Failure 400 {object} map[string]string "Invalid request (e.g. missing required field, unsupported format)"
// @Failure 403 {object} map[string]string "Forbidden (create permission or access denied)"
// @Failure 404 {object} map[string]string "Source or archive file not found"
// @Failure 413 {object} map[string]string "Request Entity Too Large (archive size exceeds maxArchiveSizeGB limit)"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/resources/unarchive [post]
func unarchiveHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (status int, returnErr error) {
	if d.share != nil {
		return http.StatusForbidden, fmt.Errorf("unarchive not allowed for shares")
	}
	currentUser, authErr := currentAuthenticatedReadUser(d.user, d.token)
	if authErr != nil {
		return http.StatusForbidden, authErr
	}

	var req unarchiveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return http.StatusBadRequest, fmt.Errorf("invalid JSON body: %v", err)
	}
	if req.FromSource == "" || req.Path == "" || req.Destination == "" {
		return http.StatusBadRequest, fmt.Errorf("fromSource, path, and destination are required")
	}
	if req.DeleteAfter && !currentUser.Permissions.Delete {
		return http.StatusForbidden, fmt.Errorf("user is not allowed to delete the source archive")
	}
	if req.ToSource == "" {
		req.ToSource = req.FromSource
	}

	pathClean, err := utils.SanitizeUserPath(req.Path)
	if err != nil {
		return http.StatusBadRequest, err
	}
	destClean, err := utils.SanitizeUserPath(req.Destination)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("invalid destination: %v", err)
	}
	req.Path = pathClean
	req.Destination = destClean

	if indexing.GetIndex(req.FromSource) == nil {
		return http.StatusNotFound, fmt.Errorf("source %s not found", req.FromSource)
	}
	archiveTarget, err := resolveAuthenticatedReadTarget(currentUser, req.FromSource, req.Path)
	if err != nil {
		return errToStatus(err), fmt.Errorf("archive path is unavailable: %w", err)
	}
	if req.DeleteAfter && authenticatedReadPathContainsSymlink(archiveTarget.SourcePath, archiveTarget.LogicalPath) {
		return http.StatusForbidden, fmt.Errorf("source archive path traverses a symlink: %w", commonerrors.ErrAccessDenied)
	}
	archiveReal := archiveTarget.RealPath

	if indexing.GetIndex(req.ToSource) == nil {
		return http.StatusNotFound, fmt.Errorf("source %s not found", req.ToSource)
	}
	destinationTarget, err := resolveAuthenticatedReadTarget(currentUser, req.ToSource, req.Destination)
	if err != nil {
		if errors.Is(err, commonerrors.ErrAccessDenied) {
			return http.StatusForbidden, fmt.Errorf("destination path is unavailable: %w", err)
		}
		return http.StatusBadRequest, fmt.Errorf("destination path is unavailable: %w", err)
	}
	if destinationTarget.Info == nil || !destinationTarget.Info.IsDir() {
		return http.StatusBadRequest, fmt.Errorf("destination must be a directory: %s", req.Destination)
	}
	destReal := destinationTarget.RealPath

	info := archiveTarget.Info
	if info == nil || info.IsDir() {
		return http.StatusBadRequest, fmt.Errorf("path is not an archive file: %s", req.Path)
	}

	// Check archive size limit if configured
	if config.Server.MaxArchiveSizeGB > 0 {
		maxSizeBytes := config.Server.MaxArchiveSizeGB * 1024 * 1024 * 1024
		if info.Size() > maxSizeBytes {
			return http.StatusRequestEntityTooLarge, fmt.Errorf("archive size would exceed the maximum allowed size (maxArchiveSize: %d GB)", config.Server.MaxArchiveSizeGB)
		}
	}

	lower := strings.ToLower(archiveReal)
	isZip := strings.HasSuffix(lower, ".zip")
	isTarGz := strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz")
	if !isZip && !isTarGz {
		return http.StatusBadRequest, fmt.Errorf("unsupported archive format (use .zip or .tar.gz)")
	}
	auditEnabled := AuditRecorderFromRequest(r) != nil
	auditItemCount := int64(1)
	if auditEnabled {
		overwrite := false
		metadata := resourceWriteAuditMetadata(auditdb.MethodPOST, auditItemCount)
		metadata.Overwrite = &overwrite
		if auditErr := prepareResourceWriteAudit(r, auditdb.ActionArchiveExtract, req.ToSource,
			destinationTarget.LogicalPath, destinationTarget.CanonicalPath, "", "", "", metadata); auditErr != nil {
			return http.StatusServiceUnavailable, ErrAuditUnavailable
		}
		if auditErr := reserveResourceWriteAudit(r); auditErr != nil {
			return http.StatusServiceUnavailable, ErrAuditUnavailable
		}
		defer func() {
			successCount := int64(0)
			failedCount := int64(0)
			deniedCount := int64(0)
			switch {
			case status >= http.StatusOK && status < http.StatusBadRequest:
				successCount = 1
			case status == http.StatusUnauthorized || status == http.StatusForbidden:
				deniedCount = 1
			default:
				failedCount = 1
			}
			_ = mergeResourceWriteAuditMetadata(r,
				resourceWriteAuditOutcomeMetadata(auditItemCount, successCount, failedCount, deniedCount))
		}()
	}
	archiveSnapshot, _, cleanupArchiveSnapshot, snapshotErr := snapshotAuthenticatedReadTarget(archiveTarget)
	if snapshotErr != nil {
		return errToStatus(snapshotErr), fmt.Errorf("archive snapshot is unavailable: %w", snapshotErr)
	}
	defer cleanupArchiveSnapshot()
	var (
		extractionPlan *archiveExtractionPlan
		preflightErr   error
	)
	if isZip {
		extractionPlan, preflightErr = scanZipExtractionPlan(archiveSnapshot, destReal)
	} else {
		extractionPlan, preflightErr = scanTarGzExtractionPlan(archiveSnapshot, destReal)
	}
	if preflightErr != nil {
		return archiveExtractionPreflightStatus(preflightErr), preflightErr
	}
	currentUser, authErr = currentAuthenticatedReadUser(d.user, d.token)
	if authErr != nil {
		return http.StatusForbidden, authErr
	}
	if req.DeleteAfter && !currentUser.Permissions.Delete {
		return http.StatusForbidden, fmt.Errorf("user is not allowed to delete the source archive")
	}
	currentArchiveTarget, targetErr := resolveAuthenticatedReadTarget(currentUser, req.FromSource, req.Path)
	if targetErr != nil {
		return errToStatus(targetErr), fmt.Errorf("archive path is unavailable: %w", targetErr)
	}
	if !sameArchiveTargetSnapshot(archiveTarget, currentArchiveTarget) {
		return http.StatusConflict, fmt.Errorf("source archive changed during preflight")
	}
	currentDestinationTarget, targetErr := resolveAuthenticatedReadTarget(currentUser, req.ToSource, req.Destination)
	if targetErr != nil {
		return errToStatus(targetErr), fmt.Errorf("destination path is unavailable: %w", targetErr)
	}
	if !sameAuthenticatedReadTarget(destinationTarget, currentDestinationTarget) {
		return http.StatusConflict, fmt.Errorf("extraction destination changed during preflight")
	}
	archiveTarget = currentArchiveTarget
	destinationTarget = currentDestinationTarget
	archiveReal = archiveTarget.RealPath
	destReal = destinationTarget.RealPath
	if preflightErr = authorizeArchiveExtractionPlan(currentUser, destinationTarget, extractionPlan); preflightErr != nil {
		return archiveExtractionPreflightStatus(preflightErr), preflightErr
	}
	if auditEnabled {
		overwrite := false
		for _, entry := range extractionPlan.entries {
			if entry.existingInfo != nil {
				overwrite = true
				break
			}
		}
		_ = mergeResourceWriteAuditMetadata(r, &auditdb.MetadataV1{
			SchemaVersion: auditdb.CurrentMetadataSchemaVersion,
			Overwrite:     &overwrite,
		})
	}

	var extractErr error
	if isZip {
		extractErr = extractZipWithPlan(archiveSnapshot, destReal, extractionPlan)
	} else {
		extractErr = extractTarGzWithPlan(archiveSnapshot, destReal, extractionPlan)
	}
	if extractErr != nil {
		if errors.Is(extractErr, errArchiveExtractionConflict) {
			return http.StatusConflict, extractErr
		}
		return http.StatusInternalServerError, extractErr
	}

	if req.DeleteAfter {
		currentUser, authErr = currentAuthenticatedReadUser(d.user, d.token)
		if authErr != nil || !currentUser.Permissions.Delete {
			return http.StatusForbidden, fmt.Errorf("user is not allowed to delete the source archive")
		}
		currentArchiveTarget, targetErr = resolveAuthenticatedReadTarget(currentUser, req.FromSource, req.Path)
		if targetErr != nil {
			return errToStatus(targetErr), fmt.Errorf("archive path is unavailable: %w", targetErr)
		}
		if !sameArchiveTargetSnapshot(archiveTarget, currentArchiveTarget) {
			return http.StatusConflict, fmt.Errorf("source archive changed before delete")
		}
		if authenticatedReadPathContainsSymlink(currentArchiveTarget.SourcePath, currentArchiveTarget.LogicalPath) {
			return http.StatusForbidden, fmt.Errorf("source archive path traverses a symlink: %w", commonerrors.ErrAccessDenied)
		}
		if err := os.Remove(currentArchiveTarget.RealPath); err != nil {
			logger.Errorf("Failed to delete archive after extract: %v", err)
		}
	}

	return renderJSON(w, r, map[string]string{"path": req.Destination, "source": req.ToSource}, http.StatusOK)
}

// addFile adds an authenticated file or directory after resolving every member against
// the user's current token, scope, canonical path, and access rules.
func addFile(source string, path string, d *requestContext, tarWriter *tar.Writer, zipWriter *zip.Writer, flatten bool, tracker *archiveMemberTracker) error {
	err := walkAuthenticatedArchiveMembers(d, source, path, flatten, func(member authenticatedArchiveMember) error {
		if member.root {
			tracker.add(member.indexPath, member.target)
			return nil
		}
		if member.target.Info == nil {
			return commonerrors.ErrAccessDenied
		}
		if member.target.Info.IsDir() {
			if tarWriter != nil {
				header, err := tar.FileInfoHeader(member.target.Info, "")
				if err != nil {
					return err
				}
				header.Name = filepath.ToSlash(member.archivePath) + "/"
				if err = tarWriter.WriteHeader(header); err != nil {
					return err
				}
			} else if zipWriter != nil {
				header, err := zip.FileInfoHeader(member.target.Info)
				if err != nil {
					return err
				}
				header.Name = filepath.ToSlash(member.archivePath) + "/"
				header.Method = zip.Store
				if _, err = zipWriter.CreateHeader(header); err != nil {
					return err
				}
			}
			if err := reauthorizeAuthenticatedArchiveMember(d, source, member); err != nil {
				return err
			}
			tracker.add(member.indexPath, member.target)
			return nil
		}

		file, info, err := openAuthenticatedReadTarget(member.target)
		if err != nil {
			return err
		}
		defer file.Close()
		if tarWriter != nil {
			header, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			header.Name = filepath.ToSlash(member.archivePath)
			if err = tarWriter.WriteHeader(header); err != nil {
				return err
			}
			if err = copyAuthenticatedArchiveMember(d, source, member, tarWriter, file); err != nil {
				return err
			}
		} else if zipWriter != nil {
			header, err := zip.FileInfoHeader(info)
			if err != nil {
				return err
			}
			header.Name = filepath.ToSlash(member.archivePath)
			writer, err := zipWriter.CreateHeader(header)
			if err != nil {
				return err
			}
			if err = copyAuthenticatedArchiveMember(d, source, member, writer, file); err != nil {
				return err
			}
		}
		tracker.add(member.indexPath, member.target)
		return nil
	})
	if errors.Is(err, commonerrors.ErrAccessDenied) && !errors.Is(err, errAuthenticatedArchiveReadPermissions) {
		return nil
	}
	return err
}

// addSingleFile writes one file into the given zip or tar writer.
func addSingleFile(realPath, archivePath string, zipWriter *zip.Writer, tarWriter *tar.Writer) error {
	file, err := os.Open(realPath)
	if err != nil {
		if strings.Contains(err.Error(), "is a directory") {
			return nil
		}
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	if info.IsDir() {
		return nil
	}

	if tarWriter != nil {
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(archivePath)
		if err = tarWriter.WriteHeader(header); err != nil {
			return err
		}
		_, err = io.Copy(tarWriter, file)
		return err
	}

	if zipWriter != nil {
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = archivePath
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}
		_, err = io.Copy(writer, file)
		return err
	}

	return nil
}

func addPublicShareArchiveEntry(d *requestContext, entry *publicShareArchiveEntry, tarWriter *tar.Writer, zipWriter *zip.Writer) error {
	target, err := reauthorizePublicShareArchiveEntry(d, *entry)
	if err != nil {
		return err
	}
	archivePath := filepath.ToSlash(entry.ArchivePath)
	if target.IsDir {
		archivePath = strings.TrimSuffix(archivePath, "/") + "/"
		if tarWriter != nil {
			header, err := tar.FileInfoHeader(target.info, "")
			if err != nil {
				return err
			}
			header.Name = archivePath
			return tarWriter.WriteHeader(header)
		}
		if zipWriter != nil {
			header, err := zip.FileInfoHeader(target.info)
			if err != nil {
				return err
			}
			header.Name = archivePath
			header.Method = zip.Store
			_, err = zipWriter.CreateHeader(header)
			return err
		}
		return nil
	}

	file, err := os.Open(target.RealPath)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.IsDir() || !publicShareSameFileIdentity(target.info, info) {
		return fmt.Errorf("public archive member changed")
	}

	hasher := sha256.New()
	var writer io.Writer
	if tarWriter != nil {
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = archivePath
		if err = tarWriter.WriteHeader(header); err != nil {
			return err
		}
		writer = tarWriter
	} else if zipWriter != nil {
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = archivePath
		writer, err = zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("public archive writer is missing")
	}
	if _, err = io.Copy(io.MultiWriter(writer, hasher), file); err != nil {
		return err
	}
	after, err := file.Stat()
	if err != nil || !publicShareSameFileIdentity(info, after) {
		return fmt.Errorf("public archive member changed while reading")
	}
	digest := [sha256.Size]byte(hasher.Sum(nil))
	if entry.ContentSHA256 != ([sha256.Size]byte{}) && entry.ContentSHA256 != digest {
		return fmt.Errorf("public archive member content changed")
	}
	entry.ContentSHA256 = digest
	return nil
}

func createPublicShareZip(d *requestContext, w io.Writer) error {
	zipWriter := zip.NewWriter(w)
	for i := range d.shareArchive {
		if err := addPublicShareArchiveEntry(d, &d.shareArchive[i], nil, zipWriter); err != nil {
			_ = zipWriter.Close()
			return err
		}
	}
	return zipWriter.Close()
}

func createPublicShareTarGz(d *requestContext, w io.Writer) error {
	gzipWriter := gzip.NewWriter(w)
	tarWriter := tar.NewWriter(gzipWriter)
	for i := range d.shareArchive {
		if err := addPublicShareArchiveEntry(d, &d.shareArchive[i], tarWriter, nil); err != nil {
			_ = tarWriter.Close()
			_ = gzipWriter.Close()
			return err
		}
	}
	if err := tarWriter.Close(); err != nil {
		_ = gzipWriter.Close()
		return err
	}
	return gzipWriter.Close()
}

func validatePublicShareArchiveEntryContent(d *requestContext, entry publicShareArchiveEntry) error {
	target, err := reauthorizePublicShareArchiveEntry(d, entry)
	if err != nil {
		return err
	}
	if target.IsDir {
		return nil
	}
	if entry.ContentSHA256 == ([sha256.Size]byte{}) {
		return fmt.Errorf("public archive member digest is missing")
	}
	file, err := os.Open(target.RealPath)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.IsDir() || !publicShareSameFileIdentity(target.info, info) {
		return fmt.Errorf("public archive member changed")
	}
	hasher := sha256.New()
	if _, err = io.Copy(hasher, file); err != nil {
		return err
	}
	after, err := file.Stat()
	if err != nil || !publicShareSameFileIdentity(info, after) {
		return fmt.Errorf("public archive member changed while reading")
	}
	if [sha256.Size]byte(hasher.Sum(nil)) != entry.ContentSHA256 {
		return fmt.Errorf("public archive member content changed")
	}
	return nil
}

func publicShareArchiveManifestMatches(current, original []publicShareArchiveEntry) bool {
	if len(current) != len(original) {
		return false
	}
	for i := range original {
		currentEntry := current[i]
		originalEntry := original[i]
		if currentEntry.LogicalPath != originalEntry.LogicalPath ||
			currentEntry.CanonicalPath != originalEntry.CanonicalPath ||
			!publicShareSameRealPath(currentEntry.RealPath, originalEntry.RealPath) ||
			currentEntry.ArchivePath != originalEntry.ArchivePath ||
			currentEntry.IsDir != originalEntry.IsDir ||
			!publicShareSameFileIdentity(currentEntry.info, originalEntry.info) {
			return false
		}
	}
	return true
}

func publicShareArchiveSize(d *requestContext) (int64, error) {
	var size int64
	for _, entry := range d.shareArchive {
		if entry.IsDir {
			continue
		}
		target, err := reauthorizePublicShareArchiveEntry(d, entry)
		if err != nil {
			return 0, err
		}
		info, err := os.Stat(target.RealPath)
		if err != nil || info.IsDir() {
			return 0, fmt.Errorf("public archive member changed")
		}
		size += info.Size()
	}
	return size, nil
}

// createZip writes a ZIP archive into w containing the given paths; access rules apply.
func createZip(d *requestContext, source string, w io.Writer, filenames ...string) error {
	return createZipTracked(d, source, w, nil, filenames...)
}

func createZipTracked(d *requestContext, source string, w io.Writer, tracker *archiveMemberTracker, filenames ...string) error {
	zipWriter := zip.NewWriter(w)

	for _, filepath := range filenames {
		err := addFile(source, filepath, d, nil, zipWriter, false, tracker)
		if err != nil {
			logger.Errorf("Failed to add %s to ZIP: %v", filepath, err)
			return err
		}
	}

	if err := zipWriter.Close(); err != nil {
		return fmt.Errorf("failed to finalize ZIP archive: %w", err)
	}
	return nil
}

// createTarGz writes a tar.gz archive into w containing the given paths; access rules apply.
func createTarGz(d *requestContext, source string, w io.Writer, filenames ...string) error {
	return createTarGzTracked(d, source, w, nil, filenames...)
}

func createTarGzTracked(d *requestContext, source string, w io.Writer, tracker *archiveMemberTracker, filenames ...string) error {
	gzWriter := gzip.NewWriter(w)
	tarWriter := tar.NewWriter(gzWriter)

	for _, filepath := range filenames {
		err := addFile(source, filepath, d, tarWriter, nil, false, tracker)
		if err != nil {
			logger.Errorf("Failed to add %s to TAR.GZ: %v", filepath, err)
			return err
		}
	}

	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("failed to finalize TAR archive: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		return fmt.Errorf("failed to finalize GZIP compression: %w", err)
	}
	return nil
}

// createTarGzWithLevel writes a tar.gz archive into w with the given gzip compression level (0=default, 1-9).
func createTarGzWithLevel(d *requestContext, source string, w io.Writer, level int, filenames ...string) error {
	return createTarGzWithLevelTracked(d, source, w, level, nil, filenames...)
}

func createTarGzWithLevelTracked(d *requestContext, source string, w io.Writer, level int, tracker *archiveMemberTracker, filenames ...string) error {
	var gzWriter *gzip.Writer
	if level >= 1 && level <= 9 {
		var err error
		gzWriter, err = gzip.NewWriterLevel(w, level)
		if err != nil {
			return err
		}
	} else {
		gzWriter = gzip.NewWriter(w)
	}
	defer gzWriter.Close()
	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	for _, filepath := range filenames {
		err := addFile(source, filepath, d, tarWriter, nil, false, tracker)
		if err != nil {
			logger.Errorf("Failed to add %s to TAR.GZ: %v", filepath, err)
			return err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("failed to finalize TAR archive: %w", err)
	}
	return nil
}

func archiveExtensionForAlgorithm(algo string) (string, error) {
	switch algo {
	case "zip", "true", "":
		return ".zip", nil
	case "tar.gz":
		return ".tar.gz", nil
	default:
		return "", errors.New("format not implemented")
	}
}

// BuildAndStreamArchive builds a zip or tar.gz for multi-file/directory download.
// Plain GET without Range streams the archive straight to the response (no temp file), matching
// clients with chunked downloads disabled. HEAD or Range builds a temp file under cacheDir downloads,
// returns X-Archive-Token on the first response, and serves via ServeContent for Range/resume;
// follow-up GETs use ?archiveToken=.... Idle chunked sessions delete the spool file after
// archiveMultiRequestIdle without another request.
//
// server.maxArchiveSizeGB is enforced only for the HEAD/Range spool path.
func BuildAndStreamArchive(w http.ResponseWriter, r *http.Request, d *requestContext, source string, fileList []string) (int, error) {
	requestedItemCount := int64(len(fileList))
	var shareRealPath string
	if d.share != nil {
		idx := indexing.GetIndex(source)
		if idx == nil {
			return http.StatusInternalServerError, fmt.Errorf("source %s is not available", source)
		}
		if len(d.shareTargets) == 0 {
			return http.StatusForbidden, fmt.Errorf("public share archive target is missing")
		}
		shareRealPath = d.shareTargets[0].RealPath
	}
	extension, err := archiveExtensionForAlgorithm(r.URL.Query().Get("algo"))
	if err != nil {
		return http.StatusInternalServerError, err
	}
	var shareOriginalFileName string
	if d.share != nil {
		shareOriginalFileName = archiveAttachmentStem(fileList, shareRealPath) + extension
	}

	token := r.URL.Query().Get("archiveToken")
	if token != "" {
		session, ok := archiveSpoolCache.Get(token)
		if !ok {
			if d.share != nil {
				return http.StatusNotFound, fmt.Errorf("invalid or expired archiveToken")
			}
			return http.StatusGone, fmt.Errorf("invalid or expired archiveToken")
		}
		if d.share != nil {
			if session.shareHash != d.share.Hash || session.shareLink == nil || session.shareLink != d.share ||
				session.source != source || session.archiveExtension != extension ||
				session.originalFileName != shareOriginalFileName || len(session.shareTargets) != len(d.shareTargets) ||
				d.user == nil || session.userID != d.user.ID || session.username != d.user.Username {
				removeSpooledArchiveNow(token, session.tmpPath)
				return http.StatusForbidden, fmt.Errorf("archiveToken is not valid for this share")
			}
			sourceInfo, exists := config.Server.SourceMap[d.share.Source]
			if !exists || session.sourcePath == "" || sourceInfo.Path != session.sourcePath || sourceInfo.Name != session.source {
				removeSpooledArchiveNow(token, session.tmpPath)
				return http.StatusForbidden, fmt.Errorf("public archive source changed")
			}
			for i, originalTarget := range session.shareTargets {
				currentTarget := d.shareTargets[i]
				if currentTarget.LogicalPath != originalTarget.LogicalPath || currentTarget.CanonicalPath != originalTarget.CanonicalPath ||
					!publicShareSameRealPath(currentTarget.RealPath, originalTarget.RealPath) || currentTarget.IsDir != originalTarget.IsDir {
					removeSpooledArchiveNow(token, session.tmpPath)
					return http.StatusForbidden, fmt.Errorf("public archive target changed")
				}
				if _, authErr := reauthorizePublicShareTarget(d, sourceInfo.Path, originalTarget); authErr != nil {
					removeSpooledArchiveNow(token, session.tmpPath)
					return http.StatusForbidden, fmt.Errorf("public archive target authorization changed")
				}
			}
			if !publicShareArchiveManifestMatches(d.shareArchive, session.shareMembers) {
				removeSpooledArchiveNow(token, session.tmpPath)
				return http.StatusForbidden, fmt.Errorf("public archive members changed")
			}
			for _, member := range session.shareMembers {
				if authErr := validatePublicShareArchiveEntryContent(d, member); authErr != nil {
					removeSpooledArchiveNow(token, session.tmpPath)
					return http.StatusForbidden, fmt.Errorf("public archive authorization changed")
				}
			}
		} else {
			if session.shareHash != "" {
				return http.StatusForbidden, fmt.Errorf("archiveToken is not valid for this request")
			}
			if session.username == "" || session.userID != d.user.ID || session.username != d.user.Username || session.source != source || !slices.Equal(session.requestFileList, fileList) {
				return http.StatusForbidden, fmt.Errorf("archive resume session is not valid for the current user scope")
			}
			idx := indexing.GetIndex(session.source)
			if idx == nil || session.sourcePath == "" || idx.Path != session.sourcePath {
				return http.StatusForbidden, fmt.Errorf("archive resume source is not available")
			}
			if _, authErr := currentAuthenticatedArchiveUser(d); authErr != nil {
				return errToStatus(authErr), authErr
			}
			if authErr := reauthorizeAuthenticatedArchiveMembers(d, session.source, session.memberPaths, session.memberTargets); authErr != nil {
				denied := fmt.Errorf("archive member access has changed: %w", commonerrors.ErrAccessDenied)
				return errToStatus(denied), denied
			}
			if len(session.memberTargets) == 0 {
				return http.StatusForbidden, fmt.Errorf("archive contains no accessible members")
			}
			itemCount := int64(len(session.requestFileList))
			if auditErr := setCoreFileAuditReadTarget(r, session.memberTargets[0], &auditdb.MetadataV1{
				SchemaVersion: auditdb.CurrentMetadataSchemaVersion,
				ItemCount:     &itemCount,
			}); auditErr != nil {
				return http.StatusServiceUnavailable, ErrAuditUnavailable
			}
		}

		session, ok = acquireArchiveSpool(token, session)
		if !ok {
			return http.StatusGone, fmt.Errorf("archive no longer available")
		}
		fd, fi, err := settings.OpenDownloadArchiveSpool(session.tmpPath, session.spoolInfo)
		if err != nil {
			releaseArchiveSpool(token, session, true)
			return http.StatusGone, err
		}
		released := false
		defer func() {
			if !released {
				_ = fd.Close()
				releaseArchiveSpool(token, session, true)
			}
		}()
		code, srvErr := serveArchiveWithServeContent(w, r, d, fd, fi, session.originalFileName)
		if closeErr := fd.Close(); closeErr != nil && srvErr == nil {
			srvErr = closeErr
		}
		complete := srvErr == nil && archiveGetDeliversThroughEOF(r, fi.Size())
		releaseArchiveSpool(token, session, srvErr != nil || complete)
		released = true
		return code, srvErr
	}

	idx := indexing.GetIndex(source)
	if idx == nil {
		return http.StatusInternalServerError, fmt.Errorf("source %s is not available", source)
	}
	requestFileList := append([]string(nil), fileList...)
	if d.share == nil {
		if _, authErr := currentAuthenticatedArchiveUser(d); authErr != nil {
			return errToStatus(authErr), authErr
		}
		permitted := make([]string, 0, len(fileList))
		for _, filePath := range fileList {
			if _, authErr := resolveCurrentAuthenticatedArchiveTarget(d, source, filePath); authErr != nil {
				if errors.Is(authErr, errAuthenticatedArchiveReadPermissions) {
					return errToStatus(authErr), authErr
				}
				if errors.Is(authErr, commonerrors.ErrAccessDenied) {
					continue
				}
				return errToStatus(authErr), authErr
			}
			permitted = append(permitted, filePath)
		}
		fileList = permitted
		if len(fileList) == 0 {
			return http.StatusForbidden, fmt.Errorf("no archive members are accessible")
		}
	}
	var realPath string
	if d.share != nil {
		realPath = shareRealPath
	} else {
		var firstTarget authenticatedReadTarget
		firstTarget, err = resolveCurrentAuthenticatedArchiveTarget(d, source, fileList[0])
		if err != nil {
			return errToStatus(err), fmt.Errorf("failed to resolve archive path %s: %w", fileList[0], err)
		}
		realPath = firstTarget.RealPath
		if auditErr := setCoreFileAuditReadTarget(r, firstTarget, &auditdb.MetadataV1{
			SchemaVersion: auditdb.CurrentMetadataSchemaVersion,
			ItemCount:     &requestedItemCount,
		}); auditErr != nil {
			return http.StatusServiceUnavailable, ErrAuditUnavailable
		}
	}
	originalFileName := archiveAttachmentStem(fileList, realPath) + extension

	// HEAD or Range: same condition as chunked archive probing / retained spool (X-Archive-Token).
	needMultiRequestSession := r.Method == http.MethodHead || r.Header.Get("Range") != ""

	if needMultiRequestSession && config.Server.MaxArchiveSizeGB > 0 {
		var estimatedSize int64
		if d.share != nil {
			estimatedSize, err = publicShareArchiveSize(d)
		} else {
			estimatedSize, err = computeArchiveSize(source, fileList, d)
		}
		if err != nil {
			status := http.StatusInternalServerError
			if d.share == nil {
				status = errToStatus(err)
			}
			return status, fmt.Errorf("failed to compute archive size: %w", err)
		}
		maxSizeBytes := config.Server.MaxArchiveSizeGB * 1024 * 1024 * 1024
		if estimatedSize > maxSizeBytes {
			return http.StatusRequestEntityTooLarge, fmt.Errorf("archive size would exceed the maximum allowed size (maxArchiveSize: %d GB)", config.Server.MaxArchiveSizeGB)
		}
	}

	// Direct streaming: no temp file (typical browser download when chunked downloads are disabled).
	if !needMultiRequestSession {
		if r.Method != http.MethodGet {
			return http.StatusMethodNotAllowed, fmt.Errorf("method not allowed")
		}
		setContentDisposition(w, r, originalFileName)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "private")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		writer := io.Writer(w)
		if d.share != nil && d.share.MaxBandwidth > 0 {
			limit := rate.Limit(d.share.MaxBandwidth * 1024)
			burst := d.share.MaxBandwidth * 1024
			writer = newThrottledWriter(w, limit, burst, r.Context())
		}
		if d.share != nil && extension == ".zip" {
			err = createPublicShareZip(d, writer)
		} else if d.share != nil {
			err = createPublicShareTarGz(d, writer)
		} else if extension == ".zip" {
			err = createZip(d, source, writer, fileList...)
		} else {
			err = createTarGz(d, source, writer, fileList...)
		}
		if err != nil {
			status := http.StatusInternalServerError
			if d.share == nil {
				status = errToStatus(err)
			}
			return status, err
		}
		return 0, nil
	}

	tmpF, spoolInfo, err := settings.CreateDownloadArchiveSpool(extension)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("create temp archive: %w", err)
	}
	tmpPath := tmpF.Name()
	tempOwned := true
	defer func() {
		if tempOwned {
			_ = tmpF.Close()
			removeArchiveSpoolFile(tmpPath, spoolInfo)
		}
	}()
	memberTracker := &archiveMemberTracker{}

	if d.share != nil && extension == ".zip" {
		err = createPublicShareZip(d, tmpF)
	} else if d.share != nil {
		err = createPublicShareTarGz(d, tmpF)
	} else if extension == ".zip" {
		err = createZipTracked(d, source, tmpF, memberTracker, fileList...)
	} else {
		err = createTarGzTracked(d, source, tmpF, memberTracker, fileList...)
	}
	if err != nil {
		status := http.StatusInternalServerError
		if d.share == nil {
			status = errToStatus(err)
		}
		return status, err
	}
	if d.share == nil {
		if authErr := reauthorizeAuthenticatedArchiveMembers(d, source, memberTracker.paths, memberTracker.targets); authErr != nil {
			return http.StatusForbidden, commonerrors.ErrAccessDenied
		}
	}

	if _, err = tmpF.Seek(0, 0); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("seek temp archive: %w", err)
	}
	fi, err := tmpF.Stat()
	if err != nil {
		return http.StatusInternalServerError, err
	}

	sizeInMB := fi.Size() / 1024 / 1024
	if sizeInMB > 500 {
		logger.Debugf("User %v is downloading large (%d MB) archive: %v", d.user.Username, sizeInMB, originalFileName)
	}

	// needMultiRequestSession: HEAD or Range — always spool and use ServeContent (+ token for follow-ups).
	if err = tmpF.Close(); err != nil {
		return http.StatusInternalServerError, err
	}
	newTok, err := archiveSpoolTokenFunc()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	fd, fi2, err := settings.OpenDownloadArchiveSpool(tmpPath, spoolInfo)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	fdOwned := true
	defer func() {
		if fdOwned {
			_ = fd.Close()
		}
	}()
	session := archiveSpoolSession{
		tmpPath:          tmpPath,
		spoolInfo:        spoolInfo,
		originalFileName: originalFileName,
		source:           source,
		sourcePath:       idx.Path,
		requestFileList:  requestFileList,
		memberPaths:      append([]string(nil), memberTracker.paths...),
		memberTargets:    append([]authenticatedReadTarget(nil), memberTracker.targets...),
		archiveExtension: extension,
		lifecycle:        &archiveSpoolLifecycle{active: 1},
		userID:           d.user.ID,
		username:         d.user.Username,
	}
	if d.share != nil {
		session.shareHash = d.share.Hash
		session.shareLink = d.share
		session.shareTargets = append([]publicShareTarget(nil), d.shareTargets...)
		session.shareMembers = append([]publicShareArchiveEntry(nil), d.shareArchive...)
	} else if authErr := reauthorizeAuthenticatedArchiveMembers(d, source, session.memberPaths, session.memberTargets); authErr != nil {
		return http.StatusForbidden, commonerrors.ErrAccessDenied
	}
	archiveSpoolCache.SetWithExp(newTok, session, archiveSpoolActiveCacheTTL)
	released := false
	defer func() {
		if !released {
			_ = fd.Close()
			releaseArchiveSpool(newTok, session, true)
		}
	}()
	fdOwned = false
	tempOwned = false
	w.Header().Set("X-Archive-Token", newTok)

	code, srvErr := serveArchiveWithServeContent(w, r, d, fd, fi2, originalFileName)
	if closeErr := fd.Close(); closeErr != nil && srvErr == nil {
		srvErr = closeErr
	}
	complete := srvErr == nil && archiveGetDeliversThroughEOF(r, fi2.Size())
	releaseArchiveSpool(newTok, session, srvErr != nil || complete)
	released = true
	return code, srvErr
}

// archiveCreateRequest is the body for POST /resources/archive (server-side create).
type archiveCreateRequest struct {
	// Source name where the paths to archive live (required). Example: "default"
	FromSource string `json:"fromSource"`
	// Source name where the archive file will be written (optional; default: fromSource). Example: "backups"
	ToSource string `json:"toSource"`
	// Paths of files or directories to add; directories are walked; access-denied entries skipped (required). Example: ["/docs/file.txt", "/photos"]
	Paths []string `json:"paths"`
	// Full path where the archive will be created; use .zip or .tar.gz extension (required). Example: "/backups/my-archive.zip"
	Destination string `json:"destination"`
	// Archive format: "zip" or "tar.gz" (optional; inferred from destination if omitted). Example: "zip"
	Format string `json:"format"`
	// Gzip compression level for tar.gz only, 0-9; 0 = default; ignored for zip (optional). Example: 6
	Compression int `json:"compression"`
	// If true, delete the source files/directories after successful archive creation (optional; requires delete permission). Example: true
	DeleteAfter bool `json:"deleteAfter"`
}

// unarchiveRequest is the body for POST /resources/unarchive (server-side extract).
type unarchiveRequest struct {
	// Source name where the archive file lives (required). Example: "default"
	FromSource string `json:"fromSource"`
	// Source name where contents will be extracted (optional; default: fromSource). Example: "restored"
	ToSource string `json:"toSource"`
	// Path to the archive file on fromSource; .zip, .tar.gz, or .tgz (required). Example: "/downloads/data.zip"
	Path string `json:"path"`
	// Directory path on toSource to extract into (required). Example: "/projects/imported"
	Destination string `json:"destination"`
	// If true, delete the archive file after successful extraction (optional; default: false). Example: true
	DeleteAfter bool `json:"deleteAfter"`
}

var errArchiveExtractionConflict = errors.New("archive extraction target conflict")

const maxArchiveSymlinkTargetBytes = 4096

type archiveExtractionEntryKind uint8

const (
	archiveExtractionDirectory archiveExtractionEntryKind = iota + 1
	archiveExtractionRegularFile
	archiveExtractionSymlink
)

type archiveExtractionPlanEntry struct {
	relative      string
	kind          archiveExtractionEntryKind
	explicit      bool
	symlinkTarget string
	existingInfo  os.FileInfo
}

type archiveExtractionPlan struct {
	entries map[string]*archiveExtractionPlanEntry
}

func requireArchiveDestinationPermission(permissions users.Permissions, target authenticatedReadTarget) error {
	if target.Info == nil {
		if !permissions.Create {
			return fmt.Errorf("user is not allowed to create the destination archive: %w", commonerrors.ErrAccessDenied)
		}
		return nil
	}
	if !target.Info.Mode().IsRegular() {
		return fmt.Errorf("destination archive path is not a regular file: %w", errArchiveExtractionConflict)
	}
	if !permissions.Modify {
		return fmt.Errorf("user is not allowed to modify the destination archive: %w", commonerrors.ErrAccessDenied)
	}
	return nil
}

func archiveWritePreflightStatus(err error) int {
	if errors.Is(err, commonerrors.ErrAccessDenied) {
		return http.StatusForbidden
	}
	if errors.Is(err, errArchiveExtractionConflict) {
		return http.StatusConflict
	}
	return errToStatus(err)
}

func archiveExtractionPreflightStatus(err error) int {
	if errors.Is(err, commonerrors.ErrAccessDenied) {
		return http.StatusForbidden
	}
	if errors.Is(err, errArchiveExtractionConflict) {
		return http.StatusConflict
	}
	return http.StatusBadRequest
}

func archiveExtractionPlanKey(relative string) string {
	return strings.ToLower(path.Clean(strings.ReplaceAll(relative, "\\", "/")))
}

func (plan *archiveExtractionPlan) add(relative string, kind archiveExtractionEntryKind) error {
	parts := strings.Split(relative, "/")
	for i := 1; i < len(parts); i++ {
		if err := plan.addOne(strings.Join(parts[:i], "/"), archiveExtractionDirectory, false); err != nil {
			return err
		}
	}
	return plan.addOne(relative, kind, true)
}

func (plan *archiveExtractionPlan) addOne(relative string, kind archiveExtractionEntryKind, explicit bool) error {
	if plan.entries == nil {
		plan.entries = make(map[string]*archiveExtractionPlanEntry)
	}
	key := archiveExtractionPlanKey(relative)
	if existing, ok := plan.entries[key]; ok {
		if existing.relative != relative || existing.kind != kind || (explicit && existing.explicit) {
			return fmt.Errorf("conflicting archive entries at %q: %w", relative, errArchiveExtractionConflict)
		}
		existing.explicit = existing.explicit || explicit
		return nil
	}
	plan.entries[key] = &archiveExtractionPlanEntry{
		relative: relative,
		kind:     kind,
		explicit: explicit,
	}
	return nil
}

func (plan *archiveExtractionPlan) sortedEntries() []*archiveExtractionPlanEntry {
	entries := make([]*archiveExtractionPlanEntry, 0, len(plan.entries))
	for _, entry := range plan.entries {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].relative < entries[j].relative
	})
	return entries
}

func readZipArchiveSymlinkTarget(entry *zip.File) (string, error) {
	if entry.UncompressedSize64 > maxArchiveSymlinkTargetBytes {
		return "", fmt.Errorf("symlink target for %q is too large: %w", entry.Name, errArchiveExtractionConflict)
	}
	entryReader, err := entry.Open()
	if err != nil {
		return "", err
	}
	target, readErr := io.ReadAll(io.LimitReader(entryReader, maxArchiveSymlinkTargetBytes+1))
	closeErr := entryReader.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if len(target) > maxArchiveSymlinkTargetBytes {
		return "", fmt.Errorf("symlink target for %q is too large: %w", entry.Name, errArchiveExtractionConflict)
	}
	return strings.TrimSpace(string(target)), nil
}

func scanZipExtractionPlan(archivePath, destDir string) (*archiveExtractionPlan, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	plan := &archiveExtractionPlan{entries: make(map[string]*archiveExtractionPlanEntry)}
	for _, entry := range reader.File {
		relative, normalizeErr := normalizeArchiveEntryName(entry.Name)
		if normalizeErr != nil {
			return nil, fmt.Errorf("invalid entry path %q: %w", entry.Name, normalizeErr)
		}
		destPath, pathErr := safeExtractPath(destDir, entry.Name)
		if pathErr != nil {
			return nil, pathErr
		}

		mode := entry.FileInfo().Mode()
		trailingSeparator := strings.HasSuffix(entry.Name, "/") || strings.HasSuffix(entry.Name, "\\")
		var kind archiveExtractionEntryKind
		switch {
		case mode.Type() == fs.ModeSymlink:
			kind = archiveExtractionSymlink
			target, targetErr := readZipArchiveSymlinkTarget(entry)
			if targetErr != nil {
				return nil, targetErr
			}
			if targetErr = symlinkTargetStaysUnderDest(destDir, destPath, target); targetErr != nil {
				return nil, targetErr
			}
			if addErr := plan.add(relative, kind); addErr != nil {
				return nil, addErr
			}
			plan.entries[archiveExtractionPlanKey(relative)].symlinkTarget = target
			continue
		case mode.Type() == fs.ModeDir:
			kind = archiveExtractionDirectory
		case mode.IsRegular() && trailingSeparator:
			kind = archiveExtractionDirectory
		case mode.IsRegular():
			kind = archiveExtractionRegularFile
		default:
			return nil, fmt.Errorf("unsupported ZIP entry type for %q (%s): %w", entry.Name, mode.Type(), errArchiveExtractionConflict)
		}
		if addErr := plan.add(relative, kind); addErr != nil {
			return nil, addErr
		}
	}
	if err := validateArchiveSymlinkPlan(destDir, plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func scanTarGzExtractionPlan(archivePath, destDir string) (*archiveExtractionPlan, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()

	plan := &archiveExtractionPlan{entries: make(map[string]*archiveExtractionPlanEntry)}
	tarReader := tar.NewReader(gzipReader)
	for {
		header, nextErr := tarReader.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return nil, nextErr
		}
		relative, normalizeErr := normalizeArchiveEntryName(header.Name)
		if normalizeErr != nil {
			return nil, fmt.Errorf("invalid entry path %q: %w", header.Name, normalizeErr)
		}
		destPath, pathErr := safeExtractPath(destDir, header.Name)
		if pathErr != nil {
			return nil, pathErr
		}

		var kind archiveExtractionEntryKind
		switch header.Typeflag {
		case tar.TypeDir:
			kind = archiveExtractionDirectory
		case tar.TypeReg, tar.TypeRegA:
			kind = archiveExtractionRegularFile
		case tar.TypeSymlink:
			kind = archiveExtractionSymlink
			if targetErr := symlinkTargetStaysUnderDest(destDir, destPath, strings.TrimSpace(header.Linkname)); targetErr != nil {
				return nil, targetErr
			}
			if addErr := plan.add(relative, kind); addErr != nil {
				return nil, addErr
			}
			plan.entries[archiveExtractionPlanKey(relative)].symlinkTarget = strings.TrimSpace(header.Linkname)
			continue
		default:
			return nil, fmt.Errorf("unsupported TAR entry type for %q (%#x): %w", header.Name, header.Typeflag, errArchiveExtractionConflict)
		}
		if addErr := plan.add(relative, kind); addErr != nil {
			return nil, addErr
		}
	}
	if err := validateArchiveSymlinkPlan(destDir, plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func validateArchiveSymlinkPlan(destDir string, plan *archiveExtractionPlan) error {
	for _, entry := range plan.entries {
		if entry.kind != archiveExtractionSymlink {
			continue
		}
		destPath, err := safeExtractPath(destDir, entry.relative)
		if err != nil {
			return err
		}
		targetRelative, err := resolveArchiveSymlinkTargetRelative(destDir, destPath, entry.symlinkTarget)
		if err != nil {
			return err
		}
		parts := strings.Split(targetRelative, "/")
		for i := 1; i <= len(parts); i++ {
			planned, ok := plan.entries[archiveExtractionPlanKey(strings.Join(parts[:i], "/"))]
			if !ok {
				continue
			}
			if planned.kind == archiveExtractionSymlink || (i < len(parts) && planned.kind != archiveExtractionDirectory) {
				return fmt.Errorf("symlink %q targets an unsafe planned path: %w", entry.relative, errArchiveExtractionConflict)
			}
		}
	}
	return nil
}

func authorizeArchiveExtractionPlan(user *users.User, destination authenticatedReadTarget, plan *archiveExtractionPlan) error {
	if user == nil || destination.Index == nil || destination.Info == nil || !destination.Info.IsDir() || store.Access == nil {
		return commonerrors.ErrAccessDenied
	}
	for _, entry := range plan.sortedEntries() {
		logicalPath := normalizePublicShareIndexPath(path.Join(destination.LogicalPath, entry.relative))
		canonicalPath := normalizePublicShareIndexPath(path.Join(destination.CanonicalPath, entry.relative))
		if !publicSharePathWithin(destination.UserScope, logicalPath) ||
			!publicSharePathWithin(destination.UserScope, canonicalPath) ||
			!store.Access.PermittedFresh(destination.Index.Path, logicalPath, user.Username) ||
			!store.Access.PermittedFresh(destination.Index.Path, canonicalPath, user.Username) {
			return fmt.Errorf("access denied to extraction path %q: %w", entry.relative, commonerrors.ErrAccessDenied)
		}

		realPath, err := safeExtractPath(destination.RealPath, entry.relative)
		if err != nil {
			return err
		}
		info, statErr := os.Lstat(realPath)
		if os.IsNotExist(statErr) {
			entry.existingInfo = nil
			if !user.Permissions.Create {
				return fmt.Errorf("user is not allowed to create extraction path %q: %w", entry.relative, commonerrors.ErrAccessDenied)
			}
			continue
		}
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.Mode().IsRegular() && !info.IsDir()) {
			return fmt.Errorf("existing extraction path %q has an unsafe type: %w", entry.relative, errArchiveExtractionConflict)
		}
		entry.existingInfo = info

		switch entry.kind {
		case archiveExtractionDirectory:
			if !info.IsDir() {
				return fmt.Errorf("existing extraction path %q is not a directory: %w", entry.relative, errArchiveExtractionConflict)
			}
			if entry.explicit && !user.Permissions.Modify {
				return fmt.Errorf("user is not allowed to modify extraction directory %q: %w", entry.relative, commonerrors.ErrAccessDenied)
			}
		case archiveExtractionRegularFile:
			if !info.Mode().IsRegular() {
				return fmt.Errorf("existing extraction path %q is not a regular file: %w", entry.relative, errArchiveExtractionConflict)
			}
			if !user.Permissions.Modify {
				return fmt.Errorf("user is not allowed to modify extraction file %q: %w", entry.relative, commonerrors.ErrAccessDenied)
			}
		case archiveExtractionSymlink:
			return fmt.Errorf("existing extraction path %q cannot be replaced by a symlink: %w", entry.relative, errArchiveExtractionConflict)
		}
	}
	return nil
}

// normalizeArchiveEntryName turns a raw zip/tar name into a safe relative path (slash-separated).
// Many Windows zips use backslashes; some start with a leading backslash, which would make
// filepath.Join drop destDir and write under the drive root. Backslashes are not path separators
// on Unix, so we always normalize '\' -> '/' and trim leading '/' before path.Clean.
func normalizeArchiveEntryName(name string) (string, error) {
	s := strings.TrimSpace(name)
	if s == "" {
		return "", errors.New("empty path")
	}
	s = strings.ReplaceAll(s, "\\", "/")
	if strings.HasPrefix(s, "//") {
		return "", errors.New("UNC or invalid path")
	}
	s = strings.TrimLeft(s, "/")
	// Reject e.g. "C:/path" in archive
	if len(s) >= 3 && s[1] == ':' && s[2] == '/' {
		if 'A' <= s[0] && s[0] <= 'Z' || 'a' <= s[0] && s[0] <= 'z' {
			return "", errors.New("absolute path in archive")
		}
	}
	if s == ".." {
		return "", errors.New("path traversal")
	}
	if strings.HasPrefix(s, "../") {
		return "", errors.New("path traversal")
	}
	cleaned := path.Clean(s)
	if cleaned == "" || cleaned == "." {
		return "", errors.New("empty path after clean")
	}
	if cleaned == ".." {
		return "", errors.New("path traversal after clean")
	}
	if strings.HasPrefix(cleaned, "../") {
		return "", errors.New("path traversal after clean")
	}
	return cleaned, nil
}

// safeExtractPath ensures name does not escape destDir (no ".." or drive-root / UNC tricks).
func safeExtractPath(destDir, name string) (string, error) {
	relSlash, err := normalizeArchiveEntryName(name)
	if err != nil {
		return "", fmt.Errorf("invalid entry path: %q: %w", name, err)
	}
	// Convert to platform separators so filepath.Join and os.Mkdir work correctly
	abs := filepath.Join(destDir, filepath.FromSlash(relSlash))
	destAbs, err := filepath.Abs(destDir)
	if err != nil {
		return "", err
	}
	entryAbs, err := filepath.Abs(abs)
	if err != nil {
		return "", err
	}
	// Case-sensitive/prefix issues on Windows: use Rel instead of HasPrefix on absolute paths
	rel, err := filepath.Rel(destAbs, entryAbs)
	if err != nil {
		return "", fmt.Errorf("invalid entry path: %q: %w", name, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid entry path: %q", name)
	}
	return abs, nil
}

// applyArchivedTimesAndPerm sets permission bits and modification time from an archive entry using
func applyArchivedTimesAndPerm(path string, mode fs.FileMode, modTime time.Time) error {
	switch {
	case mode.Type() == fs.ModeSymlink:
		if !modTime.IsZero() {
			_ = os.Chtimes(path, modTime, modTime)
		}
		return nil
	case mode.Type() == fs.ModeDir:
		if p := mode.Perm(); p != 0 {
			_ = os.Chmod(path, p)
		}
		if modTime.IsZero() {
			return nil
		}
		return os.Chtimes(path, modTime, modTime)
	case mode.IsRegular():
		if p := mode.Perm(); p != 0 {
			_ = os.Chmod(path, p)
		}
		if modTime.IsZero() {
			return nil
		}
		return os.Chtimes(path, modTime, modTime)
	default:
		if !modTime.IsZero() {
			_ = os.Chtimes(path, modTime, modTime)
		}
		return nil
	}
}

func archiveRelativePathUnderRoot(root, target string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(rootAbs, targetAbs)
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes extraction destination: %w", errArchiveExtractionConflict)
	}
	return relative, nil
}

func ensureArchivePathHasNoSymlink(root, target string, includeLeaf bool) error {
	relative, err := archiveRelativePathUnderRoot(root, target)
	if err != nil {
		return err
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	rootInfo, err := os.Lstat(rootAbs)
	if err != nil {
		return err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return fmt.Errorf("extraction destination root has an unsafe type: %w", errArchiveExtractionConflict)
	}
	if relative == "." {
		return nil
	}
	parts := strings.Split(filepath.Clean(relative), string(filepath.Separator))
	limit := len(parts)
	if !includeLeaf {
		limit--
	}
	current := rootAbs
	for i := 0; i < limit; i++ {
		current = filepath.Join(current, parts[i])
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) {
			return nil
		}
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path %q traverses a symlink: %w", current, errArchiveExtractionConflict)
		}
		if i < len(parts)-1 && !info.IsDir() {
			return fmt.Errorf("path ancestor %q is not a directory: %w", current, errArchiveExtractionConflict)
		}
	}
	return nil
}

func resolveArchiveSymlinkTargetRelative(destRoot, destPath, linkname string) (string, error) {
	linkname = strings.TrimSpace(linkname)
	if linkname == "" {
		return "", fmt.Errorf("empty symlink target: %w", errArchiveExtractionConflict)
	}
	if len(linkname) > maxArchiveSymlinkTargetBytes {
		return "", fmt.Errorf("symlink target is too large: %w", errArchiveExtractionConflict)
	}
	if strings.IndexByte(linkname, 0) >= 0 {
		return "", fmt.Errorf("symlink target contains a NUL byte: %w", errArchiveExtractionConflict)
	}
	portableTarget := strings.ReplaceAll(linkname, "\\", "/")
	if strings.HasPrefix(portableTarget, "/") ||
		(len(portableTarget) >= 2 && portableTarget[1] == ':' &&
			(('A' <= portableTarget[0] && portableTarget[0] <= 'Z') || ('a' <= portableTarget[0] && portableTarget[0] <= 'z'))) {
		return "", fmt.Errorf("symlink has an absolute target: %w", errArchiveExtractionConflict)
	}
	destRelative, err := archiveRelativePathUnderRoot(destRoot, destPath)
	if err != nil {
		return "", err
	}
	resolvedRelative := path.Clean(path.Join(path.Dir(filepath.ToSlash(destRelative)), portableTarget))
	if resolvedRelative == ".." || strings.HasPrefix(resolvedRelative, "../") {
		return "", fmt.Errorf("symlink target escapes destination directory: %w", errArchiveExtractionConflict)
	}
	return resolvedRelative, nil
}

// symlinkTargetStaysUnderDest rejects targets that escape lexically or through an existing symlink.
func symlinkTargetStaysUnderDest(destRoot, destPath, linkname string) error {
	resolvedRelative, err := resolveArchiveSymlinkTargetRelative(destRoot, destPath, linkname)
	if err != nil {
		return err
	}
	resolvedPath := filepath.Join(destRoot, filepath.FromSlash(resolvedRelative))
	return ensureArchivePathHasNoSymlink(destRoot, resolvedPath, true)
}

// extractArchivedDir creates a directory from an archive entry and reapplies mode and mtime.
func extractArchivedDir(destRoot, destPath string, mode fs.FileMode, modTime time.Time) error {
	if err := ensureArchivePathHasNoSymlink(destRoot, destPath, false); err != nil {
		return err
	}
	if info, err := os.Lstat(destPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("directory target %q changed type: %w", destPath, errArchiveExtractionConflict)
		}
		return applyArchivedTimesAndPerm(destPath, mode, modTime)
	} else if !os.IsNotExist(err) {
		return err
	}
	perm := mode.Perm()
	if perm == 0 {
		perm = fileutils.EffectiveDirPerm()
	}
	if err := os.MkdirAll(destPath, perm); err != nil {
		return fmt.Errorf("mkdir %q: %w", destPath, err)
	}
	if info, err := os.Lstat(destPath); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		if err != nil {
			return err
		}
		return fmt.Errorf("directory target %q changed type: %w", destPath, errArchiveExtractionConflict)
	}
	return applyArchivedTimesAndPerm(destPath, mode, modTime)
}

// extractArchivedRegularFile stages one regular file beside its target before replacing it.
func extractArchivedRegularFile(destRoot, destPath string, mode fs.FileMode, modTime time.Time, expectedInfo os.FileInfo, enforceExpected bool, src io.ReadCloser) (returnErr error) {
	defer func() { _ = src.Close() }()
	if err := ensureArchivePathHasNoSymlink(destRoot, destPath, false); err != nil {
		return err
	}
	parent := filepath.Dir(destPath)
	if err := os.MkdirAll(parent, fileutils.EffectiveDirPerm()); err != nil {
		return fmt.Errorf("mkdir %q: %w", parent, err)
	}
	if err := ensureArchivePathHasNoSymlink(destRoot, destPath, false); err != nil {
		return err
	}
	var originalInfo os.FileInfo
	if info, err := os.Lstat(destPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("file target %q changed type: %w", destPath, errArchiveExtractionConflict)
		}
		originalInfo = info
	} else if !os.IsNotExist(err) {
		return err
	}
	if enforceExpected {
		if expectedInfo == nil && originalInfo != nil {
			return fmt.Errorf("new file target %q appeared after authorization: %w", destPath, errArchiveExtractionConflict)
		}
		if expectedInfo != nil && (originalInfo == nil || !os.SameFile(expectedInfo, originalInfo) ||
			expectedInfo.Size() != originalInfo.Size() || expectedInfo.Mode() != originalInfo.Mode() ||
			!expectedInfo.ModTime().Equal(originalInfo.ModTime())) {
			return fmt.Errorf("existing file target %q changed after authorization: %w", destPath, errArchiveExtractionConflict)
		}
	}
	perm := mode.Perm()
	if perm == 0 {
		perm = fileutils.EffectiveFilePerm()
	}
	out, err := os.CreateTemp(parent, ".filebrowser-extract-*")
	if err != nil {
		return err
	}
	tempPath := out.Name()
	committed := false
	defer func() {
		if out != nil {
			if closeErr := out.Close(); closeErr != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("close extraction temporary file: %w", closeErr))
			}
		}
		if !committed {
			if removeErr := os.Remove(tempPath); removeErr != nil && !os.IsNotExist(removeErr) {
				returnErr = errors.Join(returnErr, fmt.Errorf("remove extraction temporary file: %w", removeErr))
			}
		}
	}()

	_, copyErr := io.Copy(out, src)
	if copyErr != nil {
		return copyErr
	}
	if err := applyArchivedTimesAndPerm(tempPath, perm, modTime); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	out = nil

	if err := ensureArchivePathHasNoSymlink(destRoot, destPath, false); err != nil {
		return err
	}
	currentInfo, statErr := os.Lstat(destPath)
	if originalInfo == nil {
		if statErr == nil {
			return fmt.Errorf("new file target %q appeared during extraction: %w", destPath, errArchiveExtractionConflict)
		}
		if !os.IsNotExist(statErr) {
			return statErr
		}
	} else {
		if statErr != nil {
			return fmt.Errorf("existing file target %q changed during extraction: %w", destPath, errArchiveExtractionConflict)
		}
		if currentInfo.Mode()&os.ModeSymlink != 0 || !currentInfo.Mode().IsRegular() ||
			!os.SameFile(originalInfo, currentInfo) || originalInfo.Size() != currentInfo.Size() ||
			!originalInfo.ModTime().Equal(currentInfo.ModTime()) {
			return fmt.Errorf("existing file target %q changed during extraction: %w", destPath, errArchiveExtractionConflict)
		}
	}
	if err := os.Rename(tempPath, destPath); err != nil {
		return fmt.Errorf("replace extracted file %q: %w", destPath, err)
	}
	committed = true
	return nil
}

// extractArchivedSymlink creates a symlink after validating the target stays under destRoot.
func extractArchivedSymlink(destRoot, destPath, target string, modTime time.Time) error {
	target = strings.TrimSpace(target)
	if err := ensureArchivePathHasNoSymlink(destRoot, destPath, false); err != nil {
		return err
	}
	symParent := filepath.Dir(destPath)
	if err := os.MkdirAll(symParent, fileutils.EffectiveDirPerm()); err != nil {
		return fmt.Errorf("mkdir %q: %w", symParent, err)
	}
	if err := symlinkTargetStaysUnderDest(destRoot, destPath, target); err != nil {
		return err
	}
	if err := ensureArchivePathHasNoSymlink(destRoot, destPath, false); err != nil {
		return err
	}
	if _, err := os.Lstat(destPath); err == nil {
		return fmt.Errorf("symlink target %q already exists: %w", destPath, errArchiveExtractionConflict)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Symlink(target, destPath); err != nil {
		return err
	}
	return applyArchivedTimesAndPerm(destPath, fs.ModeSymlink, modTime)
}

func requireArchiveExtractionPlanEntry(plan *archiveExtractionPlan, relative string, kind archiveExtractionEntryKind) (*archiveExtractionPlanEntry, error) {
	if plan == nil {
		return nil, nil
	}
	entry, ok := plan.entries[archiveExtractionPlanKey(relative)]
	if !ok || entry.relative != relative || entry.kind != kind {
		return nil, fmt.Errorf("archive entry %q changed after preflight: %w", relative, errArchiveExtractionConflict)
	}
	return entry, nil
}

func extractZip(archivePath, destDir string) error {
	return extractZipWithPlan(archivePath, destDir, nil)
}

func extractZipWithPlan(archivePath, destDir string, plan *archiveExtractionPlan) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer r.Close()

	// Central directory order is arbitrary. Some zips (e.g. Windows driver packs) use names that
	// are similar length at different tree depths, so byte length is a poor order key. Use the
	// number of path segments in the *normalized* entry name: deeper trees first, then
	// lexicographic, so parent dirs exist before shorter entries that might be mis-tagged.
	type orderedName struct {
		f     *zip.File
		rel   string
		depth int
	}
	ordered := make([]orderedName, 0, len(r.File))
	for _, f := range r.File {
		rel, nerr := normalizeArchiveEntryName(f.Name)
		if nerr != nil {
			rel = strings.TrimLeft(strings.ReplaceAll(strings.TrimSpace(f.Name), "\\", "/"), "/")
		}
		depth := 0
		if rel != "" {
			depth = strings.Count(rel, "/") + 1
		}
		ordered = append(ordered, orderedName{f: f, rel: rel, depth: depth})
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].depth != ordered[j].depth {
			return ordered[i].depth > ordered[j].depth
		}
		if ordered[i].rel != ordered[j].rel {
			return ordered[i].rel < ordered[j].rel
		}
		return ordered[i].f.Name < ordered[j].f.Name
	})

	for _, o := range ordered {
		f := o.f
		var destPath string
		destPath, err = safeExtractPath(destDir, f.Name)
		if err != nil {
			return err
		}

		fi := f.FileInfo()
		mode := fi.Mode()
		trailingSeparator := strings.HasSuffix(f.Name, "/") || strings.HasSuffix(f.Name, "\\")
		if mode.Type() == fs.ModeSymlink {
			if _, err = requireArchiveExtractionPlanEntry(plan, o.rel, archiveExtractionSymlink); err != nil {
				return err
			}
			target, targetErr := readZipArchiveSymlinkTarget(f)
			if targetErr != nil {
				return targetErr
			}
			if err = extractArchivedSymlink(destDir, destPath, target, f.Modified); err != nil {
				return err
			}
			continue
		}
		if mode.Type() == fs.ModeDir || (mode.IsRegular() && trailingSeparator) {
			if _, err = requireArchiveExtractionPlanEntry(plan, o.rel, archiveExtractionDirectory); err != nil {
				return err
			}
			if err = extractArchivedDir(destDir, destPath, mode, f.Modified); err != nil {
				return err
			}
			continue
		}
		if !mode.IsRegular() {
			return fmt.Errorf("unsupported ZIP entry type for %q (%s): %w", f.Name, mode.Type(), errArchiveExtractionConflict)
		}
		plannedEntry, planErr := requireArchiveExtractionPlanEntry(plan, o.rel, archiveExtractionRegularFile)
		if planErr != nil {
			return planErr
		}

		var rc io.ReadCloser
		rc, err = f.Open()
		if err != nil {
			return err
		}
		var expectedInfo os.FileInfo
		if plannedEntry != nil {
			expectedInfo = plannedEntry.existingInfo
		}
		if err = extractArchivedRegularFile(destDir, destPath, mode, f.Modified, expectedInfo, plannedEntry != nil, rc); err != nil {
			return err
		}
	}
	return nil
}

func extractTarGz(archivePath, destDir string) error {
	return extractTarGzWithPlan(archivePath, destDir, nil)
}

func extractTarGzWithPlan(archivePath, destDir string, plan *archiveExtractionPlan) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		relative, normalizeErr := normalizeArchiveEntryName(h.Name)
		if normalizeErr != nil {
			return normalizeErr
		}
		var destPath string
		destPath, err = safeExtractPath(destDir, h.Name)
		if err != nil {
			return err
		}

		switch h.Typeflag {
		case tar.TypeDir:
			if _, err = requireArchiveExtractionPlanEntry(plan, relative, archiveExtractionDirectory); err != nil {
				return err
			}
			mode := h.FileInfo().Mode()
			if err = extractArchivedDir(destDir, destPath, mode, h.ModTime); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			plannedEntry, planErr := requireArchiveExtractionPlanEntry(plan, relative, archiveExtractionRegularFile)
			if planErr != nil {
				return planErr
			}
			mode := h.FileInfo().Mode()
			var expectedInfo os.FileInfo
			if plannedEntry != nil {
				expectedInfo = plannedEntry.existingInfo
			}
			if err = extractArchivedRegularFile(destDir, destPath, mode, h.ModTime, expectedInfo, plannedEntry != nil, io.NopCloser(tr)); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if _, err = requireArchiveExtractionPlanEntry(plan, relative, archiveExtractionSymlink); err != nil {
				return err
			}
			if err = extractArchivedSymlink(destDir, destPath, h.Linkname, h.ModTime); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported TAR entry type for %q (%#x): %w", h.Name, h.Typeflag, errArchiveExtractionConflict)
		}
	}
	return nil
}

// computeArchiveSize returns the combined size of the given paths, respecting access rules.
// Paths denied by access are skipped (not counted).
func computeArchiveSize(source string, fileList []string, d *requestContext) (int64, error) {
	var estimatedSize int64
	if _, err := currentAuthenticatedArchiveUser(d); err != nil {
		return 0, err
	}
	for _, indexPath := range fileList {
		err := walkAuthenticatedArchiveMembers(d, source, indexPath, false, func(member authenticatedArchiveMember) error {
			if !member.root && member.target.Info != nil && !member.target.Info.IsDir() {
				estimatedSize += member.target.Info.Size()
			}
			return nil
		})
		if err == nil {
			continue
		}
		if errors.Is(err, errAuthenticatedArchiveReadPermissions) {
			return 0, err
		}
		if errors.Is(err, commonerrors.ErrAccessDenied) {
			continue
		}
		return 0, err
	}
	return estimatedSize, nil
}
