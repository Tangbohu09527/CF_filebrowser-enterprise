package http

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	commonerrors "github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
	"github.com/gtsteffaniak/filebrowser/backend/preview"
	"github.com/gtsteffaniak/go-logger/logger"
)

type FileCache interface {
	Store(ctx context.Context, key string, value []byte) error
	Load(ctx context.Context, key string) ([]byte, bool, error)
	Delete(ctx context.Context, key string) error
}

// authenticatedPreviewGenerationHook lets security tests bracket downstream reads.
var authenticatedPreviewGenerationHook func(before bool)

var authenticatedPreviewFileGenerator = preview.GetSafePreviewForFile

type authenticatedPreviewSnapshotTicket struct {
	path      string
	name      string
	info      os.FileInfo
	expiresAt time.Time
	validate  func() error
}

var authenticatedPreviewSnapshots = struct {
	sync.Mutex
	tickets map[string]authenticatedPreviewSnapshotTicket
}{tickets: make(map[string]authenticatedPreviewSnapshotTicket)}

func registerAuthenticatedPreviewSnapshot(path, name string, validate func() error) (string, func(), error) {
	file, err := os.Open(path)
	if err != nil {
		return "", nil, normalizeAuthenticatedReadError(err)
	}
	info, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil || closeErr != nil || !info.Mode().IsRegular() || validate == nil {
		return "", nil, commonerrors.ErrAccessDenied
	}

	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", nil, fmt.Errorf("authenticated preview snapshot ticket is unavailable")
	}
	token := base64.RawURLEncoding.EncodeToString(random[:])
	ticket := authenticatedPreviewSnapshotTicket{
		path:      path,
		name:      name,
		info:      info,
		expiresAt: time.Now().Add(time.Minute),
		validate:  validate,
	}
	authenticatedPreviewSnapshots.Lock()
	authenticatedPreviewSnapshots.tickets[token] = ticket
	authenticatedPreviewSnapshots.Unlock()

	revoke := func() {
		authenticatedPreviewSnapshots.Lock()
		delete(authenticatedPreviewSnapshots.tickets, token)
		authenticatedPreviewSnapshots.Unlock()
	}
	return token, revoke, nil
}

func consumeAuthenticatedPreviewSnapshot(token string) (authenticatedPreviewSnapshotTicket, bool) {
	authenticatedPreviewSnapshots.Lock()
	defer authenticatedPreviewSnapshots.Unlock()
	ticket, found := authenticatedPreviewSnapshots.tickets[token]
	if found {
		delete(authenticatedPreviewSnapshots.tickets, token)
	}
	if !found || time.Now().After(ticket.expiresAt) {
		return authenticatedPreviewSnapshotTicket{}, false
	}
	return ticket, true
}

func authenticatedPreviewSnapshotHandler(w http.ResponseWriter, r *http.Request) {
	ticket, found := consumeAuthenticatedPreviewSnapshot(r.PathValue("ticket"))
	if !found || ticket.validate() != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	file, err := os.Open(ticket.path)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(ticket.info, info) || info.Size() != ticket.info.Size() {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, ticket.name, ticket.info.ModTime(), file)
}

func authenticatedPreviewSnapshotURL(r *http.Request, token string) string {
	pathURL := strings.TrimSuffix(config.Server.BaseURL, "/") + "/api/resources/preview-source/" + token
	if config.Server.InternalUrl != "" {
		return strings.TrimSuffix(config.Server.InternalUrl, "/") + pathURL
	}
	if config.Server.ExternalUrl != "" {
		return strings.TrimSuffix(config.Server.ExternalUrl, "/") + pathURL
	}
	localAddress, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	if !ok || localAddress.IP == nil || localAddress.IP.IsUnspecified() || localAddress.Port <= 0 {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(localAddress.IP.String(), strconv.Itoa(localAddress.Port)) + pathURL
}

// isClientCancellation checks if an error is due to client cancellation (navigation away)
func isClientCancellation(ctx context.Context, err error) bool {
	// Check context state first
	if ctx.Err() == context.Canceled {
		return true
	}

	// Check if the error chain contains context cancellation
	return errors.Is(err, context.Canceled)
}

// previewHandler handles the preview request for images.
// @Summary Get image preview
// @Description Returns a preview image based on the requested path and size.
// @Tags Resources
// @Accept json
// @Produce json
// @Param path query string true "File path of the image to preview"
// @Param size query string false "Preview size ('small' or 'large'). Default is based on server config."
// @Success 200 {file} file "Preview image content"
// @Failure 202 {object} map[string]string "Download permissions required"
// @Failure 400 {object} map[string]string "Invalid request path"
// @Failure 403 {object} map[string]string "Browse, preview, or download permission required"
// @Failure 404 {object} map[string]string "File not found"
// @Failure 415 {object} map[string]string "Unsupported file type for preview"
// @Failure 500 {object} map[string]string "Internal server error"
// @Failure 501 {object} map[string]string "Preview generation not implemented"
// @Router /api/resources/preview [get]
func previewHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	original := r.URL.Query().Get("size") == "original"
	currentUser, err := currentAuthenticatedReadUser(d.user, d.token)
	if err != nil || !currentUser.Permissions.Browse || original && !currentUser.Permissions.Download || !original && !currentUser.Permissions.Preview {
		return http.StatusForbidden, commonerrors.ErrAccessDenied
	}
	if config.Server.DisablePreviews {
		return http.StatusNotImplemented, fmt.Errorf("preview is disabled")
	}
	path, err := sanitizeAuthenticatedReadPath(r.URL.Query().Get("path"))
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("invalid preview path: %v", err)
	}
	source := r.URL.Query().Get("source")
	if source == "" {
		return http.StatusBadRequest, fmt.Errorf("source is required")
	}
	target, err := resolveAuthenticatedBrowseTarget(currentUser, source, path)
	if err != nil {
		return errToStatus(err), err
	}
	if err = setCoreFileAuditReadTarget(r, target, nil); err != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
	}
	fileInfo, err := files.FileInfoFaster(utils.FileOptions{
		Path:           target.ScopedPath,
		Source:         source,
		Expand:         true,
		FollowSymlinks: false,
	}, store.Access, currentUser, store.Share)
	if err != nil {
		logger.Errorf("error getting file info: %v", err)
		err = normalizeAuthenticatedReadError(err)
		return errToStatus(err), err
	}
	applyAuthenticatedFileInfoIdentity(fileInfo, target)
	if err = filterAuthenticatedDirectoryFileInfo(currentUser, source, target, fileInfo); err != nil {
		return http.StatusForbidden, commonerrors.ErrAccessDenied
	}
	d.fileInfo = *fileInfo
	status, err := previewHelperFunc(w, r, d)
	if err != nil {
		// Error already logged in previewHelperFunc or its callees
		return errToStatus(err), err
	}
	return status, nil
}

func shouldServeOriginalPreview(ext string, resizable bool, realPath, previewSize string, fileSize int64) bool {
	if !resizable {
		return false
	}
	// HEIC/TIFF still need conversion for reliable web display.
	switch ext {
	case ".heic", ".heif", ".tiff", ".tif":
		return false
	}
	const maxSizeForOriginal = 256 * 1024 // 256KB
	if config.Server.DisableResize || fileSize < maxSizeForOriginal {
		return true
	}
	return preview.ShouldServeOriginalImage(realPath, previewSize)
}

func shouldServeOriginalPreviewReader(ext string, resizable bool, reader io.ReadSeeker, previewSize string, fileSize int64) bool {
	if !resizable {
		return false
	}
	switch ext {
	case ".heic", ".heif", ".tiff", ".tif":
		return false
	}
	const maxSizeForOriginal = 256 * 1024
	if config.Server.DisableResize || fileSize < maxSizeForOriginal {
		return true
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return false
	}
	imageConfig, _, err := image.DecodeConfig(reader)
	_, seekErr := reader.Seek(0, io.SeekStart)
	return err == nil && seekErr == nil && preview.ImageFitsPreviewSize(imageConfig.Width, imageConfig.Height, previewSize)
}

func serveRawFile(w http.ResponseWriter, r *http.Request, file iteminfo.ExtendedFileInfo, reader io.ReadSeeker) (int, error) {
	setContentDisposition(w, r, file.Name)
	w.Header().Set("Cache-Control", "private")
	http.ServeContent(w, r, file.Name, file.ModTime, reader)
	return 0, nil
}

func rawFileHandler(w http.ResponseWriter, r *http.Request, file iteminfo.ExtendedFileInfo, allowOriginal bool, snapshotPath string) (int, error) {
	if !allowOriginal {
		return http.StatusForbidden, fmt.Errorf("download permission is required for original previews")
	}
	readPath := file.RealPath
	if snapshotPath != "" {
		readPath = snapshotPath
	}
	fd, err := os.Open(readPath)
	if err != nil {
		if snapshotPath != "" {
			err = normalizeAuthenticatedReadError(err)
		}
		return http.StatusInternalServerError, err
	}
	defer fd.Close()
	return serveRawFile(w, r, file, fd)
}

func snapshotAuthenticatedPreviewFile(user *users.User, target authenticatedReadTarget, file iteminfo.ExtendedFileInfo, includeAlbumArt bool, revalidate func() error) (iteminfo.ExtendedFileInfo, func(), error) {
	snapshotPath, opened, cleanup, err := snapshotAuthenticatedReadTarget(target)
	if err != nil {
		return iteminfo.ExtendedFileInfo{}, nil, err
	}
	file.RealPath = target.RealPath
	file.Size = opened.Size()
	file.ModTime = opened.ModTime()
	file.PreviewSourcePath = snapshotPath
	if revalidate != nil {
		if revalidateErr := revalidate(); revalidateErr != nil {
			cleanup()
			return iteminfo.ExtendedFileInfo{}, nil, revalidateErr
		}
	}

	if !includeAlbumArt || !strings.HasPrefix(file.Type, "audio") {
		return file, cleanup, nil
	}
	audioInfo, err := files.FileInfoFaster(utils.FileOptions{
		Path:           target.ScopedPath,
		Source:         file.Source,
		AlbumArt:       true,
		Expand:         true,
		FollowSymlinks: false,
		ReadPath:       snapshotPath,
	}, store.Access, user, store.Share)
	if err != nil {
		cleanup()
		return iteminfo.ExtendedFileInfo{}, nil, normalizeAuthenticatedReadError(err)
	}
	applyAuthenticatedFileInfoIdentity(audioInfo, target)
	audioInfo.Size = opened.Size()
	audioInfo.ModTime = opened.ModTime()
	audioInfo.PreviewSourcePath = snapshotPath
	return *audioInfo, cleanup, nil
}

func revalidateAuthenticatedPreviewTarget(d *requestContext, expected authenticatedReadTarget, source, requestedPath, previewSize string, requireDownload bool) error {
	currentUser, err := currentAuthenticatedReadUser(d.user, d.token)
	if err != nil || !currentUser.Permissions.Browse || previewSize == "original" && !currentUser.Permissions.Download || previewSize != "original" && !currentUser.Permissions.Preview || requireDownload && !currentUser.Permissions.Download {
		return commonerrors.ErrAccessDenied
	}
	current, err := resolveAuthenticatedReadTarget(currentUser, source, requestedPath)
	if err != nil || !sameAuthenticatedReadTarget(expected, current) {
		return commonerrors.ErrAccessDenied
	}
	return nil
}

func revalidateAuthenticatedPreviewAccess(d *requestContext, expected authenticatedReadTarget, source, previewSize string, requireDownload bool) error {
	currentUser, err := currentAuthenticatedReadUser(d.user, d.token)
	if err != nil || !currentUser.Permissions.Browse || previewSize == "original" && !currentUser.Permissions.Download || previewSize != "original" && !currentUser.Permissions.Preview || requireDownload && !currentUser.Permissions.Download {
		return commonerrors.ErrAccessDenied
	}
	idx, userScope, err := authenticatedReadScope(currentUser, source)
	if err != nil || userScope != expected.UserScope || !publicSharePathWithin(userScope, expected.LogicalPath) || !publicSharePathWithin(userScope, expected.CanonicalPath) {
		return commonerrors.ErrAccessDenied
	}
	sourceReal, scopeReal, err := authenticatedReadRoots(idx, userScope)
	if err != nil || !publicShareRealPathWithin(expected.SourceReal, sourceReal) || !publicShareRealPathWithin(sourceReal, expected.SourceReal) || !publicShareRealPathWithin(expected.ScopeReal, scopeReal) || !publicShareRealPathWithin(scopeReal, expected.ScopeReal) {
		return commonerrors.ErrAccessDenied
	}
	scopeInfo, err := stableAuthenticatedReadInfo(scopeReal)
	if err != nil || expected.ScopeInfo == nil || !os.SameFile(expected.ScopeInfo, scopeInfo) {
		return commonerrors.ErrAccessDenied
	}
	if !store.Access.PermittedFresh(idx.Path, expected.LogicalPath, currentUser.Username) || !store.Access.PermittedFresh(idx.Path, expected.CanonicalPath, currentUser.Username) {
		return commonerrors.ErrAccessDenied
	}
	return nil
}

// getDirectoryPreview returns the previewable file at the given frame index (0–3) for motion preview.
// atPercentage maps to frame: 0→0, 1–25→1, 26–50→2, 51–100→3. The returned file is frameIndex % n where n is the number of previewable items.
func getDirectoryPreview(r *http.Request, d *requestContext, frameIndex int) (*iteminfo.ExtendedFileInfo, error) {
	// Build list of previewable item names in stable order (same as d.fileInfo.Files)
	var previewableNames []string
	for _, item := range d.fileInfo.Files {
		if !iteminfo.ShouldBubbleUpToFolderPreview(item.ItemInfo) {
			continue
		}
		previewableNames = append(previewableNames, item.Name)
	}
	if len(previewableNames) == 0 {
		return nil, fmt.Errorf("no previewable files found in directory")
	}
	// Cycle: 1 image → always 0; 2 images → 0,1,0,1; 3 → 0,1,2,0; 4 → 0,1,2,3
	index := frameIndex % len(previewableNames)
	name := previewableNames[index]

	source := d.fileInfo.Source
	path := utils.JoinPathAsUnix(d.fileInfo.Path, name)
	requestedPath := path
	var user *users.User
	var authenticatedTarget *authenticatedReadTarget
	if d.share != nil {
		sourceInfo, ok := config.Server.SourceMap[d.share.Source]
		if !ok {
			return nil, fmt.Errorf("source not found for share")
		}
		source = sourceInfo.Name
		path = d.IndexPath + name
		user = d.shareUser
	} else {
		currentUser, err := currentAuthenticatedReadUser(d.user, d.token)
		if err != nil || !currentUser.Permissions.Browse || !currentUser.Permissions.Preview {
			return nil, commonerrors.ErrAccessDenied
		}
		user = currentUser
		target, err := resolveAuthenticatedReadTarget(user, source, path)
		if err != nil {
			return nil, err
		}
		authenticatedTarget = &target
		path = target.ScopedPath
	}
	options := utils.FileOptions{
		Path:           path,
		Source:         source,
		FollowSymlinks: false,
	}
	if authenticatedTarget == nil {
		options.AlbumArt = true
		options.Metadata = true
	}
	fileInfo, err := files.FileInfoFaster(options, store.Access, user, store.Share)
	if err != nil {
		if authenticatedTarget != nil {
			err = normalizeAuthenticatedReadError(err)
		}
		return nil, err
	}
	if authenticatedTarget != nil {
		applyAuthenticatedFileInfoIdentity(fileInfo, *authenticatedTarget)
		fileInfo.Path = requestedPath
	}
	previewFile := *fileInfo
	cleanup := func() {}
	if authenticatedTarget != nil {
		previewFile, cleanup, err = snapshotAuthenticatedPreviewFile(user, *authenticatedTarget, previewFile, true, func() error {
			return revalidateAuthenticatedPreviewTarget(d, *authenticatedTarget, source, requestedPath, "small", false)
		})
		if err != nil {
			return nil, err
		}
	}
	defer cleanup()
	tempCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	getPreview := preview.GetPreviewForFile
	if d.share == nil && d.user != nil {
		getPreview = authenticatedPreviewFileGenerator
	}
	_, previewErr := getPreview(tempCtx, previewFile, "small", "", 0)
	cancel()
	if previewErr != nil {
		if !errors.Is(previewErr, context.Canceled) && !errors.Is(previewErr, context.DeadlineExceeded) {
			logger.Debugf("Skipping preview file in directory '%s': %s (error: %v)", d.fileInfo.Name, name, previewErr)
			// Fallback: try first item (frame 0) once so atPercentage=0 still works when another frame fails
			if index != 0 {
				return getDirectoryPreview(r, d, 0)
			}
		}
		if authenticatedTarget != nil {
			previewErr = normalizeAuthenticatedReadError(previewErr)
		}
		return nil, previewErr
	}
	return fileInfo, nil
}

func previewHelperFunc(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	ctx := r.Context()
	if d.ctx != nil {
		ctx = d.ctx
	}

	previewSize := r.URL.Query().Get("size")
	if !(previewSize == "large" || previewSize == "original" || previewSize == "xlarge") {
		previewSize = "small"
	}
	if d.share != nil && !d.fileInfo.HasPreview {
		return http.StatusBadRequest, fmt.Errorf("this item does not have a preview")
	}

	seekPercentage := 0
	percentage := r.URL.Query().Get("atPercentage")
	if percentage != "" {
		var err error
		seekPercentage, err = strconv.Atoi(percentage)
		if err != nil {
			seekPercentage = 0
		}
		if seekPercentage < 0 || seekPercentage > 100 {
			seekPercentage = 0
		}
	}

	// For directories: map atPercentage to frame index 0–3 for motion preview (cycle over previewable items)
	var dirFrameIndex int
	if d.fileInfo.Type == "directory" {
		switch {
		case seekPercentage <= 0:
			dirFrameIndex = 0
		case seekPercentage <= 25:
			dirFrameIndex = 1
		case seekPercentage <= 50:
			dirFrameIndex = 2
		default:
			dirFrameIndex = 3
		}
		fileInfo, err := getDirectoryPreview(r, d, dirFrameIndex)
		if err != nil {
			if isClientCancellation(ctx, err) {
				return http.StatusOK, nil
			}
			if ctx.Err() == context.DeadlineExceeded || errors.Is(err, context.DeadlineExceeded) {
				return http.StatusRequestTimeout, fmt.Errorf("preview generation timed out")
			}
			logger.Errorf("error getting directory preview: %v", err)
			return http.StatusInternalServerError, err
		}
		d.fileInfo = *fileInfo
		seekPercentage = 0
	}

	allowOriginal := d.share != nil
	var authenticatedTarget *authenticatedReadTarget
	snapshotPath := ""
	if d.share == nil {
		currentUser, err := currentAuthenticatedReadUser(d.user, d.token)
		if err != nil || !currentUser.Permissions.Browse || previewSize == "original" && !currentUser.Permissions.Download || previewSize != "original" && !currentUser.Permissions.Preview {
			return http.StatusForbidden, commonerrors.ErrAccessDenied
		}
		if !d.fileInfo.HasPreview && !strings.HasPrefix(d.fileInfo.Type, "audio") {
			return http.StatusBadRequest, fmt.Errorf("this item does not have a preview: %w", commonerrors.ErrInvalidRequestParams)
		}
		currentTarget, err := resolveAuthenticatedReadTarget(currentUser, d.fileInfo.Source, d.fileInfo.Path)
		if err != nil {
			return errToStatus(err), err
		}
		allowOriginal = currentUser.Permissions.Download
		isImage := strings.HasPrefix(d.fileInfo.Type, "image")
		ext := strings.ToLower(filepath.Ext(d.fileInfo.Name))
		resizable := iteminfo.ResizableImageTypes[ext]
		if previewSize == "original" {
			file, opened, openErr := openAuthenticatedReadTarget(currentTarget)
			if openErr != nil {
				return errToStatus(openErr), openErr
			}
			defer file.Close()
			d.fileInfo.Size = opened.Size()
			d.fileInfo.ModTime = opened.ModTime()
			if revalidateErr := revalidateAuthenticatedPreviewTarget(d, currentTarget, d.fileInfo.Source, d.fileInfo.Path, previewSize, true); revalidateErr != nil {
				return http.StatusForbidden, revalidateErr
			}
			return serveRawFile(w, r, d.fileInfo, file)
		}
		if allowOriginal && isImage {
			file, opened, openErr := openAuthenticatedReadTarget(currentTarget)
			if openErr != nil {
				return errToStatus(openErr), openErr
			}
			d.fileInfo.Size = opened.Size()
			d.fileInfo.ModTime = opened.ModTime()
			serveOriginal := shouldServeOriginalPreviewReader(ext, resizable, file, previewSize, opened.Size())
			if serveOriginal {
				defer file.Close()
				if revalidateErr := revalidateAuthenticatedPreviewTarget(d, currentTarget, d.fileInfo.Source, d.fileInfo.Path, previewSize, true); revalidateErr != nil {
					return http.StatusForbidden, revalidateErr
				}
				return serveRawFile(w, r, d.fileInfo, file)
			}
			_ = file.Close()
		}
		if isImage && currentTarget.Info.Size() > iteminfo.LargeFileSizeThreshold {
			return http.StatusInternalServerError, fmt.Errorf("image file is too large for preview")
		}
		prepared, cleanup, err := snapshotAuthenticatedPreviewFile(currentUser, currentTarget, d.fileInfo, previewSize != "original", func() error {
			return revalidateAuthenticatedPreviewTarget(d, currentTarget, d.fileInfo.Source, d.fileInfo.Path, previewSize, false)
		})
		if err != nil {
			return errToStatus(err), err
		}
		defer cleanup()
		d.fileInfo = prepared
		if !d.fileInfo.HasPreview {
			return http.StatusBadRequest, fmt.Errorf("this item does not have a preview: %w", commonerrors.ErrInvalidRequestParams)
		}
		authenticatedTarget = &currentTarget
		snapshotPath = d.fileInfo.PreviewSourcePath
	}
	isImage := strings.HasPrefix(d.fileInfo.Type, "image")
	ext := strings.ToLower(filepath.Ext(d.fileInfo.Name))
	resizable := iteminfo.ResizableImageTypes[ext]
	readPath := d.fileInfo.RealPath
	if snapshotPath != "" {
		readPath = snapshotPath
	}

	// Public shares retain their existing original-serving behavior. Authenticated
	// original responses have already returned through a stable open handle above.
	if authenticatedTarget == nil && allowOriginal && isImage && shouldServeOriginalPreview(ext, resizable, readPath, previewSize, d.fileInfo.Size) {
		return rawFileHandler(w, r, d.fileInfo, allowOriginal, snapshotPath)
	}

	authenticatedOnlyOffice := authenticatedTarget != nil && preview.UsesOnlyOfficePreview(d.fileInfo)
	officeUrl := ""
	if authenticatedOnlyOffice {
		ticket, revoke, err := registerAuthenticatedPreviewSnapshot(snapshotPath, d.fileInfo.Name, func() error {
			return revalidateAuthenticatedPreviewAccess(d, *authenticatedTarget, d.fileInfo.Source, previewSize, false)
		})
		if err != nil {
			return errToStatus(err), err
		}
		defer revoke()
		officeUrl = authenticatedPreviewSnapshotURL(r, ticket)
		if officeUrl == "" {
			return http.StatusInternalServerError, fmt.Errorf("authenticated preview callback URL is unavailable")
		}
	} else if d.fileInfo.OnlyOfficeId != "" {
		pathURL := fmt.Sprintf("/api/resources/download?file=%s&source=%s&auth=%s", url.QueryEscape(d.fileInfo.Path), url.QueryEscape(d.fileInfo.Source), url.QueryEscape(d.token))
		if config.Server.InternalUrl != "" {
			officeUrl = strings.TrimSuffix(config.Server.InternalUrl, "/") + pathURL
		} else {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			officeUrl = scheme + "://" + r.Host + pathURL
		}
	}
	getPreview := preview.GetPreviewForFile
	if d.share == nil && d.user != nil {
		getPreview = authenticatedPreviewFileGenerator
	}
	var previewImg []byte
	var err error
	generatePreview := func() {
		if authenticatedTarget != nil {
			if accessErr := revalidateAuthenticatedPreviewAccess(d, *authenticatedTarget, d.fileInfo.Source, previewSize, false); accessErr != nil {
				err = accessErr
				return
			}
		}
		previewImg, err = getPreview(ctx, d.fileInfo, previewSize, officeUrl, seekPercentage)
	}
	if authenticatedTarget != nil && authenticatedPreviewGenerationHook != nil {
		func() {
			authenticatedPreviewGenerationHook(true)
			defer authenticatedPreviewGenerationHook(false)
			generatePreview()
		}()
	} else {
		generatePreview()
	}
	if err != nil {
		if errors.Is(err, commonerrors.ErrAccessDenied) {
			return http.StatusForbidden, err
		}
		// Check if it was a context cancellation (client navigated away)
		if isClientCancellation(ctx, err) {
			// Return 200 to avoid error logging - client cancellation is normal
			return http.StatusOK, nil
		}

		// Check if it was a context timeout (server-side timeout)
		if ctx.Err() == context.DeadlineExceeded || errors.Is(err, context.DeadlineExceeded) {
			logger.Errorf("Preview timeout for file '%s' after 15 seconds", d.fileInfo.Name)
			return http.StatusRequestTimeout, fmt.Errorf("preview generation timed out after 15 seconds")
		}

		// Log detailed error information for actual server errors
		logger.Errorf("Preview generation failed for file '%s' (type: %s, size: %s, seek: %d%%): %v",
			d.fileInfo.Name, d.fileInfo.Type, previewSize, seekPercentage, err)

		if authenticatedTarget != nil {
			err = normalizeAuthenticatedReadError(err)
		}
		return http.StatusInternalServerError, err
	}
	if authenticatedTarget != nil {
		if err := revalidateAuthenticatedPreviewTarget(d, *authenticatedTarget, d.fileInfo.Source, d.fileInfo.Path, previewSize, false); err != nil {
			return http.StatusForbidden, err
		}
	}
	setContentDisposition(w, r, d.fileInfo.Name)
	w.Header().Set("Cache-Control", "private")
	w.Header().Set("Content-Type", "image/jpeg")
	http.ServeContent(w, r, d.fileInfo.Name+"-preview.jpg", d.fileInfo.ModTime, bytes.NewReader(previewImg))
	return 0, nil
}
