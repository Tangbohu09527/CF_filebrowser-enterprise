package http

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	"github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
	"github.com/gtsteffaniak/filebrowser/backend/preview"
	"github.com/gtsteffaniak/go-logger/logger"
	"golang.org/x/time/rate"

	_ "github.com/gtsteffaniak/filebrowser/backend/swagger/docs"
)

// publicDownloadHandler serves the raw content of a file, multiple files, or directory via a public share.
// @Summary Download files from a public share
// @Description Downloads raw content from a public share. Supports single files, multiple files, or directories as archives. Enforces download limits (global or per-user) and blocks anonymous users when per-user limits are enabled.
// @Description
// @Description **Multiple Files:**
// @Description - Use repeated query parameters: `?file=file1.txt&file=file2.txt&file=file3.txt`
// @Description - This supports filenames containing commas and special characters
// @Tags Shares
// @Accept json
// @Produce octet-stream
// @Param hash query string true "Share hash for authentication"
// @Param file query []string true "File path (can be repeated for multiple files)"
// @Param inline query bool false "If true, sets 'Content-Disposition' to 'inline'. Otherwise, defaults to 'attachment'."
// @Param algo query string false "Compression algorithm for archiving multiple files or directories. Options: 'zip' and 'tar.gz'. Default is 'zip'."
// @Success 200 {file} file "Raw file or directory content, or archive for multiple files"
// @Failure 400 {object} map[string]string "Invalid request path or encoding"
// @Failure 403 {object} map[string]string "Download limit reached, anonymous access blocked, or share unavailable"
// @Failure 404 {object} map[string]string "Share not found or file not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Failure 501 {object} map[string]string "Downloads disabled for upload shares"
// @Router /public/api/resources/download [get]
func publicDownloadHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if d.share.ShareType == "upload" {
		return http.StatusNotImplemented, fmt.Errorf("downloads are disabled for upload shares")
	}

	// Check DisableDownload permission for normal shares
	if d.share.DisableDownload {
		return http.StatusForbidden, fmt.Errorf("downloads are not allowed for this share")
	}
	if len(d.shareTargets) == 0 {
		return http.StatusForbidden, fmt.Errorf("public share access denied")
	}

	sourceInfo, ok := config.Server.SourceMap[d.share.Source]
	if !ok {
		return http.StatusInternalServerError, fmt.Errorf("source not found for share")
	}
	manifest, err := buildPublicShareArchiveManifest(d, sourceInfo.Path, d.shareTargets)
	if err != nil {
		invalidatePublicShareArchiveToken(d.shareQuery.Get("archiveToken"), d.share.Hash)
		if err == errors.ErrAccessDenied {
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
		return http.StatusNotFound, fmt.Errorf("public share target not available")
	}
	d.shareArchive = manifest

	// Check global download limit (if not using per-user limits)
	if !d.share.PerUserDownloadLimit && d.share.DownloadsLimit > 0 && d.share.Downloads >= d.share.DownloadsLimit {
		return http.StatusForbidden, fmt.Errorf("share downloads limit reached")
	}

	// Check per-user download limit
	if d.share.PerUserDownloadLimit {
		// Block anonymous users
		if d.user.Username == "anonymous" {
			return http.StatusForbidden, fmt.Errorf("anonymous downloads are not allowed with per-user limits")
		}
		// Check if user has reached their limit
		if d.share.HasReachedUserLimit(d.user.Username) {
			return http.StatusForbidden, fmt.Errorf("user download limit reached for this share")
		}
	}

	d.share.Mu.Lock()
	d.share.Downloads++
	d.share.Mu.Unlock()

	// Track per-user download if enabled
	if d.share.PerUserDownloadLimit {
		d.share.IncrementUserDownload(d.user.Username)
	}

	var status int
	if len(d.shareTargets) == 1 && !d.shareTargets[0].IsDir {
		status, err = servePublicShareFile(w, r, d, sourceInfo.Path, d.shareTargets[0])
	} else {
		logicalPaths := make([]string, 0, len(d.shareTargets))
		for _, target := range d.shareTargets {
			logicalPaths = append(logicalPaths, target.LogicalPath)
		}
		status, err = BuildAndStreamArchive(w, r, d, sourceInfo.Name, logicalPaths)
	}
	if err != nil {
		if err == errors.ErrDownloadNotAllowed {
			return http.StatusForbidden, errors.ErrDownloadNotAllowed
		}
		logger.Errorf("public share handler: error processing filelist with error %v", err)
		return status, fmt.Errorf("error processing public share filelist")
	}
	return status, nil
}

type publicShareArchiveEntry struct {
	LogicalPath   string
	CanonicalPath string
	RealPath      string
	ArchivePath   string
	IsDir         bool
}

func publicShareSameRealPath(first, second string) bool {
	first = filepath.Clean(first)
	second = filepath.Clean(second)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(first, second)
	}
	return first == second
}

func reauthorizePublicShareTarget(d *requestContext, sourcePath string, checked publicShareTarget) (publicShareTarget, error) {
	current, err := resolvePublicShareLogicalTarget(d, sourcePath, checked.LogicalPath)
	if err != nil {
		return publicShareTarget{}, err
	}
	if current.CanonicalPath != checked.CanonicalPath || !publicShareSameRealPath(current.RealPath, checked.RealPath) || current.IsDir != checked.IsDir {
		return publicShareTarget{}, errors.ErrAccessDenied
	}
	current.RequestedPath = checked.RequestedPath
	return current, nil
}

func buildPublicShareArchiveManifest(d *requestContext, sourcePath string, targets []publicShareTarget) ([]publicShareArchiveEntry, error) {
	manifest := make([]publicShareArchiveEntry, 0, len(targets))
	for _, checked := range targets {
		target, err := reauthorizePublicShareTarget(d, sourcePath, checked)
		if err != nil {
			return nil, err
		}
		if !target.IsDir {
			manifest = append(manifest, publicShareArchiveEntry{
				LogicalPath:   target.LogicalPath,
				CanonicalPath: target.CanonicalPath,
				RealPath:      target.RealPath,
				ArchivePath:   filepath.Base(target.RealPath),
			})
			continue
		}

		baseName := filepath.Base(target.RealPath)
		err = filepath.WalkDir(target.RealPath, func(filePath string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relativePath, err := filepath.Rel(target.RealPath, filePath)
			if err != nil || relativePath == "." {
				return err
			}
			logicalPath := normalizePublicShareIndexPath(path.Join(target.LogicalPath, filepath.ToSlash(relativePath)))
			child, err := resolvePublicShareLogicalTarget(d, sourcePath, logicalPath)
			if err != nil {
				return err
			}
			manifest = append(manifest, publicShareArchiveEntry{
				LogicalPath:   child.LogicalPath,
				CanonicalPath: child.CanonicalPath,
				RealPath:      child.RealPath,
				ArchivePath:   path.Join(baseName, filepath.ToSlash(relativePath)),
				IsDir:         child.IsDir,
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return manifest, nil
}

func reauthorizePublicShareArchiveEntry(d *requestContext, entry publicShareArchiveEntry) (publicShareTarget, error) {
	sourceInfo, ok := config.Server.SourceMap[d.share.Source]
	if !ok {
		return publicShareTarget{}, errors.ErrAccessDenied
	}
	checked := publicShareTarget{
		LogicalPath:   entry.LogicalPath,
		CanonicalPath: entry.CanonicalPath,
		RealPath:      entry.RealPath,
		IsDir:         entry.IsDir,
	}
	return reauthorizePublicShareTarget(d, sourceInfo.Path, checked)
}

func servePublicShareFile(w http.ResponseWriter, r *http.Request, d *requestContext, sourcePath string, checked publicShareTarget) (int, error) {
	target, err := reauthorizePublicShareTarget(d, sourcePath, checked)
	if err != nil || target.IsDir {
		return http.StatusForbidden, errors.ErrAccessDenied
	}
	file, err := os.Open(target.RealPath)
	if err != nil {
		return http.StatusNotFound, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.IsDir() {
		return http.StatusNotFound, fmt.Errorf("public share target is not a file")
	}

	fileName := filepath.Base(target.LogicalPath)
	setContentDisposition(w, r, fileName)
	w.Header().Set("Cache-Control", "private")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	var reader io.ReadSeeker = file
	if d.share.MaxBandwidth > 0 {
		limit := rate.Limit(d.share.MaxBandwidth * 1024)
		reader = newThrottledReadSeeker(file, limit, d.share.MaxBandwidth*1024, r.Context())
	}
	http.ServeContent(w, r, fileName, info.ModTime(), reader)
	return http.StatusOK, nil
}

func filterPublicShareFileInfo(d *requestContext, parent publicShareTarget, file *iteminfo.ExtendedFileInfo, idx *indexing.Index) {
	filesAllowed := file.Files[:0]
	for _, child := range file.Files {
		logicalPath := normalizePublicShareIndexPath(path.Join(parent.LogicalPath, child.Name))
		target, err := resolvePublicShareLogicalTarget(d, idx.Path, logicalPath)
		if err == nil && !target.IsDir {
			filesAllowed = append(filesAllowed, child)
		}
	}
	file.Files = filesAllowed

	foldersAllowed := file.Folders[:0]
	for _, child := range file.Folders {
		logicalPath := normalizePublicShareIndexPath(path.Join(parent.LogicalPath, child.Name))
		target, err := resolvePublicShareLogicalTarget(d, idx.Path, logicalPath)
		if err == nil && target.IsDir {
			foldersAllowed = append(foldersAllowed, child)
		}
	}
	file.Folders = foldersAllowed

	file.Size = 0
	file.HasPreview = false
	for _, child := range file.Files {
		file.Size += child.Size
		file.HasPreview = file.HasPreview || child.HasPreview
	}
	for _, child := range file.Folders {
		file.Size += child.Size
		file.HasPreview = file.HasPreview || child.HasPreview
	}
}

func populatePublicShareMetadata(d *requestContext, albumArt bool) error {
	if len(d.shareTargets) != 1 {
		return errors.ErrAccessDenied
	}
	sourceInfo, ok := config.Server.SourceMap[d.share.Source]
	if !ok {
		return errors.ErrAccessDenied
	}
	parent := d.shareTargets[0]
	if !parent.IsDir {
		current, err := reauthorizePublicShareTarget(d, sourceInfo.Path, parent)
		if err != nil {
			return err
		}
		metadata, err := files.FileInfoFaster(utils.FileOptions{
			Path:                     current.ScopedPath,
			Source:                   sourceInfo.Name,
			Expand:                   true,
			Metadata:                 true,
			AlbumArt:                 albumArt,
			ExtractEmbeddedSubtitles: config.Integrations.Media.ExtractEmbeddedSubtitles && d.share.ExtractEmbeddedSubtitles,
			ShowHidden:               d.share.ShowHidden,
			HideFileExt:              d.share.HideFileExt,
			FollowSymlinks:           true,
		}, store.Access, d.shareUser, store.Share)
		if err != nil {
			return err
		}
		d.fileInfo.Metadata = metadata.Metadata
		d.fileInfo.Subtitles = metadata.Subtitles
		d.fileInfo.RealPath = current.RealPath
		return nil
	}

	for i := range d.fileInfo.Files {
		child := &d.fileInfo.Files[i]
		if !strings.HasPrefix(child.Type, "audio") && !strings.HasPrefix(child.Type, "video") {
			continue
		}
		logicalPath := normalizePublicShareIndexPath(path.Join(parent.LogicalPath, child.Name))
		current, err := resolvePublicShareLogicalTarget(d, sourceInfo.Path, logicalPath)
		if err != nil || current.IsDir {
			continue
		}
		metadata, err := files.FileInfoFaster(utils.FileOptions{
			Path:           current.ScopedPath,
			Source:         sourceInfo.Name,
			Expand:         false,
			Metadata:       true,
			AlbumArt:       albumArt,
			ShowHidden:     d.share.ShowHidden,
			HideFileExt:    d.share.HideFileExt,
			FollowSymlinks: true,
		}, store.Access, d.shareUser, store.Share)
		if err == nil {
			child.Metadata = metadata.Metadata
		}
	}
	return nil
}

func publicVerifiedMetadataHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if err := populatePublicShareMetadata(d, d.shareQuery.Get("albumArt") == "true"); err != nil {
		return http.StatusNotFound, fmt.Errorf("metadata is not available")
	}
	return renderJSON(w, r, d.fileInfo)
}

// publicShareHandler returns file or directory information from a public share.
// @Summary Get file/directory information from a public share
// @Description Returns metadata for files or directories accessible via a public share link. Browsing is disabled for upload-only shares.
// @Tags Shares
// @Accept json
// @Produce json
// @Param hash query string true "Share hash for authentication"
// @Param path query string false "Path within the share to retrieve information for. Defaults to share root."
// @Param content query string false "Include file content if true"
// @Param metadata query string false "Extract audio/video metadata if true"
// @Success 200 {object} iteminfo.FileInfo "File or directory metadata"
// @Failure 403 {object} map[string]string "Share unavailable or access denied"
// @Failure 404 {object} map[string]string "Share not found or file not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Failure 501 {object} map[string]string "Browsing disabled for upload shares"
// @Router /public/api/resources [get]
func publicGetResourceHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if d.share.ShareType == "upload" {
		return http.StatusNotImplemented, fmt.Errorf("browsing is disabled for upload shares")
	}
	if d.shareQuery.Get("metadata") == "true" {
		if err := populatePublicShareMetadata(d, d.shareQuery.Get("albumArt") == "true"); err != nil {
			return http.StatusNotFound, fmt.Errorf("metadata is not available")
		}
	}
	return renderJSON(w, r, d.fileInfo)
}

// publicUploadHandler processes file uploads to a public upload share.
// @Summary Upload files to a public upload share
// @Description Handles file and directory uploads to an upload-only public share. Supports chunked uploads, conflict resolution (override), and directory creation.
// @Tags Shares
// @Accept multipart/form-data
// @Produce json
// @Param hash query string true "Share hash for authentication"
// @Param path query string true "path within the share to upload to. Must be relative to share root."
// @Param override query bool false "If true, overwrite existing files/folders. Defaults to false."
// @Param action query string false "Upload action: 'override' to replace files, 'rename' to auto-rename"
// @Param file formData file true "File to upload"
// @Success 200 {object} map[string]string "Upload successful"
// @Failure 400 {object} map[string]string "Invalid request or parameters"
// @Failure 403 {object} map[string]string "Share unavailable or upload not allowed"
// @Failure 404 {object} map[string]string "Share not found"
// @Failure 409 {object} map[string]string "File or directory already exists (conflict)"
// @Failure 500 {object} map[string]string "Internal server error during upload"
// @Failure 501 {object} map[string]string "Uploading disabled for non-upload shares"
// @Router /public/api/resources [post]
func publicUploadHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if d.share.ShareType != "upload" && !d.share.AllowCreate {
		return http.StatusForbidden, fmt.Errorf("uploading is disabled for this share")
	}
	if !d.share.AllowReplacements &&
		(r.URL.Query().Get("action") == "override" || r.URL.Query().Get("override") == "true") {
		return http.StatusForbidden, fmt.Errorf("cannot overwrite files for this share")
	}
	// Go automatically decodes query params
	source := config.Server.SourceMap[d.share.Source].Name
	// adjust query params to match resourcePostHandler
	q := r.URL.Query()
	q.Set("source", source)
	q.Set("path", d.IndexPath)
	r.URL.RawQuery = q.Encode()
	status, err := resourcePostHandler(w, r, d)
	if err != nil {
		logger.Errorf("public upload handler: error uploading with error %v", err)
		return status, fmt.Errorf("upload failure occured on backend")
	}
	return status, nil
}

// health godoc
// @Summary Health Check
// @Schemes
// @Description Returns the health status of the API.
// @Accept json
// @Produce json
// @Success 200 {object} HttpResponse "successful health check response"
// @Router /health [get]
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := HttpResponse{Message: "ok"}    // Create response with status "ok"
	err := json.NewEncoder(w).Encode(response) // Encode the response into JSON
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// publicPreviewHandler handles the preview request for images from public shares.
// @Summary Get image/video preview from a public share
// @Description Returns a preview (thumbnail) for images or videos accessible via a public share. Preview generation can be disabled globally or per-share. Not available for upload-only shares.
// @Tags Shares
// @Accept json
// @Produce image/jpeg
// @Param hash query string true "Share hash for authentication"
// @Param path query string true "File path within the share to preview"
// @Param size query string false "Preview size: 'small' or 'large'. Default is based on server config."
// @Success 200 {file} file "Preview image content (JPEG)"
// @Failure 403 {object} map[string]string "Share unavailable or access denied"
// @Failure 404 {object} map[string]string "File not found or preview not available"
// @Failure 500 {object} map[string]string "Internal server error"
// @Failure 501 {object} map[string]string "Previews disabled globally, for this share, or for upload shares"
// @Router /public/api/resources/preview [get]
func publicPreviewHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if config.Server.DisablePreviews {
		return http.StatusNotImplemented, fmt.Errorf("preview is disabled")
	}
	if d.share.ShareType == "upload" {
		return http.StatusForbidden, fmt.Errorf("preview is disabled for upload shares")
	}
	if d.fileInfo.Type == "directory" {
		file, err := publicShareDirectoryPreviewFile(r, d)
		if err != nil {
			return http.StatusNotFound, fmt.Errorf("preview not available for this item")
		}
		d.fileInfo = *file
	}
	if publicPreviewServesOriginal(r, d.fileInfo) {
		if !d.shareAccess.allows(d.shareRoute.requirement|publicShareReadViewer|publicShareReadDownload) ||
			!consumePublicShareOriginalRead(d) {
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
	}
	status, err := previewHelperFunc(w, r, d)
	if err != nil {
		logger.Errorf("public preview handler: error getting preview with error %v", err)
		// Obfuscate errors for shares to prevent information leakage
		return http.StatusNotFound, fmt.Errorf("preview not available for this item")
	}
	return status, err
}

func consumePublicShareOriginalRead(d *requestContext) bool {
	d.share.Mu.Lock()
	defer d.share.Mu.Unlock()
	if d.share.DownloadsLimit > 0 {
		if d.share.PerUserDownloadLimit {
			if d.share.UserDownloads[d.user.Username] >= d.share.DownloadsLimit {
				return false
			}
		} else if d.share.Downloads >= d.share.DownloadsLimit {
			return false
		}
	}
	d.share.Downloads++
	if d.share.PerUserDownloadLimit {
		if d.share.UserDownloads == nil {
			d.share.UserDownloads = make(map[string]int)
		}
		d.share.UserDownloads[d.user.Username]++
	}
	return true
}

func publicShareDirectoryPreviewFile(r *http.Request, d *requestContext) (*iteminfo.ExtendedFileInfo, error) {
	if len(d.shareTargets) != 1 {
		return nil, errors.ErrAccessDenied
	}
	previewableNames := make([]string, 0, len(d.fileInfo.Files))
	for _, child := range d.fileInfo.Files {
		if iteminfo.ShouldBubbleUpToFolderPreview(child.ItemInfo) {
			previewableNames = append(previewableNames, child.Name)
		}
	}
	if len(previewableNames) == 0 {
		return nil, fmt.Errorf("no previewable files found")
	}
	percentage, err := strconv.Atoi(d.shareQuery.Get("atPercentage"))
	if err != nil || percentage < 0 || percentage > 100 {
		percentage = 0
	}
	frame := 0
	switch {
	case percentage > 50:
		frame = 3
	case percentage > 25:
		frame = 2
	case percentage > 0:
		frame = 1
	}
	name := previewableNames[frame%len(previewableNames)]
	sourceInfo, ok := config.Server.SourceMap[d.share.Source]
	if !ok {
		return nil, errors.ErrAccessDenied
	}
	logicalPath := normalizePublicShareIndexPath(path.Join(d.shareTargets[0].LogicalPath, name))
	target, err := resolvePublicShareLogicalTarget(d, sourceInfo.Path, logicalPath)
	if err != nil || target.IsDir {
		return nil, errors.ErrAccessDenied
	}
	file, err := files.FileInfoFaster(utils.FileOptions{
		Path:           target.ScopedPath,
		Source:         sourceInfo.Name,
		AlbumArt:       true,
		Metadata:       true,
		FollowSymlinks: true,
	}, store.Access, d.shareUser, store.Share)
	if err != nil {
		return nil, err
	}
	file.RealPath = target.RealPath
	return file, nil
}

func publicPreviewServesOriginal(r *http.Request, file iteminfo.ExtendedFileInfo) bool {
	previewSize := r.URL.Query().Get("size")
	if previewSize != "large" && previewSize != "original" && previewSize != "xlarge" {
		previewSize = "small"
	}
	if previewSize == "original" {
		return true
	}
	ext := strings.ToLower(filepath.Ext(file.Name))
	return strings.HasPrefix(file.Type, "image") &&
		shouldServeOriginalPreview(ext, iteminfo.ResizableImageTypes[ext], file.RealPath, previewSize, file.Size)
}

// publicPutHandler handles the PUT request for a public share.
// @Summary Update a file in a public share
// @Description Updates the content of a file in a public share.
// @Tags Shares
// @Accept json
// @Produce json
// @Param hash query string true "Share hash for authentication"
// @Param path query string true "Path to the file to update"
// @Param content body string true "New content for the file"
// @Success 200 {object} map[string]string "File updated successfully"
// @Failure 400 {object} map[string]string "Invalid request or parameters"
// @Failure 403 {object} map[string]string "Share unavailable or update not allowed"
// @Failure 404 {object} map[string]string "Share not found or file not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /public/api/resources [put]
func publicPutHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	// update path to be the source path
	if !d.share.AllowModify {
		return http.StatusForbidden, fmt.Errorf("create is not allowed for this share")
	}
	sourceName := d.share.GetSourceName()
	if sourceName == "" {
		return http.StatusNotFound, fmt.Errorf("source not available")
	}

	if !d.share.AllowModify {
		return http.StatusForbidden, fmt.Errorf("edit permission not allowed for this share")
	}
	// Go automatically decodes query params
	path := r.URL.Query().Get("path")

	// Rule 1: Validate user-provided path to prevent path traversal
	cleanPath, err := utils.SanitizeUserPath(path)
	if err != nil {
		return http.StatusBadRequest, err
	}

	resolvedPath := utils.JoinPathAsUnix(d.share.Path, cleanPath)
	err = files.WriteFile(sourceName, resolvedPath, r.Body)
	// hide the error
	if err != nil {
		logger.Errorf("public put handler: error updating resource with error %v", err)
		return http.StatusInternalServerError, fmt.Errorf("an error occurred while updating the resource")
	}
	return http.StatusOK, nil
}

// deprecated -- see publicBulkDeleteHandler
func publicDeleteHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if !d.share.AllowDelete {
		return http.StatusForbidden, fmt.Errorf("delete is not allowed for this share")
	}
	fileInfo, err := files.FileInfoFaster(utils.FileOptions{
		FollowSymlinks: true,
		Path:           d.IndexPath,
		Source:         d.share.Source,
	}, store.Access, d.shareUser, store.Share)
	if err != nil {
		return http.StatusNotFound, fmt.Errorf("resource not available")
	}
	err = files.DeleteFiles(d.share.Source, fileInfo.RealPath, fileInfo.Type == "directory")
	if err != nil {
		logger.Errorf("public delete handler: error deleting resource with error %v", err)
		return http.StatusInternalServerError, fmt.Errorf("an error occured while deleting the resource")
	}
	// delete thumbnails
	preview.DelThumbs(r.Context(), *fileInfo)
	return http.StatusOK, nil
}

// publicBulkDeleteHandler deletes multiple resources from a public share in a single request.
// @Summary Bulk delete resources from public share
// @Description Deletes multiple resources specified in the request body. Returns a list of succeeded and failed deletions.
// @Tags Shares
// @Accept json
// @Produce json
// @Param hash query string true "Share hash for authentication"
// @Param items body []BulkDeleteItem true "Array of items to delete, each with source and path"
// @Success 200 {object} BulkDeleteResponse "All resources deleted successfully"
// @Success 207 {object} BulkDeleteResponse "Partial success - some resources deleted, some failed"
// @Failure 400 {object} map[string]string "Bad request - invalid JSON or empty items array"
// @Failure 403 {object} map[string]string "Forbidden - delete not allowed for this share"
// @Failure 500 {object} map[string]string "Internal server error - all deletions failed"
// @Router /public/api/resources/bulk [delete]
func publicBulkDeleteHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if !d.share.AllowDelete {
		return http.StatusForbidden, fmt.Errorf("delete is not allowed for this share")
	}
	// hide the error
	status, err := resourceBulkDeleteHandler(w, r, d)
	if err != nil {
		logger.Errorf("public bulk delete handler: error deleting resources with error %v", err)
		return http.StatusInternalServerError, fmt.Errorf("an error occurred while processing the request")
	}
	return status, nil
}

// publicPatchHandler performs a patch operation (e.g., move, copy, rename) on resources in a public share.
// @Summary Move, copy, or rename resources in a public share
// @Description Performs move, copy, or rename operations on multiple resources within a public share. All operations are performed atomically.
// @Tags Shares
// @Accept json
// @Produce json
// @Param hash query string true "Share hash for authentication"
// @Param request body MoveCopyRequest true "Move/copy request with items and action"
// @Success 200 {object} MoveCopyResponse "All operations completed successfully"
// @Success 207 {object} MoveCopyResponse "Partial success - some operations succeeded, some failed"
// @Failure 400 {object} map[string]string "Bad request - invalid JSON or parameters"
// @Failure 403 {object} map[string]string "Forbidden - modify not allowed for this share"
// @Failure 404 {object} map[string]string "Share or resource not found"
// @Failure 500 {object} MoveCopyResponse "Internal server error"
// @Router /public/api/resources [patch]
func publicPatchHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if !d.share.AllowModify {
		return http.StatusForbidden, fmt.Errorf("edit permission not allowed for this share")
	}

	// Get the source from the share
	sourceName := d.share.GetSourceName()
	if sourceName == "" {
		return http.StatusNotFound, fmt.Errorf("source not available")
	}

	// Replace user with the share creator's user for proper permission checking
	shareCreatedByUser, err := store.Users.Get(d.share.UserID)
	if err != nil {
		return http.StatusNotFound, fmt.Errorf("user for share no longer exists")
	}
	d.user = shareCreatedByUser

	// Parse the request body
	var req MoveCopyRequest
	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		return http.StatusBadRequest, fmt.Errorf("invalid JSON body: %v", err)
	}

	if req.Action == "" {
		return http.StatusBadRequest, fmt.Errorf("action is required (copy, move, or rename)")
	}

	// Transform the request: prepend share path and add source to each item
	// This normalizes the request to look like a regular user request
	// Note: Share paths are absolute, so we don't strip user scope here
	// resourcePatchHandler will skip adding scope for shares
	for i := range req.Items {
		var sanitizedPath string
		sanitizedPath, err = utils.SanitizeUserPath(req.Items[i].FromPath)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid from path: %w", err)
		}
		req.Items[i].FromSource = sourceName
		req.Items[i].FromPath = utils.JoinPathAsUnix(d.share.Path, sanitizedPath)
		sanitizedPath, err = utils.SanitizeUserPath(req.Items[i].ToPath)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid to path: %w", err)
		}
		req.Items[i].ToSource = sourceName
		req.Items[i].ToPath = utils.JoinPathAsUnix(d.share.Path, sanitizedPath)
	}
	d.Data = req

	// Call the regular handler (will treat this like a normal user request now)
	status, err := resourcePatchHandler(w, r, d)

	// For shares, we need to sanitize the response to hide internal details
	// The response has already been written by resourcePatchHandler, but we can still return error
	if err != nil {
		logger.Errorf("public patch handler: error processing patch with error %v", err)
		// Obfuscate errors for security
		return http.StatusInternalServerError, fmt.Errorf("an error occurred while processing the request")
	}

	return status, err
}

// getShareImage serves banner or favicon files for shares as resizable previews
// @Summary Get share image (banner or favicon) as preview
// @Description Returns a resizable preview (large size) for the banner or favicon file of a share
// @Tags Shares
// @Produce image/jpeg
// @Param hash query string true "Share hash"
// @Param banner query bool false "Request banner file"
// @Param favicon query bool false "Request favicon file"
// @Success 200 {file} file "Preview image content (JPEG)"
// @Failure 400 {object} map[string]string "Invalid request"
// @Failure 403 {object} map[string]string "Permission denied"
// @Failure 404 {object} map[string]string "Asset not found"
// @Router /public/api/share/image [get]
func getShareImage(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	// Determine which asset is being requested
	isBanner := r.URL.Query().Get("banner") == "true"
	isFavicon := r.URL.Query().Get("favicon") == "true"

	if !isBanner && !isFavicon {
		return http.StatusBadRequest, fmt.Errorf("either banner or favicon parameter must be true")
	}

	sourceName, assetPath, err := d.share.GetShareImagePartsHelper(isBanner)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("invalid asset configuration: %v", err)
	}
	sourceInfo, ok := config.Server.SourceMap[d.share.Source]
	if !ok || sourceName != sourceInfo.Name {
		return http.StatusForbidden, fmt.Errorf("public share access denied")
	}
	target, err := resolvePublicShareLogicalTarget(d, sourceInfo.Path, assetPath)
	if err != nil || target.IsDir {
		return http.StatusForbidden, fmt.Errorf("public share access denied")
	}

	// Get file info
	fileInfo, err := files.FileInfoFaster(utils.FileOptions{
		Path:           target.ScopedPath,
		Source:         sourceInfo.Name,
		Expand:         false,
		Content:        false,
		Metadata:       false,
		ShowHidden:     false,
		FollowSymlinks: true,
	}, store.Access, d.shareUser, store.Share)

	if err != nil {
		logger.Errorf("error accessing share asset: source=%v path=%v error=%v", sourceName, assetPath, err)
		return http.StatusNotFound, fmt.Errorf("asset file not found or not accessible")
	}

	// Ensure it's an image file
	if !strings.HasPrefix(fileInfo.Type, "image/") {
		return http.StatusBadRequest, fmt.Errorf("invalid file type, must be image")
	}

	// Set file info in request context for preview generation
	fileInfo.RealPath = target.RealPath
	d.fileInfo = *fileInfo
	q := r.URL.Query()
	if isBanner {
		q.Set("size", "xlarge")
	} else {
		q.Set("size", "small")
	}
	r.URL.RawQuery = q.Encode()
	if publicPreviewServesOriginal(r, d.fileInfo) {
		if !d.shareAccess.allows(d.shareRoute.requirement|publicShareReadViewer|publicShareReadDownload) ||
			!consumePublicShareOriginalRead(d) {
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
	}

	// Use the preview helper to generate and serve a resized preview
	status, err := previewHelperFunc(w, r, d)
	if err != nil {
		logger.Errorf("error generating preview for share asset: source=%v path=%v error=%v", sourceName, assetPath, err)
		return http.StatusNotFound, fmt.Errorf("preview not available for this asset")
	}

	return status, err
}

// publicItemsGetHandler efficiently returns a basic list of items for a directory in a public share.
// @Summary Get directory items (public share)
// @Description Efficiently returns a basic list of items for the specified path in a public share. Use hash for authentication instead of source. Use 'only' parameter to filter by only files or folders.
// @Tags Shares
// @Accept json
// @Produce json
// @Param hash query string true "Share hash for authentication"
// @Param path query string false "Path within the share to list child items. Defaults to share root."
// @Param only query string false "Filter: 'files', 'folders', or omit for both"
// @Success 200 {object} files.Items "lists files and folders"
// @Failure 403 {object} map[string]string "Forbidden (access denied)"
// @Failure 404 {object} map[string]string "Share not found or source not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /public/api/resources/items [get]
func publicItemsGetHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if d.share.ShareType == "upload" {
		return http.StatusForbidden, fmt.Errorf("browsing is disabled for upload shares")
	}
	if d.fileInfo.Type != "directory" {
		return http.StatusNotFound, fmt.Errorf("path is not a directory")
	}
	items := files.Items{}
	only := d.shareQuery.Get("only")
	if only == "" || only == "files" {
		for _, file := range d.fileInfo.Files {
			items.Files = append(items.Files, file.Name)
		}
	}
	if only == "" || only == "folders" {
		for _, folder := range d.fileInfo.Folders {
			items.Folders = append(items.Folders, folder.Name)
		}
	}
	return renderJSON(w, r, items)
}
