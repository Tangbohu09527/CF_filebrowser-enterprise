package http

import (
	"encoding/json"
	stderrors "errors"
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
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
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

	archiveToken := d.shareQuery.Get("archiveToken")
	isArchive := len(d.shareTargets) != 1 || d.shareTargets[0].IsDir
	if archiveToken != "" && !isArchive {
		invalidatePublicShareArchiveToken(archiveToken, d.share.Hash)
		return http.StatusForbidden, fmt.Errorf("archiveToken is not valid for a single file")
	}
	if isArchive {
		if _, err := archiveExtensionForAlgorithm(d.shareQuery.Get("algo")); err != nil {
			return http.StatusInternalServerError, err
		}
	}
	if archiveToken == "" && !consumePublicShareOriginalRead(d) {
		return http.StatusForbidden, fmt.Errorf("share downloads limit reached")
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
	ContentSHA256 [32]byte
	info          os.FileInfo
}

func publicShareSameRealPath(first, second string) bool {
	first = filepath.Clean(first)
	second = filepath.Clean(second)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(first, second)
	}
	return first == second
}

func publicShareSameFileIdentity(original, current os.FileInfo) bool {
	if original == nil || current == nil || !os.SameFile(original, current) {
		return false
	}
	return original.Mode().Type() == current.Mode().Type() &&
		original.Size() == current.Size() &&
		original.ModTime().Equal(current.ModTime())
}

func reauthorizePublicShareTarget(d *requestContext, sourcePath string, checked publicShareTarget) (publicShareTarget, error) {
	current, err := resolvePublicShareLogicalTarget(d, sourcePath, checked.LogicalPath)
	if err != nil {
		return publicShareTarget{}, err
	}
	if current.CanonicalPath != checked.CanonicalPath || !publicShareSameRealPath(current.RealPath, checked.RealPath) ||
		current.IsDir != checked.IsDir || !publicShareSameFileIdentity(checked.info, current.info) {
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
				info:          target.info,
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
				info:          child.info,
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
		info:          entry.info,
	}
	return reauthorizePublicShareTarget(d, sourceInfo.Path, checked)
}

func servePublicShareFile(w http.ResponseWriter, r *http.Request, d *requestContext, sourcePath string, checked publicShareTarget) (int, error) {
	target, err := reauthorizePublicShareTarget(d, sourcePath, checked)
	if err != nil || target.IsDir {
		return http.StatusForbidden, errors.ErrAccessDenied
	}
	before, err := os.Lstat(target.RealPath)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() ||
		!publicShareSameFileIdentity(target.info, before) {
		return http.StatusForbidden, errors.ErrAccessDenied
	}
	file, err := os.Open(target.RealPath)
	if err != nil {
		return http.StatusNotFound, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) ||
		!publicShareSameFileIdentity(target.info, info) {
		return http.StatusForbidden, errors.ErrAccessDenied
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

func populatePublicShareMetadata(r *http.Request, d *requestContext, albumArt bool) error {
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
		if err := sanitizePublicMediaInfo(r, d, current, metadata, albumArt); err != nil {
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
			if sanitizeErr := sanitizePublicMediaInfo(r, d, current, metadata, albumArt); sanitizeErr != nil {
				return sanitizeErr
			}
			child.Metadata = metadata.Metadata
		}
	}
	return nil
}

func publicVerifiedMetadataHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if !d.shareAccess.allows(publicShareReadBrowse | publicShareReadViewer) {
		return http.StatusForbidden, errors.ErrAccessDenied
	}
	albumArt := d.shareQuery.Get("albumArt") == "true"
	if albumArt && config.Server.DisablePreviews {
		return http.StatusNotImplemented, fmt.Errorf("preview is disabled")
	}
	if err := populatePublicShareMetadata(r, d, albumArt); err != nil {
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
		if err := populatePublicShareMetadata(r, d, d.shareQuery.Get("albumArt") == "true"); err != nil {
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
		if !d.fileInfo.HasPreview || len(d.shareTargets) != 1 {
			return http.StatusBadRequest, fmt.Errorf("this item does not have a preview")
		}
		sourceInfo, ok := config.Server.SourceMap[d.share.Source]
		if !ok {
			return http.StatusNotFound, fmt.Errorf("source not found")
		}
		return servePublicShareFile(w, r, d, sourceInfo.Path, d.shareTargets[0])
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
	target, err = reauthorizePublicShareTarget(d, sourceInfo.Path, target)
	if err != nil {
		return nil, errors.ErrAccessDenied
	}
	file.RealPath = target.RealPath
	d.shareTargets = []publicShareTarget{target}
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
	if len(d.shareTargets) != 1 || !d.shareAccess.modify {
		return http.StatusForbidden, fmt.Errorf("edit permission not allowed for this share")
	}
	target := d.shareTargets[0]
	if target.info == nil || target.IsDir || !publicShareWriteTargetUnchanged(target) {
		return http.StatusForbidden, fmt.Errorf("public share access denied")
	}
	sourceName := d.share.GetSourceName()
	if sourceName == "" {
		return http.StatusNotFound, fmt.Errorf("source not available")
	}
	overwrite := true
	itemCount := int64(1)
	if err := reservePublicShareWriteAudit(r, auditdb.ActionFileModify, sourceName, target, &auditdb.MetadataV1{
		SchemaVersion: auditdb.CurrentMetadataSchemaVersion,
		Overwrite:     &overwrite,
		Method:        auditdb.MethodPUT,
		ItemCount:     &itemCount,
	}); err != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
	}
	countedBody := &publicShareAuditCountingReader{reader: r.Body}
	err := files.WriteFileWithPreCommit(sourceName, target.CanonicalPath, target.RealPath, countedBody,
		resourceAuditWritePreCommit(d, sourceName, target.RequestedPath, authenticatedReadTarget{}))
	if auditErr := mergePublicShareWriteAuditResult(r, countedBody.bytesRead, 1, err == nil); auditErr != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
	}
	// hide the error
	if err != nil {
		if stderrors.Is(err, errResourceAuditTargetChanged) {
			return http.StatusConflict, errResourceAuditTargetChanged
		}
		logger.Errorf("public put handler: error updating resource with error %v", err)
		return http.StatusInternalServerError, fmt.Errorf("an error occurred while updating the resource")
	}
	return http.StatusOK, nil
}

// deprecated -- see publicBulkDeleteHandler
func publicDeleteHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if len(d.shareTargets) != 1 || !d.shareAccess.delete {
		return http.StatusForbidden, fmt.Errorf("delete is not allowed for this share")
	}
	target := d.shareTargets[0]
	if target.info == nil || !publicShareWriteTargetUnchanged(target) {
		return http.StatusForbidden, fmt.Errorf("public share access denied")
	}
	sourceInfo, ok := config.Server.SourceMap[d.share.Source]
	if !ok {
		return http.StatusNotFound, fmt.Errorf("source not found")
	}
	manifest, err := buildPublicShareDeleteManifest(d, sourceInfo.Path, target)
	if err != nil || !publicShareWriteManifestUnchanged(manifest) {
		return http.StatusForbidden, fmt.Errorf("public share access denied")
	}
	fileInfo, err := files.FileInfoFaster(utils.FileOptions{
		FollowSymlinks: true,
		Path:           target.ScopedPath,
		Source:         d.share.Source,
	}, store.Access, d.shareUser, store.Share)
	if err != nil {
		return http.StatusNotFound, fmt.Errorf("resource not available")
	}
	fileInfo.RealPath = target.RealPath
	if !publicShareWriteTargetUnchanged(target) {
		return http.StatusForbidden, fmt.Errorf("public share access denied")
	}
	itemCount := int64(1)
	if err = reservePublicShareWriteAudit(r, auditdb.ActionFileDelete, sourceInfo.Name, target, &auditdb.MetadataV1{
		SchemaVersion: auditdb.CurrentMetadataSchemaVersion,
		Method:        auditdb.MethodDELETE,
		ItemCount:     &itemCount,
	}); err != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
	}
	err = files.DeleteFiles(d.share.Source, target.RealPath, target.IsDir)
	if auditErr := mergePublicShareWriteAuditCounts(r, 1, boolToAuditCount(err == nil), boolToAuditCount(err != nil), 0); auditErr != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
	}
	if err != nil {
		logger.Errorf("public delete handler: error deleting resource with error %v", err)
		return http.StatusInternalServerError, fmt.Errorf("an error occured while deleting the resource")
	}
	// delete thumbnails
	preview.DelThumbs(r.Context(), *fileInfo)
	return http.StatusOK, nil
}

func publicShareWriteTargetUnchanged(target publicShareTarget) bool {
	if target.info == nil {
		return false
	}
	current, err := os.Lstat(target.RealPath)
	return err == nil && current.Mode()&os.ModeSymlink == 0 &&
		current.Mode().Type() == target.info.Mode().Type() && os.SameFile(target.info, current)
}

func buildPublicShareDeleteManifest(d *requestContext, sourcePath string, root publicShareTarget) ([]publicShareTarget, error) {
	manifest := []publicShareTarget{root}
	if !root.IsDir {
		return manifest, nil
	}
	err := filepath.WalkDir(root.RealPath, func(currentPath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relativePath, err := filepath.Rel(root.RealPath, currentPath)
		if err != nil || relativePath == "." {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.ErrAccessDenied
		}
		requestedPath := path.Join(root.RequestedPath, filepath.ToSlash(relativePath))
		child, exists, err := authorizePublicShareWriteTarget(d, sourcePath, requestedPath)
		if err != nil || !exists || !publicShareWriteTargetUnchanged(child) {
			return errors.ErrAccessDenied
		}
		if !child.IsDir && (child.info == nil || !child.info.Mode().IsRegular()) {
			return errors.ErrAccessDenied
		}
		manifest = append(manifest, child)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func publicShareWriteManifestUnchanged(manifest []publicShareTarget) bool {
	for _, target := range manifest {
		if !publicShareWriteTargetUnchanged(target) {
			return false
		}
	}
	return true
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
	if !d.shareAccess.delete {
		return http.StatusForbidden, fmt.Errorf("delete is not allowed for this share")
	}
	var items []BulkDeleteItem
	if err := json.NewDecoder(r.Body).Decode(&items); err != nil {
		return http.StatusBadRequest, fmt.Errorf("invalid JSON body")
	}
	if len(items) == 0 {
		return http.StatusBadRequest, fmt.Errorf("items array cannot be empty")
	}
	sourceInfo, ok := config.Server.SourceMap[d.share.Source]
	if !ok {
		return http.StatusNotFound, fmt.Errorf("source not found")
	}
	targets := make([]publicShareTarget, 0, len(items))
	manifests := make([][]publicShareTarget, 0, len(items))
	for i := range items {
		target, exists, err := authorizePublicShareWriteTarget(d, sourceInfo.Path, items[i].Path)
		if err != nil || !exists || target.RequestedPath == "" || !publicShareWriteTargetUnchanged(target) {
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
		for _, planned := range targets {
			if publicSharePathsOverlap(planned.CanonicalPath, target.CanonicalPath) {
				return http.StatusConflict, fmt.Errorf("delete targets overlap")
			}
		}
		manifest, err := buildPublicShareDeleteManifest(d, sourceInfo.Path, target)
		if err != nil {
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
		items[i].Path = target.RequestedPath
		targets = append(targets, target)
		manifests = append(manifests, manifest)
	}
	for _, manifest := range manifests {
		if !publicShareWriteManifestUnchanged(manifest) {
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
	}

	fileInfos := make([]*iteminfo.ExtendedFileInfo, len(targets))
	for i, target := range targets {
		fileInfo, err := files.FileInfoFaster(utils.FileOptions{
			FollowSymlinks: true,
			Path:           target.ScopedPath,
			Source:         d.share.Source,
			ShowHidden:     true,
		}, store.Access, d.shareUser, store.Share)
		if err != nil || !publicShareWriteTargetUnchanged(target) {
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
		fileInfo.RealPath = target.RealPath
		fileInfos[i] = fileInfo
	}
	for _, manifest := range manifests {
		if !publicShareWriteManifestUnchanged(manifest) {
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
	}
	auditTarget := targets[0]
	if len(targets) > 1 {
		root, resolveErr := resolvePublicShareLogicalTarget(d, sourceInfo.Path, d.share.Path)
		if resolveErr != nil {
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
		auditTarget = root
	}
	itemCount := int64(len(targets))
	if err := reservePublicShareWriteAudit(r, auditdb.ActionFileDelete, sourceInfo.Name, auditTarget, &auditdb.MetadataV1{
		SchemaVersion: auditdb.CurrentMetadataSchemaVersion,
		Method:        auditdb.MethodDELETE,
		ItemCount:     &itemCount,
	}); err != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
	}

	response := BulkDeleteResponse{Succeeded: make([]BulkDeleteItem, 0, len(items)), Failed: []BulkDeleteItem{}}
	for i, target := range targets {
		if err := files.DeleteFiles(d.share.Source, target.RealPath, target.IsDir); err != nil {
			logger.Errorf("public bulk delete handler: error deleting resource with error %v", err)
			response.Failed = append(response.Failed, BulkDeleteItem{Message: "error deleting resource"})
			continue
		}
		preview.DelThumbs(r.Context(), *fileInfos[i])
		response.Succeeded = append(response.Succeeded, items[i])
	}
	status := http.StatusOK
	if len(response.Failed) != 0 {
		status = http.StatusMultiStatus
	}
	if err := mergePublicShareWriteAuditCounts(r, int64(len(targets)), int64(len(response.Succeeded)), int64(len(response.Failed)), 0); err != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
	}
	return renderJSON(w, r, response, status)
}

type publicSharePatchPlan struct {
	from     publicShareTarget
	to       publicShareTarget
	toExists bool
}

func publicShareVersionedRequest(requestedPath string, counter int) string {
	directory, name := path.Split(requestedPath)
	extension := path.Ext(name)
	base := strings.TrimSuffix(name, extension)
	return path.Join(directory, fmt.Sprintf("%s(%d)%s", base, counter, extension))
}

func publicShareDestinationCollision(reserved []publicShareTarget, candidate publicShareTarget) (exact, overlap bool) {
	for _, existing := range reserved {
		if !publicSharePathsOverlap(existing.CanonicalPath, candidate.CanonicalPath) {
			continue
		}
		if publicSharePathWithin(existing.CanonicalPath, candidate.CanonicalPath) &&
			publicSharePathWithin(candidate.CanonicalPath, existing.CanonicalPath) {
			return true, true
		}
		return false, true
	}
	return false, false
}

func authorizePublicSharePatchTree(d *requestContext, sourcePath string, plan publicSharePatchPlan, overwrite bool) error {
	if !plan.from.IsDir {
		return nil
	}
	return filepath.WalkDir(plan.from.RealPath, func(currentPath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relativePath, err := filepath.Rel(plan.from.RealPath, currentPath)
		if err != nil || relativePath == "." {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.ErrAccessDenied
		}
		fromRequest := path.Join(plan.from.RequestedPath, filepath.ToSlash(relativePath))
		fromTarget, exists, err := authorizePublicShareWriteTarget(d, sourcePath, fromRequest)
		if err != nil || !exists || !publicShareWriteTargetUnchanged(fromTarget) {
			return errors.ErrAccessDenied
		}
		if !fromTarget.IsDir && (fromTarget.info == nil || !fromTarget.info.Mode().IsRegular()) {
			return errors.ErrAccessDenied
		}

		toRequest := path.Join(plan.to.RequestedPath, filepath.ToSlash(relativePath))
		toTarget, toExists, err := authorizePublicShareWriteTarget(d, sourcePath, toRequest)
		if err != nil {
			return errors.ErrAccessDenied
		}
		if toExists {
			if !overwrite || !d.shareAccess.replace || !publicShareWriteTargetUnchanged(toTarget) {
				return errors.ErrAccessDenied
			}
		} else if !d.shareAccess.create {
			return errors.ErrAccessDenied
		}
		return nil
	})
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
	if !d.shareAccess.modify {
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

	if req.Action != "copy" && req.Action != "move" && req.Action != "rename" {
		return http.StatusBadRequest, fmt.Errorf("action is required (copy, move, or rename)")
	}
	if len(req.Items) == 0 {
		return http.StatusBadRequest, fmt.Errorf("items array cannot be empty")
	}
	if (req.Action == "move" || req.Action == "rename") && !d.shareAccess.delete {
		return http.StatusForbidden, fmt.Errorf("delete permission not allowed for this share")
	}

	sourceInfo, ok := config.Server.SourceMap[d.share.Source]
	if !ok {
		return http.StatusNotFound, fmt.Errorf("source not found")
	}
	autoRename := req.Rename
	plans := make([]publicSharePatchPlan, 0, len(req.Items))
	reservedDestinations := make([]publicShareTarget, 0, len(req.Items))
	// Authorize and freeze every top-level source and destination before mutation.
	for i := range req.Items {
		fromTarget, fromExists, authorizeErr := authorizePublicShareWriteTarget(d, sourceInfo.Path, req.Items[i].FromPath)
		if authorizeErr != nil || !fromExists || fromTarget.RequestedPath == "" || !publicShareWriteTargetUnchanged(fromTarget) {
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
		toTarget, toExists, authorizeErr := authorizePublicShareWriteTarget(d, sourceInfo.Path, req.Items[i].ToPath)
		if authorizeErr != nil || toTarget.RequestedPath == "" {
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
		reserved, overlapsReserved := publicShareDestinationCollision(reservedDestinations, toTarget)
		if overlapsReserved && !reserved {
			return http.StatusConflict, fmt.Errorf("destination overlaps another destination")
		}
		if toExists || reserved {
			if !autoRename {
				if reserved || !req.Overwrite {
					return http.StatusConflict, fmt.Errorf("destination already exists or overlaps another destination")
				}
				if !d.shareAccess.replace || !publicShareWriteTargetUnchanged(toTarget) {
					return http.StatusForbidden, fmt.Errorf("public share access denied")
				}
			} else {
				originalRequest := toTarget.RequestedPath
				for counter := 1; ; counter++ {
					alternateRequest := publicShareVersionedRequest(originalRequest, counter)
					candidate, candidateExists, candidateErr := authorizePublicShareWriteTarget(d, sourceInfo.Path, alternateRequest)
					if candidateErr != nil {
						return http.StatusForbidden, fmt.Errorf("public share access denied")
					}
					exactCollision, overlapCollision := publicShareDestinationCollision(reservedDestinations, candidate)
					if overlapCollision && !exactCollision {
						return http.StatusConflict, fmt.Errorf("destination overlaps another destination")
					}
					if candidateExists || exactCollision {
						continue
					}
					toTarget = candidate
					toExists = false
					break
				}
			}
		} else if !d.shareAccess.create {
			return http.StatusForbidden, fmt.Errorf("create permission not allowed for this share")
		}
		if !toExists && !d.shareAccess.create {
			return http.StatusForbidden, fmt.Errorf("create permission not allowed for this share")
		}
		if _, collision := publicShareDestinationCollision(reservedDestinations, toTarget); collision {
			return http.StatusConflict, fmt.Errorf("destination overlaps another destination")
		}
		for _, planned := range plans {
			if (fromTarget.IsDir || planned.from.IsDir) && publicSharePathsOverlap(fromTarget.CanonicalPath, planned.from.CanonicalPath) {
				return http.StatusConflict, fmt.Errorf("source trees overlap")
			}
		}
		if fromTarget.IsDir && publicSharePathsOverlap(fromTarget.CanonicalPath, toTarget.CanonicalPath) {
			return http.StatusConflict, fmt.Errorf("destination overlaps source tree")
		}
		if publicShareWriteTargetUnchanged(fromTarget) && toExists && publicShareWriteTargetUnchanged(toTarget) &&
			os.SameFile(fromTarget.info, toTarget.info) {
			return http.StatusBadRequest, fmt.Errorf("source and destination must differ")
		}
		plans = append(plans, publicSharePatchPlan{from: fromTarget, to: toTarget, toExists: toExists})
		reservedDestinations = append(reservedDestinations, toTarget)
		req.Items[i].FromSource = sourceName
		req.Items[i].FromPath = fromTarget.CanonicalPath
		req.Items[i].ToSource = sourceName
		req.Items[i].ToPath = toTarget.CanonicalPath
	}
	for _, destinationPlan := range plans {
		for _, sourcePlan := range plans {
			if !publicSharePathsOverlap(destinationPlan.to.CanonicalPath, sourcePlan.from.CanonicalPath) {
				continue
			}
			exact := publicSharePathWithin(destinationPlan.to.CanonicalPath, sourcePlan.from.CanonicalPath) &&
				publicSharePathWithin(sourcePlan.from.CanonicalPath, destinationPlan.to.CanonicalPath)
			if exact || destinationPlan.from.IsDir || sourcePlan.from.IsDir {
				return http.StatusConflict, fmt.Errorf("destination overlaps a source tree")
			}
		}
	}
	for _, plan := range plans {
		if err := authorizePublicSharePatchTree(d, sourceInfo.Path, plan, req.Overwrite); err != nil {
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
		if !publicShareWriteTargetUnchanged(plan.from) || (plan.toExists && !publicShareWriteTargetUnchanged(plan.to)) {
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
	}
	// Every automatic destination is now fixed and authorized. Do not let the shared
	// handler select a different path if filesystem state changes before mutation.
	req.Rename = false
	d.Data = req
	d.shareTargets = []publicShareTarget{plans[0].from, plans[0].to}

	// Call the regular handler (will treat this like a normal user request now)
	status, err := resourcePatchHandler(w, r, d)

	// For shares, we need to sanitize the response to hide internal details
	// The response has already been written by resourcePatchHandler, but we can still return error
	if err != nil {
		if status == http.StatusServiceUnavailable {
			return status, err
		}
		logger.Errorf("public patch handler: error processing patch with error %v", err)
		// Obfuscate errors for security
		return http.StatusInternalServerError, fmt.Errorf("an error occurred while processing the request")
	}

	return status, err
}

type publicShareAuditCountingReader struct {
	reader    io.Reader
	bytesRead int64
}

func (reader *publicShareAuditCountingReader) Read(buffer []byte) (int, error) {
	read, err := reader.reader.Read(buffer)
	reader.bytesRead += int64(read)
	return read, err
}

func reservePublicShareWriteAudit(
	r *http.Request,
	action auditdb.Action,
	source string,
	target publicShareTarget,
	metadata *auditdb.MetadataV1,
) error {
	recorder := AuditRecorderFromRequest(r)
	if recorder == nil {
		return nil
	}
	if err := recorder.SetAction(action); err != nil {
		return ErrAuditUnavailable
	}
	if err := recorder.SetResource(source, target.LogicalPath, target.CanonicalPath); err != nil {
		return ErrAuditUnavailable
	}
	if err := recorder.MergeMetadata(metadata); err != nil {
		return ErrAuditUnavailable
	}
	if err := recorder.ReservePending(); err != nil {
		return ErrAuditUnavailable
	}
	return nil
}

func mergePublicShareWriteAuditResult(r *http.Request, bytesRead, itemCount int64, success bool) error {
	succeeded := boolToAuditCount(success)
	failed := boolToAuditCount(!success)
	denied := int64(0)
	metadata := &auditdb.MetadataV1{
		SchemaVersion: auditdb.CurrentMetadataSchemaVersion,
		Bytes:         &bytesRead,
		ItemCount:     &itemCount,
		SuccessCount:  &succeeded,
		FailedCount:   &failed,
		DeniedCount:   &denied,
	}
	recorder := AuditRecorderFromRequest(r)
	if recorder == nil {
		return nil
	}
	return recorder.MergeMetadata(metadata)
}

func mergePublicShareWriteAuditCounts(r *http.Request, items, succeeded, failed, denied int64) error {
	recorder := AuditRecorderFromRequest(r)
	if recorder == nil {
		return nil
	}
	return recorder.MergeMetadata(&auditdb.MetadataV1{
		SchemaVersion: auditdb.CurrentMetadataSchemaVersion,
		ItemCount:     &items,
		SuccessCount:  &succeeded,
		FailedCount:   &failed,
		DeniedCount:   &denied,
	})
}

func boolToAuditCount(value bool) int64 {
	if value {
		return 1
	}
	return 0
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
	target, err = reauthorizePublicShareTarget(d, sourceInfo.Path, target)
	if err != nil {
		return http.StatusForbidden, fmt.Errorf("public share access denied")
	}
	if auditErr := setPublicShareAuditContext(r, d, d.share, &target); auditErr != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
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
