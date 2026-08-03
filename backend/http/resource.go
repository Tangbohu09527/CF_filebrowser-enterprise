package http

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	"github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
	"github.com/gtsteffaniak/filebrowser/backend/preview"
	"github.com/gtsteffaniak/go-cache/cache"
	"github.com/gtsteffaniak/go-logger/logger"
)

var pauseCache = cache.NewCache[string](1 * time.Minute)
var publicPauseCache = cache.NewCache[string](1 * time.Minute)

var errResourceAuditTargetChanged = stderrors.New("audited resource target changed")

type resourceAuditCountingReader struct {
	reader    io.Reader
	bytesRead int64
}

func (reader *resourceAuditCountingReader) Read(buffer []byte) (int, error) {
	read, err := reader.reader.Read(buffer)
	reader.bytesRead += int64(read)
	return read, err
}

func prepareResourceWriteAudit(
	request *http.Request,
	action auditdb.Action,
	source, logicalPath, canonicalPath string,
	targetSource, targetLogicalPath, targetCanonicalPath string,
	metadata *auditdb.MetadataV1,
) error {
	recorder := AuditRecorderFromRequest(request)
	if recorder == nil {
		return nil
	}
	if err := recorder.SetAction(action); err != nil {
		return err
	}
	if err := recorder.SetResource(source, logicalPath, canonicalPath); err != nil {
		return err
	}
	if targetCanonicalPath != "" {
		if err := recorder.SetTarget(targetSource, targetLogicalPath, targetCanonicalPath); err != nil {
			return err
		}
	}
	return recorder.MergeMetadata(metadata)
}

func prepareResourceWriteAuditAction(request *http.Request, action auditdb.Action, metadata *auditdb.MetadataV1) error {
	recorder := AuditRecorderFromRequest(request)
	if recorder == nil {
		return nil
	}
	if err := recorder.SetAction(action); err != nil {
		return err
	}
	return recorder.MergeMetadata(metadata)
}

func setResourceWriteAuditPaths(
	request *http.Request,
	source, logicalPath, canonicalPath string,
	targetSource, targetLogicalPath, targetCanonicalPath string,
) error {
	recorder := AuditRecorderFromRequest(request)
	if recorder == nil {
		return nil
	}
	if err := recorder.SetResource(source, logicalPath, canonicalPath); err != nil {
		return err
	}
	if targetCanonicalPath == "" {
		return nil
	}
	return recorder.SetTarget(targetSource, targetLogicalPath, targetCanonicalPath)
}

func mergeResourceWriteAuditMetadata(request *http.Request, metadata *auditdb.MetadataV1) error {
	recorder := AuditRecorderFromRequest(request)
	if recorder == nil {
		return nil
	}
	return recorder.MergeMetadata(metadata)
}

func reserveResourceWriteAudit(request *http.Request) error {
	recorder := AuditRecorderFromRequest(request)
	if recorder == nil {
		return nil
	}
	return recorder.ReservePending()
}

func resourceWriteAuditMetadata(method auditdb.Method, itemCount int64) *auditdb.MetadataV1 {
	zero := int64(0)
	return &auditdb.MetadataV1{
		SchemaVersion: auditdb.CurrentMetadataSchemaVersion,
		Method:        method,
		ItemCount:     &itemCount,
		SuccessCount:  &zero,
		FailedCount:   &zero,
		DeniedCount:   &zero,
	}
}

func resourceWriteAuditOutcomeMetadata(itemCount, successCount, failedCount, deniedCount int64) *auditdb.MetadataV1 {
	return &auditdb.MetadataV1{
		SchemaVersion: auditdb.CurrentMetadataSchemaVersion,
		ItemCount:     &itemCount,
		SuccessCount:  &successCount,
		FailedCount:   &failedCount,
		DeniedCount:   &deniedCount,
	}
}

func resourceAuditAccessDenied(err error) bool {
	return stderrors.Is(err, errors.ErrAccessDenied) ||
		stderrors.Is(err, errors.ErrPermissionDenied) || os.IsPermission(err)
}

func resolveResourceAuditWriteTarget(user *users.User, source, requestedPath string) (authenticatedReadTarget, error) {
	target, err := resolveAuthenticatedWriteTarget(user, source, requestedPath)
	if err == nil || (!stderrors.Is(err, errors.ErrNotExist) && !os.IsNotExist(err)) {
		return target, err
	}

	safePath, err := sanitizeAuthenticatedReadPath(requestedPath)
	if err != nil {
		return target, err
	}
	idx, userScope, err := authenticatedReadScope(user, source)
	if err != nil {
		return target, err
	}
	logicalPath := normalizePublicShareIndexPath(utils.JoinPathAsUnix(userScope, safePath))
	if store.Access == nil || !publicSharePathWithin(userScope, logicalPath) ||
		!store.Access.PermittedFresh(idx.Path, logicalPath, user.Username) {
		return target, errors.ErrAccessDenied
	}

	remaining := []string{path.Base(safePath)}
	parentPath := path.Dir(safePath)
	for {
		parent, parentErr := resolveAuthenticatedBrowseTarget(user, source, parentPath)
		if parentErr == nil {
			if parent.Info == nil || !parent.Info.IsDir() {
				return target, errors.ErrAccessDenied
			}
			relativeSuffix := path.Join(remaining...)
			canonicalPath := normalizePublicShareIndexPath(path.Join(parent.CanonicalPath, relativeSuffix))
			realPath := filepath.Join(parent.RealPath, filepath.FromSlash(relativeSuffix))
			if !publicSharePathWithin(userScope, canonicalPath) ||
				!store.Access.PermittedFresh(idx.Path, canonicalPath, user.Username) ||
				!publicShareRealPathWithin(parent.SourceReal, realPath) ||
				!publicShareRealPathWithin(parent.ScopeReal, realPath) {
				return target, errors.ErrAccessDenied
			}
			scopedPath, scopedErr := publicShareScopedPath(userScope, canonicalPath)
			if scopedErr != nil {
				return target, scopedErr
			}
			return authenticatedReadTarget{
				Index:         idx,
				SourcePath:    idx.Path,
				SourceReal:    parent.SourceReal,
				UserScope:     userScope,
				ScopeReal:     parent.ScopeReal,
				ScopeInfo:     parent.ScopeInfo,
				RequestedPath: safePath,
				LogicalPath:   logicalPath,
				LogicalAccess: true,
				CanonicalPath: canonicalPath,
				EntryPath:     canonicalPath,
				ScopedPath:    scopedPath,
				RealPath:      realPath,
			}, nil
		}
		if !stderrors.Is(parentErr, errors.ErrNotExist) && !os.IsNotExist(parentErr) {
			return target, parentErr
		}
		if parentPath == "/" || parentPath == "." {
			return target, parentErr
		}
		remaining = append([]string{path.Base(parentPath)}, remaining...)
		parentPath = path.Dir(parentPath)
	}
}

func resourceAuditWriteTarget(d *requestContext, source, requestedPath string) (authenticatedReadTarget, error) {
	if d.share != nil && len(d.shareTargets) != 0 {
		shareTarget := d.shareTargets[0]
		return authenticatedReadTarget{
			RequestedPath: shareTarget.RequestedPath,
			LogicalPath:   shareTarget.LogicalPath,
			CanonicalPath: shareTarget.CanonicalPath,
			RealPath:      shareTarget.RealPath,
			Info:          shareTarget.info,
		}, nil
	}
	return resolveResourceAuditWriteTarget(d.user, source, requestedPath)
}

func resourceAuditCanonicalPath(idx *indexing.Index, realPath string) (string, error) {
	if idx == nil {
		return "", errors.ErrAccessDenied
	}
	sourceReal, err := filepath.EvalSymlinks(idx.Path)
	if err != nil {
		return "", err
	}
	targetAbsolute, err := filepath.Abs(realPath)
	if err != nil || !publicShareRealPathWithin(sourceReal, targetAbsolute) {
		return "", errors.ErrAccessDenied
	}
	relative, err := filepath.Rel(sourceReal, targetAbsolute)
	if err != nil || filepath.IsAbs(relative) {
		return "", errors.ErrAccessDenied
	}
	relative = publicShareCanonicalCaseRelative(sourceReal, relative)
	canonicalPath := normalizePublicShareIndexPath(filepath.ToSlash(relative))
	if canonicalPath == "/" {
		return "", errors.ErrAccessDenied
	}
	return canonicalPath, nil
}

func sameResourceAuditWriteTarget(original, current authenticatedReadTarget) bool {
	if original.Index == nil || current.Index == nil || original.ScopeInfo == nil || current.ScopeInfo == nil {
		return false
	}
	if original.Index.Name != current.Index.Name || original.SourcePath != current.SourcePath ||
		original.UserScope != current.UserScope || original.LogicalPath != current.LogicalPath ||
		original.CanonicalPath != current.CanonicalPath ||
		!publicShareSameRealPath(original.SourceReal, current.SourceReal) ||
		!publicShareSameRealPath(original.ScopeReal, current.ScopeReal) ||
		!publicShareSameRealPath(original.RealPath, current.RealPath) ||
		!os.SameFile(original.ScopeInfo, current.ScopeInfo) {
		return false
	}
	if original.Info == nil || current.Info == nil {
		return original.Info == nil && current.Info == nil
	}
	return original.Info.Mode().Type() == current.Info.Mode().Type() && os.SameFile(original.Info, current.Info)
}

func samePublicShareAuditWriteTarget(original, current publicShareTarget, currentExists bool) bool {
	originalExists := original.info != nil
	if originalExists != currentExists || original.RequestedPath != current.RequestedPath ||
		original.LogicalPath != current.LogicalPath || original.CanonicalPath != current.CanonicalPath ||
		original.ScopedPath != current.ScopedPath ||
		!publicShareSameRealPath(original.RealPath, current.RealPath) {
		return false
	}
	if !originalExists {
		return true
	}
	return current.info != nil && original.IsDir == current.IsDir &&
		original.info.Mode().Type() == current.info.Mode().Type() && os.SameFile(original.info, current.info)
}

func resourceAuditWritePreCommit(
	d *requestContext,
	source, requestedPath string,
	original authenticatedReadTarget,
) func() error {
	if d.share != nil && len(d.shareTargets) != 0 {
		shareTarget := d.shareTargets[0]
		idx := indexing.GetIndex(source)
		return func() error {
			if idx == nil {
				return errResourceAuditTargetChanged
			}
			current, exists, err := authorizePublicShareWriteTarget(d, idx.Path, shareTarget.RequestedPath)
			if err != nil || !samePublicShareAuditWriteTarget(shareTarget, current, exists) {
				return errResourceAuditTargetChanged
			}
			return nil
		}
	}
	return func() error {
		current, err := resolveResourceAuditWriteTarget(d.user, source, requestedPath)
		if err != nil || !sameResourceAuditWriteTarget(original, current) {
			return errResourceAuditTargetChanged
		}
		return nil
	}
}

// validateMoveOperation checks if a move/rename operation is valid at the HTTP level
// It prevents moving a directory into itself or its subdirectories
func validateMoveOperation(src, dst string, isSrcDir bool) error {
	// Clean and normalize paths
	src = filepath.Clean(src)
	dst = filepath.Clean(dst)

	// If source is a directory, check if destination is within source
	if isSrcDir {
		// Get the parent directory of the destination
		dstParent := filepath.Dir(dst)

		// Check if destination parent is the source directory or a subdirectory of it
		if strings.HasPrefix(dstParent+string(filepath.Separator), src+string(filepath.Separator)) || dstParent == src {
			return fmt.Errorf("cannot move directory '%s' to a location within itself: '%s'", src, dst)
		}
	}

	// Check if destination parent directory exists
	dstParent := filepath.Dir(dst)
	if dstParent != "." && dstParent != "/" {
		if _, err := os.Stat(dstParent); os.IsNotExist(err) {
			return fmt.Errorf("destination directory does not exist: '%s'", dstParent)
		}
	}

	return nil
}

// resourceGetHandler retrieves information about a resource.
// @Summary Get resource information
// @Description Returns metadata and optionally file contents for a specified resource path.
// @Tags Resources
// @Accept json
// @Produce json
// @Param path query string true "Path to the resource"
// @Param skipExtendedAttrs query string false "When true, omit index-level extended fields (e.g. hasPreview); does not disable ffmpeg/media extraction"
// @Param source query string true "Source name for the desired source, default is used if not provided"
// @Param content query string false "Include file content if true"
// @Param metadata query string false "When true, run audio/video metadata extraction, subtitles, and directory media batch processing"
// @Param checksum query string false "Optional checksum validation"
// @Success 200 {object} iteminfo.FileInfo "Resource metadata"
// @Failure 404 {object} map[string]string "Resource not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/resources [get]
func resourceGetHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if !d.user.Permissions.Browse {
		return http.StatusForbidden, fmt.Errorf("user is not allowed to browse resources")
	}

	path, err := sanitizeAuthenticatedReadPath(r.URL.Query().Get("path"))
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("invalid resource path: %v", err)
	}
	source := r.URL.Query().Get("source")
	getContent := r.URL.Query().Get("content") == "true"
	checksumAlgo := r.URL.Query().Get("checksum")
	getMetadata := r.URL.Query().Get("metadata") == "true"
	if (getContent || checksumAlgo != "") && !d.user.Permissions.Download {
		return http.StatusForbidden, fmt.Errorf("user is not allowed to read resource contents")
	}
	readUser, err := currentAuthenticatedReadUser(d.user, d.token)
	if err != nil || !readUser.Permissions.Browse || ((getContent || checksumAlgo != "") && !readUser.Permissions.Download) {
		return http.StatusForbidden, errors.ErrAccessDenied
	}
	canReadMetadata := getMetadata && readUser.Permissions.Preview
	target, err := resolveAuthenticatedBrowseTarget(readUser, source, path)
	if err != nil {
		return errToStatus(err), err
	}
	skipExtendedAttrs := r.URL.Query().Get("skipExtendedAttrs") == "true"
	fileOpts := utils.FileOptions{
		FollowSymlinks:           false,
		Path:                     target.ScopedPath,
		Source:                   source,
		Expand:                   true,
		Content:                  false,
		ExtractEmbeddedSubtitles: config.Integrations.Media.ExtractEmbeddedSubtitles,
		ShowHidden:               readUser.ShowHidden,
		HideFileExt:              readUser.HideFileExt,
		SkipExtendedAttrs:        skipExtendedAttrs,
		ShowSharedAttr:           true,
		ShowPinnedItems:          true,
	}
	fileInfo, err := files.FileInfoFaster(fileOpts, store.Access, readUser, store.Share)
	if err != nil {
		err = normalizeAuthenticatedResourceError(err)
		return errToStatus(err), err
	}
	applyAuthenticatedFileInfoIdentity(fileInfo, target)
	if err = filterAuthenticatedDirectoryFileInfo(readUser, source, target, fileInfo); err != nil {
		return http.StatusForbidden, errors.ErrAccessDenied
	}
	isAudio := strings.HasPrefix(fileInfo.Type, "audio")
	isVideo := strings.HasPrefix(fileInfo.Type, "video")
	protectedMediaTargets := make([]authenticatedReadTarget, 0)
	if fileInfo.Type == "directory" && canReadMetadata {
		protectedMediaTargets, err = enrichAuthenticatedResourceDirectoryMetadata(fileInfo, fileOpts, d, source, path, target)
		if err != nil {
			return http.StatusForbidden, errors.ErrAccessDenied
		}
	} else if (isAudio || isVideo) && canReadMetadata {
		readUser, err = revalidateAuthenticatedResourceRead(d, source, path, target, nil, getContent, canReadMetadata)
		if err != nil {
			return http.StatusForbidden, errors.ErrAccessDenied
		}
		snapshotPath, _, cleanup, snapshotErr := snapshotAuthenticatedReadTarget(target)
		if snapshotErr != nil {
			return errToStatus(snapshotErr), snapshotErr
		}
		if _, err = revalidateAuthenticatedResourceRead(d, source, path, target, nil, getContent, canReadMetadata); err != nil {
			cleanup()
			return http.StatusForbidden, errors.ErrAccessDenied
		}
		mediaOpts := fileOpts
		mediaOpts.Expand = false
		mediaOpts.Metadata = canReadMetadata
		mediaOpts.ReadPath = snapshotPath
		mediaOpts.SkipExtendedAttrs = false
		fileInfo, err = files.FileInfoFaster(mediaOpts, store.Access, readUser, store.Share)
		cleanup()
		if err != nil {
			err = normalizeAuthenticatedResourceError(err)
			return errToStatus(err), err
		}
		applyAuthenticatedFileInfoIdentity(fileInfo, target)
		protectedMediaTargets = append(protectedMediaTargets, authenticatedMediaSidecarTargets(fileInfo, source, target, readUser)...)
	}
	if getContent && fileInfo.Type != "directory" {
		_, err = revalidateAuthenticatedResourceRead(d, source, path, target, nil, true, false)
		if err != nil {
			return http.StatusForbidden, errors.ErrAccessDenied
		}
		fileInfo.Content, err = readAuthenticatedTextContent(target)
		if err != nil {
			return errToStatus(err), err
		}
	}

	if !getContent {
		fileInfo.Content = ""
	}
	if fileInfo.Type != "directory" && checksumAlgo != "" {
		_, err = revalidateAuthenticatedResourceRead(d, source, path, target, nil, true, false)
		if err != nil {
			return http.StatusForbidden, errors.ErrAccessDenied
		}
		checksum, checksumErr := checksumAuthenticatedReadTarget(target, checksumAlgo)
		if checksumErr == errors.ErrInvalidOption {
			return http.StatusBadRequest, nil
		} else if checksumErr != nil {
			return http.StatusInternalServerError, checksumErr
		}
		fileInfo.Checksums = make(map[string]string)
		fileInfo.Checksums[checksumAlgo] = checksum
	}
	responseUser, err := revalidateAuthenticatedResourceRead(d, source, path, target, protectedMediaTargets, getContent || checksumAlgo != "", canReadMetadata)
	if err != nil {
		return http.StatusForbidden, errors.ErrAccessDenied
	}
	currentTarget, err := resolveAuthenticatedBrowseTarget(responseUser, source, path)
	if err != nil || !sameAuthenticatedReadTarget(target, currentTarget) {
		return http.StatusForbidden, errors.ErrAccessDenied
	}
	if err = filterAuthenticatedDirectoryFileInfo(responseUser, source, currentTarget, fileInfo); err != nil {
		return http.StatusForbidden, errors.ErrAccessDenied
	}
	if err = setCoreFileAuditReadTarget(r, currentTarget, nil); err != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
	}
	if !responseUser.Permissions.Preview {
		fileInfo.Metadata = nil
		fileInfo.Subtitles = nil
		for i := range fileInfo.Files {
			fileInfo.Files[i].Metadata = nil
		}
	}
	return renderJSON(w, r, fileInfo)

}

func normalizeAuthenticatedResourceError(err error) error {
	return normalizeAuthenticatedReadError(err)
}

func applyAuthenticatedFileInfoIdentity(fileInfo *iteminfo.ExtendedFileInfo, target authenticatedReadTarget) {
	fileInfo.Path = target.RequestedPath
	fileInfo.RealPath = target.RealPath
	if target.Info != nil {
		fileInfo.Size = target.Info.Size()
		fileInfo.ModTime = target.Info.ModTime()
	}
	logicalMatchesCanonical := publicSharePathWithin(target.LogicalPath, target.CanonicalPath) &&
		publicSharePathWithin(target.CanonicalPath, target.LogicalPath)
	if !logicalMatchesCanonical {
		fileInfo.Name = authenticatedReadTargetName(target, fileInfo.Name)
	}
}

func filterAuthenticatedDirectoryFileInfo(user *users.User, source string, directoryTarget authenticatedReadTarget, fileInfo *iteminfo.ExtendedFileInfo) error {
	if fileInfo == nil || fileInfo.Type != "directory" {
		return nil
	}
	filteredFiles := fileInfo.Files[:0]
	for _, child := range fileInfo.Files {
		childPath := utils.JoinPathAsUnix(directoryTarget.LogicalPath, child.Name)
		childTarget, err := resolveAuthenticatedReadIndexTarget(user, source, childPath)
		if err != nil || childTarget.Info == nil || childTarget.Info.IsDir() {
			continue
		}
		child.Size = childTarget.Info.Size()
		child.ModTime = childTarget.Info.ModTime()
		filteredFiles = append(filteredFiles, child)
	}
	fileInfo.Files = filteredFiles

	filteredFolders := fileInfo.Folders[:0]
	for _, child := range fileInfo.Folders {
		childPath := utils.JoinPathAsUnix(directoryTarget.LogicalPath, child.Name)
		childTarget, err := resolveAuthenticatedReadIndexTarget(user, source, childPath)
		if err != nil || childTarget.Info == nil || !childTarget.Info.IsDir() {
			continue
		}
		child.Size = childTarget.Info.Size()
		child.ModTime = childTarget.Info.ModTime()
		filteredFolders = append(filteredFolders, child)
	}
	fileInfo.Folders = filteredFolders
	if !directoryTarget.LogicalAccess && len(fileInfo.Files)+len(fileInfo.Folders) == 0 {
		return errors.ErrAccessDenied
	}
	return nil
}

func filterAuthenticatedDirectoryItems(user *users.User, source string, directoryTarget authenticatedReadTarget, items files.Items) (files.Items, error) {
	filtered := files.Items{}
	for _, name := range items.Files {
		childPath := utils.JoinPathAsUnix(directoryTarget.LogicalPath, name)
		childTarget, err := resolveAuthenticatedReadIndexTarget(user, source, childPath)
		if err == nil && childTarget.Info != nil && !childTarget.Info.IsDir() {
			filtered.Files = append(filtered.Files, name)
		}
	}
	for _, name := range items.Folders {
		childPath := utils.JoinPathAsUnix(directoryTarget.LogicalPath, name)
		childTarget, err := resolveAuthenticatedReadIndexTarget(user, source, childPath)
		if err == nil && childTarget.Info != nil && childTarget.Info.IsDir() {
			filtered.Folders = append(filtered.Folders, name)
		}
	}
	if !directoryTarget.LogicalAccess && len(filtered.Files)+len(filtered.Folders) == 0 {
		return filtered, errors.ErrAccessDenied
	}
	return filtered, nil
}

func enrichAuthenticatedResourceDirectoryMetadata(fileInfo *iteminfo.ExtendedFileInfo, fileOpts utils.FileOptions, d *requestContext, source, requestedPath string, directoryTarget authenticatedReadTarget) ([]authenticatedReadTarget, error) {
	protectedTargets := make([]authenticatedReadTarget, 0)
	for i := range fileInfo.Files {
		child := &fileInfo.Files[i]
		if !strings.HasPrefix(child.Type, "audio") && !strings.HasPrefix(child.Type, "video") {
			continue
		}
		currentUser, err := currentAuthenticatedReadUser(d.user, d.token)
		if err != nil || !currentUser.Permissions.Browse || !currentUser.Permissions.Preview {
			return nil, errors.ErrAccessDenied
		}
		currentDirectory, err := resolveAuthenticatedBrowseTarget(currentUser, source, requestedPath)
		if err != nil || !sameAuthenticatedReadTarget(directoryTarget, currentDirectory) {
			return nil, errors.ErrAccessDenied
		}
		childPath := utils.JoinPathAsUnix(currentDirectory.LogicalPath, child.Name)
		childTarget, err := resolveAuthenticatedReadIndexTarget(currentUser, source, childPath)
		if err != nil {
			continue
		}
		snapshotPath, _, cleanup, err := snapshotAuthenticatedReadTarget(childTarget)
		if err != nil {
			continue
		}
		if _, err = revalidateAuthenticatedResourceRead(d, source, requestedPath, directoryTarget, []authenticatedReadTarget{childTarget}, false, true); err != nil {
			cleanup()
			return nil, errors.ErrAccessDenied
		}
		childOpts := fileOpts
		childOpts.Path = childTarget.ScopedPath
		childOpts.Expand = false
		childOpts.Content = false
		childOpts.Metadata = true
		childOpts.ReadPath = snapshotPath
		childOpts.SkipExtendedAttrs = false
		enriched, err := files.FileInfoFaster(childOpts, store.Access, currentUser, store.Share)
		cleanup()
		if err != nil {
			continue
		}
		child.Metadata = enriched.Metadata
		protectedTargets = append(protectedTargets, childTarget)
		protectedTargets = append(protectedTargets, authenticatedMediaSidecarTargets(enriched, source, childTarget, currentUser)...)
	}
	return protectedTargets, nil
}

func revalidateAuthenticatedResourceRead(d *requestContext, source, requestedPath string, target authenticatedReadTarget, mediaTargets []authenticatedReadTarget, requireDownload, requirePreview bool) (*users.User, error) {
	currentUser, err := currentAuthenticatedReadUser(d.user, d.token)
	if err != nil || !currentUser.Permissions.Browse || requireDownload && !currentUser.Permissions.Download || requirePreview && !currentUser.Permissions.Preview {
		return nil, errors.ErrAccessDenied
	}
	currentTarget, err := resolveAuthenticatedBrowseTarget(currentUser, source, requestedPath)
	if err != nil || !sameAuthenticatedReadTarget(target, currentTarget) {
		return nil, errors.ErrAccessDenied
	}
	for _, mediaTarget := range mediaTargets {
		currentMediaTarget, err := resolveAuthenticatedReadIndexTarget(currentUser, source, mediaTarget.LogicalPath)
		if err != nil || !sameAuthenticatedReadTarget(mediaTarget, currentMediaTarget) {
			return nil, errors.ErrAccessDenied
		}
	}
	return currentUser, nil
}

// resourceDeleteHandler deletes a resource at a specified path.
// @Summary Delete a resource
// @Description Deletes a resource located at the specified path.
// @Tags Resources
// @Accept json
// @Produce json
// @Param path query string true "Path to the resource"
// @Param source query string true "Source name for the desired source, default is used if not provided"
// @Success 200 "Resource deleted successfully"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 404 {object} map[string]string "Resource not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/resources [delete]
func resourceDeleteHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {

	if !d.user.Permissions.Delete {
		return http.StatusForbidden, fmt.Errorf("user is not allowed to delete")
	}
	path := r.URL.Query().Get("path")
	source := r.URL.Query().Get("source")

	if path == "/" {
		return http.StatusForbidden, fmt.Errorf("cannot delete your user's root directory")
	}

	idx := indexing.GetIndex(source)
	if idx == nil {
		return http.StatusNotFound, fmt.Errorf("source %s not found", source)
	}

	if idx.Config.ReadOnly {
		return http.StatusForbidden, fmt.Errorf("source is read-only")
	}

	fileInfo, err := files.FileInfoFaster(utils.FileOptions{
		Path:        path,
		Source:      source,
		Expand:      false,
		ShowHidden:  d.user.ShowHidden,
		HideFileExt: d.user.HideFileExt,
	}, store.Access, d.user, store.Share)
	if err != nil {
		return errToStatus(err), err
	}
	if AuditRecorderFromRequest(r) != nil {
		auditTarget, auditErr := resolveAuthenticatedReadTarget(d.user, source, path)
		if auditErr != nil {
			return errToStatus(auditErr), auditErr
		}
		metadata := resourceWriteAuditMetadata(auditdb.MethodDELETE, 1)
		if auditErr = prepareResourceWriteAudit(r, auditdb.ActionFileDelete,
			source, auditTarget.LogicalPath, auditTarget.CanonicalPath, "", "", "", metadata); auditErr != nil {
			return http.StatusServiceUnavailable, ErrAuditUnavailable
		}
		if auditErr = reserveResourceWriteAudit(r); auditErr != nil {
			return http.StatusServiceUnavailable, ErrAuditUnavailable
		}
	}

	// delete thumbnails
	preview.DelThumbs(r.Context(), *fileInfo)

	err = files.DeleteFiles(source, fileInfo.RealPath, fileInfo.Type == "directory")
	if err != nil {
		_ = mergeResourceWriteAuditMetadata(r, resourceWriteAuditOutcomeMetadata(1, 0, 1, 0))
		return errToStatus(err), err
	}
	_ = mergeResourceWriteAuditMetadata(r, resourceWriteAuditOutcomeMetadata(1, 1, 0, 0))
	return http.StatusOK, nil

}

// BulkDeleteItem represents a single item in a bulk delete request
type BulkDeleteItem struct {
	Source  string `json:"source"`
	Path    string `json:"path"`
	Message string `json:"message,omitempty"`
}

// BulkDeleteResponse represents the response from a bulk delete operation
type BulkDeleteResponse struct {
	Succeeded []BulkDeleteItem `json:"succeeded"`
	Failed    []BulkDeleteItem `json:"failed"`
}

// MoveCopyItem represents a single item in a move/copy request
type MoveCopyItem struct {
	FromSource string `json:"fromSource,omitempty"`
	FromPath   string `json:"fromPath,omitempty"`
	ToSource   string `json:"toSource,omitempty"`
	ToPath     string `json:"toPath,omitempty"`
	Message    string `json:"message,omitempty"`
}

// MoveCopyRequest represents a move/copy operation request
type MoveCopyRequest struct {
	Items     []MoveCopyItem `json:"items"`
	Action    string         `json:"action"`    // "copy", "move", or "rename"
	Overwrite bool           `json:"overwrite"` // Overwrite if destination exists
	Rename    bool           `json:"rename"`    // Auto-rename if destination exists
}

// MoveCopyResponse represents the response from a move/copy operation
type MoveCopyResponse struct {
	Succeeded []MoveCopyItem `json:"succeeded"`
	Failed    []MoveCopyItem `json:"failed"`
}

// resourceBulkDeleteHandler deletes multiple resources in a single request.
// @Summary Bulk delete resources
// @Description Deletes multiple resources specified in the request body. Returns a list of succeeded and failed deletions.
// @Tags Resources
// @Accept json
// @Produce json
// @Param items body []BulkDeleteItem true "Array of items to delete, each with source and path"
// @Success 200 {object} BulkDeleteResponse "All resources deleted successfully"
// @Success 207 {object} BulkDeleteResponse "Partial success - some resources deleted, some failed"
// @Failure 400 {object} map[string]string "Bad request - invalid JSON or empty items array"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 500 {object} map[string]string "Internal server error - all deletions failed"
// @Router /api/resources/bulk [delete]
func resourceBulkDeleteHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	filePermUser := d.user
	if d.share != nil {
		filePermUser = d.shareUser
	}
	// Check permissions - either user delete permission or share delete permission
	if d.share == nil {
		if !d.user.Permissions.Delete {
			return http.StatusForbidden, fmt.Errorf("user is not allowed to delete")
		}
	}

	// Parse request body
	var items []BulkDeleteItem
	if err := json.NewDecoder(r.Body).Decode(&items); err != nil {
		return http.StatusBadRequest, fmt.Errorf("invalid JSON body: %v", err)
	}

	if len(items) == 0 {
		return http.StatusBadRequest, fmt.Errorf("items array cannot be empty")
	}

	response := BulkDeleteResponse{
		Succeeded: make([]BulkDeleteItem, 0),
		Failed:    make([]BulkDeleteItem, 0),
	}
	itemCount := int64(len(items))
	auditEnabled := AuditRecorderFromRequest(r) != nil
	if err := prepareResourceWriteAuditAction(r, auditdb.ActionFileDelete,
		resourceWriteAuditMetadata(auditdb.MethodDELETE, itemCount)); err != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
	}
	auditReserved := false
	auditDeniedCount := int64(0)
	defer func() {
		successCount := int64(len(response.Succeeded))
		failedCount := int64(len(response.Failed)) - auditDeniedCount
		if failedCount < 0 {
			failedCount = 0
		}
		_ = mergeResourceWriteAuditMetadata(r,
			resourceWriteAuditOutcomeMetadata(itemCount, successCount, failedCount, auditDeniedCount))
	}()

	// Process each item one at a time
	for _, item := range items {
		rawPath := item.Path
		// Validate item
		if rawPath == "" {
			response.Failed = append(response.Failed, BulkDeleteItem{
				Source:  item.Source,
				Path:    rawPath,
				Message: "path was empty",
			})
			continue
		}

		// Prevent deletion of root
		if rawPath == "/" {
			response.Failed = append(response.Failed, BulkDeleteItem{
				Source:  item.Source,
				Path:    rawPath,
				Message: "cannot delete root directory",
			})
			continue
		}
		sanitizedPath, err := utils.SanitizeUserPath(rawPath)
		if err != nil {
			response.Failed = append(response.Failed, BulkDeleteItem{
				Source:  item.Source,
				Path:    sanitizedPath,
				Message: err.Error(),
			})
			continue
		}

		if d.share != nil {
			sourceName := d.share.GetSourceName()
			if sourceName == "" {
				response.Failed = append(response.Failed, BulkDeleteItem{
					Source:  item.Source,
					Path:    sanitizedPath,
					Message: "source name is empty",
				})
				continue
			}

			idx := indexing.GetIndex(sourceName)
			if idx == nil {
				response.Failed = append(response.Failed, BulkDeleteItem{
					Source:  item.Source,
					Path:    sanitizedPath,
					Message: "source not found",
				})
				continue
			}

			if idx.Config.ReadOnly {
				auditDeniedCount++
				response.Failed = append(response.Failed, BulkDeleteItem{
					Source:  item.Source,
					Path:    sanitizedPath,
					Message: "source is read-only",
				})
				continue
			}

			// get user scope path from share
			userScope, err := d.shareUser.GetScopeForSourceName(sourceName)
			if err != nil {
				auditDeniedCount++
				response.Failed = append(response.Failed, BulkDeleteItem{
					Source:  item.Source,
					Path:    sanitizedPath,
					Message: "user does not have access",
				})
				continue
			}
			withoutUserScope := strings.TrimPrefix(d.share.Path, userScope)
			indexPath := utils.JoinPathAsUnix(withoutUserScope, sanitizedPath)

			fileInfo, err := files.FileInfoFaster(utils.FileOptions{
				FollowSymlinks: true,
				Path:           indexPath,
				Source:         sourceName,
				ShowHidden:     true,
			}, store.Access, filePermUser, store.Share)
			if err != nil {
				return http.StatusNotFound, fmt.Errorf("resource not available")
			}

			// Delete the file/directory
			err = files.DeleteFiles(sourceName, fileInfo.RealPath, fileInfo.Type == "directory")
			if err != nil {
				logger.Errorf("resource bulk delete handler: error deleting file/directory: %v", err)
				response.Failed = append(response.Failed, BulkDeleteItem{
					Source:  item.Source,
					Path:    sanitizedPath,
					Message: "error deleting file/directory, admin must check the logs",
				})
				continue
			}
			// Delete thumbnails
			preview.DelThumbs(r.Context(), *fileInfo)
		} else {
			// Regular user context - validate source and check user scope
			if item.Source == "" {
				response.Failed = append(response.Failed, BulkDeleteItem{
					Source:  item.Source,
					Path:    sanitizedPath,
					Message: "source was empty, source is required",
				})
				continue
			}

			// Check user scope for this source
			_, err := filePermUser.GetScopeForSourceName(item.Source)
			if err != nil {
				auditDeniedCount++
				response.Failed = append(response.Failed, BulkDeleteItem{
					Source:  item.Source,
					Path:    sanitizedPath,
					Message: fmt.Sprintf("user does not have access: %v", err),
				})
				continue
			}

			idx := indexing.GetIndex(item.Source)
			if idx == nil {
				response.Failed = append(response.Failed, BulkDeleteItem{
					Source:  item.Source,
					Path:    sanitizedPath,
					Message: "source not found",
				})
				continue
			}

			if idx.Config.ReadOnly {
				auditDeniedCount++
				response.Failed = append(response.Failed, BulkDeleteItem{
					Source:  item.Source,
					Path:    sanitizedPath,
					Message: "source is read-only",
				})
				continue
			}

			// Get file info
			fileInfo, err := files.FileInfoFaster(utils.FileOptions{
				FollowSymlinks: true,
				Path:           sanitizedPath,
				Source:         item.Source,
				ShowHidden:     true,
			}, store.Access, filePermUser, store.Share)
			if err != nil {
				if resourceAuditAccessDenied(err) {
					auditDeniedCount++
				}
				response.Failed = append(response.Failed, BulkDeleteItem{
					Source:  item.Source,
					Path:    sanitizedPath,
					Message: err.Error(),
				})
				continue
			}
			if auditEnabled && !auditReserved {
				auditTarget, auditErr := resolveAuthenticatedReadTarget(filePermUser, item.Source, sanitizedPath)
				if auditErr != nil {
					if resourceAuditAccessDenied(auditErr) {
						auditDeniedCount++
					}
					response.Failed = append(response.Failed, BulkDeleteItem{
						Source: item.Source, Path: sanitizedPath, Message: "resource path is unavailable",
					})
					continue
				}
				if auditErr = setResourceWriteAuditPaths(r, item.Source,
					auditTarget.LogicalPath, auditTarget.CanonicalPath, "", "", ""); auditErr != nil {
					return http.StatusServiceUnavailable, ErrAuditUnavailable
				}
				if auditErr = reserveResourceWriteAudit(r); auditErr != nil {
					return http.StatusServiceUnavailable, ErrAuditUnavailable
				}
				auditReserved = true
			}
			err = files.DeleteFiles(item.Source, fileInfo.RealPath, fileInfo.Type == "directory")
			if err != nil {
				response.Failed = append(response.Failed, BulkDeleteItem{
					Source:  item.Source,
					Path:    sanitizedPath,
					Message: err.Error(),
				})
				continue
			}
			preview.DelThumbs(r.Context(), *fileInfo)
		}
		// Success
		response.Succeeded = append(response.Succeeded, item)
	}

	// Determine status code based on results
	statusCode := http.StatusOK
	if len(response.Failed) > 0 {
		statusCode = http.StatusMultiStatus
	}

	return renderJSON(w, r, response, statusCode)
}

// resourcePauseHandler registers a graceful pause for an in-flight chunked upload.
// Call immediately before aborting the chunk POST so the server keeps partial data.
// @Summary Register graceful chunked upload pause
// @Description Sets a short-lived server flag for the given source and path. When the active chunk POST then fails (e.g. client abort), the server trims the incomplete chunk but keeps the temp partial file for resume.
// @Tags Resources
// @Accept json
// @Produce json
// @Param path query string true "Destination path (same as upload)"
// @Param source query string true "Source name (same as upload)"
// @Success 200 "Pause registered"
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 404 {object} map[string]string "Source not found"
// @Router /api/resources/pause [post]
func resourcePauseHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if d.share != nil {
		return http.StatusBadRequest, fmt.Errorf("use public pause endpoint for share uploads")
	}
	if !d.user.Permissions.Create {
		return http.StatusForbidden, fmt.Errorf("user is not allowed to pause uploads")
	}
	path := r.URL.Query().Get("path")
	source := r.URL.Query().Get("source")
	cleanPath, err := utils.SanitizeUserPath(path)
	if err != nil {
		return http.StatusBadRequest, err
	}
	path = cleanPath
	idx := indexing.GetIndex(source)
	if idx == nil {
		logger.Debugf("source %s not found", source)
		return http.StatusNotFound, fmt.Errorf("source %s not found", source)
	}
	if _, err := d.user.GetScopeForSourceName(source); err != nil {
		return http.StatusForbidden, err
	}
	if !store.Access.Permitted(idx.Path, path, d.user.Username) {
		return http.StatusForbidden, fmt.Errorf("access denied to path %s", path)
	}
	pauseCache.Set(chunkUploadPauseKey(d, source, path), "1")
	return http.StatusOK, nil
}

// publicPauseHandler registers a graceful pause for a public share chunked upload.
// @Summary Register graceful chunked upload pause (public share)
// @Description Same as authenticated pause, for upload shares. Uses hash and path query parameters like other public resource APIs.
// @Tags Shares
// @Accept json
// @Produce json
// @Param hash query string true "Share hash"
// @Param path query string true "Path within the share (same as upload)"
// @Success 200 "Pause registered"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 404 {object} map[string]string "Source not found"
// @Router /public/api/resources/pause [post]
func publicPauseHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if d.share.ShareType != "upload" && !d.share.AllowCreate {
		return http.StatusForbidden, fmt.Errorf("pausing uploads is not allowed for this share")
	}
	src, ok := config.Server.SourceMap[d.share.Source]
	if !ok {
		return http.StatusNotFound, fmt.Errorf("source not found")
	}
	sourceName := src.Name
	publicPauseCache.Set(chunkUploadPauseKey(d, sourceName, d.IndexPath), "1")
	return http.StatusOK, nil
}

// resourcePostHandler creates or uploads a new resource.
// @Summary Create or upload a resource
// @Description Creates a new resource or uploads a file at the specified path. Supports file uploads and directory creation.
// @Tags Resources
// @Accept json
// @Produce json
// @Param path query string true "url encoded destination path where to place the files inside the destination source"
// @Param source query string true "Name for the desired filebrowser destination source name, default is used if not provided"
// @Param override query bool false "Override existing file if true"
// @Param isDir query bool false "Explicitly specify if the resource is a directory"
// @Success 200 "Resource created successfully"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 404 {object} map[string]string "Resource not found"
// @Failure 409 {object} map[string]string "Conflict - Resource already exists"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/resources [post]
func resourcePostHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (status int, returnErr error) {
	path := r.URL.Query().Get("path")
	source := r.URL.Query().Get("source")

	// Rule 1: Validate user-provided path to prevent path traversal
	cleanPath, err := utils.SanitizeUserPath(path)
	if err != nil {
		return http.StatusBadRequest, err
	}
	path = cleanPath

	idx := indexing.GetIndex(source)
	if idx == nil {
		logger.Debugf("source %s not found", source)
		return http.StatusNotFound, fmt.Errorf("source %s not found", source)
	}

	if idx.Config.ReadOnly {
		return http.StatusForbidden, fmt.Errorf("source is read-only")
	}

	filePermUser := d.user
	if d.share != nil {
		filePermUser = d.shareUser
	}
	isDir := r.URL.Query().Get("isDir") == "true"
	fileOpts := utils.FileOptions{
		Path:           path,
		Source:         source,
		Expand:         false,
		FollowSymlinks: true,
	}

	userscope, err := filePermUser.GetScopeForSourceName(source)
	if err != nil {
		logger.Debugf("error getting scope from source name: %v", err)
		return http.StatusForbidden, err
	}
	userscope = strings.TrimRight(userscope, "/")

	fullIndexPath := utils.JoinPathAsUnix(userscope, path)

	// get scoped path
	realPath, _, _ := idx.GetRealPath(fullIndexPath)
	auditEnabled := AuditRecorderFromRequest(r) != nil
	var auditTarget authenticatedReadTarget
	if auditEnabled {
		var auditErr error
		auditTarget, auditErr = resourceAuditWriteTarget(d, source, path)
		if auditErr != nil {
			return errToStatus(auditErr), auditErr
		}
		realPath = auditTarget.RealPath
	}

	// Check access control for the target path
	if !store.Access.Permitted(idx.Path, path, filePermUser.Username) {
		return http.StatusForbidden, fmt.Errorf("access denied to path %s", path)
	}

	chunkOffsetStr := r.Header.Get("X-File-Chunk-Offset")
	unlockTarget, locked := tryLockChunkUploadTarget(realPath)
	if !locked {
		return http.StatusConflict, fmt.Errorf("another upload request is active for this target")
	}
	defer unlockTarget()

	// Check permissions and file/folder conflicts before any write.
	targetExists := false
	if stat, statErr := os.Stat(realPath); statErr == nil {
		targetExists = true
		if d.share == nil && !d.user.Permissions.Modify {
			return http.StatusForbidden, fmt.Errorf("user is not allowed to modify")
		}

		// Path exists, check for type conflicts
		existingIsDir := stat.IsDir()
		requestingDir := isDir

		if r.URL.Query().Get("override") != "true" {
			return http.StatusConflict, nil
		}

		// If type mismatch (file vs folder or folder vs file) and not overriding
		if existingIsDir != requestingDir && r.URL.Query().Get("override") != "true" {
			logger.Debugf("Type conflict detected in chunked: existing is dir=%v, requesting dir=%v at path=%v", existingIsDir, requestingDir, realPath)
			return http.StatusConflict, nil
		}
	} else if os.IsNotExist(statErr) {
		if d.share == nil && !d.user.Permissions.Create {
			return http.StatusForbidden, fmt.Errorf("user is not allowed to create")
		}
	} else {
		return errToStatus(statErr), statErr
	}

	itemCount := int64(1)
	auditBytes := int64(0)
	var auditPreCommit func() error
	if auditEnabled {
		action := auditdb.ActionFileUpload
		if targetExists {
			action = auditdb.ActionFileModify
		}
		overwrite := targetExists
		metadata := resourceWriteAuditMetadata(auditdb.MethodPOST, itemCount)
		metadata.Bytes = &auditBytes
		metadata.Overwrite = &overwrite
		if auditErr := prepareResourceWriteAudit(r, action, source,
			auditTarget.LogicalPath, auditTarget.CanonicalPath, "", "", "", metadata); auditErr != nil {
			return http.StatusServiceUnavailable, ErrAuditUnavailable
		}
		if auditErr := reserveResourceWriteAudit(r); auditErr != nil {
			return http.StatusServiceUnavailable, ErrAuditUnavailable
		}
		auditPreCommit = resourceAuditWritePreCommit(d, source, path, auditTarget)
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
			outcome := resourceWriteAuditOutcomeMetadata(itemCount, successCount, failedCount, deniedCount)
			outcome.Bytes = &auditBytes
			_ = mergeResourceWriteAuditMetadata(r, outcome)
		}()
	}
	if chunkOffsetStr != "" {
		cleanupStaleChunkUploadTemps(filepath.Dir(realPath), realPath)
	}

	// Directories creation on POST.
	if isDir {
		// Create a new FileOptions with the full index path
		dirOpts := fileOpts
		dirOpts.Path = fullIndexPath

		if auditEnabled {
			err = files.WriteDirectoryWithPreCommit(dirOpts, realPath, auditPreCommit)
		} else {
			err = files.WriteDirectory(dirOpts)
		}
		if err != nil {
			if stderrors.Is(err, errResourceAuditTargetChanged) {
				return http.StatusConflict, errResourceAuditTargetChanged
			}
			logger.Debugf("error writing directory: %v", err)
			return errToStatus(err), err
		}

		return http.StatusOK, nil
	}

	// Handle Chunked Uploads
	if chunkOffsetStr != "" {
		offset, parseErr := strconv.ParseInt(chunkOffsetStr, 10, 64)
		if parseErr != nil {
			logger.Debugf("invalid chunk offset: %v", parseErr)
			return http.StatusBadRequest, fmt.Errorf("invalid chunk offset: %v", parseErr)
		}
		if offset < 0 {
			return http.StatusBadRequest, fmt.Errorf("invalid chunk offset: must not be negative")
		}

		totalSizeStr := r.Header.Get("X-File-Total-Size")
		totalSize, parseErr := strconv.ParseInt(totalSizeStr, 10, 64)
		if parseErr != nil {
			logger.Debugf("invalid total size: %v", parseErr)
			return http.StatusBadRequest, fmt.Errorf("invalid total size: %v", parseErr)
		}
		if totalSize < 0 {
			return http.StatusBadRequest, fmt.Errorf("invalid total size: must not be negative")
		}
		if offset > totalSize {
			return http.StatusBadRequest, fmt.Errorf("chunk offset exceeds total size")
		}

		remaining := totalSize - offset
		if r.ContentLength >= 0 && r.ContentLength > remaining {
			return http.StatusBadRequest, fmt.Errorf("chunk exceeds declared total size")
		}

		// On the first chunk, check for conflicts or handle override.
		if offset == 0 {
			var fileInfo *iteminfo.ExtendedFileInfo
			fileInfo, err = files.FileInfoFaster(fileOpts, store.Access, filePermUser, store.Share)
			if err == nil { // File exists
				if r.URL.Query().Get("override") != "true" {
					logger.Debugf("resource already exists: %v", fileInfo.RealPath)
					return http.StatusConflict, nil
				}
				// If overriding, delete existing thumbnails
				preview.DelThumbs(r.Context(), *fileInfo)
			}
		}

		outFile, tempFilePath, created, status, openErr := openChunkUploadFile(
			realPath,
			chunkUploadPrincipal(d),
			offset,
			totalSize,
		)
		if openErr != nil {
			return status, openErr
		}
		fileClosed := false
		closeOutFile := func() error {
			if fileClosed {
				return nil
			}
			fileClosed = true
			return outFile.Close()
		}
		defer func() {
			_ = closeOutFile()
		}()

		chunkSize, tooLarge, copyErr := copyChunkUploadBody(outFile, r.Body, remaining)
		auditBytes = chunkSize
		if copyErr != nil {
			logger.Debugf("could not write chunk to temp file: %v", copyErr)
			resetErr := resetChunkUploadFile(outFile, offset)
			closeErr := closeOutFile()
			if resetErr != nil || closeErr != nil {
				removeChunkUploadTemp(tempFilePath)
				return http.StatusInternalServerError, fmt.Errorf("could not restore chunk upload after a failed write")
			}

			gracefulPause := false
			if d.share != nil {
				k := chunkUploadPauseKey(d, source, path)
				if _, ok := publicPauseCache.Get(k); ok {
					gracefulPause = true
					publicPauseCache.Delete(k)
				}
			} else {
				k := chunkUploadPauseKey(d, source, path)
				if _, ok := pauseCache.Get(k); ok {
					gracefulPause = true
					pauseCache.Delete(k)
				}
			}

			if gracefulPause {
				if offset == 0 {
					removeChunkUploadTemp(tempFilePath)
					logger.Debugf("chunk upload ended after graceful pause; removed empty session (source=%s path=%s)", source, path)
				} else {
					scheduleChunkUploadTempCleanup(realPath, tempFilePath)
					logger.Debugf("chunk upload ended after graceful pause; keeping partial file (source=%s path=%s)", source, path)
				}
				return 499, nil
			}
			removeChunkUploadTemp(tempFilePath)
			return http.StatusInternalServerError, fmt.Errorf("could not write chunk to temp file: %v", copyErr)
		}

		if tooLarge {
			resetErr := resetChunkUploadFile(outFile, offset)
			closeErr := closeOutFile()
			if created || resetErr != nil || closeErr != nil {
				removeChunkUploadTemp(tempFilePath)
			} else {
				scheduleChunkUploadTempCleanup(realPath, tempFilePath)
			}
			if resetErr != nil || closeErr != nil {
				return http.StatusInternalServerError, fmt.Errorf("could not restore chunk upload after an oversized chunk")
			}
			return http.StatusBadRequest, fmt.Errorf("chunk exceeds declared total size")
		}

		expectedSize := offset + chunkSize
		fileInfo, statErr := outFile.Stat()
		if statErr != nil || !fileInfo.Mode().IsRegular() || fileInfo.Size() != expectedSize {
			_ = closeOutFile()
			removeChunkUploadTemp(tempFilePath)
			return http.StatusConflict, fmt.Errorf("chunk upload length changed unexpectedly")
		}

		if chunkSize == 0 && expectedSize < totalSize {
			closeErr := closeOutFile()
			if created || closeErr != nil {
				removeChunkUploadTemp(tempFilePath)
			} else {
				scheduleChunkUploadTempCleanup(realPath, tempFilePath)
			}
			if closeErr != nil {
				return http.StatusInternalServerError, fmt.Errorf("could not close empty chunk upload: %v", closeErr)
			}
			return http.StatusBadRequest, fmt.Errorf("chunk must advance the upload offset")
		}

		if expectedSize < totalSize {
			if closeErr := closeOutFile(); closeErr != nil {
				removeChunkUploadTemp(tempFilePath)
				return http.StatusInternalServerError, fmt.Errorf("could not close chunk upload file: %v", closeErr)
			}
			scheduleChunkUploadTempCleanup(realPath, tempFilePath)
			return http.StatusOK, nil
		}

		if syncErr := outFile.Sync(); syncErr != nil {
			_ = closeOutFile()
			removeChunkUploadTemp(tempFilePath)
			return http.StatusInternalServerError, fmt.Errorf("could not sync completed chunk upload: %v", syncErr)
		}
		fileInfo, statErr = outFile.Stat()
		if statErr != nil || !fileInfo.Mode().IsRegular() || fileInfo.Size() != totalSize {
			_ = closeOutFile()
			removeChunkUploadTemp(tempFilePath)
			return http.StatusConflict, fmt.Errorf("completed chunk upload size does not match declared total size")
		}
		if closeErr := closeOutFile(); closeErr != nil {
			removeChunkUploadTemp(tempFilePath)
			return http.StatusInternalServerError, fmt.Errorf("could not close completed chunk upload: %v", closeErr)
		}
		if auditPreCommit != nil {
			if preCommitErr := auditPreCommit(); preCommitErr != nil {
				removeChunkUploadTemp(tempFilePath)
				return http.StatusConflict, errResourceAuditTargetChanged
			}
		}

		// The target can change while the final request body is being read.
		if _, statErr := os.Stat(realPath); statErr == nil {
			if d.share == nil && !d.user.Permissions.Modify {
				removeChunkUploadTemp(tempFilePath)
				return http.StatusForbidden, fmt.Errorf("user is not allowed to modify")
			}
			if r.URL.Query().Get("override") != "true" {
				removeChunkUploadTemp(tempFilePath)
				return http.StatusConflict, fmt.Errorf("resource appeared before chunk upload commit")
			}
		} else if os.IsNotExist(statErr) {
			if d.share == nil && !d.user.Permissions.Create {
				removeChunkUploadTemp(tempFilePath)
				return http.StatusForbidden, fmt.Errorf("user is not allowed to create")
			}
		} else {
			removeChunkUploadTemp(tempFilePath)
			return errToStatus(statErr), statErr
		}

		err = files.MoveResource(false, source, source, tempFilePath, realPath, store.Share, store.Access)
		if err != nil {
			logger.Debugf("could not move file from %v to %v: %v", tempFilePath, realPath, err)
			removeChunkUploadTemp(tempFilePath)
			return http.StatusInternalServerError, fmt.Errorf("could not move file from chunked folder to destination: %v", err)
		}
		stopChunkUploadTempCleanup(tempFilePath)
		return http.StatusOK, nil
	}

	fileInfo, err := files.FileInfoFaster(fileOpts, store.Access, filePermUser, store.Share)
	if err == nil { // File exists
		if r.URL.Query().Get("override") != "true" {
			logger.Debugf("resource already exists: %v", fileInfo.RealPath)
			return http.StatusConflict, nil
		}
		// If overriding, delete existing thumbnails
		preview.DelThumbs(r.Context(), *fileInfo)
	}

	input := io.Reader(r.Body)
	var countingBody *resourceAuditCountingReader
	if auditEnabled {
		countingBody = &resourceAuditCountingReader{reader: r.Body}
		input = countingBody
	}
	if auditEnabled {
		err = files.WriteFileWithPreCommit(fileOpts.Source, fullIndexPath, realPath, input, auditPreCommit)
	} else {
		err = files.WriteFile(fileOpts.Source, fullIndexPath, input)
	}
	if countingBody != nil {
		auditBytes = countingBody.bytesRead
	}
	if err != nil {
		if stderrors.Is(err, errResourceAuditTargetChanged) {
			return http.StatusConflict, errResourceAuditTargetChanged
		}
		logger.Debugf("error writing file: %v", err)
		return errToStatus(err), err
	}
	return http.StatusOK, nil
}

// resourcePutHandler updates an existing file resource.
// @Summary Update a file resource
// @Description Updates an existing file at the specified path.
// @Tags Resources
// @Accept json
// @Produce json
// @Param path query string true "Destination path where to place the files inside the destination source"
// @Param source query string true "Source name for the desired source, default is used if not provided"
// @Success 200 "Resource updated successfully"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 404 {object} map[string]string "Resource not found"
// @Failure 405 {object} map[string]string "Method not allowed"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/resources [put]
func resourcePutHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (status int, returnErr error) {
	source := r.URL.Query().Get("source")
	path := r.URL.Query().Get("path")

	// Rule 1: Validate user-provided path to prevent path traversal
	cleanPath, err := utils.SanitizeUserPath(path)
	if err != nil {
		return http.StatusBadRequest, err
	}
	path = cleanPath
	// Get user scope to resolve full index path for write operation
	userScope, err := d.user.GetScopeForSourceName(source)
	if err != nil {
		return http.StatusForbidden, err
	}
	fullIndexPath := utils.JoinPathAsUnix(userScope, path)
	// Check access control for the target path
	idx := indexing.GetIndex(source)
	if idx == nil {
		return http.StatusNotFound, fmt.Errorf("source %s not found", source)
	}
	if idx.Config.ReadOnly {
		return http.StatusForbidden, fmt.Errorf("source is read-only")
	}
	if store.Access != nil && !store.Access.Permitted(idx.Path, fullIndexPath, d.user.Username) {
		logger.Debugf("user %s denied access to path %s", d.user.Username, fullIndexPath)
		return http.StatusForbidden, fmt.Errorf("access denied to path %s", path)
	}
	auditEnabled := AuditRecorderFromRequest(r) != nil
	var auditTarget authenticatedReadTarget
	realPath := filepath.Join(idx.Path + fullIndexPath)
	if auditEnabled {
		var auditErr error
		auditTarget, auditErr = resourceAuditWriteTarget(d, source, path)
		if auditErr != nil {
			return errToStatus(auditErr), auditErr
		}
		realPath = auditTarget.RealPath
	}

	// Check target permissions before WriteFile can create or truncate it.
	targetExists := false
	stat, statErr := os.Stat(realPath)
	if statErr == nil {
		targetExists = true
		if !d.user.Permissions.Modify {
			return http.StatusForbidden, fmt.Errorf("user is not allowed to modify")
		}
		if stat.IsDir() {
			return http.StatusMethodNotAllowed, fmt.Errorf("path is a directory")
		}
	} else if os.IsNotExist(statErr) {
		if !d.user.Permissions.Create {
			return http.StatusForbidden, fmt.Errorf("user is not allowed to create")
		}
	} else {
		return errToStatus(statErr), statErr
	}

	itemCount := int64(1)
	auditBytes := int64(0)
	var auditPreCommit func() error
	if auditEnabled {
		action := auditdb.ActionFileUpload
		if targetExists {
			action = auditdb.ActionFileModify
		}
		overwrite := targetExists
		metadata := resourceWriteAuditMetadata(auditdb.MethodPUT, itemCount)
		metadata.Bytes = &auditBytes
		metadata.Overwrite = &overwrite
		if auditErr := prepareResourceWriteAudit(r, action, source,
			auditTarget.LogicalPath, auditTarget.CanonicalPath, "", "", "", metadata); auditErr != nil {
			return http.StatusServiceUnavailable, ErrAuditUnavailable
		}
		if auditErr := reserveResourceWriteAudit(r); auditErr != nil {
			return http.StatusServiceUnavailable, ErrAuditUnavailable
		}
		auditPreCommit = resourceAuditWritePreCommit(d, source, path, auditTarget)
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
			outcome := resourceWriteAuditOutcomeMetadata(itemCount, successCount, failedCount, deniedCount)
			outcome.Bytes = &auditBytes
			_ = mergeResourceWriteAuditMetadata(r, outcome)
		}()
	}

	input := io.Reader(r.Body)
	var countingBody *resourceAuditCountingReader
	if auditEnabled {
		countingBody = &resourceAuditCountingReader{reader: r.Body}
		input = countingBody
	}
	if auditEnabled {
		err = files.WriteFileWithPreCommit(source, fullIndexPath, realPath, input, auditPreCommit)
	} else {
		err = files.WriteFile(source, fullIndexPath, input)
	}
	if countingBody != nil {
		auditBytes = countingBody.bytesRead
	}
	if stderrors.Is(err, errResourceAuditTargetChanged) {
		return http.StatusConflict, errResourceAuditTargetChanged
	}
	return errToStatus(err), err
}

// resourcePatchHandler performs a patch operation (e.g., move, copy, rename) on resources.
// @Summary Move, copy, or rename resources
// @Description Performs move, copy, or rename operations on multiple resources. All operations are performed atomically.
// @Tags Resources
// @Accept json
// @Produce json
// @Param request body MoveCopyRequest true "Move/copy request with items and action"
// @Success 200 {object} MoveCopyResponse "All operations completed successfully"
// @Success 207 {object} MoveCopyResponse "Partial success - some operations succeeded, some failed"
// @Failure 400 {object} map[string]string "Bad request - invalid JSON or parameters"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 404 {object} map[string]string "Resource not found"
// @Failure 500 {object} MoveCopyResponse "All operations failed"
// @Router /api/resources [patch]
func resourcePatchHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (status int, returnErr error) {
	req, ok := d.Data.(MoveCopyRequest)
	if req.Action == "" || !ok {
		// Parse request body
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid JSON body: %v", err)
		}
	}

	if len(req.Items) == 0 {
		return http.StatusBadRequest, fmt.Errorf("items array cannot be empty")
	}

	if req.Action == "" {
		return http.StatusBadRequest, fmt.Errorf("action is required (copy, move, or rename)")
	}
	auditAction := auditdb.Action("")
	switch req.Action {
	case "rename":
		auditAction = auditdb.ActionFileRename
	case "move":
		auditAction = auditdb.ActionFileMove
	}
	auditEnabled := AuditRecorderFromRequest(r) != nil && auditAction != ""
	itemCount := int64(len(req.Items))
	if auditEnabled {
		metadata := resourceWriteAuditMetadata(auditdb.MethodPATCH, itemCount)
		metadata.Overwrite = &req.Overwrite
		if err := prepareResourceWriteAuditAction(r, auditAction, metadata); err != nil {
			return http.StatusServiceUnavailable, ErrAuditUnavailable
		}
	}
	if !d.user.Permissions.Modify && d.share == nil {
		if auditEnabled {
			_ = mergeResourceWriteAuditMetadata(r, resourceWriteAuditOutcomeMetadata(itemCount, 0, 0, itemCount))
		}
		return http.StatusForbidden, fmt.Errorf("user is not allowed to create or modify")
	}

	response := MoveCopyResponse{
		Succeeded: make([]MoveCopyItem, 0),
		Failed:    make([]MoveCopyItem, 0),
	}
	auditReserved := false
	auditDeniedCount := int64(0)
	if auditEnabled {
		defer func() {
			successCount := int64(len(response.Succeeded))
			failedCount := int64(len(response.Failed)) - auditDeniedCount
			if failedCount < 0 {
				failedCount = 0
			}
			_ = mergeResourceWriteAuditMetadata(r,
				resourceWriteAuditOutcomeMetadata(itemCount, successCount, failedCount, auditDeniedCount))
		}()
	}

	// Process each item
	for _, item := range req.Items {

		// Validate all fields are provided
		if item.FromSource == "" || item.FromPath == "" || item.ToSource == "" || item.ToPath == "" {
			item.Message = "fromSource, fromPath, toSource, and toPath are required"
			if d.share != nil {
				response.Failed = append(response.Failed, MoveCopyItem{
					Message: item.Message,
				})
				continue
			}
			response.Failed = append(response.Failed, item)
			continue
		}
		cleanFromPath, err := utils.SanitizeUserPath(item.FromPath)
		if err != nil {
			item.Message = fmt.Sprintf("invalid fromPath: %v", err)
			response.Failed = append(response.Failed, item)
			continue
		}
		cleanToPath, err := utils.SanitizeUserPath(item.ToPath)
		if err != nil {
			item.Message = fmt.Sprintf("invalid toPath: %v", err)
			response.Failed = append(response.Failed, item)
			continue
		}
		item.FromPath = cleanFromPath
		item.ToPath = cleanToPath

		// Get user scopes for both sources
		// For shares, paths are already absolute, so use empty scope
		userscopeSrc := ""
		userscopeDst := ""
		if d.share == nil {
			userscopeSrc, err = d.user.GetScopeForSourceName(item.FromSource)
			if err != nil {
				auditDeniedCount++
				item.Message = "source not available"
				response.Failed = append(response.Failed, item)
				continue
			}
			userscopeDst, err = d.user.GetScopeForSourceName(item.ToSource)
			if err != nil {
				auditDeniedCount++
				item.Message = "destination source not available"
				response.Failed = append(response.Failed, item)
				continue
			}
		}

		// Get source index
		srcIdx := indexing.GetIndex(item.FromSource)
		if srcIdx == nil {
			item.Message = "source not found"
			if d.share != nil {
				response.Failed = append(response.Failed, MoveCopyItem{
					Message: item.Message,
				})
				continue
			}
			response.Failed = append(response.Failed, item)
			continue
		}

		// Get destination index
		dstIdx := indexing.GetIndex(item.ToSource)
		if dstIdx == nil {
			item.Message = "destination source not found"
			if d.share != nil {
				response.Failed = append(response.Failed, MoveCopyItem{
					Message: item.Message,
				})
				continue
			}
			response.Failed = append(response.Failed, item)
			continue
		}

		if srcIdx.Config.ReadOnly && req.Action == "move" {
			item.Message = "From source is read-only and cannot be moved"
			if d.share != nil {
				response.Failed = append(response.Failed, MoveCopyItem{
					Message: item.Message,
				})
				continue
			}
		}

		if dstIdx.Config.ReadOnly {
			auditDeniedCount++
			item.Message = "destination source is read-only"
			if d.share != nil {
				response.Failed = append(response.Failed, MoveCopyItem{
					Message: item.Message,
				})
				continue
			}
			response.Failed = append(response.Failed, item)
			continue
		}

		// Build full index paths for access control
		fullSrcIndexPath := utils.JoinPathAsUnix(userscopeSrc, item.FromPath)
		fullDstIndexPath := utils.JoinPathAsUnix(userscopeDst, item.ToPath)
		if fullDstIndexPath == "/" || fullSrcIndexPath == "/" {
			auditDeniedCount++
			item.Message = "source or destination is the root or unautharized directory"
			response.Failed = append(response.Failed, item)
			continue
		}

		// Check access control for both source and destination paths
		if !store.Access.Permitted(srcIdx.Path, fullSrcIndexPath, d.user.Username) {
			auditDeniedCount++
			item.Message = "access denied to source path"
			if d.share != nil {
				response.Failed = append(response.Failed, MoveCopyItem{
					Message: item.Message,
				})
				continue
			}
			response.Failed = append(response.Failed, item)
			continue
		}
		if !store.Access.Permitted(dstIdx.Path, fullDstIndexPath, d.user.Username) {
			auditDeniedCount++
			item.Message = "access denied to destination path"
			if d.share != nil {
				response.Failed = append(response.Failed, MoveCopyItem{
					Message: item.Message,
				})
				continue
			}
			response.Failed = append(response.Failed, item)
			continue
		}

		// Get real paths
		// Combine user scope with item paths BEFORE calling GetRealPath to avoid double scope application
		fullSrcPath := utils.JoinPathAsUnix(userscopeSrc, item.FromPath)
		realSrc, isSrcDir, err := srcIdx.GetRealPath(fullSrcPath)
		if err != nil {
			logger.Errorf("could not resolve source path: %v, item.FromPath: %v", err, item.FromPath)
			item.Message = "could not resolve source path"
			if d.share != nil {
				response.Failed = append(response.Failed, MoveCopyItem{
					Message: item.Message,
				})
				continue
			}
			response.Failed = append(response.Failed, item)
			continue
		}

		// Check destination parent directory exists
		dstParentPath := filepath.Dir(item.ToPath)
		fullDstParentPath := utils.JoinPathAsUnix(userscopeDst, dstParentPath)
		parentDir, _, err := dstIdx.GetRealPath(fullDstParentPath)
		if err != nil {
			item.Message = "destination directory does not exist"
			if d.share != nil {
				response.Failed = append(response.Failed, MoveCopyItem{
					Message: item.Message,
				})
				continue
			}
			response.Failed = append(response.Failed, item)
			continue
		}
		realDest := parentDir + "/" + filepath.Base(item.ToPath)

		// Auto-rename if requested
		if req.Rename {
			realDest = addVersionSuffix(realDest)
		}

		// Validate move/rename operation to prevent circular references
		if req.Action == "rename" || req.Action == "move" {
			if err = validateMoveOperation(realSrc, realDest, isSrcDir); err != nil {
				item.Message = "invalid move operation, circular reference"
				if d.share != nil {
					response.Failed = append(response.Failed, MoveCopyItem{
						Message: item.Message,
					})
					continue
				}
				response.Failed = append(response.Failed, item)
				continue
			}
		}
		if auditEnabled && !auditReserved {
			var sourceLogicalPath, sourceCanonicalPath, targetLogicalPath, targetCanonicalPath string
			if d.share != nil && len(d.shareTargets) >= 2 {
				sourceLogicalPath = d.shareTargets[0].LogicalPath
				sourceCanonicalPath = d.shareTargets[0].CanonicalPath
				targetLogicalPath = d.shareTargets[1].LogicalPath
				targetCanonicalPath = d.shareTargets[1].CanonicalPath
			} else {
				sourceLogicalPath = normalizePublicShareIndexPath(fullSrcIndexPath)
				targetLogicalPath = normalizePublicShareIndexPath(fullDstIndexPath)
				sourceCanonicalPath, err = resourceAuditCanonicalPath(srcIdx, realSrc)
				if err == nil {
					targetCanonicalPath, err = resourceAuditCanonicalPath(dstIdx, realDest)
				}
				cleanSourceScope := normalizePublicShareIndexPath(userscopeSrc)
				cleanTargetScope := normalizePublicShareIndexPath(userscopeDst)
				if err == nil && (!publicSharePathWithin(cleanSourceScope, sourceCanonicalPath) ||
					!publicSharePathWithin(cleanTargetScope, targetCanonicalPath) ||
					!store.Access.PermittedFresh(srcIdx.Path, sourceCanonicalPath, d.user.Username) ||
					!store.Access.PermittedFresh(dstIdx.Path, targetCanonicalPath, d.user.Username)) {
					err = errors.ErrAccessDenied
				}
				if req.Rename && err == nil && targetCanonicalPath != normalizePublicShareIndexPath(fullDstIndexPath) {
					targetLogicalPath = targetCanonicalPath
				}
			}
			if err != nil {
				if resourceAuditAccessDenied(err) {
					auditDeniedCount++
				}
				item.Message = "audit path is unavailable"
				response.Failed = append(response.Failed, item)
				continue
			}
			if err = setResourceWriteAuditPaths(r, item.FromSource, sourceLogicalPath, sourceCanonicalPath,
				item.ToSource, targetLogicalPath, targetCanonicalPath); err != nil {
				return http.StatusServiceUnavailable, ErrAuditUnavailable
			}
			if err = reserveResourceWriteAudit(r); err != nil {
				return http.StatusServiceUnavailable, ErrAuditUnavailable
			}
			auditReserved = true
		}

		// Perform the action
		err = patchAction(r.Context(), patchActionParams{
			action:   req.Action,
			srcIndex: item.FromSource,
			dstIndex: item.ToSource,
			src:      realSrc,
			dst:      realDest,
			d:        d,
			isSrcDir: isSrcDir,
		})
		if err != nil {
			logger.Errorf("Could not run patch action. src=%v dst=%v err=%v", realSrc, realDest, err)
			if d.share != nil {
				item.Message = "could not run patch action"
				response.Failed = append(response.Failed, MoveCopyItem{
					Message: item.Message,
				})
				continue
			}
			item.Message = err.Error()
			response.Failed = append(response.Failed, item)
			continue
		}

		// Success
		response.Succeeded = append(response.Succeeded, item)
	}

	if len(response.Failed) == 0 && len(response.Succeeded) == 0 {
		response.Failed = append(response.Failed, MoveCopyItem{
			Message: "no operations performed",
		})
	}

	// For shares, sanitize the response to only include messages (hide paths)
	if d.share != nil {
		sanitizedFailed := make([]MoveCopyItem, len(response.Failed))
		for i, item := range response.Failed {
			sanitizedFailed[i] = MoveCopyItem{
				Message: item.Message,
			}
		}
		response.Failed = sanitizedFailed

		// Clear succeeded items details for shares (only keep count implicitly via array length)
		sanitizedSucceeded := make([]MoveCopyItem, len(response.Succeeded))
		response.Succeeded = sanitizedSucceeded
	}

	// Determine status code based on results
	statusCode := http.StatusOK
	if len(response.Failed) > 0 && len(response.Succeeded) == 0 {
		// All operations failed - return 500 error
		statusCode = http.StatusInternalServerError
	} else if len(response.Failed) > 0 && len(response.Succeeded) > 0 {
		// Some succeeded, some failed - return 207 multi-status
		statusCode = http.StatusMultiStatus
	}
	// If all succeeded, statusCode remains 200 OK
	return renderJSON(w, r, response, statusCode)
}

func addVersionSuffix(source string) string {
	counter := 1
	dir, name := path.Split(source)
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for {
		if _, err := os.Stat(source); err != nil {
			break
		}
		renamed := fmt.Sprintf("%s(%d)%s", base, counter, ext)
		source = path.Join(dir, renamed)
		counter++
	}
	return source
}

type patchActionParams struct {
	action   string
	srcIndex string
	dstIndex string
	src      string
	dst      string
	d        *requestContext
	isSrcDir bool
}

func patchAction(ctx context.Context, params patchActionParams) error {
	switch params.action {
	case "copy":
		err := files.CopyResource(params.isSrcDir, params.srcIndex, params.dstIndex, params.src, params.dst)
		return err
	case "rename", "move":
		idx := indexing.GetIndex(params.srcIndex)
		srcPath := idx.MakeIndexPath(params.src, params.isSrcDir)
		userScope := ""
		userScope, _ = params.d.user.GetScopeForSourceName(params.srcIndex)
		if userScope != "" && userScope != "/" {
			// Strip the user scope from srcPath so FileInfoFaster doesn't double it
			srcPath = strings.TrimPrefix(srcPath, userScope)
		}

		fileInfo, err := files.FileInfoFaster(utils.FileOptions{
			FollowSymlinks: true,
			Path:           srcPath,
			Source:         params.srcIndex,
			IsDir:          params.isSrcDir,
			ShowHidden:     params.d.user.ShowHidden,
			HideFileExt:    params.d.user.HideFileExt,
		}, store.Access, params.d.user, store.Share)

		if err != nil {
			return err
		}

		// delete thumbnails
		preview.DelThumbs(ctx, *fileInfo)
		return files.MoveResource(params.isSrcDir, params.srcIndex, params.dstIndex, params.src, params.dst, store.Share, store.Access)
	default:
		return fmt.Errorf("unsupported action %s: %w", params.action, errors.ErrInvalidRequestParams)
	}
}

func inspectIndex(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	source := r.URL.Query().Get("source")
	isNotDir := r.URL.Query().Get("isDir") == "false" // default to isDir true
	index := indexing.GetIndex(source)
	if index == nil {
		http.Error(w, "source not found", http.StatusNotFound)
		return
	}
	info, _ := index.GetReducedMetadata(path, !isNotDir)
	renderJSON(w, r, info) // nolint:errcheck
}

func mockData(w http.ResponseWriter, r *http.Request) {
	d := r.URL.Query().Get("numDirs")
	f := r.URL.Query().Get("numFiles")
	NumDirs, err := strconv.Atoi(d)
	numFiles, err2 := strconv.Atoi(f)
	if err != nil || err2 != nil {
		return
	}
	mockDir := indexing.CreateMockData(NumDirs, numFiles)
	renderJSON(w, r, mockDir) // nolint:errcheck
}

// itemsGetHandler efficiently returns a basic list of items for a directory.
// @Summary Get directory items
// @Description Efficiently returns a basic list of items for the specified path and source. Use 'only' parameter to filter by only files or folders
// @Tags Resources
// @Accept json
// @Produce json
// @Param path query string true "A directory path to list child items"
// @Param source query string true "The source name which contains the path"
// @Param only query string false "Filter: 'files', 'folders', or omit for both"
// @Success 200 {object} files.Items "lists files and folders"
// @Failure 403 {object} map[string]string "Forbidden (access denied)"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/resources/items [get]
func itemsGetHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if !d.user.Permissions.Browse {
		return http.StatusForbidden, fmt.Errorf("user is not allowed to browse resources")
	}

	path, err := sanitizeAuthenticatedReadPath(r.URL.Query().Get("path"))
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("invalid resource path: %v", err)
	}

	source := r.URL.Query().Get("source")
	readUser, err := currentAuthenticatedReadUser(d.user, d.token)
	if err != nil || !readUser.Permissions.Browse {
		return http.StatusForbidden, errors.ErrAccessDenied
	}
	target, err := resolveAuthenticatedBrowseTarget(readUser, source, path)
	if err != nil {
		return errToStatus(err), err
	}
	items, err := files.GetDirItems(utils.FileOptions{
		FollowSymlinks: false,
		Path:           target.ScopedPath,
		Source:         source,
		ShowHidden:     readUser.ShowHidden,
		Only:           r.URL.Query().Get("only"),
	}, store.Access, readUser)
	if err != nil {
		err = normalizeAuthenticatedReadError(err)
		return errToStatus(err), err
	}
	currentUser, err := currentAuthenticatedReadUser(d.user, d.token)
	if err != nil || !currentUser.Permissions.Browse {
		return http.StatusForbidden, errors.ErrAccessDenied
	}
	currentTarget, err := resolveAuthenticatedBrowseTarget(currentUser, source, path)
	if err != nil || !sameAuthenticatedReadTarget(target, currentTarget) {
		return http.StatusForbidden, errors.ErrAccessDenied
	}
	items, err = filterAuthenticatedDirectoryItems(currentUser, source, currentTarget, items)
	if err != nil {
		return http.StatusForbidden, errors.ErrAccessDenied
	}
	if err = setCoreFileAuditReadTarget(r, currentTarget, nil); err != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
	}
	return renderJSON(w, r, items)
}
