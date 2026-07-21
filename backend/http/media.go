package http

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	commonerrors "github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/ffmpeg"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
	"github.com/gtsteffaniak/filebrowser/backend/preview"
)

// subtitlesHandler handles subtitle requests for both external files and embedded streams
// @Summary Get subtitle content
// @Description Returns raw subtitle content from external files or embedded streams
// @Tags Resources
// @Accept json
// @Produce text/plain
// @Param path query string true "Index path to the video file"
// @Param source query string true "Source name for the desired source"
// @Param name query string true "Subtitle track name (filename for external, descriptive name for embedded)"
// @Param embedded query bool false "Whether this is an embedded stream (true) or external file (false), defaults to false"
// @Success 200 {string} string "Raw subtitle content in original format"
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 404 {object} map[string]string "Resource not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/media/subtitles [get]
func subtitlesHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	currentUser, err := currentAuthenticatedReadUser(d.user, d.token)
	if err != nil || !currentUser.Permissions.Browse || !currentUser.Permissions.Download {
		return http.StatusForbidden, fmt.Errorf("browse and download permissions are required for subtitles")
	}
	path := r.URL.Query().Get("path")
	source := r.URL.Query().Get("source")
	name := r.URL.Query().Get("name")
	embedded := r.URL.Query().Get("embedded") == "true"

	if path == "" || source == "" {
		return http.StatusBadRequest, fmt.Errorf("path and source are required")
	}
	if name == "" {
		return http.StatusBadRequest, fmt.Errorf("name parameter is required")
	}

	mediaTarget, err := resolveAuthenticatedReadTarget(currentUser, source, path)
	if err != nil {
		return errToStatus(err), err
	}
	fileInfo, err := authenticatedMediaFileInfo(mediaTarget, source, currentUser, false, false, "")
	if err != nil {
		return errToStatus(err), err
	}
	if !strings.HasPrefix(fileInfo.Type, "video") {
		return http.StatusNotFound, fmt.Errorf("file is not a video")
	}

	var content string
	protectedTargets := make([]authenticatedReadTarget, 0, 1)
	if !embedded {
		if !isExternalSubtitleForMedia(fileInfo.Name, name) {
			return http.StatusNotFound, fmt.Errorf("subtitle track '%s' not found", name)
		}
		sidecarTarget, sidecarErr := authorizedMediaSidecar(mediaTarget.LogicalPath, source, name, currentUser)
		if sidecarErr != nil {
			return mediaSidecarStatus(sidecarErr), sidecarErr
		}
		protectedTargets = append(protectedTargets, sidecarTarget)
		if _, err = revalidateAuthenticatedResourceRead(d, source, path, mediaTarget, protectedTargets, true, false); err != nil {
			return http.StatusForbidden, commonerrors.ErrAccessDenied
		}
		content, err = readAuthorizedTextSidecar(sidecarTarget)
		if err != nil {
			return mediaSidecarStatus(err), fmt.Errorf("subtitle sidecar content is unavailable")
		}
	} else {
		if _, err = revalidateAuthenticatedResourceRead(d, source, path, mediaTarget, nil, true, false); err != nil {
			return http.StatusForbidden, commonerrors.ErrAccessDenied
		}
		snapshotPath, _, cleanup, snapshotErr := snapshotAuthenticatedReadTarget(mediaTarget)
		if snapshotErr != nil {
			return errToStatus(snapshotErr), snapshotErr
		}
		defer cleanup()
		currentUser, err = revalidateAuthenticatedResourceRead(d, source, path, mediaTarget, nil, true, false)
		if err != nil {
			return http.StatusForbidden, commonerrors.ErrAccessDenied
		}
		fileInfo, err = authenticatedMediaFileInfo(mediaTarget, source, currentUser, true, false, snapshotPath)
		if err != nil {
			return errToStatus(err), err
		}
		track := findSubtitleTrack(fileInfo.Subtitles, name, true)
		if track == nil {
			return http.StatusNotFound, fmt.Errorf("subtitle track '%s' not found", name)
		}
		if track.Index == nil {
			return http.StatusNotFound, fmt.Errorf("embedded subtitle track '%s' not found", name)
		}
		if _, err = revalidateAuthenticatedResourceRead(d, source, path, mediaTarget, nil, true, false); err != nil {
			return http.StatusForbidden, commonerrors.ErrAccessDenied
		}
		content, err = ffmpeg.ExtractSubtitleContent(snapshotPath, *track.Index)
		if err != nil {
			return http.StatusInternalServerError, fmt.Errorf("embedded subtitle content is unavailable")
		}
	}
	if _, err = revalidateAuthenticatedResourceRead(d, source, path, mediaTarget, protectedTargets, true, false); err != nil {
		return http.StatusForbidden, commonerrors.ErrAccessDenied
	}

	// Return raw content with appropriate content type
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Cache-Control", "private")
	http.ServeContent(w, r, name, time.Now(), bytes.NewReader([]byte(content)))
	return http.StatusOK, nil
}

func findSubtitleTrack(subtitles []utils.SubtitleTrack, name string, embedded bool) *utils.SubtitleTrack {
	for i := range subtitles {
		sub := &subtitles[i]
		if sub.Name == name && sub.Embedded == embedded {
			return sub
		}
	}
	return nil
}

func isExternalSubtitleForMedia(mediaName, sidecarName string) bool {
	ext := strings.ToLower(filepath.Ext(sidecarName))
	if !iteminfo.SubtitleExts[ext] {
		return false
	}
	mediaBase := strings.TrimSuffix(mediaName, filepath.Ext(mediaName))
	sidecarBase := strings.TrimSuffix(sidecarName, filepath.Ext(sidecarName))
	withoutLanguage := strings.TrimSuffix(sidecarBase, filepath.Ext(sidecarBase))
	return sidecarBase == mediaBase || withoutLanguage == mediaBase
}

var (
	errInvalidMediaSidecar = errors.New("invalid media sidecar path")
)

func mediaSidecarIndexPath(mediaPath, name string) (string, error) {
	if mediaPath == "" || name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return "", errInvalidMediaSidecar
	}
	mediaPath = strings.ReplaceAll(mediaPath, "\\", "/")
	mediaPath = pathpkg.Clean("/" + strings.TrimPrefix(mediaPath, "/"))
	if mediaPath == "/" {
		return "", errInvalidMediaSidecar
	}
	return pathpkg.Join(pathpkg.Dir(mediaPath), name), nil
}

func authorizedMediaSidecar(mediaPath, source, name string, user *users.User) (authenticatedReadTarget, error) {
	var target authenticatedReadTarget
	sidecarPath, err := mediaSidecarIndexPath(mediaPath, name)
	if err != nil {
		return target, err
	}
	target, err = resolveAuthenticatedReadIndexTarget(user, source, sidecarPath)
	if err != nil {
		return target, err
	}
	if target.Info == nil || !target.Info.Mode().IsRegular() {
		return target, os.ErrNotExist
	}
	return target, nil
}

func readAuthorizedTextSidecar(target authenticatedReadTarget) (string, error) {
	const maxSidecarSize = 50 * 1024 * 1024

	file, info, err := openAuthenticatedReadTarget(target)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if info.Size() > maxSidecarSize {
		return "", errors.New("media sidecar is too large")
	}

	content, err := io.ReadAll(io.LimitReader(file, maxSidecarSize+1))
	if err != nil {
		return "", err
	}
	if len(content) > maxSidecarSize {
		return "", errors.New("media sidecar is too large")
	}
	if !isTextSidecar(content) {
		return "", nil
	}
	return string(content), nil
}

func isTextSidecar(content []byte) bool {
	if len(content) == 0 {
		return true
	}
	sample := content
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	if bytes.Count(sample, []byte{0}) > len(sample)/20 {
		return false
	}
	return utf8.Valid(content)
}

func mediaSidecarStatus(err error) int {
	switch {
	case errors.Is(err, errInvalidMediaSidecar):
		return http.StatusBadRequest
	default:
		return errToStatus(err)
	}
}

func authenticatedMediaSidecarTargets(fileInfo *iteminfo.ExtendedFileInfo, source string, mediaTarget authenticatedReadTarget, currentUser *users.User) []authenticatedReadTarget {
	if fileInfo == nil || currentUser == nil {
		return nil
	}
	targets := make([]authenticatedReadTarget, 0, len(fileInfo.Subtitles)+1)
	seen := make(map[string]struct{}, len(fileInfo.Subtitles)+1)
	appendTarget := func(target authenticatedReadTarget) {
		key := target.LogicalPath + "\x00" + target.CanonicalPath
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
	}

	logicalMediaName := pathpkg.Base(mediaTarget.LogicalPath)
	filtered := make([]utils.SubtitleTrack, 0, len(fileInfo.Subtitles))
	for _, track := range fileInfo.Subtitles {
		if track.Embedded {
			filtered = append(filtered, track)
			continue
		}
		if !isExternalSubtitleForMedia(logicalMediaName, track.Name) {
			continue
		}
		if target, err := authorizedMediaSidecar(mediaTarget.LogicalPath, source, track.Name, currentUser); err == nil {
			filtered = append(filtered, track)
			appendTarget(target)
		}
	}
	fileInfo.Subtitles = filtered

	if strings.HasPrefix(fileInfo.Type, "audio") && fileInfo.Metadata != nil && !fileInfo.Metadata.HasLyrics {
		lrcName := strings.TrimSuffix(logicalMediaName, filepath.Ext(logicalMediaName)) + ".lrc"
		if target, err := authorizedMediaSidecar(mediaTarget.LogicalPath, source, lrcName, currentUser); err == nil {
			fileInfo.Metadata.HasLyrics = true
			appendTarget(target)
		}
	}
	return targets
}

func authenticatedMediaFileInfo(target authenticatedReadTarget, source string, user *users.User, metadata, albumArt bool, readPath string) (*iteminfo.ExtendedFileInfo, error) {
	fileInfo, err := files.FileInfoFaster(utils.FileOptions{
		FollowSymlinks:           false,
		Path:                     target.ScopedPath,
		Source:                   source,
		Expand:                   false,
		Content:                  false,
		Metadata:                 metadata,
		AlbumArt:                 albumArt,
		ReadPath:                 readPath,
		ExtractEmbeddedSubtitles: metadata && config.Integrations.Media.ExtractEmbeddedSubtitles,
		ShowHidden:               user.ShowHidden,
		HideFileExt:              user.HideFileExt,
		SkipExtendedAttrs:        false,
	}, store.Access, user, store.Share)
	if err != nil {
		return nil, normalizeAuthenticatedReadError(err)
	}
	applyAuthenticatedFileInfoIdentity(fileInfo, target)
	return fileInfo, nil
}

func authenticatedMediaTargetsByLogicalName(targets []authenticatedReadTarget) map[string]authenticatedReadTarget {
	byName := make(map[string]authenticatedReadTarget, len(targets))
	for _, target := range targets {
		byName[pathpkg.Base(target.LogicalPath)] = target
	}
	return byName
}

// metadataHandler returns the same directory resource shape as GET /api/resources with metadata enabled,
// for client-side patching after a fast listing load.
// @Summary Directory with media metadata
// @Description Same ExtendedFileInfo as resources GET with metadata=true (typically used for directories).
// @Tags Resources
// @Accept json
// @Produce json
// @Param path query string true "Path to the directory or file"
// @Param source query string true "Source name"
// @Param albumArt query bool false "When true, include embedded album art bytes in audio metadata"
// @Success 200 {object} iteminfo.ExtendedFileInfo
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 404 {object} map[string]string "Not found"
// @Router /api/media/metadata [get]
func metadataHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	currentUser, err := currentAuthenticatedReadUser(d.user, d.token)
	if err != nil || !currentUser.Permissions.Browse {
		return http.StatusForbidden, fmt.Errorf("browse permission is required for media metadata")
	}
	path := r.URL.Query().Get("path")
	source := r.URL.Query().Get("source")
	albumArt := r.URL.Query().Get("albumArt") == "true"
	if albumArt {
		if !currentUser.Permissions.Preview {
			return http.StatusForbidden, fmt.Errorf("browse and preview permissions are required for album art")
		}
		if config.Server.DisablePreviews {
			return http.StatusNotImplemented, fmt.Errorf("preview is disabled")
		}
	}
	target, err := resolveAuthenticatedBrowseTarget(currentUser, source, path)
	if err != nil {
		return errToStatus(err), err
	}
	fileOpts := utils.FileOptions{
		FollowSymlinks:           false,
		Path:                     target.ScopedPath,
		Source:                   source,
		Expand:                   true,
		Content:                  false,
		Metadata:                 false,
		AlbumArt:                 false,
		ExtractEmbeddedSubtitles: false,
		ShowHidden:               currentUser.ShowHidden,
		HideFileExt:              currentUser.HideFileExt,
		SkipExtendedAttrs:        false,
		ShowSharedAttr:           true,
	}
	fileInfo, err := files.FileInfoFaster(fileOpts, store.Access, currentUser, store.Share)
	if err != nil {
		err = normalizeAuthenticatedReadError(err)
		return errToStatus(err), err
	}
	applyAuthenticatedFileInfoIdentity(fileInfo, target)
	if err = filterAuthenticatedDirectoryFileInfo(currentUser, source, target, fileInfo); err != nil {
		return http.StatusForbidden, commonerrors.ErrAccessDenied
	}

	protectedTargets := make([]authenticatedReadTarget, 0)
	derivedMedia := false
	if currentUser.Permissions.Preview {
		_, err = revalidateAuthenticatedResourceRead(d, source, path, target, nil, false, true)
		if err != nil {
			return http.StatusForbidden, commonerrors.ErrAccessDenied
		}
		if fileInfo.Type == "directory" {
			mediaOpts := fileOpts
			mediaOpts.AlbumArt = albumArt
			mediaOpts.ExtractEmbeddedSubtitles = config.Integrations.Media.ExtractEmbeddedSubtitles
			protectedTargets, err = enrichAuthenticatedResourceDirectoryMetadata(fileInfo, mediaOpts, d, source, path, target)
			if err != nil {
				return http.StatusForbidden, commonerrors.ErrAccessDenied
			}
			derivedMedia = len(protectedTargets) > 0
		} else if strings.HasPrefix(fileInfo.Type, "audio") || strings.HasPrefix(fileInfo.Type, "video") {
			snapshotPath, _, cleanup, snapshotErr := snapshotAuthenticatedReadTarget(target)
			if snapshotErr != nil {
				return errToStatus(snapshotErr), snapshotErr
			}
			currentUser, err = revalidateAuthenticatedResourceRead(d, source, path, target, nil, false, true)
			if err != nil {
				cleanup()
				return http.StatusForbidden, commonerrors.ErrAccessDenied
			}
			mediaOpts := fileOpts
			mediaOpts.Expand = false
			mediaOpts.Metadata = true
			mediaOpts.AlbumArt = albumArt
			mediaOpts.ExtractEmbeddedSubtitles = config.Integrations.Media.ExtractEmbeddedSubtitles
			mediaOpts.ReadPath = snapshotPath
			fileInfo, err = files.FileInfoFaster(mediaOpts, store.Access, currentUser, store.Share)
			cleanup()
			if err != nil {
				err = normalizeAuthenticatedReadError(err)
				return errToStatus(err), err
			}
			applyAuthenticatedFileInfoIdentity(fileInfo, target)
			protectedTargets = append(protectedTargets, target)
			protectedTargets = append(protectedTargets, authenticatedMediaSidecarTargets(fileInfo, source, target, currentUser)...)
			derivedMedia = true
		}
	}
	if albumArt {
		deriveAlbumArt := func(info iteminfo.ExtendedFileInfo, mediaTarget authenticatedReadTarget) ([]byte, error) {
			if _, revalidateErr := revalidateAuthenticatedResourceRead(d, source, path, target, []authenticatedReadTarget{mediaTarget}, false, true); revalidateErr != nil {
				return nil, commonerrors.ErrAccessDenied
			}
			info.HasPreview = true
			derived, previewErr := preview.GetSafePreviewForFile(r.Context(), info, "small", "", 0)
			if previewErr != nil {
				return nil, previewErr
			}
			if _, revalidateErr := revalidateAuthenticatedResourceRead(d, source, path, target, []authenticatedReadTarget{mediaTarget}, false, true); revalidateErr != nil {
				return nil, commonerrors.ErrAccessDenied
			}
			return derived, nil
		}
		if fileInfo.Metadata != nil && len(fileInfo.Metadata.AlbumArt) > 0 {
			derivedAlbumArt, previewErr := deriveAlbumArt(*fileInfo, target)
			if previewErr != nil {
				if errors.Is(previewErr, commonerrors.ErrAccessDenied) {
					return http.StatusForbidden, commonerrors.ErrAccessDenied
				}
				return http.StatusInternalServerError, fmt.Errorf("failed to create album art preview: %w", previewErr)
			}
			fileInfo.Metadata.AlbumArt = derivedAlbumArt
		}
		childTargets := authenticatedMediaTargetsByLogicalName(protectedTargets)
		for i := range fileInfo.Files {
			child := &fileInfo.Files[i]
			if child.Metadata == nil || len(child.Metadata.AlbumArt) == 0 {
				continue
			}
			childTarget, ok := childTargets[child.Name]
			if !ok {
				child.Metadata.AlbumArt = nil
				continue
			}
			child.Size = childTarget.Info.Size()
			child.ModTime = childTarget.Info.ModTime()
			childInfo := iteminfo.ExtendedFileInfo{
				FileInfo: iteminfo.FileInfo{
					ItemInfo: child.ItemInfo,
					Path:     utils.JoinPathAsUnix(fileInfo.Path, child.Name),
				},
				Metadata: child.Metadata,
				Source:   fileInfo.Source,
				RealPath: childTarget.RealPath,
			}
			derivedAlbumArt, previewErr := deriveAlbumArt(childInfo, childTarget)
			if previewErr != nil {
				if errors.Is(previewErr, commonerrors.ErrAccessDenied) {
					return http.StatusForbidden, commonerrors.ErrAccessDenied
				}
				return http.StatusInternalServerError, fmt.Errorf("failed to create album art preview for %s: %w", child.Name, previewErr)
			}
			child.Metadata.AlbumArt = derivedAlbumArt
		}
	}
	responseUser, err := revalidateAuthenticatedResourceRead(d, source, path, target, protectedTargets, false, derivedMedia)
	if err != nil {
		return http.StatusForbidden, commonerrors.ErrAccessDenied
	}
	currentTarget, err := resolveAuthenticatedBrowseTarget(responseUser, source, path)
	if err != nil || !sameAuthenticatedReadTarget(target, currentTarget) {
		return http.StatusForbidden, commonerrors.ErrAccessDenied
	}
	if err = filterAuthenticatedDirectoryFileInfo(responseUser, source, currentTarget, fileInfo); err != nil {
		return http.StatusForbidden, commonerrors.ErrAccessDenied
	}
	if !derivedMedia {
		fileInfo.Metadata = nil
		fileInfo.Subtitles = nil
		for i := range fileInfo.Files {
			fileInfo.Files[i].Metadata = nil
		}
	}
	return renderJSON(w, r, fileInfo)
}

// publicMetadataHandler is the share-link variant of metadataHandler.
// @Summary Directory with media metadata (public share)
// @Tags Shares
// @Produce json
// @Param hash query string true "Share hash"
// @Param path query string false "Path within the share"
// @Param albumArt query bool false "When true, include embedded album art bytes in audio metadata (heavier)"
// @Success 200 {object} iteminfo.ExtendedFileInfo
// @Router /public/api/media/metadata [get]
func publicMetadataHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if d.share.ShareType == "upload" {
		return http.StatusNotImplemented, fmt.Errorf("browsing is disabled for upload shares")
	}
	path := r.URL.Query().Get("path")
	albumArt := r.URL.Query().Get("albumArt") == "true"
	sourceCfg, ok := config.Server.SourceMap[d.share.Source]
	if !ok {
		return http.StatusNotFound, fmt.Errorf("source not found")
	}
	fileInfo, err := files.FileInfoFaster(utils.FileOptions{
		Path:                     d.IndexPath,
		Source:                   sourceCfg.Name,
		Expand:                   true,
		Content:                  false,
		Metadata:                 true,
		AlbumArt:                 albumArt,
		ExtractEmbeddedSubtitles: config.Integrations.Media.ExtractEmbeddedSubtitles && d.share.ExtractEmbeddedSubtitles,
		ShowHidden:               d.share.ShowHidden,
		HideFileExt:              d.user.HideFileExt,
		FollowSymlinks:           false,
	}, store.Access, d.shareUser, store.Share)
	if err != nil {
		return errToStatus(err), err
	}
	fileInfo.Path = utils.AddTrailingSlashIfNotExists(path)
	return renderJSON(w, r, fileInfo)
}

// lyricsHandler returns synced/unsynced lyrics (with or without timestamps) for an audio file (embedded or from .lrc files).
// @Summary Get lyrics for an audio file
// @Description Returns parsed lyrics with optional timestamps from embedded tags or sidecar .lrc files.
// @Tags Resources
// @Accept json
// @Produce json
// @Param path query string true "Path to the directory or file"
// @Param source query string true "Source name"
// @Success 200 {object} map[string]interface{} "Lyrics array"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 404 {object} map[string]string "Not found"
// @Router /api/media/lyrics [get]
func lyricsHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	currentUser, err := currentAuthenticatedReadUser(d.user, d.token)
	if err != nil || !currentUser.Permissions.Browse || !currentUser.Permissions.Download {
		return http.StatusForbidden, fmt.Errorf("browse and download permissions are required for lyrics")
	}
	path := r.URL.Query().Get("path")
	source := r.URL.Query().Get("source")
	if path == "" || source == "" {
		return http.StatusBadRequest, fmt.Errorf("path and source are required")
	}

	mediaTarget, err := resolveAuthenticatedReadTarget(currentUser, source, path)
	if err != nil {
		return errToStatus(err), err
	}
	fileInfo, err := authenticatedMediaFileInfo(mediaTarget, source, currentUser, false, false, "")
	if err != nil {
		return errToStatus(err), err
	}
	if !strings.HasPrefix(fileInfo.Type, "audio") {
		return http.StatusNotFound, fmt.Errorf("file is not an audio file")
	}

	lrcName := strings.TrimSuffix(fileInfo.Name, filepath.Ext(fileInfo.Name)) + ".lrc"
	sidecarContent := ""
	protectedTargets := make([]authenticatedReadTarget, 0, 1)
	sidecarTarget, sidecarErr := authorizedMediaSidecar(mediaTarget.LogicalPath, source, lrcName, currentUser)
	if sidecarErr != nil {
		if errToStatus(sidecarErr) != http.StatusNotFound {
			return mediaSidecarStatus(sidecarErr), sidecarErr
		}
	} else {
		protectedTargets = append(protectedTargets, sidecarTarget)
		if _, err = revalidateAuthenticatedResourceRead(d, source, path, mediaTarget, protectedTargets, true, false); err != nil {
			return http.StatusForbidden, commonerrors.ErrAccessDenied
		}
		sidecarContent, err = readAuthorizedTextSidecar(sidecarTarget)
		if err != nil {
			return mediaSidecarStatus(err), fmt.Errorf("lyrics sidecar content is unavailable")
		}
	}

	if _, err = revalidateAuthenticatedResourceRead(d, source, path, mediaTarget, protectedTargets, true, false); err != nil {
		return http.StatusForbidden, commonerrors.ErrAccessDenied
	}
	snapshotPath, _, cleanup, snapshotErr := snapshotAuthenticatedReadTarget(mediaTarget)
	if snapshotErr != nil {
		return errToStatus(snapshotErr), snapshotErr
	}
	defer cleanup()
	if _, err = revalidateAuthenticatedResourceRead(d, source, path, mediaTarget, protectedTargets, true, false); err != nil {
		return http.StatusForbidden, commonerrors.ErrAccessDenied
	}
	lyrics, err := files.ExtractLyrics(snapshotPath, sidecarContent)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("lyrics content is unavailable")
	}
	if _, err = revalidateAuthenticatedResourceRead(d, source, path, mediaTarget, protectedTargets, true, false); err != nil {
		return http.StatusForbidden, commonerrors.ErrAccessDenied
	}
	return renderJSON(w, r, map[string]any{"lyrics": lyrics})
}

// publicLyricsHandler is the share-link variant of lyricsHandler.
// @Summary Get lyrics for an audio file (public share)
// @Tags Shares
// @Produce json
// @Param hash query string true "Share hash"
// @Param path query string false "Path within the share"
// @Success 200 {object} map[string]interface{} "Lyrics array"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 404 {object} map[string]string "Not found"
// @Router /public/api/media/lyrics [get]
func publicLyricsHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	sourceCfg, ok := config.Server.SourceMap[d.share.Source]
	if !ok {
		return http.StatusNotFound, fmt.Errorf("source not found")
	}

	fileInfo, err := files.FileInfoFaster(utils.FileOptions{
		Path:              d.IndexPath,
		Source:            sourceCfg.Name,
		Expand:            true,
		Content:           false,
		Metadata:          false,
		ShowHidden:        d.share.ShowHidden,
		HideFileExt:       d.user.HideFileExt,
		FollowSymlinks:    false,
		SkipExtendedAttrs: false,
	}, store.Access, d.shareUser, store.Share)
	if err != nil {
		return errToStatus(err), err
	}
	if !strings.HasPrefix(fileInfo.Type, "audio") {
		return http.StatusNotFound, fmt.Errorf("file is not an audio file")
	}

	lyrics, err := files.ExtractLyrics(fileInfo.RealPath)
	if err != nil {
		return http.StatusInternalServerError, errors.New("failed to extract lyrics")
	}
	return renderJSON(w, r, map[string]any{"lyrics": lyrics})
}
