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
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
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
	if d.user == nil || !d.user.Permissions.Browse || !d.user.Permissions.Download {
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

	fileInfo, err := files.FileInfoFaster(utils.FileOptions{
		FollowSymlinks:           true,
		Path:                     path,
		Source:                   source,
		Expand:                   true,
		Content:                  false,
		Metadata:                 true,
		ExtractEmbeddedSubtitles: config.Integrations.Media.ExtractEmbeddedSubtitles,
		ShowHidden:               d.user.ShowHidden,
		HideFileExt:              d.user.HideFileExt,
		SkipExtendedAttrs:        false,
	}, store.Access, d.user, store.Share)
	if err != nil {
		return errToStatus(err), err
	}
	if !strings.HasPrefix(fileInfo.Type, "video") {
		return http.StatusNotFound, fmt.Errorf("file is not a video")
	}

	var track *utils.SubtitleTrack
	if embedded {
		track = findSubtitleTrack(fileInfo.Subtitles, name, true)
		if track == nil {
			return http.StatusNotFound, fmt.Errorf("subtitle track '%s' not found", name)
		}
	} else {
		if !isExternalSubtitleForMedia(fileInfo.Name, name) {
			return http.StatusNotFound, fmt.Errorf("subtitle track '%s' not found", name)
		}
		track = &utils.SubtitleTrack{Name: name}
	}

	var content string
	if !embedded {
		sidecarInfo, sidecarErr := authorizedMediaSidecar(fileInfo.Path, source, track.Name, d)
		if sidecarErr != nil {
			return mediaSidecarStatus(sidecarErr), sidecarErr
		}
		content, err = readAuthorizedTextSidecar(sidecarInfo.RealPath)
		if err != nil {
			return mediaSidecarStatus(err), fmt.Errorf("failed to get subtitle sidecar content: %w", err)
		}
	} else {
		if track.Index == nil {
			return http.StatusNotFound, fmt.Errorf("embedded subtitle track '%s' not found", name)
		}
		content, err = ffmpeg.ExtractSubtitleContent(fileInfo.RealPath, *track.Index)
		if err != nil {
			return http.StatusInternalServerError, fmt.Errorf("failed to extract embedded subtitle: %v", err)
		}
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
	errUnsafeMediaSidecar  = errors.New("unsafe media sidecar")
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

func authorizedMediaSidecar(mediaPath, source, name string, d *requestContext) (*iteminfo.ExtendedFileInfo, error) {
	sidecarPath, err := mediaSidecarIndexPath(mediaPath, name)
	if err != nil {
		return nil, err
	}
	info, err := files.FileInfoFaster(utils.FileOptions{
		Path:              sidecarPath,
		Source:            source,
		Expand:            false,
		Content:           false,
		Metadata:          false,
		ShowHidden:        d.user.ShowHidden,
		HideFileExt:       d.user.HideFileExt,
		FollowSymlinks:    false,
		SkipExtendedAttrs: true,
	}, store.Access, d.user, store.Share)
	if err != nil {
		return nil, err
	}
	if info.Type == "directory" {
		return nil, os.ErrNotExist
	}
	return info, nil
}

func readAuthorizedTextSidecar(realPath string) (string, error) {
	const maxSidecarSize = 50 * 1024 * 1024

	before, err := os.Lstat(realPath)
	if err != nil {
		return "", err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return "", errUnsafeMediaSidecar
	}
	if before.Size() > maxSidecarSize {
		return "", errors.New("media sidecar is too large")
	}

	file, err := os.Open(realPath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !os.SameFile(before, after) || !after.Mode().IsRegular() {
		return "", errUnsafeMediaSidecar
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
	case errors.Is(err, errUnsafeMediaSidecar):
		return http.StatusForbidden
	default:
		return errToStatus(err)
	}
}

func filterInaccessibleSubtitleSidecars(fileInfo *iteminfo.ExtendedFileInfo, source string, d *requestContext) {
	filtered := make([]utils.SubtitleTrack, 0, len(fileInfo.Subtitles))
	for _, track := range fileInfo.Subtitles {
		if track.Embedded {
			filtered = append(filtered, track)
			continue
		}
		if _, err := authorizedMediaSidecar(fileInfo.Path, source, track.Name, d); err == nil {
			filtered = append(filtered, track)
		}
	}
	fileInfo.Subtitles = filtered
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
	if d.user == nil || !d.user.Permissions.Browse {
		return http.StatusForbidden, fmt.Errorf("browse permission is required for media metadata")
	}
	path := r.URL.Query().Get("path")
	source := r.URL.Query().Get("source")
	albumArt := r.URL.Query().Get("albumArt") == "true"
	if albumArt {
		if !d.user.Permissions.Preview {
			return http.StatusForbidden, fmt.Errorf("browse and preview permissions are required for album art")
		}
		if config.Server.DisablePreviews {
			return http.StatusNotImplemented, fmt.Errorf("preview is disabled")
		}
	}
	fileInfo, err := files.FileInfoFaster(utils.FileOptions{
		FollowSymlinks:           true,
		Path:                     path,
		Source:                   source,
		Expand:                   true,
		Content:                  false,
		Metadata:                 true,
		AlbumArt:                 albumArt,
		ExtractEmbeddedSubtitles: config.Integrations.Media.ExtractEmbeddedSubtitles,
		ShowHidden:               d.user.ShowHidden,
		HideFileExt:              d.user.HideFileExt,
		SkipExtendedAttrs:        false,
		ShowSharedAttr:           true,
	}, store.Access, d.user, store.Share)
	if err != nil {
		return errToStatus(err), err
	}
	filterInaccessibleSubtitleSidecars(fileInfo, source, d)
	if albumArt {
		deriveAlbumArt := func(info iteminfo.ExtendedFileInfo) ([]byte, error) {
			info.HasPreview = true
			return preview.GetSafePreviewForFile(r.Context(), info, "small", "", 0)
		}
		if fileInfo.Metadata != nil && len(fileInfo.Metadata.AlbumArt) > 0 {
			derivedAlbumArt, previewErr := deriveAlbumArt(*fileInfo)
			if previewErr != nil {
				return http.StatusInternalServerError, fmt.Errorf("failed to create album art preview: %w", previewErr)
			}
			fileInfo.Metadata.AlbumArt = derivedAlbumArt
		}
		for i := range fileInfo.Files {
			child := &fileInfo.Files[i]
			if child.Metadata == nil || len(child.Metadata.AlbumArt) == 0 {
				continue
			}
			childInfo := iteminfo.ExtendedFileInfo{
				FileInfo: iteminfo.FileInfo{
					ItemInfo: child.ItemInfo,
					Path:     utils.JoinPathAsUnix(fileInfo.Path, child.Name),
				},
				Metadata: child.Metadata,
				Source:   fileInfo.Source,
				RealPath: filepath.Join(fileInfo.RealPath, child.Name),
			}
			derivedAlbumArt, previewErr := deriveAlbumArt(childInfo)
			if previewErr != nil {
				return http.StatusInternalServerError, fmt.Errorf("failed to create album art preview for %s: %w", child.Name, previewErr)
			}
			child.Metadata.AlbumArt = derivedAlbumArt
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
	if d.user == nil || !d.user.Permissions.Browse || !d.user.Permissions.Download {
		return http.StatusForbidden, fmt.Errorf("browse and download permissions are required for lyrics")
	}
	path := r.URL.Query().Get("path")
	source := r.URL.Query().Get("source")
	if path == "" || source == "" {
		return http.StatusBadRequest, fmt.Errorf("path and source are required")
	}

	fileInfo, err := files.FileInfoFaster(utils.FileOptions{
		FollowSymlinks:    true,
		Path:              path,
		Source:            source,
		Expand:            true,
		Content:           false,
		Metadata:          false,
		ShowHidden:        d.user.ShowHidden,
		HideFileExt:       d.user.HideFileExt,
		SkipExtendedAttrs: false,
	}, store.Access, d.user, store.Share)
	if err != nil {
		return errToStatus(err), err
	}
	if !strings.HasPrefix(fileInfo.Type, "audio") {
		return http.StatusNotFound, fmt.Errorf("file is not an audio file")
	}

	lrcName := strings.TrimSuffix(fileInfo.Name, filepath.Ext(fileInfo.Name)) + ".lrc"
	sidecarContent := ""
	sidecarInfo, sidecarErr := authorizedMediaSidecar(fileInfo.Path, source, lrcName, d)
	if sidecarErr != nil {
		if errToStatus(sidecarErr) != http.StatusNotFound {
			return mediaSidecarStatus(sidecarErr), sidecarErr
		}
	} else {
		sidecarContent, err = readAuthorizedTextSidecar(sidecarInfo.RealPath)
		if err != nil {
			return mediaSidecarStatus(err), fmt.Errorf("failed to get lyrics sidecar content: %w", err)
		}
	}

	lyrics, err := files.ExtractLyrics(fileInfo.RealPath, sidecarContent)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to extract lyrics: %v", err)
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
