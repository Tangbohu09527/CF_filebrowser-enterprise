package http

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
	"github.com/gtsteffaniak/go-logger/logger"
)

type requestContext struct {
	user         *users.User
	shareUser    *users.User
	shareAccess  publicShareAccess
	shareQuery   url.Values
	shareRoute   publicShareRoute
	shareScope   string
	shareTargets []publicShareTarget
	shareArchive []publicShareArchiveEntry
	fileInfo     iteminfo.ExtendedFileInfo
	token        string
	share        *share.Link
	ctx          context.Context
	MaxBandwidth int
	Data         interface{}
	IndexPath    string
}

type HttpResponse struct {
	Status  int    `json:"status,omitempty"`
	Message string `json:"message,omitempty"`
	Token   string `json:"token,omitempty"`
}

var FileInfoFasterFunc = files.FileInfoFaster

// Updated handleFunc to match the new signature
type handleFunc func(w http.ResponseWriter, r *http.Request, data *requestContext) (int, error)

type publicShareReadRequirement uint8

const (
	publicShareReadNone   publicShareReadRequirement = 0
	publicShareReadBrowse publicShareReadRequirement = 1 << iota
	publicShareReadThumbnail
	publicShareReadViewer
	publicShareReadDownload
	publicShareReadOriginalViewer = publicShareReadBrowse | publicShareReadViewer | publicShareReadDownload
)

type publicShareTargetMode uint8

const (
	publicShareTargetNone publicShareTargetMode = iota
	publicShareTargetPath
	publicShareTargetFiles
	publicShareTargetImage
)

type publicShareRoute struct {
	recognized                bool
	read                      bool
	requirement               publicShareReadRequirement
	targetMode                publicShareTargetMode
	skipFileInfo              bool
	albumArt                  bool
	uploadInitializationProbe bool
}

type publicShareTarget struct {
	RequestedPath string
	LogicalPath   string
	CanonicalPath string
	ScopedPath    string
	RealPath      string
	IsDir         bool
}

type publicShareAccess struct {
	browse    bool
	thumbnail bool
	viewer    bool
	download  bool
}

func calculatePublicShareAccess(link *share.Link, owner *users.User) publicShareAccess {
	readable := link.ShareType != "upload"
	return publicShareAccess{
		browse:    readable && owner.Permissions.Browse,
		thumbnail: readable && owner.Permissions.Preview && !link.DisableThumbnails,
		viewer:    readable && owner.Permissions.Preview && !link.DisableFileViewer,
		download:  readable && owner.Permissions.Download && !link.DisableDownload,
	}
}

func (access publicShareAccess) allows(requirement publicShareReadRequirement) bool {
	if requirement&publicShareReadBrowse != 0 && !access.browse {
		return false
	}
	if requirement&publicShareReadThumbnail != 0 && !access.thumbnail {
		return false
	}
	if requirement&publicShareReadViewer != 0 && !access.viewer {
		return false
	}
	if requirement&publicShareReadDownload != 0 && !access.download {
		return false
	}
	return true
}

func isPublicShareUploadInitializationProbe(method, routePath string, query url.Values) bool {
	if method != http.MethodGet || routePath != "/resources" || query.Get("hash") == "" || query.Get("path") == "" {
		return false
	}
	for key := range query {
		switch key {
		case "hash", "path", "token":
		default:
			return false
		}
	}
	return true
}

func publicShareRouteForRequest(method, routePath string, query url.Values) (publicShareRoute, error) {
	readMethod := method == http.MethodGet || method == http.MethodHead
	if readMethod {
		switch routePath {
		case "/resources":
			requirement := publicShareReadBrowse
			uploadInitializationProbe := isPublicShareUploadInitializationProbe(method, routePath, query)
			if query.Get("content") == "true" {
				requirement = publicShareReadOriginalViewer
			} else if query.Get("metadata") == "true" {
				requirement = publicShareReadBrowse | publicShareReadViewer
			}
			return publicShareRoute{
				recognized:                true,
				read:                      true,
				requirement:               requirement,
				targetMode:                publicShareTargetPath,
				uploadInitializationProbe: uploadInitializationProbe,
			}, nil
		case "/resources/items":
			return publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse, targetMode: publicShareTargetPath}, nil
		case "/resources/download", "/raw":
			return publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse | publicShareReadDownload, targetMode: publicShareTargetFiles, skipFileInfo: true}, nil
		case "/resources/preview":
			requirement := publicShareReadBrowse | publicShareReadThumbnail
			switch query.Get("size") {
			case "large", "xlarge":
				requirement = publicShareReadBrowse | publicShareReadViewer
			case "original":
				requirement = publicShareReadOriginalViewer
			}
			return publicShareRoute{recognized: true, read: true, requirement: requirement, targetMode: publicShareTargetPath, albumArt: true}, nil
		case "/media/metadata", "/media/lyrics":
			return publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse | publicShareReadViewer, targetMode: publicShareTargetPath}, nil
		case "/office/config":
			return publicShareRoute{recognized: true, read: true, requirement: publicShareReadOriginalViewer, targetMode: publicShareTargetPath}, nil
		case "/share/image":
			isBanner := query.Get("banner") == "true"
			isFavicon := query.Get("favicon") == "true"
			if isBanner == isFavicon {
				return publicShareRoute{}, fmt.Errorf("exactly one share image type is required")
			}
			requirement := publicShareReadBrowse | publicShareReadThumbnail
			if isBanner {
				requirement |= publicShareReadViewer
			}
			return publicShareRoute{recognized: true, read: true, requirement: requirement, targetMode: publicShareTargetImage, skipFileInfo: true}, nil
		}
	}

	switch {
	case method == http.MethodPost && routePath == "/resources":
		return publicShareRoute{recognized: true, targetMode: publicShareTargetPath, skipFileInfo: true}, nil
	case method == http.MethodPost && routePath == "/resources/pause":
		return publicShareRoute{recognized: true, targetMode: publicShareTargetPath, skipFileInfo: true}, nil
	case (method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete) && routePath == "/resources":
		return publicShareRoute{recognized: true, targetMode: publicShareTargetPath}, nil
	case method == http.MethodDelete && routePath == "/resources/bulk":
		return publicShareRoute{recognized: true, targetMode: publicShareTargetPath}, nil
	case (method == http.MethodGet || method == http.MethodPost) && routePath == "/office/callback":
		return publicShareRoute{recognized: true, targetMode: publicShareTargetPath}, nil
	default:
		return publicShareRoute{}, nil
	}
}

func publicShareReadRequirementForRequest(r *http.Request) publicShareReadRequirement {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return publicShareReadNone
	}
	route, err := publicShareRouteForRequest(r.Method, r.URL.Path, query)
	if err != nil || !route.recognized || !route.read {
		return publicShareReadNone
	}
	return route.requirement
}

func publicShareRequirementUsesDownload(requirement publicShareReadRequirement) bool {
	return requirement&publicShareReadDownload != 0
}

func normalizePublicShareIndexPath(value string) string {
	value = strings.ReplaceAll(value, "\\", "/")
	return pathpkg.Clean("/" + strings.TrimPrefix(value, "/"))
}

func publicSharePathWithin(base, target string) bool {
	base = normalizePublicShareIndexPath(base)
	target = normalizePublicShareIndexPath(target)
	if runtime.GOOS == "windows" {
		base = strings.ToLower(base)
		target = strings.ToLower(target)
	}
	return base == "/" || target == base || strings.HasPrefix(target, strings.TrimSuffix(base, "/")+"/")
}

func publicSharePathsOverlap(first, second string) bool {
	return publicSharePathWithin(first, second) || publicSharePathWithin(second, first)
}

func publicShareSingleQueryValue(query url.Values, key string) (string, error) {
	values, ok := query[key]
	if !ok {
		return "", nil
	}
	if len(values) != 1 {
		return "", fmt.Errorf("ambiguous %s parameter", key)
	}
	return values[0], nil
}

func validatePublicShareQuery(query url.Values) error {
	for _, key := range []string{
		"hash", "path", "content", "metadata", "size", "banner", "favicon",
		"albumArt", "atPercentage", "only", "archiveToken", "algo", "inline",
		"auth", "token", "password", "override", "action",
	} {
		if _, err := publicShareSingleQueryValue(query, key); err != nil {
			return err
		}
	}
	return nil
}

func publicShareHasDotDotSegment(value string) bool {
	value = strings.ReplaceAll(value, "\\", "/")
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

func publicShareHasDrivePrefix(value string) bool {
	value = strings.TrimPrefix(strings.ReplaceAll(value, "\\", "/"), "/")
	return len(value) >= 2 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':'
}

func publicShareWindowsReservedSegment(segment string) bool {
	segment = strings.TrimSuffix(segment, ".")
	base := strings.ToUpper(strings.SplitN(segment, ".", 2)[0])
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" {
		return true
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
		return true
	}
	return false
}

func publicShareRepeatedEncodingIsDangerous(value string) bool {
	current := value
	for range 3 {
		next, err := url.PathUnescape(current)
		if err != nil {
			return true
		}
		if next == current {
			return false
		}
		if strings.ContainsAny(next, "/\\\x00") || publicShareHasDotDotSegment(next) || publicShareHasDrivePrefix(next) ||
			(runtime.GOOS == "windows" && strings.Contains(next, ":")) {
			return true
		}
		current = next
	}
	return false
}

func cleanPublicShareRelativePath(value string) (string, error) {
	if strings.ContainsRune(value, '\x00') || publicShareRepeatedEncodingIsDangerous(value) {
		return "", fmt.Errorf("invalid public path")
	}
	if strings.HasPrefix(value, "\\") {
		return "", fmt.Errorf("invalid public path")
	}
	normalized := strings.ReplaceAll(value, "\\", "/")
	if strings.HasPrefix(normalized, "//") {
		return "", fmt.Errorf("invalid public path")
	}
	if strings.HasPrefix(normalized, "/") {
		normalized = strings.TrimPrefix(normalized, "/")
	}
	if strings.HasPrefix(normalized, "/") || publicShareHasDotDotSegment(normalized) || publicShareHasDrivePrefix(normalized) {
		return "", fmt.Errorf("invalid public path")
	}
	for _, segment := range strings.Split(normalized, "/") {
		if runtime.GOOS == "windows" && (strings.Contains(segment, ":") || strings.HasSuffix(segment, " ") ||
			strings.HasSuffix(segment, ".") || publicShareWindowsReservedSegment(segment)) {
			return "", fmt.Errorf("invalid public path")
		}
	}
	cleaned := pathpkg.Clean(normalized)
	if cleaned == "." {
		return "", nil
	}
	if pathpkg.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("invalid public path")
	}
	return cleaned, nil
}

func publicShareRealPathWithin(base, target string) bool {
	relative, err := filepath.Rel(base, target)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func publicShareCanonicalCaseRelative(root, relative string) string {
	if runtime.GOOS != "windows" || relative == "." || relative == "" {
		return relative
	}
	current := root
	parts := strings.Split(filepath.Clean(relative), string(filepath.Separator))
	for i, part := range parts {
		entries, err := os.ReadDir(current)
		if err != nil {
			return relative
		}
		actual := part
		for _, entry := range entries {
			if entry.Name() == part {
				actual = entry.Name()
				break
			}
			if strings.EqualFold(entry.Name(), part) {
				actual = entry.Name()
			}
		}
		parts[i] = actual
		current = filepath.Join(current, actual)
	}
	return filepath.Join(parts...)
}

func publicShareScopedPath(ownerScope, logicalPath string) (string, error) {
	ownerScope = normalizePublicShareIndexPath(ownerScope)
	logicalPath = normalizePublicShareIndexPath(logicalPath)
	if !publicSharePathWithin(ownerScope, logicalPath) {
		return "", errors.ErrAccessDenied
	}
	if ownerScope == "/" {
		return logicalPath, nil
	}
	if ownerScope == logicalPath || (runtime.GOOS == "windows" && strings.EqualFold(ownerScope, logicalPath)) {
		return "/", nil
	}
	prefixLength := len(ownerScope)
	if prefixLength > len(logicalPath) || (runtime.GOOS == "windows" && !strings.EqualFold(logicalPath[:prefixLength], ownerScope)) {
		return "", errors.ErrAccessDenied
	}
	return normalizePublicShareIndexPath(logicalPath[prefixLength:]), nil
}

func resolvePublicShareLogicalTarget(d *requestContext, sourcePath, logicalPath string) (publicShareTarget, error) {
	var target publicShareTarget
	shareRootRelative, err := cleanPublicShareRelativePath(d.share.Path)
	if err != nil {
		return target, errors.ErrAccessDenied
	}
	shareRoot := normalizePublicShareIndexPath(shareRootRelative)
	logicalRelative, err := cleanPublicShareRelativePath(logicalPath)
	if err != nil {
		return target, errors.ErrAccessDenied
	}
	logicalPath = normalizePublicShareIndexPath(logicalRelative)
	if !publicSharePathWithin(shareRoot, logicalPath) {
		return target, errors.ErrAccessDenied
	}

	sourceAbsolute, err := filepath.Abs(sourcePath)
	if err != nil {
		return target, err
	}
	sourceReal, err := filepath.EvalSymlinks(sourceAbsolute)
	if err != nil {
		return target, err
	}
	shareRootReal, err := filepath.EvalSymlinks(filepath.Join(sourceAbsolute, filepath.FromSlash(strings.TrimPrefix(shareRoot, "/"))))
	if err != nil || !publicShareRealPathWithin(sourceReal, shareRootReal) {
		return target, errors.ErrAccessDenied
	}
	targetReal, err := filepath.EvalSymlinks(filepath.Join(sourceAbsolute, filepath.FromSlash(strings.TrimPrefix(logicalPath, "/"))))
	if err != nil {
		return target, err
	}
	if !publicShareRealPathWithin(sourceReal, targetReal) || !publicShareRealPathWithin(shareRootReal, targetReal) {
		return target, errors.ErrAccessDenied
	}
	canonicalRelative, err := filepath.Rel(sourceReal, targetReal)
	if err != nil {
		return target, errors.ErrAccessDenied
	}
	canonicalRelative = publicShareCanonicalCaseRelative(sourceReal, canonicalRelative)
	canonicalPath := normalizePublicShareIndexPath(filepath.ToSlash(canonicalRelative))
	if !publicSharePathWithin(d.shareScope, logicalPath) || !publicSharePathWithin(d.shareScope, canonicalPath) {
		return target, errors.ErrAccessDenied
	}
	if store.Access == nil || !store.Access.PermittedFresh(sourcePath, logicalPath, d.shareUser.Username) ||
		!store.Access.PermittedFresh(sourcePath, canonicalPath, d.shareUser.Username) {
		return target, errors.ErrAccessDenied
	}
	scopedPath, err := publicShareScopedPath(d.shareScope, canonicalPath)
	if err != nil {
		return target, err
	}
	info, err := os.Stat(targetReal)
	if err != nil {
		return target, err
	}
	target = publicShareTarget{
		LogicalPath:   logicalPath,
		CanonicalPath: canonicalPath,
		ScopedPath:    scopedPath,
		RealPath:      targetReal,
		IsDir:         info.IsDir(),
	}
	return target, nil
}

func resolvePublicShareTarget(d *requestContext, sourcePath, requestedPath string) (publicShareTarget, error) {
	var target publicShareTarget
	requestedRelative, err := cleanPublicShareRelativePath(requestedPath)
	if err != nil {
		return target, err
	}
	shareRootRelative, err := cleanPublicShareRelativePath(d.share.Path)
	if err != nil {
		return target, err
	}
	logicalPath := normalizePublicShareIndexPath(pathpkg.Join("/"+shareRootRelative, requestedRelative))
	target, err = resolvePublicShareLogicalTarget(d, sourcePath, logicalPath)
	if err != nil {
		return target, err
	}
	target.RequestedPath = requestedRelative
	return target, nil

}

func resolvePublicShareWriteTarget(linkPath, ownerScope, requestedPath string) (string, error) {
	shareRoot := normalizePublicShareIndexPath(linkPath)
	ownerScope = normalizePublicShareIndexPath(ownerScope)
	requestedPath = strings.TrimPrefix(filepath.ToSlash(requestedPath), "/")
	target := normalizePublicShareIndexPath(pathpkg.Join(shareRoot, requestedPath))
	if !publicSharePathWithin(shareRoot, target) || !publicSharePathWithin(ownerScope, target) {
		return "", errors.ErrAccessDenied
	}
	return publicShareScopedPath(ownerScope, target)
}

// Middleware to handle file requests by hash and pass it to the handler
func withHashFileHelper(fn handleFunc) handleFunc {
	authenticated := withOrWithoutUserHelper(func(w http.ResponseWriter, r *http.Request, data *requestContext) (int, error) {
		query := data.shareQuery
		route := data.shareRoute
		var err error
		hash := query.Get("hash")
		inputPath := query.Get("path")
		requestedPath := inputPath
		if !route.read {
			requestedPath, err = utils.SanitizeUserPath(inputPath)
			if err != nil && inputPath != "" {
				return http.StatusBadRequest, err
			}
			requestedPath = filepath.ToSlash(requestedPath)
		}

		link, err := store.Share.GetByHash(hash)
		if err != nil {
			data.share = &share.Link{}
			return http.StatusNotFound, fmt.Errorf("share hash not found")
		}
		if link.DisableAnonymous && data.user.Username == "anonymous" {
			return http.StatusForbidden, fmt.Errorf("share is not available to anonymous users")
		}
		// Block anonymous users if per-user download limit is enabled
		if link.PerUserDownloadLimit && data.user.Username == "anonymous" {
			return http.StatusForbidden, fmt.Errorf("anonymous downloads are not allowed with per-user limits")
		}
		if len(link.AllowedUsernames) > 0 {
			if !slices.Contains(link.AllowedUsernames, data.user.Username) {
				return http.StatusForbidden, fmt.Errorf("share is not available to this user")
			}
		}
		// Check per-user download limit
		if link.PerUserDownloadLimit && link.HasReachedUserLimit(data.user.Username) {
			return http.StatusForbidden, fmt.Errorf("user download limit reached for this share")
		}
		data.share = link
		// Authenticate the share request if needed
		var status int
		if link.Hash != "" {
			status, err = authenticateShareRequest(r, link)
			if err != nil || status != http.StatusOK {
				return status, fmt.Errorf("could not authenticate share request")
			}
		}
		if link.Path == "" {
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
		if _, pathErr := cleanPublicShareRelativePath(link.Path); pathErr != nil {
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
		source, ok := config.Server.SourceMap[link.Source]
		if !ok {
			return http.StatusNotFound, fmt.Errorf("source not found")
		}
		if source.Config.Private {
			return http.StatusForbidden, fmt.Errorf("the target source is private")
		}

		data.shareUser, err = store.Users.Get(link.UserID)
		if err != nil {
			return http.StatusNotFound, fmt.Errorf("user for share no longer exists")
		}
		data.shareAccess = calculatePublicShareAccess(link, data.shareUser)
		if link.ShareType == "upload" && route.uploadInitializationProbe && r.Header.Get("Range") == "" {
			if _, pathErr := cleanPublicShareRelativePath(inputPath); pathErr != nil {
				return http.StatusForbidden, fmt.Errorf("public share access denied")
			}
			return http.StatusNotImplemented, fmt.Errorf("browsing is disabled for upload shares")
		}
		if route.read && !data.shareAccess.allows(route.requirement) {
			invalidatePublicShareArchiveToken(query.Get("archiveToken"), link.Hash)
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
		if route.read && r.URL.Path == "/office/config" && !link.EnableOnlyOffice {
			invalidatePublicShareArchiveToken(query.Get("archiveToken"), link.Hash)
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}

		reachedDownloadsLimit := !link.PerUserDownloadLimit && link.Downloads >= link.DownloadsLimit && link.DownloadsLimit > 0
		if route.read && reachedDownloadsLimit && publicShareRequirementUsesDownload(route.requirement) {
			invalidatePublicShareArchiveToken(query.Get("archiveToken"), link.Hash)
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}

		userScope, err := data.shareUser.GetScopeForSourceName(source.Name)
		if err != nil || userScope == "" {
			invalidatePublicShareArchiveToken(query.Get("archiveToken"), link.Hash)
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
		cleanScope, scopeErr := cleanPublicShareRelativePath(userScope)
		if scopeErr != nil {
			invalidatePublicShareArchiveToken(query.Get("archiveToken"), link.Hash)
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
		data.shareScope = normalizePublicShareIndexPath(cleanScope)

		if route.targetMode == publicShareTargetImage {
			return fn(w, r, data)
		}

		if route.targetMode == publicShareTargetFiles {
			requestedFiles := query["file"]
			if len(requestedFiles) == 0 {
				requestedFiles = []string{"/"}
			}
			data.shareTargets = make([]publicShareTarget, 0, len(requestedFiles))
			for _, requestedFile := range requestedFiles {
				if requestedFile == "" {
					return http.StatusBadRequest, fmt.Errorf("invalid file path")
				}
				target, resolveErr := resolvePublicShareTarget(data, source.Path, requestedFile)
				if resolveErr != nil {
					invalidatePublicShareArchiveToken(query.Get("archiveToken"), link.Hash)
					return http.StatusForbidden, fmt.Errorf("public share access denied")
				}
				if len(data.shareTargets) == 0 {
					data.IndexPath = utils.AddTrailingSlashIfNotExists(target.ScopedPath)
				}
				data.shareTargets = append(data.shareTargets, target)
			}
			return fn(w, r, data)
		}

		var readTarget publicShareTarget
		if route.read {
			readTarget, err = resolvePublicShareTarget(data, source.Path, requestedPath)
			if err != nil {
				invalidatePublicShareArchiveToken(query.Get("archiveToken"), link.Hash)
				return http.StatusForbidden, fmt.Errorf("public share access denied")
			}
			data.shareTargets = []publicShareTarget{readTarget}
			data.IndexPath = utils.AddTrailingSlashIfNotExists(readTarget.ScopedPath)
		} else {
			var scopedPath string
			scopedPath, err = resolvePublicShareWriteTarget(link.Path, data.shareScope, requestedPath)
			if err != nil {
				return http.StatusForbidden, fmt.Errorf("public share access denied")
			}
			data.IndexPath = utils.AddTrailingSlashIfNotExists(scopedPath)
		}

		if route.skipFileInfo {
			return fn(w, r, data)
		}

		getContent := query.Get("content") == "true"
		file, err := FileInfoFasterFunc(utils.FileOptions{
			Path:                     data.IndexPath,
			Source:                   source.Name,
			Expand:                   true,
			Content:                  getContent,
			Metadata:                 false,
			AlbumArt:                 route.albumArt,
			ExtractEmbeddedSubtitles: config.Integrations.Media.ExtractEmbeddedSubtitles && link.ExtractEmbeddedSubtitles,
			ShowHidden:               link.ShowHidden,
			HideFileExt:              link.HideFileExt,
			FollowSymlinks:           true,
		}, store.Access, data.shareUser, store.Share)
		if err != nil {
			logger.Errorf("error fetching file info for share. hash=%v path=%v error=%v", hash, requestedPath, err)
			return errToStatus(err), fmt.Errorf("error fetching share from server")
		}
		if route.read {
			file.RealPath = readTarget.RealPath
			if file.Type == "directory" {
				idx := indexing.GetIndex(source.Name)
				if idx == nil {
					return http.StatusNotFound, fmt.Errorf("source not found")
				}
				filterPublicShareFileInfo(data, readTarget, file, idx)
			}
		}
		file.Token = link.Token
		file.Source = link.Hash
		file.Hash = link.Hash
		if !link.EnableOnlyOffice || !data.shareAccess.allows(publicShareReadOriginalViewer) || reachedDownloadsLimit {
			file.OnlyOfficeId = ""
		}
		if getContent && file.Content != "" {
			link.Mu.Lock()
			link.Downloads++
			link.Mu.Unlock()
			// Track per-user download if enabled
			if link.PerUserDownloadLimit {
				link.IncrementUserDownload(data.user.Username)
			}
		}
		file.Path = utils.AddTrailingSlashIfNotExists(inputPath)
		// Set the file info in the `data` object
		data.fileInfo = *file
		if route.read && r.URL.Path == "/media/metadata" {
			return publicVerifiedMetadataHandler(w, r, data)
		}
		// Call the next handler with the data
		return fn(w, r, data)
	})
	return func(w http.ResponseWriter, r *http.Request, data *requestContext) (int, error) {
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || validatePublicShareQuery(query) != nil {
			return http.StatusForbidden, fmt.Errorf("invalid public share query")
		}
		route, err := publicShareRouteForRequest(r.Method, r.URL.Path, query)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid public share request")
		}
		if !route.recognized {
			return http.StatusForbidden, fmt.Errorf("public share route is not allowed")
		}
		data.shareQuery = query
		data.shareRoute = route
		r.URL.RawQuery = query.Encode()
		return authenticated(w, r, data)
	}
}

// Middleware to ensure the user is an admin
func withAdminHelper(fn handleFunc) handleFunc {
	return withUserHelper(func(w http.ResponseWriter, r *http.Request, data *requestContext) (int, error) {
		// Ensure the user has admin permissions
		if !data.user.Permissions.Admin {
			return http.StatusForbidden, nil
		}
		return fn(w, r, data)
	})
}

// extractUserFromExpiredToken attempts to extract user information from an expired token
// This is used by withOrWithoutUserHelper to get user context even when tokens are expired
func extractUserFromExpiredToken(r *http.Request, data *requestContext) *users.User {
	if config.Auth.Methods.NoAuth {
		user, err := store.Users.Get(uint(1))
		if err != nil {
			logger.Errorf("no auth: %v", err)
			return nil
		}
		return user
	}

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return []byte(config.Auth.Key), nil
	}

	tokenString, err := extractToken(r)
	if err != nil {
		return nil
	}

	data.token = tokenString
	var tk users.AuthToken
	token, err := jwt.ParseWithClaims(tokenString, &tk, keyFunc)
	if err != nil {
		return nil
	}

	if !token.Valid {
		return nil
	}

	// Token is valid (but might be expired or revoked)
	// Try to get the user regardless of expiration status
	user, err := store.Users.Get(tk.BelongsTo)
	if err != nil {
		logger.Errorf("Failed to get user with ID %v: %v", tk.BelongsTo, err)
		return nil
	}

	if user.Username == "" {
		return nil
	}

	return user
}

// withOrWithoutUserHelper is a middleware that tries to authenticate a user.
// If authentication is successful, the user is added to the request context.
// If authentication fails, the request continues without a user.
func withOrWithoutUserHelper(fn handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, data *requestContext) (int, error) {
		hash := r.URL.Query().Get("hash")
		if hash != "" {
			_, err := store.Share.GetByHash(hash)
			if err != nil {
				return http.StatusNotFound, fmt.Errorf("share hash not found")
			}
		}

		// Try to authenticate user first
		status, err := withUserHelper(nil)(w, r, data)
		if err == nil && status < 400 {
			if data.share != nil && data.user != nil {
				data.user.CustomTheme = data.share.ShareTheme
			}
			return fn(w, r, data)
		}

		// Authentication failed, but try to extract user info from expired tokens
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			// Try to extract user info from potentially expired token
			userFromExpiredToken := extractUserFromExpiredToken(r, data)
			if userFromExpiredToken != nil {
				data.user = userFromExpiredToken
				if data.share != nil {
					data.user.CustomTheme = data.share.ShareTheme
				}
				setUserInResponseWriter(w, data.user)
				return fn(w, r, data)
			}

			// No valid token or user found, fall back to anonymous
			data.user = &users.User{Username: "anonymous"}
			settings.ApplyUserDefaults(data.user)
			// Clear any user data that might have been partially set
			data.token = ""
			if data.share != nil {
				data.user.CustomTheme = data.share.ShareTheme
			}
			// Call the handler function without user context
			return fn(w, r, data)
		}
		return status, fmt.Errorf("could not authenticate request")
	}
}

func withoutUserHelper(fn handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, data *requestContext) (int, error) {
		// This middleware is used when no user authentication is required
		// Call the actual handler function with the updated context
		return fn(w, r, data)
	}
}

// allow user without OTP to pass
func LoginHelper(disableOtp bool, fn handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {

		if config.Auth.Methods.ProxyAuth.Enabled {
			proxyUser := r.Header.Get(config.Auth.Methods.ProxyAuth.Header)
			if proxyUser != "" {
				return getProxyUser(w, r, d, fn, proxyUser)
			}
		}

		// Try LDAP first if enabled; on success set d.user and continue to handler
		if config.Auth.Methods.LdapAuth.Enabled {
			// No valid admin token - proceed with username/password authentication
			username := r.URL.Query().Get("username")
			password := r.Header.Get("X-Password")
			// URL-decode password to support special characters in headers
			password, err := url.QueryUnescape(password)
			if err != nil {
				return 401, fmt.Errorf("invalid password encoding")
			}
			logger.Debug("ldap auth, calling AuthenticateLDAPUser")
			ldapUser, err := AuthenticateLDAPUser(username, password)
			if err == nil {
				logger.Debugf("ldap auth successful, calling handler")
				d.user = ldapUser
				return fn(w, r, d)
			}
			logger.Debug("ldap auth failed, calling password auth", err)
		}
		if config.Auth.Methods.PasswordAuth.Enabled {
			auther, err := store.Auth.Get("password")
			if err != nil {
				return 401, errors.ErrUnauthorized
			}
			// OTP routes: password only (do not mutate stored *JSONAuth).
			if ja, ok := auther.(*auth.JSONAuth); ok {
				x := *ja
				x.DisableOtp = disableOtp
				auther = &x
			}
			user, err := auther.Auth(r, store.Users)
			if err != nil {
				logger.Debug("password auth failed, calling handler:", err)
				if err == errors.ErrNoTotpProvided {
					return 403, err
				}
				return 401, errors.ErrUnauthorized
			}
			d.user = user
			return fn(w, r, d)
		}
		return withUserHelper(fn)(w, r, d)
	}
}

// Middleware to retrieve and authenticate user
func withUserHelper(fn handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, data *requestContext) (int, error) {
		if config.Auth.Methods.NoAuth {
			var err error
			// Retrieve the user from the store and store it in the context
			data.user, err = store.Users.Get(uint(1))
			if err != nil {
				logger.Errorf("no auth: %v", err)
				return http.StatusInternalServerError, err
			}
			if fn == nil {
				return http.StatusOK, nil
			}
			return fn(w, r, data)
		}

		// Check for JWT external auth first (header or query param)
		if config.Auth.Methods.JwtAuth.Enabled {
			jwtToken := r.Header.Get(config.Auth.Methods.JwtAuth.Header)
			if jwtToken == "" {
				// Check query parameter (hardcoded to "jwt")
				jwtToken = r.URL.Query().Get("jwt")
			}

			if jwtToken != "" {
				return getJwtUser(w, r, data, fn, jwtToken)
			}
		}

		proxyUser := r.Header.Get(config.Auth.Methods.ProxyAuth.Header)
		isProxyUser := config.Auth.Methods.ProxyAuth.Enabled && proxyUser != ""
		keyFunc := func(token *jwt.Token) (interface{}, error) {
			return []byte(config.Auth.Key), nil
		}
		if data.token == "" {
			var err error
			data.token, err = extractToken(r)
			if err != nil && !isProxyUser {
				return http.StatusUnauthorized, err
			}
		}

		var tk users.AuthToken
		token, err := jwt.ParseWithClaims(data.token, &tk, keyFunc)
		if err != nil {
			if isProxyUser {
				return getProxyUser(w, r, data, fn, proxyUser)
			}
			// JWT library automatically validates expiration - if expired, it returns an error
			return http.StatusUnauthorized, fmt.Errorf("invalid token: %v", err)
		}
		if !token.Valid {
			return http.StatusUnauthorized, fmt.Errorf("invalid token")
		}
		if auth.IsRevokedApiToken(store.Access, data.token) {
			return http.StatusUnauthorized, fmt.Errorf("token is expired or revoked")
		}
		// ExpiresAt should always be set in valid tokens created by our system
		// JWT library populates RegisteredClaims.ExpiresAt
		if tk.RegisteredClaims.ExpiresAt == nil {
			return http.StatusUnauthorized, fmt.Errorf("token is invalid or revoked")
		}
		// Check if token is about to expire for renewal header
		if tk.RegisteredClaims.ExpiresAt.Unix() < time.Now().Add(time.Minute*30).Unix() {
			w.Header().Add("X-Renew-Token", "true")
		}
		// Check if token is minimal/stateful (no BelongsTo in claim)
		minimalToken := tk.BelongsTo == 0
		if minimalToken {
			// Hash the token and look up user ID in access storage
			userID, found := store.Access.GetUserIDFromToken(data.token)
			if !found {
				return http.StatusUnauthorized, fmt.Errorf("token is invalid or revoked")
			}
			tk.BelongsTo = userID
		}
		data.user, err = store.Users.Get(tk.BelongsTo)
		if err != nil {
			logger.Errorf("Failed to get user with ID %v: %v", tk.BelongsTo, err)
			return http.StatusInternalServerError, err
		}
		if !minimalToken {
			findAPIToken := func(tokens map[string]users.AuthToken) (users.AuthToken, bool) {
				for _, apiToken := range tokens {
					if apiToken.Token == data.token || apiToken.Key == data.token {
						return apiToken, true
					}
				}
				return users.AuthToken{}, false
			}
			storedToken, stored := findAPIToken(data.user.Tokens)
			if !stored {
				storedToken, stored = findAPIToken(data.user.ApiKeys)
			}

			var tokenPermissions users.Permissions
			applyTokenPermissions := false
			switch {
			case tk.Name != "":
				if tk.PermissionsVersion != users.CurrentPermissionsVersion ||
					(stored && storedToken.PermissionsVersion != users.CurrentPermissionsVersion) {
					return http.StatusUnauthorized, fmt.Errorf("invalid API token permissions version")
				}
				tokenPermissions = tk.Permissions
				applyTokenPermissions = true
			case stored:
				if tk.PermissionsVersion != 0 || storedToken.PermissionsVersion != 0 {
					return http.StatusUnauthorized, fmt.Errorf("invalid API token permissions version")
				}
				tokenPermissions = users.NormalizeLegacyPermissions(tk.Permissions)
				applyTokenPermissions = true
			case tk.PermissionsVersion != 0:
				return http.StatusUnauthorized, fmt.Errorf("invalid API token permissions version")
			}

			if applyTokenPermissions {
				requestUser := *data.user
				requestUser.Permissions = users.IntersectPermissions(data.user.Permissions, tokenPermissions)
				data.user = &requestUser
			}
		}

		// Set cookie. Some clients like gvfs relies on it for concurrent uploads
		if tk.RegisteredClaims.ExpiresAt != nil {
			setSessionCookie(w, r, data.token, tk.RegisteredClaims.ExpiresAt.Time)
		}
		setUserInResponseWriter(w, data.user)
		if data.user.Username == "" {
			return http.StatusForbidden, errors.ErrUnauthorized
		}
		// Call the handler function, passing in the context (or return OK if no handler)
		if fn == nil {
			return http.StatusOK, nil
		}
		return fn(w, r, data)
	}
}

func getJwtUser(w http.ResponseWriter, r *http.Request, data *requestContext, fn handleFunc, jwtToken string) (int, error) {
	// Verify the external JWT token
	username, claims, err := auth.VerifyExternalJWT(
		jwtToken,
		config.Auth.Methods.JwtAuth.Secret,
		config.Auth.Methods.JwtAuth.Algorithm,
		config.Auth.Methods.JwtAuth.UserIdentifier,
	)
	if err != nil {
		logger.Debugf("JWT verification failed: %v", err)
		return http.StatusForbidden, fmt.Errorf("JWT authentication failed: %w", err)
	}

	// Setup user based on JWT claims
	user, err := setupJwtUser(r, data, username, claims)
	if err != nil {
		return http.StatusForbidden, err
	}
	data.user = user
	setUserInResponseWriter(w, data.user)
	if data.user.Username == "" {
		return http.StatusForbidden, errors.ErrUnauthorized
	}

	// Generate a FileBrowser session token for JWT users if they don't have one
	if data.token == "" {
		expires := time.Hour * time.Duration(config.Auth.TokenExpirationHours)
		tokenString, _, err := auth.MakeSignedTokenAPI(user, "WEB_TOKEN_"+utils.InsecureRandomIdentifier(4), expires, user.Permissions, false)
		if err != nil {
			logger.Errorf("Failed to generate token for JWT user %s: %v", username, err)
			return http.StatusInternalServerError, fmt.Errorf("failed to generate token")
		}
		data.token = tokenString
	}

	// Call the handler function, passing in the context (or return OK if no handler)
	if fn == nil {
		return http.StatusOK, nil
	}
	return fn(w, r, data)
}

func getProxyUser(w http.ResponseWriter, r *http.Request, data *requestContext, fn handleFunc, proxyUser string) (int, error) {
	// proxy user logic
	user, err := setupProxyUser(r, data, proxyUser)
	if err != nil {
		return http.StatusForbidden, err
	}
	data.user = user
	setUserInResponseWriter(w, data.user)
	if data.user.Username == "" {
		return http.StatusForbidden, errors.ErrUnauthorized
	}
	// Generate a token for proxy users if they don't have one
	if data.token == "" {
		expires := time.Hour * time.Duration(config.Auth.TokenExpirationHours)
		tokenString, _, err := auth.MakeSignedTokenAPI(user, "WEB_TOKEN_"+utils.InsecureRandomIdentifier(4), expires, user.Permissions, false)
		if err != nil {
			logger.Errorf("Failed to generate token for proxy user %s: %v", proxyUser, err)
			return http.StatusInternalServerError, fmt.Errorf("failed to generate token")
		}
		data.token = tokenString
	}
	// Call the handler function, passing in the context (or return OK if no handler)
	if fn == nil {
		return http.StatusOK, nil
	}
	return fn(w, r, data)
}

// Middleware to ensure the user is either the requested user or an admin
func withSelfOrAdminHelper(fn handleFunc) handleFunc {
	return withUserHelper(func(w http.ResponseWriter, r *http.Request, data *requestContext) (int, error) {
		// Check if the current user is the same as the requested user or if they are an admin
		if !data.user.Permissions.Admin {
			return http.StatusForbidden, nil
		}
		// Call the actual handler function with the updated context
		return fn(w, r, data)
	})
}

func wrapHandler(fn handleFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := &requestContext{
			ctx: r.Context(),
		}

		// Call the actual handler function and get status code and error
		status, err := fn(w, r, data)
		// Handle the error case if there is one
		if err != nil {
			// Create an error response in JSON format
			response := &HttpResponse{
				Status:  status, // Use the status code from the middleware
				Message: err.Error(),
			}

			// Set the content type to JSON and status code
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(status)

			// Marshal the error response to JSON
			errorBytes, marshalErr := json.Marshal(response)
			if marshalErr != nil {
				logger.Errorf("Error marshalling error response: %v", marshalErr)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			// Write the JSON error response
			if _, writeErr := w.Write(errorBytes); writeErr != nil {
				logger.Debugf("Error writing error response: %v", writeErr)
			}
			return
		}

		// No error, proceed to write status if non-zero
		if status != 0 {
			w.WriteHeader(status)
		}
	}
}

// wrapHandlerBasicAuth wraps a handler and automatically sets WWW-Authenticate header
// for 401 Unauthorized responses, triggering Basic Auth challenge
func wrapHandlerBasicAuth(fn handleFunc) http.HandlerFunc {
	// Wrap the handler to set WWW-Authenticate header for 401 responses
	wrappedFn := func(w http.ResponseWriter, r *http.Request, data *requestContext) (int, error) {
		status, err := fn(w, r, data)
		// Set WWW-Authenticate header before returning 401
		if status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV"`)
		}
		return status, err
	}
	return wrapHandler(wrappedFn)
}

func withPermShareHelper(fn handleFunc) handleFunc {
	return withUserHelper(func(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
		if !d.user.Permissions.Share {
			return http.StatusForbidden, nil
		}
		return fn(w, r, d)
	})
}

// withBasicAuthHelper extracts Basic Auth credentials and uses the password as a JWT token
// to authenticate the user. The username is ignored, and the password should be a JWT token.
func withBasicAuthHelper(fn handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, data *requestContext) (int, error) {
		_, password, ok := r.BasicAuth()
		if !ok || password == "" {
			// Return 401 - wrapHandlerBasicAuth will set WWW-Authenticate header
			return http.StatusUnauthorized, fmt.Errorf("basic authentication required")
		}
		data.token = password
		return withUserHelper(fn)(w, r, data)
	}
}

// withBasicAuth returns an http.HandlerFunc for use with router.Handle.
// It extracts Basic Auth credentials and uses the password as a JWT token to authenticate the user.
func withBasicAuth(fn handleFunc) http.HandlerFunc {
	return wrapHandlerBasicAuth(withBasicAuthHelper(fn))
}

func withPermShare(fn handleFunc) http.HandlerFunc {
	return wrapHandler(withPermShareHelper(fn))
}

func withHashFile(fn handleFunc) http.HandlerFunc {
	return wrapHandler(withHashFileHelper(fn))
}

func withAdmin(fn handleFunc) http.HandlerFunc {
	return wrapHandler(withAdminHelper(fn))
}

func withUser(fn handleFunc) http.HandlerFunc {
	return wrapHandler(withUserHelper(fn))
}

func withOrWithoutUser(fn handleFunc) http.HandlerFunc {
	return wrapHandler(withOrWithoutUserHelper(fn))
}

func withoutUser(fn handleFunc) http.HandlerFunc {
	return wrapHandler(withoutUserHelper(fn))
}

func loginHelper(fn handleFunc) handleFunc {
	return LoginHelper(false, fn)
}

func withSelfOrAdmin(fn handleFunc) http.HandlerFunc {
	return wrapHandler(withSelfOrAdminHelper(fn))
}

// withTimeoutHelper adds a configurable timeout context to any operation
func withTimeoutHelper(timeout time.Duration, fn handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, data *requestContext) (int, error) {
		// Create a context with the specified timeout
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		// Log timeout warning at 80% of timeout duration
		warningTime := time.Duration(float64(timeout) * 0.8)
		go func() {
			select {
			case <-time.After(warningTime):
				if ctx.Err() == nil {
					logger.Api(http.StatusRequestTimeout, fmt.Sprintf("Request approaching timeout (%.1fs/%.0fs): %s %s", warningTime.Seconds(), timeout.Seconds(), r.Method, r.URL.Path))
				}
			case <-ctx.Done():
				// Context finished before warning time
				return
			}
		}()

		// Replace the request context with the timeout context
		r = r.WithContext(ctx)
		data.ctx = ctx
		// Call the handler and check for timeout
		status, err := fn(w, r, data)

		// Check if the context was cancelled due to timeout
		if ctx.Err() == context.DeadlineExceeded {
			return http.StatusRequestTimeout, fmt.Errorf("request timed out after %.0f seconds", timeout.Seconds())
		}

		return status, err
	}
}

func withTimeout(timeout time.Duration, fn handleFunc) http.HandlerFunc {
	return wrapHandler(withTimeoutHelper(timeout, fn))
}

func muxWithMiddleware(mux *http.ServeMux) *http.ServeMux {
	wrappedMux := http.NewServeMux()
	wrappedMux.Handle("/", LoggingMiddleware(mux))
	return wrappedMux
}

// ResponseWriterWrapper wraps the standard http.ResponseWriter to capture the status code
type ResponseWriterWrapper struct {
	http.ResponseWriter
	StatusCode  int
	wroteHeader bool
	PayloadSize int
	User        string
}

// WriteHeader captures the status code and ensures it's only written once
func (w *ResponseWriterWrapper) WriteHeader(statusCode int) {
	if !w.wroteHeader { // Prevent WriteHeader from being called multiple times
		if statusCode == 0 {
			statusCode = http.StatusInternalServerError
		}
		w.StatusCode = statusCode
		w.ResponseWriter.WriteHeader(statusCode)
		w.wroteHeader = true
	}
}

// Write is the method to write the response body and ensure WriteHeader is called
func (w *ResponseWriterWrapper) Write(b []byte) (int, error) {
	if !w.wroteHeader { // Default to 200 if WriteHeader wasn't called explicitly
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Helper function to set the user in the ResponseWriterWrapper
func setUserInResponseWriter(w http.ResponseWriter, user *users.User) {
	// Wrap the response writer to set the user field
	if wrappedWriter, ok := w.(*ResponseWriterWrapper); ok {
		if user != nil {
			wrappedWriter.User = user.Username
		}
	}
}

func getRemoteIP(r *http.Request) string {
	// 1. Check X-Forwarded-For
	xff := r.Header.Get("X-Forwarded-For")
	if config.Http.TrustedHeaders["x-forwarded-for"] && xff != "" {
		// The first IP is the original client
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// 2. Check X-Real-IP
	xri := r.Header.Get("X-Real-IP")
	if config.Http.TrustedHeaders["x-real-ip"] && xri != "" {
		return xri
	}

	// 3. Fallback to RemoteAddr (strip port if necessary)
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// LoggingMiddleware logs each request and its status code.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// DEFER RECOVERY FUNCTION
		defer func() {
			if rcv := recover(); rcv != nil {
				method := r.Method
				url := r.URL.String()
				username := "unknown" // Default username

				// Attempt to get username from ResponseWriterWrapper if it's set
				if ww, ok := w.(*ResponseWriterWrapper); ok && ww.User != "" {
					username = ww.User
				}
				// Get Go-level stack trace
				buf := make([]byte, 16384)     // Increased buffer size for potentially long CGo traces
				n := runtime.Stack(buf, false) // false for current goroutine only
				stackTrace := string(buf[:n])

				logger.Errorf("PANIC RECOVERED: %v\nUser: %s\nMethod: %s\nURL: %s\nRemoteAddr: %s\nGo Stack Trace:\n%s",
					rcv, username, method, url, getRemoteIP(r), stackTrace)

				// Attempt to send a 500 error response to the client
				// This is a best-effort; the connection might be broken or process too unstable.
				if ww, ok := w.(*ResponseWriterWrapper); ok { // Check if it's our wrapper
					if !ww.wroteHeader { // Only write if headers haven't been sent
						ww.Header().Set("Content-Type", "application/json; charset=utf-8")
						ww.WriteHeader(http.StatusInternalServerError)
					}
				} else {
					_, _ = renderJSON(w, r, &HttpResponse{
						Status:  500,
						Message: "A critical internal error occurred. Please try again later.",
					}, http.StatusInternalServerError)
				}

			}
		}()

		start := time.Now()
		wrappedWriter := &ResponseWriterWrapper{ResponseWriter: w, StatusCode: http.StatusOK}

		// Call the next handler in the chain
		next.ServeHTTP(wrappedWriter, r)

		// Existing logging logic for normal requests
		fullURL := r.URL.Path
		if r.URL.RawQuery != "" {
			fullURL += "?" + r.URL.RawQuery
		}
		truncUser := wrappedWriter.User
		if truncUser == "" {
			truncUser = "N/A" // Handle case where user might not be set (e.g., if panic occurred before user auth)
		} else if len(truncUser) > 12 {
			truncUser = truncUser[:10] + ".."
		}
		duration := time.Since(start)

		// ApiPathExclude is applied per logging sink inside go-logger (logger.ApiPath).
		logger.ApiPath(wrappedWriter.StatusCode, fullURL,
			fmt.Sprintf("%-7s | %3d | %-15s | %-12s | %-12s | \"%s\"",
				r.Method,
				wrappedWriter.StatusCode,
				getRemoteIP(r),
				truncUser,
				fmt.Sprintf("%vms", duration.Milliseconds()),
				fullURL))
	})
}

func renderJSON(w http.ResponseWriter, r *http.Request, data interface{}, statusCode ...int) (int, error) {
	// Default to 200 if status code not provided
	code := http.StatusOK
	if len(statusCode) > 0 && statusCode[0] != 0 {
		code = statusCode[0]
	}

	marsh, err := json.Marshal(data)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	// Calculate size in KB
	payloadSizeKB := len(marsh) / 1024
	// Set headers before writing
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Check if the client accepts gzip encoding and hasn't explicitly disabled it
	if acceptsGzip(r) && payloadSizeKB > 10 {
		// Enable gzip compression
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(code)
		gz := gzip.NewWriter(w)
		defer gz.Close()

		if _, err := gz.Write(marsh); err != nil {
			return http.StatusInternalServerError, err
		}
	} else {
		// Normal response without compression
		w.WriteHeader(code)
		if _, err := w.Write(marsh); err != nil {
			return http.StatusInternalServerError, err
		}
	}

	return code, nil
}

func acceptsGzip(r *http.Request) bool {
	ae := r.Header.Get("Accept-Encoding")
	return ae != "" && strings.Contains(ae, "gzip")
}

func (w *ResponseWriterWrapper) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func getScheme(r *http.Request) string {
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
