package http

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gtsteffaniak/go-logger/logger"
	"golang.org/x/net/webdav"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/fileutils"
	commonerrors "github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
)

// fileInfoWrapper wraps iteminfo.ItemInfo to implement os.FileInfo
type fileInfoWrapper struct {
	iteminfo.ItemInfo
}

func (f *fileInfoWrapper) Name() string       { return f.ItemInfo.Name }
func (f *fileInfoWrapper) Size() int64        { return f.ItemInfo.Size }
func (f *fileInfoWrapper) Mode() os.FileMode  { return f.mode() }
func (f *fileInfoWrapper) ModTime() time.Time { return f.ItemInfo.ModTime }
func (f *fileInfoWrapper) IsDir() bool        { return f.Type == "directory" }
func (f *fileInfoWrapper) Sys() interface{}   { return nil }

func (f *fileInfoWrapper) mode() os.FileMode {
	if f.IsDir() {
		return os.ModeDir | fileutils.PermDir
	}
	return fileutils.PermFile
}

// filteredFileSystem wraps a webdav.FileSystem and filters directory listings using FileInfoFaster
type filteredFileSystem struct {
	fs                      webdav.FileSystem
	source                  string
	user                    *users.User
	entryPaths              map[string]struct{}
	writeTargets            map[string]struct{}
	writePermissions        map[string]webDAVWritePermission
	removedOverwriteTargets map[string]struct{}
}

type webDAVWritePermission uint8

const (
	webDAVWriteCreate webDAVWritePermission = iota + 1
	webDAVWriteModify
)

const authenticatedWebDAVLockTokenPrefix = "urn:filebrowser-lock:"

var (
	authenticatedWebDAVLockTokenSecret     [sha256.Size]byte
	authenticatedWebDAVLockTokenSecretErr  error
	authenticatedWebDAVLockTokenSecretOnce sync.Once
)

type authenticatedWebDAVLockSystem struct {
	webdav.LockSystem
	resolveName   func(string) (string, error)
	requestPath   string
	createdTokens map[string]struct{}
}

func authenticatedWebDAVLockSecret() ([]byte, error) {
	authenticatedWebDAVLockTokenSecretOnce.Do(func() {
		_, authenticatedWebDAVLockTokenSecretErr = rand.Read(authenticatedWebDAVLockTokenSecret[:])
	})
	if authenticatedWebDAVLockTokenSecretErr != nil {
		return nil, authenticatedWebDAVLockTokenSecretErr
	}
	return authenticatedWebDAVLockTokenSecret[:], nil
}

func encodeAuthenticatedWebDAVLockToken(root, token string) (string, error) {
	secret, err := authenticatedWebDAVLockSecret()
	if err != nil {
		return "", err
	}
	rootDigest := sha256.Sum256([]byte(root))
	payload := make([]byte, 0, len(rootDigest)+len(token))
	payload = append(payload, rootDigest[:]...)
	payload = append(payload, token...)
	signer := hmac.New(sha256.New, secret)
	_, _ = signer.Write(payload)
	return authenticatedWebDAVLockTokenPrefix + base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(signer.Sum(nil)), nil
}

func decodeAuthenticatedWebDAVLockToken(token string) ([sha256.Size]byte, string, error) {
	var rootDigest [sha256.Size]byte
	encoded := strings.TrimPrefix(token, authenticatedWebDAVLockTokenPrefix)
	if encoded == token {
		return rootDigest, "", webdav.ErrForbidden
	}
	parts := strings.SplitN(encoded, ".", 2)
	if len(parts) != 2 {
		return rootDigest, "", webdav.ErrForbidden
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) <= sha256.Size {
		return rootDigest, "", webdav.ErrForbidden
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return rootDigest, "", webdav.ErrForbidden
	}
	secret, err := authenticatedWebDAVLockSecret()
	if err != nil {
		return rootDigest, "", err
	}
	signer := hmac.New(sha256.New, secret)
	_, _ = signer.Write(payload)
	if !hmac.Equal(signature, signer.Sum(nil)) {
		return rootDigest, "", webdav.ErrForbidden
	}
	copy(rootDigest[:], payload[:sha256.Size])
	return rootDigest, string(payload[sha256.Size:]), nil
}

func (ls *authenticatedWebDAVLockSystem) resolveLockName(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	return ls.resolveName(name)
}

func authenticatedWebDAVLockRootMatchesName(rootDigest [sha256.Size]byte, name string) bool {
	if name == "" {
		return false
	}
	for candidate := pathpkg.Clean(name); ; candidate = pathpkg.Dir(candidate) {
		if sha256.Sum256([]byte(candidate)) == rootDigest {
			return true
		}
		if candidate == "/" || candidate == "." {
			return false
		}
	}
}

func (ls *authenticatedWebDAVLockSystem) Confirm(now time.Time, name0, name1 string, conditions ...webdav.Condition) (func(), error) {
	name0, err := ls.resolveLockName(name0)
	if err != nil {
		return nil, webdav.ErrConfirmationFailed
	}
	name1, err = ls.resolveLockName(name1)
	if err != nil {
		return nil, webdav.ErrConfirmationFailed
	}
	translated := make([]webdav.Condition, len(conditions))
	copy(translated, conditions)
	for i := range translated {
		if translated[i].Token == "" {
			continue
		}
		rootDigest, rawToken, err := decodeAuthenticatedWebDAVLockToken(translated[i].Token)
		if err != nil || (!authenticatedWebDAVLockRootMatchesName(rootDigest, name0) && !authenticatedWebDAVLockRootMatchesName(rootDigest, name1)) {
			return nil, webdav.ErrConfirmationFailed
		}
		translated[i].Token = rawToken
	}
	return ls.LockSystem.Confirm(now, name0, name1, translated...)
}

func (ls *authenticatedWebDAVLockSystem) Create(now time.Time, details webdav.LockDetails) (string, error) {
	root, err := ls.resolveLockName(details.Root)
	if err != nil {
		return "", err
	}
	details.Root = root
	rawToken, err := ls.LockSystem.Create(now, details)
	if err != nil {
		return "", err
	}
	token, err := encodeAuthenticatedWebDAVLockToken(root, rawToken)
	if err != nil {
		_ = ls.LockSystem.Unlock(now, rawToken)
		return "", err
	}
	ls.createdTokens[token] = struct{}{}
	return token, nil
}

func (ls *authenticatedWebDAVLockSystem) Refresh(now time.Time, token string, duration time.Duration) (webdav.LockDetails, error) {
	root, err := ls.resolveLockName(ls.requestPath)
	if err != nil {
		return webdav.LockDetails{}, webdav.ErrNoSuchLock
	}
	rootDigest, rawToken, err := decodeAuthenticatedWebDAVLockToken(token)
	if err != nil || rootDigest != sha256.Sum256([]byte(root)) {
		return webdav.LockDetails{}, webdav.ErrNoSuchLock
	}
	details, err := ls.LockSystem.Refresh(now, rawToken, duration)
	if err == nil {
		details.Root = ls.requestPath
	}
	return details, err
}

func (ls *authenticatedWebDAVLockSystem) Unlock(now time.Time, token string) error {
	_, rawToken, err := decodeAuthenticatedWebDAVLockToken(token)
	if err != nil {
		return webdav.ErrForbidden
	}
	if _, created := ls.createdTokens[token]; created {
		delete(ls.createdTokens, token)
		return ls.LockSystem.Unlock(now, rawToken)
	}
	root, err := ls.resolveLockName(ls.requestPath)
	if err != nil {
		return webdav.ErrForbidden
	}
	rootDigest, _, err := decodeAuthenticatedWebDAVLockToken(token)
	if err != nil || rootDigest != sha256.Sum256([]byte(root)) {
		return webdav.ErrForbidden
	}
	return ls.LockSystem.Unlock(now, rawToken)
}

func resolveAuthenticatedWebDAVLockName(user *users.User, source, requestPath string) (string, error) {
	target, err := resolveAuthenticatedReadTarget(user, source, requestPath)
	if err != nil {
		target, err = resolveAuthenticatedWriteTarget(user, source, requestPath)
	}
	if err != nil {
		return "", err
	}
	canonicalPath := target.CanonicalPath
	if target.Info != nil {
		relativePath, relativeErr := filepath.Rel(target.SourceReal, target.RealPath)
		if relativeErr != nil || filepath.IsAbs(relativePath) {
			return "", commonerrors.ErrAccessDenied
		}
		relativePath = publicShareCanonicalCaseRelative(target.SourceReal, relativePath)
		canonicalPath = normalizePublicShareIndexPath(filepath.ToSlash(relativePath))
	}
	scopedPath, err := publicShareScopedPath(target.UserScope, canonicalPath)
	if err != nil {
		return "", err
	}
	scopeRelative, err := filepath.Rel(target.SourceReal, target.ScopeReal)
	if err != nil || filepath.IsAbs(scopeRelative) {
		return "", commonerrors.ErrAccessDenied
	}
	scopeRelative = publicShareCanonicalCaseRelative(target.SourceReal, scopeRelative)
	scopeIdentity := normalizePublicShareIndexPath(filepath.ToSlash(scopeRelative))
	scopeDigest := sha256.Sum256([]byte(source + "\x00" + scopeIdentity))
	return utils.JoinPathAsUnix("/.filebrowser-locks", fmt.Sprintf("%x", scopeDigest), scopedPath), nil
}

func webDAVPathKey(requestPath string) string {
	return normalizePublicShareIndexPath(requestPath)
}

func webDAVTargetWritePermission(target authenticatedReadTarget) webDAVWritePermission {
	if target.Info == nil {
		return webDAVWriteCreate
	}
	return webDAVWriteModify
}

func requireWebDAVWritePermission(permissions users.Permissions, required webDAVWritePermission) error {
	switch required {
	case webDAVWriteCreate:
		if !permissions.Create {
			return fmt.Errorf("create permission required")
		}
	case webDAVWriteModify:
		if !permissions.Modify {
			return fmt.Errorf("modify permission required")
		}
	default:
		return fmt.Errorf("write permission required")
	}
	return nil
}

func (ffs *filteredFileSystem) requireWritePermission(requestPath string, target authenticatedReadTarget) (webDAVWritePermission, error) {
	required := webDAVTargetWritePermission(target)
	key := webDAVPathKey(requestPath)
	if target.Info == nil {
		if _, removed := ffs.removedOverwriteTargets[key]; removed {
			if configured, ok := ffs.writePermissions[key]; ok {
				required = configured
			}
		}
	}
	return required, requireWebDAVWritePermission(ffs.user.Permissions, required)
}

func (ffs *filteredFileSystem) usesEntrySemantics(requestPath string) bool {
	_, ok := ffs.entryPaths[webDAVPathKey(requestPath)]
	return ok
}

func webDAVVirtualRoot(requestPath string) bool {
	return webDAVPathKey(requestPath) == "/"
}

func webDAVNotExist(err error) bool {
	return os.IsNotExist(err) || errors.Is(err, commonerrors.ErrNotExist)
}

func webDAVFileSystemError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, commonerrors.ErrAccessDenied), os.IsPermission(err):
		return os.ErrPermission
	case webDAVNotExist(err):
		return os.ErrNotExist
	default:
		return err
	}
}

// getFileInfo retrieves file information with fresh access control.
// requestPath should NOT include user scope - FileInfoFaster applies it internally
func (ffs *filteredFileSystem) getFileInfo(requestPath string, expand bool) (*iteminfo.ExtendedFileInfo, error) {
	target, err := resolveAuthenticatedBrowseTarget(ffs.user, ffs.source, requestPath)
	if err != nil {
		return nil, err
	}

	// FileInfoFaster applies user scope internally and enforces access control.
	fileInfo, err := files.FileInfoFaster(utils.FileOptions{
		Path:              target.ScopedPath,
		Source:            ffs.source,
		Expand:            expand,
		ShowHidden:        ffs.user.ShowHidden,
		HideFileExt:       ffs.user.HideFileExt,
		SkipExtendedAttrs: true,
		FollowSymlinks:    false,
	}, store.Access, ffs.user, store.Share)
	if err != nil {
		return nil, err
	}
	applyAuthenticatedFileInfoIdentity(fileInfo, target)
	fileInfo.Path = requestPath
	if err = filterAuthenticatedDirectoryFileInfo(ffs.user, ffs.source, target, fileInfo); err != nil {
		return nil, err
	}

	return fileInfo, nil
}

// checkAccess validates if the user can access a given path
// This is used by all write operations (mkdir, delete, rename, etc.)
// Returns nil if access is allowed, error otherwise
func (ffs *filteredFileSystem) checkAccess(requestPath string) error {
	// First, validate permissions using CheckPermissions
	indexPath, _, err := files.CheckPermissions(utils.FileOptions{
		FollowSymlinks: false,
		Path:           requestPath,
		Source:         ffs.source,
		ShowHidden:     ffs.user.ShowHidden,
	}, store.Access, ffs.user)
	if err != nil {
		logger.Debugf("checkAccess: CheckPermissions denied for %s: %v", requestPath, err)
		return err
	}

	// Existing targets must pass canonical checks before index metadata lookup. Missing
	// write targets still go through the legacy index-rule lookup so excluded parents
	// cannot become writable merely because the child does not exist yet.
	_, resolveErr := resolveAuthenticatedReadTarget(ffs.user, ffs.source, requestPath)
	if resolveErr == nil {
		_, err = ffs.getFileInfo(requestPath, false)
	} else if webDAVNotExist(resolveErr) {
		_, err = files.FileInfoFaster(utils.FileOptions{
			Path:              requestPath,
			Source:            ffs.source,
			Expand:            false,
			ShowHidden:        ffs.user.ShowHidden,
			HideFileExt:       ffs.user.HideFileExt,
			SkipExtendedAttrs: true,
			FollowSymlinks:    false,
		}, store.Access, ffs.user, store.Share)
	} else {
		return resolveErr
	}
	if err == nil {
		// Successfully got info - access allowed
		return nil
	}

	// Handle specific error cases
	if errors.Is(err, commonerrors.ErrAccessDenied) {
		logger.Debugf("checkAccess: access explicitly denied for %s", requestPath)
		return os.ErrPermission
	}

	// CRITICAL: If item is not indexed AND not viewable, deny access
	// This prevents WebDAV from creating/modifying files in non-indexed areas
	if errors.Is(err, commonerrors.ErrNotViewable) {
		logger.Debugf("checkAccess: path not viewable for %s", requestPath)
		return os.ErrPermission
	}

	// If not indexed but potentially viewable, we need to check more carefully
	if errors.Is(err, commonerrors.ErrNotIndexed) {
		// Get the index to check viewability
		idx := indexing.GetIndex(ffs.source)
		if idx == nil {
			return fmt.Errorf("source not found")
		}

		// Check if the item is viewable using GetFileInfo (without expand)
		info, getErr := idx.GetFileInfo(indexing.FileInfoRequest{
			IndexPath:         indexPath,
			FollowSymlinks:    false,
			ShowHidden:        ffs.user.ShowHidden,
			Expand:            false,
			SkipExtendedAttrs: true,
		})

		// If GetFileInfo succeeds, the item is viewable despite not being indexed
		if getErr == nil && info != nil {
			logger.Debugf("checkAccess: path not indexed but viewable for %s", requestPath)
			return nil // Allow access to viewable items
		}

		// Not viewable - deny access
		logger.Debugf("checkAccess: path not indexed and not viewable for %s", requestPath)
		return os.ErrPermission
	}

	// For other errors (like file not found), that's okay for new file/directory creation
	// The caller will handle whether the operation is appropriate
	logger.Debugf("checkAccess: path check returned: %v (may be acceptable for new items)", err)
	return nil
}

// filteredFile wraps a webdav.File and filters Readdir results based on FileInfoFaster
type filteredFile struct {
	webdav.File
	fs                *filteredFileSystem
	requestPath       string // The request path (without user scope)
	isDir             bool   // Whether this is a directory
	authenticatedRead bool
}

func (ff *filteredFile) Stat() (os.FileInfo, error) {
	if !ff.authenticatedRead {
		return ff.File.Stat()
	}
	return ff.fs.Stat(context.Background(), ff.requestPath)
}

func (ff *filteredFile) Readdir(count int) ([]os.FileInfo, error) {
	// If not a directory, use the underlying file's Readdir
	if !ff.isDir {
		return ff.File.Readdir(count)
	}

	// Pass the requestPath (without scope) to getCachedFileInfo
	// FileInfoFaster will apply the user's scope internally
	fileInfo, err := ff.fs.getFileInfo(ff.requestPath, true)
	if err != nil {
		logger.Debugf("readdir: getFileInfo failed for requestPath=%s: %v", ff.requestPath, err)
		// Handle errors gracefully - return empty directory for access/indexing issues
		// This is especially important when user's scope points to a non-viewable directory
		if errors.Is(err, commonerrors.ErrAccessDenied) ||
			errors.Is(err, commonerrors.ErrNotIndexed) ||
			errors.Is(err, commonerrors.ErrNotViewable) {
			logger.Debugf("readdir: access issue for %s: %v - returning empty", ff.requestPath, err)
			return []os.FileInfo{}, nil
		}
		// Other errors - propagate them
		return nil, err
	}

	// Build os.FileInfo list directly from FileInfoFaster's filtered results
	// No need to read from underlying filesystem - FileInfoFaster already filtered by permissions
	entries := make([]os.FileInfo, 0, len(fileInfo.Files)+len(fileInfo.Folders))

	// Add folders first (common convention)
	for _, folder := range fileInfo.Folders {
		entries = append(entries, &fileInfoWrapper{ItemInfo: folder})
	}

	// Add files
	for _, file := range fileInfo.Files {
		entries = append(entries, &fileInfoWrapper{ItemInfo: file.ItemInfo})
	}

	// Handle count parameter
	if count > 0 && len(entries) > count {
		return entries[:count], nil
	}
	return entries, nil
}

func (ffs *filteredFileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	target, err := resolveAuthenticatedWriteTarget(ffs.user, ffs.source, name)
	if err != nil {
		return webDAVFileSystemError(err)
	}
	if _, err := ffs.requireWritePermission(name, target); err != nil {
		return err
	}

	// Check access before creating directory
	if err := ffs.checkAccess(name); err != nil {
		logger.Debugf("Mkdir: access denied for %s: %v", name, err)
		return err
	}
	return ffs.fs.Mkdir(ctx, target.CanonicalPath, perm)
}

func (ffs *filteredFileSystem) OpenFile(ctx context.Context, requestPath string, flag int, perm os.FileMode) (webdav.File, error) {
	// Check if this is a write operation
	isWrite := (flag&os.O_WRONLY) != 0 || (flag&os.O_RDWR) != 0 || (flag&os.O_CREATE) != 0

	if isWrite {
		target, err := resolveAuthenticatedWriteTarget(ffs.user, ffs.source, requestPath)
		if err != nil {
			return nil, webDAVFileSystemError(err)
		}
		if target.Info != nil && target.Info.Mode()&os.ModeSymlink != 0 {
			return nil, os.ErrPermission
		}
		required, err := ffs.requireWritePermission(requestPath, target)
		if err != nil {
			return nil, err
		}
		if target.Info != nil && flag&os.O_TRUNC != 0 && !ffs.user.Permissions.Delete {
			return nil, fmt.Errorf("delete permission required to overwrite destination")
		}

		// For write operations, check access
		if accessErr := ffs.checkAccess(requestPath); accessErr != nil {
			logger.Debugf("OpenFile: write access denied for %s: %v", requestPath, accessErr)
			return nil, accessErr
		}

		if target.Info == nil && required == webDAVWriteCreate && flag&os.O_CREATE != 0 {
			flag |= os.O_EXCL
		} else if target.Info != nil && !ffs.user.Permissions.Create {
			flag &^= os.O_CREATE
		}
		file, err := ffs.fs.OpenFile(ctx, target.CanonicalPath, flag, perm)
		if err != nil {
			if required == webDAVWriteCreate && os.IsExist(err) {
				return nil, os.ErrPermission
			}
			return nil, err
		}
		stat, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		return &filteredFile{
			File:        file,
			fs:          ffs,
			requestPath: requestPath,
			isDir:       stat.IsDir(),
		}, nil
	}

	target, err := resolveAuthenticatedReadTarget(ffs.user, ffs.source, requestPath)
	if err != nil {
		return nil, webDAVFileSystemError(err)
	}
	file, stat, err := openAuthenticatedReadEntryTarget(target)
	if err != nil {
		return nil, webDAVFileSystemError(err)
	}
	return &filteredFile{
		File:              file,
		fs:                ffs,
		requestPath:       requestPath,
		isDir:             stat.IsDir(),
		authenticatedRead: true,
	}, nil
}

func (ffs *filteredFileSystem) RemoveAll(ctx context.Context, requestPath string) error {
	if webDAVVirtualRoot(requestPath) {
		return os.ErrPermission
	}
	if !ffs.user.Permissions.Delete {
		return fmt.Errorf("delete permission required")
	}

	target, err := resolveAuthenticatedEntryTarget(ffs.user, ffs.source, requestPath)
	if err != nil {
		return webDAVFileSystemError(err)
	}
	if target.Info.Mode()&os.ModeSymlink == 0 {
		if accessErr := ffs.checkAccess(requestPath); accessErr != nil {
			logger.Debugf("RemoveAll: access denied for %s: %v", requestPath, accessErr)
			return accessErr
		}
	}
	err = ffs.fs.RemoveAll(ctx, target.EntryPath)
	if err == nil {
		key := webDAVPathKey(requestPath)
		if _, overwrite := ffs.writePermissions[key]; overwrite {
			ffs.removedOverwriteTargets[key] = struct{}{}
		}
	}
	return err
}

func (ffs *filteredFileSystem) Rename(ctx context.Context, oldPath, newPath string) error {
	if webDAVVirtualRoot(oldPath) || webDAVVirtualRoot(newPath) {
		return os.ErrPermission
	}
	if !ffs.user.Permissions.Modify {
		return fmt.Errorf("modify permission required")
	}

	oldTarget, err := resolveAuthenticatedEntryTarget(ffs.user, ffs.source, oldPath)
	if err != nil {
		return webDAVFileSystemError(err)
	}
	if oldTarget.Info.Mode()&os.ModeSymlink == 0 {
		if accessErr := ffs.checkAccess(oldPath); accessErr != nil {
			logger.Debugf("Rename: access denied for source %s: %v", oldPath, accessErr)
			return accessErr
		}
	}
	newTarget, err := resolveAuthenticatedWriteTarget(ffs.user, ffs.source, newPath)
	if err != nil {
		return webDAVFileSystemError(err)
	}
	if _, err := ffs.requireWritePermission(newPath, newTarget); err != nil {
		return err
	}
	if newTarget.Info != nil && !ffs.user.Permissions.Delete {
		return fmt.Errorf("delete permission required to overwrite destination")
	}
	if newTarget.Info == nil || newTarget.Info.Mode()&os.ModeSymlink == 0 {
		if err := ffs.checkAccess(newPath); err != nil {
			logger.Debugf("Rename: access denied for destination %s: %v", newPath, err)
			return err
		}
	}
	if newTarget.Info == nil && !ffs.user.Permissions.Delete {
		if fs, ok := ffs.fs.(interface {
			RenameNoReplace(context.Context, string, string) error
		}); ok {
			return fs.RenameNoReplace(ctx, oldTarget.EntryPath, newTarget.EntryPath)
		}
		if _, ok := ffs.fs.(webdav.Dir); ok {
			return renameWebDAVNoReplace(oldTarget.RealPath, newTarget.RealPath)
		}
		return os.ErrPermission
	}
	return ffs.fs.Rename(ctx, oldTarget.EntryPath, newTarget.EntryPath)
}

func (ffs *filteredFileSystem) Stat(_ context.Context, requestPath string) (os.FileInfo, error) {
	if _, writeTarget := ffs.writeTargets[webDAVPathKey(requestPath)]; writeTarget {
		target, err := resolveAuthenticatedWriteTarget(ffs.user, ffs.source, requestPath)
		if err != nil {
			return nil, webDAVFileSystemError(err)
		}
		if _, err := ffs.requireWritePermission(requestPath, target); err != nil {
			return nil, os.ErrPermission
		}
	}
	entrySemantics := ffs.usesEntrySemantics(requestPath)
	resolveTarget := resolveAuthenticatedReadTarget
	if entrySemantics {
		resolveTarget = resolveAuthenticatedEntryTarget
	}
	target, targetErr := resolveTarget(ffs.user, ffs.source, requestPath)
	if targetErr != nil {
		return nil, webDAVFileSystemError(targetErr)
	}
	var authenticatedInfo *iteminfo.ExtendedFileInfo
	var err error
	if !entrySemantics {
		authenticatedInfo, err = ffs.getFileInfo(requestPath, false)
		if errors.Is(err, commonerrors.ErrAccessDenied) || errors.Is(err, commonerrors.ErrNotViewable) {
			return nil, os.ErrPermission
		}
		if errors.Is(err, commonerrors.ErrNotIndexed) {
			if accessErr := ffs.checkAccess(requestPath); accessErr != nil {
				return nil, os.ErrPermission
			}
		} else if err != nil {
			return nil, webDAVFileSystemError(err)
		}
	}
	current, err := resolveTarget(ffs.user, ffs.source, requestPath)
	if err != nil || !sameAuthenticatedReadTarget(target, current) {
		return nil, os.ErrPermission
	}
	if authenticatedInfo != nil {
		return &fileInfoWrapper{ItemInfo: authenticatedInfo.ItemInfo}, nil
	}
	return current.Info, nil
}

func preflightWebDAVReadTarget(user *users.User, source, requestPath string, entry, allowMissing bool) (authenticatedReadTarget, int, error) {
	var target authenticatedReadTarget
	safePath, err := sanitizeAuthenticatedReadPath(requestPath)
	if err != nil {
		return target, http.StatusBadRequest, nil
	}
	if entry {
		target, err = resolveAuthenticatedEntryTarget(user, source, safePath)
	} else {
		target, err = resolveAuthenticatedReadTarget(user, source, safePath)
	}
	if err == nil {
		return target, 0, nil
	}
	if allowMissing && webDAVNotExist(err) {
		return target, 0, nil
	}
	if errors.Is(err, commonerrors.ErrAccessDenied) || os.IsPermission(err) {
		return target, http.StatusForbidden, nil
	}
	return target, errToStatus(err), nil
}

func preflightWebDAVWriteTarget(user *users.User, source, requestPath string) (authenticatedReadTarget, int, error) {
	var target authenticatedReadTarget
	safePath, err := sanitizeAuthenticatedReadPath(requestPath)
	if err != nil {
		return target, http.StatusBadRequest, nil
	}
	target, err = resolveAuthenticatedWriteTarget(user, source, safePath)
	if err == nil {
		return target, 0, nil
	}
	if errors.Is(err, commonerrors.ErrAccessDenied) || os.IsPermission(err) {
		return target, http.StatusForbidden, nil
	}
	if webDAVNotExist(err) {
		return target, http.StatusConflict, nil
	}
	return target, errToStatus(err), nil
}

func webDAVDestinationPath(r *http.Request, prefix string) (string, int, error) {
	destination := r.Header.Get("Destination")
	if destination == "" {
		return "", http.StatusBadRequest, fmt.Errorf("missing WebDAV destination")
	}
	u, err := url.Parse(destination)
	if err != nil {
		return "", http.StatusBadRequest, fmt.Errorf("invalid WebDAV destination: %w", err)
	}
	if u.Host != "" && u.Host != r.Host {
		return "", http.StatusBadGateway, fmt.Errorf("WebDAV destination host does not match request host")
	}
	destinationPath := strings.TrimPrefix(u.Path, prefix)
	if len(destinationPath) == len(u.Path) {
		return "", http.StatusNotFound, fmt.Errorf("WebDAV destination is outside the current source")
	}
	if destinationPath == "" {
		return "", http.StatusBadGateway, fmt.Errorf("WebDAV destination path is empty")
	}
	if webDAVVirtualRoot(destinationPath) {
		return "", http.StatusForbidden, nil
	}
	return destinationPath, 0, nil
}

// webDAVHandler serves WebDAV requests.
func webDAVHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	requestPath := r.PathValue("path")
	if requestPath == "" {
		requestPath = "/"
	}
	if !strings.HasPrefix(requestPath, "/") {
		requestPath = "/" + requestPath
	}
	permissionPath := utils.AddTrailingSlashIfNotExists(requestPath)
	source := r.PathValue("source")
	webDavPrefix := config.Server.BaseURL + "dav"
	prefix := webDavPrefix + "/" + source
	entryPaths := make(map[string]struct{})
	writeTargets := make(map[string]struct{})
	writePermissions := make(map[string]webDAVWritePermission)
	removedOverwriteTargets := make(map[string]struct{})
	if r.Method == http.MethodPut || r.Method == "MKCOL" || r.Method == "LOCK" || r.Method == "UNLOCK" || r.Method == "PROPPATCH" {
		writeTargets[webDAVPathKey(requestPath)] = struct{}{}
	}

	switch r.Method {
	case "PROPFIND", http.MethodOptions:
		if !d.user.Permissions.Browse {
			return http.StatusForbidden, nil
		}
	case http.MethodGet, http.MethodHead, http.MethodPost, "COPY":
		if !d.user.Permissions.Browse || !d.user.Permissions.Download {
			// Avoid error bodies so denied HEAD requests cannot gain a Content-Length.
			return http.StatusForbidden, nil
		}
	case "LOCK", "UNLOCK":
		if !d.user.Permissions.Browse || !d.user.Permissions.Download {
			return http.StatusForbidden, nil
		}
	case "PROPPATCH":
		if !d.user.Permissions.Browse || !d.user.Permissions.Download || !d.user.Permissions.Modify {
			return http.StatusForbidden, nil
		}
	default:
		if !d.user.Permissions.Download {
			return http.StatusForbidden, fmt.Errorf("download permission required")
		}
	}
	if r.Method == "DELETE" && !d.user.Permissions.Delete {
		return http.StatusForbidden, fmt.Errorf("delete permission required")
	}
	if r.Method == "MOVE" && !d.user.Permissions.Modify {
		return http.StatusForbidden, fmt.Errorf("modify permission required")
	}
	if (r.Method == http.MethodPut || r.Method == "MKCOL" || r.Method == "LOCK" || r.Method == "UNLOCK") &&
		!d.user.Permissions.Create && !d.user.Permissions.Modify {
		return http.StatusForbidden, fmt.Errorf("create or modify permission required")
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost, "PROPFIND", "PROPPATCH":
		if _, status, err := preflightWebDAVReadTarget(d.user, source, requestPath, false, false); status != 0 {
			return status, err
		}
	case http.MethodOptions:
		if _, status, err := preflightWebDAVReadTarget(d.user, source, requestPath, false, true); status != 0 {
			return status, err
		}
	case "COPY":
		sourceTarget, status, err := preflightWebDAVReadTarget(d.user, source, requestPath, false, false)
		if status != 0 {
			return status, err
		}
		destinationPath, status, err := webDAVDestinationPath(r, prefix)
		if status != 0 {
			return status, err
		}
		destinationTarget, status, err := preflightWebDAVWriteTarget(d.user, source, destinationPath)
		if status != 0 {
			return status, err
		}
		writeTargets[webDAVPathKey(destinationPath)] = struct{}{}
		required := webDAVTargetWritePermission(destinationTarget)
		if err := requireWebDAVWritePermission(d.user.Permissions, required); err != nil {
			return http.StatusForbidden, err
		}
		if sourceTarget.Info.IsDir() && !d.user.Permissions.Create {
			return http.StatusForbidden, fmt.Errorf("create permission required for directory contents")
		}
		overwrite := destinationTarget.Info != nil && r.Header.Get("Overwrite") != "F"
		if overwrite && !d.user.Permissions.Delete {
			return http.StatusForbidden, fmt.Errorf("delete permission required to overwrite destination")
		}
		if destinationTarget.Info != nil {
			entryPaths[webDAVPathKey(destinationPath)] = struct{}{}
			writePermissions[webDAVPathKey(destinationPath)] = required
		}
	case "MOVE":
		if webDAVVirtualRoot(requestPath) {
			return http.StatusForbidden, nil
		}
		if _, status, err := preflightWebDAVReadTarget(d.user, source, requestPath, true, false); status != 0 {
			return status, err
		}
		entryPaths[webDAVPathKey(requestPath)] = struct{}{}
		destinationPath, status, err := webDAVDestinationPath(r, prefix)
		if status != 0 {
			return status, err
		}
		destinationTarget, status, err := preflightWebDAVWriteTarget(d.user, source, destinationPath)
		if status != 0 {
			return status, err
		}
		writeTargets[webDAVPathKey(destinationPath)] = struct{}{}
		required := webDAVTargetWritePermission(destinationTarget)
		if err := requireWebDAVWritePermission(d.user.Permissions, required); err != nil {
			return http.StatusForbidden, err
		}
		overwrite := destinationTarget.Info != nil && r.Header.Get("Overwrite") == "T"
		if overwrite && !d.user.Permissions.Delete {
			return http.StatusForbidden, fmt.Errorf("delete permission required to overwrite destination")
		}
		if destinationTarget.Info != nil {
			entryPaths[webDAVPathKey(destinationPath)] = struct{}{}
			writePermissions[webDAVPathKey(destinationPath)] = required
		}
	case http.MethodPut, "MKCOL":
		target, status, err := preflightWebDAVWriteTarget(d.user, source, requestPath)
		if status != 0 {
			return status, err
		}
		if target.Info != nil && target.Info.Mode()&os.ModeSymlink != 0 {
			return http.StatusForbidden, nil
		}
		required := webDAVTargetWritePermission(target)
		if err := requireWebDAVWritePermission(d.user.Permissions, required); err != nil {
			return http.StatusForbidden, err
		}
		if r.Method == http.MethodPut && target.Info != nil && !d.user.Permissions.Delete {
			return http.StatusForbidden, fmt.Errorf("delete permission required to overwrite destination")
		}
	case http.MethodDelete:
		if webDAVVirtualRoot(requestPath) {
			return http.StatusForbidden, nil
		}
		if _, status, err := preflightWebDAVReadTarget(d.user, source, requestPath, true, false); status != 0 {
			return status, err
		}
		entryPaths[webDAVPathKey(requestPath)] = struct{}{}
	case "LOCK", "UNLOCK":
		target, status, err := preflightWebDAVWriteTarget(d.user, source, requestPath)
		if status != 0 {
			return status, err
		}
		required := webDAVTargetWritePermission(target)
		if err := requireWebDAVWritePermission(d.user.Permissions, required); err != nil {
			return http.StatusForbidden, err
		}
	}

	logger.Debugf("webdav: method=%s, request=%s, source=%s, requestPath=%s", r.Method, r.URL.Path, source, permissionPath)
	_, userScope, err := files.CheckPermissions(utils.FileOptions{
		FollowSymlinks: false,
		Path:           permissionPath,
		Source:         source,
		ShowHidden:     d.user.ShowHidden,
		HideFileExt:    d.user.HideFileExt,
	}, store.Access, d.user)
	if err != nil {
		return http.StatusForbidden, err
	}

	idx := indexing.GetIndex(source)
	if idx == nil {
		return http.StatusNotFound, fmt.Errorf("source %s not found", source)
	}

	userScope = normalizePublicShareIndexPath(userScope)
	sourceRoot, _, err := authenticatedReadRoots(idx, userScope)
	if err != nil {
		return errToStatus(err), err
	}

	// Wrap the filesystem to filter directory listings using FileInfoFaster
	// We pass requestPath (without scope) to FileInfoFaster, which applies scope internally
	filteredFS := &filteredFileSystem{
		fs:                      webdav.Dir(sourceRoot),
		source:                  source,
		user:                    d.user,
		entryPaths:              entryPaths,
		writeTargets:            writeTargets,
		writePermissions:        writePermissions,
		removedOverwriteTargets: removedOverwriteTargets,
	}

	wd := &webdav.Handler{
		Prefix:     prefix,
		FileSystem: filteredFS,
		LockSystem: &authenticatedWebDAVLockSystem{
			LockSystem: idx.WebdavLock,
			resolveName: func(name string) (string, error) {
				return resolveAuthenticatedWebDAVLockName(d.user, source, name)
			},
			requestPath:   requestPath,
			createdTokens: make(map[string]struct{}),
		},
		Logger: func(req *http.Request, err error) {
			if err != nil {
				errStr := err.Error()
				// Filter out expected/benign errors that don't indicate actual failures
				if strings.Contains(errStr, "no such file or directory") ||
					strings.Contains(errStr, "skip this directory") {
					return
				}
				logger.Errorf("webdav handler failed on path %s: %s", req.URL.Path, err)
			}
		},
	}

	wd.ServeHTTP(w, r)
	return 200, nil // errors and responses (XML-formatted) are handled by webdav handler
}
