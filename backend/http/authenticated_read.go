package http

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/gtsteffaniak/filebrowser/backend/auth"
	commonerrors "github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
)

type authenticatedReadTarget struct {
	Index         *indexing.Index
	SourcePath    string
	SourceReal    string
	UserScope     string
	ScopeReal     string
	ScopeInfo     os.FileInfo
	RequestedPath string
	LogicalPath   string
	LogicalAccess bool
	CanonicalPath string
	EntryPath     string
	ScopedPath    string
	RealPath      string
	Info          os.FileInfo
}

var authenticatedReadSnapshotCompleteHook func()

func authenticatedReadScope(user *users.User, source string) (*indexing.Index, string, error) {
	if user == nil || store.Access == nil {
		return nil, "", commonerrors.ErrAccessDenied
	}
	userScope, err := user.GetScopeForSourceName(source)
	if err != nil || userScope == "" {
		return nil, "", commonerrors.ErrAccessDenied
	}
	idx := indexing.GetIndex(source)
	if idx == nil {
		return nil, "", fmt.Errorf("source %s is not available", source)
	}
	return idx, normalizePublicShareIndexPath(userScope), nil
}

func authenticatedReadRoots(idx *indexing.Index, userScope string) (string, string, error) {
	sourceAbsolute, err := filepath.Abs(idx.Path)
	if err != nil {
		return "", "", fmt.Errorf("authenticated source root is unavailable")
	}
	sourceReal, err := filepath.EvalSymlinks(sourceAbsolute)
	if err != nil {
		return "", "", normalizeAuthenticatedReadError(err)
	}
	scopeReal, err := filepath.EvalSymlinks(filepath.Join(sourceAbsolute, filepath.FromSlash(strings.TrimPrefix(userScope, "/"))))
	if err != nil || !publicShareRealPathWithin(sourceReal, scopeReal) {
		return "", "", commonerrors.ErrAccessDenied
	}
	return sourceReal, scopeReal, nil
}

func authenticatedReadPathContainsSymlink(sourceRoot, logicalPath string) bool {
	relativePath := filepath.Clean(filepath.FromSlash(strings.TrimPrefix(logicalPath, "/")))
	if relativePath == "." || relativePath == "" {
		return false
	}
	currentPath := sourceRoot
	for _, component := range strings.Split(relativePath, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		currentPath = filepath.Join(currentPath, component)
		info, err := os.Lstat(currentPath)
		if err != nil {
			return false
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

func resolveAuthenticatedReadTarget(user *users.User, source, requestedPath string) (authenticatedReadTarget, error) {
	var target authenticatedReadTarget
	safePath, err := sanitizeAuthenticatedReadPath(requestedPath)
	if err != nil {
		return target, err
	}
	idx, userScope, err := authenticatedReadScope(user, source)
	if err != nil {
		return target, err
	}
	logicalPath := normalizePublicShareIndexPath(utils.JoinPathAsUnix(userScope, safePath))
	target, err = resolveAuthenticatedReadIndexTargetWithScope(user, idx, userScope, logicalPath)
	target.RequestedPath = safePath
	return target, err
}

func resolveAuthenticatedReadIndexTarget(user *users.User, source, indexPath string) (authenticatedReadTarget, error) {
	var target authenticatedReadTarget
	safePath, err := sanitizeAuthenticatedReadPath(indexPath)
	if err != nil {
		return target, err
	}
	idx, userScope, err := authenticatedReadScope(user, source)
	if err != nil {
		return target, err
	}
	return resolveAuthenticatedReadIndexTargetWithScope(user, idx, userScope, normalizePublicShareIndexPath(safePath))
}

func resolveAuthenticatedReadIndexTargetWithScope(user *users.User, idx *indexing.Index, userScope, logicalPath string) (authenticatedReadTarget, error) {
	return resolveAuthenticatedReadIndexTargetWithScopeMode(user, idx, userScope, logicalPath, false)
}

func resolveAuthenticatedBrowseTarget(user *users.User, source, requestedPath string) (authenticatedReadTarget, error) {
	target, err := resolveAuthenticatedReadTarget(user, source, requestedPath)
	if err == nil || !errors.Is(err, commonerrors.ErrAccessDenied) || target.Index == nil || target.LogicalPath == "" || target.LogicalAccess {
		return target, err
	}
	if store.Access == nil || !store.Access.HasPermittedDescendantFresh(target.Index.Path, target.LogicalPath, user.Username) {
		return target, err
	}
	requested := target.RequestedPath
	target, err = resolveAuthenticatedReadIndexTargetWithScopeMode(user, target.Index, target.UserScope, target.LogicalPath, true)
	target.RequestedPath = requested
	return target, err
}

func resolveAuthenticatedReadIndexTargetWithScopeMode(user *users.User, idx *indexing.Index, userScope, logicalPath string, allowDeniedDirectory bool) (authenticatedReadTarget, error) {
	target := authenticatedReadTarget{
		Index:       idx,
		SourcePath:  idx.Path,
		UserScope:   userScope,
		LogicalPath: logicalPath,
	}
	if !publicSharePathWithin(userScope, logicalPath) {
		return target, commonerrors.ErrAccessDenied
	}
	target.LogicalAccess = store.Access.PermittedFresh(idx.Path, logicalPath, user.Username)
	if !target.LogicalAccess && !allowDeniedDirectory {
		return target, commonerrors.ErrAccessDenied
	}

	sourceReal, scopeReal, err := authenticatedReadRoots(idx, userScope)
	if err != nil {
		return target, err
	}
	target.SourceReal = sourceReal
	target.ScopeReal = scopeReal
	target.ScopeInfo, err = stableAuthenticatedReadInfo(scopeReal)
	if err != nil || !target.ScopeInfo.IsDir() {
		return target, commonerrors.ErrAccessDenied
	}

	sourceAbsolute, err := filepath.Abs(idx.Path)
	if err != nil {
		return target, err
	}
	targetReal, err := filepath.EvalSymlinks(filepath.Join(sourceAbsolute, filepath.FromSlash(strings.TrimPrefix(logicalPath, "/"))))
	if err != nil {
		if allowDeniedDirectory && !target.LogicalAccess {
			return target, commonerrors.ErrAccessDenied
		}
		if authenticatedReadPathContainsSymlink(sourceAbsolute, logicalPath) {
			return target, commonerrors.ErrAccessDenied
		}
		return target, normalizeAuthenticatedReadError(err)
	}
	if !publicShareRealPathWithin(sourceReal, targetReal) || !publicShareRealPathWithin(scopeReal, targetReal) {
		return target, commonerrors.ErrAccessDenied
	}

	canonicalRelative, err := filepath.Rel(sourceReal, targetReal)
	if err != nil {
		return target, commonerrors.ErrAccessDenied
	}
	canonicalRelative = publicShareCanonicalCaseRelative(sourceReal, canonicalRelative)
	canonicalPath := normalizePublicShareIndexPath(filepath.ToSlash(canonicalRelative))
	if !publicSharePathWithin(userScope, canonicalPath) {
		return target, commonerrors.ErrAccessDenied
	}
	canonicalAccess := store.Access.PermittedFresh(idx.Path, canonicalPath, user.Username)
	sameLogicalPath := publicSharePathWithin(logicalPath, canonicalPath) && publicSharePathWithin(canonicalPath, logicalPath)
	if !canonicalAccess && !(allowDeniedDirectory && !target.LogicalAccess && sameLogicalPath) {
		return target, commonerrors.ErrAccessDenied
	}
	scopedPath, err := publicShareScopedPath(userScope, canonicalPath)
	if err != nil {
		return target, err
	}
	info, err := stableAuthenticatedReadInfo(targetReal)
	if err != nil {
		if allowDeniedDirectory && !target.LogicalAccess {
			return target, commonerrors.ErrAccessDenied
		}
		return target, err
	}
	if allowDeniedDirectory && !target.LogicalAccess && (!info.IsDir() || !sameLogicalPath) {
		return target, commonerrors.ErrAccessDenied
	}
	scopeAfter, err := stableAuthenticatedReadInfo(scopeReal)
	if err != nil || !os.SameFile(target.ScopeInfo, scopeAfter) {
		return target, commonerrors.ErrAccessDenied
	}
	target.CanonicalPath = canonicalPath
	target.EntryPath = canonicalPath
	target.ScopedPath = scopedPath
	target.RealPath = targetReal
	target.Info = info
	return target, nil
}

func stableAuthenticatedReadInfo(realPath string) (os.FileInfo, error) {
	entryInfo, err := os.Lstat(realPath)
	if err != nil {
		return nil, normalizeAuthenticatedReadError(err)
	}
	if entryInfo.Mode()&os.ModeSymlink != 0 || (!entryInfo.Mode().IsRegular() && !entryInfo.IsDir()) {
		return nil, commonerrors.ErrAccessDenied
	}
	file, err := os.Open(realPath)
	if err != nil {
		return nil, normalizeAuthenticatedReadError(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, normalizeAuthenticatedReadError(err)
	}
	after, err := os.Lstat(realPath)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || after.IsDir() != info.IsDir() || !os.SameFile(info, after) {
		return nil, commonerrors.ErrAccessDenied
	}
	return info, nil
}

func openAuthenticatedReadEntryTarget(target authenticatedReadTarget) (*os.File, os.FileInfo, error) {
	if target.Info == nil || target.ScopeInfo == nil || (!target.Info.Mode().IsRegular() && !target.Info.IsDir()) {
		return nil, nil, commonerrors.ErrAccessDenied
	}
	relativePath, err := filepath.Rel(target.ScopeReal, target.RealPath)
	if err != nil || filepath.IsAbs(relativePath) || (relativePath == "." && !target.Info.IsDir()) {
		return nil, nil, commonerrors.ErrAccessDenied
	}
	root, err := os.OpenRoot(target.ScopeReal)
	if err != nil {
		return nil, nil, normalizeAuthenticatedReadError(err)
	}
	defer root.Close()
	rootInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(target.ScopeInfo, rootInfo) {
		return nil, nil, commonerrors.ErrAccessDenied
	}
	before, err := root.Lstat(relativePath)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || (!before.Mode().IsRegular() && !before.IsDir()) || !os.SameFile(target.Info, before) {
		return nil, nil, commonerrors.ErrAccessDenied
	}
	file, err := root.Open(relativePath)
	if err != nil {
		return nil, nil, normalizeAuthenticatedReadError(err)
	}
	opened, err := file.Stat()
	if err != nil || (!opened.Mode().IsRegular() && !opened.IsDir()) || opened.IsDir() != before.IsDir() || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, nil, commonerrors.ErrAccessDenied
	}
	after, err := root.Lstat(relativePath)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, after) || !os.SameFile(target.Info, opened) {
		_ = file.Close()
		return nil, nil, commonerrors.ErrAccessDenied
	}
	return file, opened, nil
}

func openAuthenticatedReadTarget(target authenticatedReadTarget) (*os.File, os.FileInfo, error) {
	file, info, err := openAuthenticatedReadEntryTarget(target)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, commonerrors.ErrAccessDenied
	}
	return file, info, nil
}

func snapshotAuthenticatedReadTarget(target authenticatedReadTarget) (string, os.FileInfo, func(), error) {
	source, info, err := openAuthenticatedReadTarget(target)
	if err != nil {
		return "", nil, nil, err
	}
	defer source.Close()

	extension := authenticatedReadSnapshotExtension(target.RealPath)
	snapshot, err := os.CreateTemp("", "filebrowser-authenticated-read-*"+extension)
	if err != nil {
		return "", nil, nil, normalizeAuthenticatedReadError(err)
	}
	snapshotPath := snapshot.Name()
	cleanup := func() {
		_ = os.Remove(snapshotPath)
	}
	failed := true
	defer func() {
		if failed {
			_ = snapshot.Close()
			cleanup()
		}
	}()

	if err := copyAuthenticatedReadSnapshot(snapshot, source, info.Size()); err != nil {
		return "", nil, nil, err
	}
	if err := snapshot.Close(); err != nil {
		return "", nil, nil, normalizeAuthenticatedReadError(err)
	}
	failed = false
	if authenticatedReadSnapshotCompleteHook != nil {
		authenticatedReadSnapshotCompleteHook()
	}
	return snapshotPath, info, cleanup, nil
}

func copyAuthenticatedReadSnapshot(destination io.Writer, source io.Reader, expectedSize int64) error {
	if expectedSize < 0 {
		return commonerrors.ErrAccessDenied
	}
	limit := expectedSize
	if expectedSize < math.MaxInt64 {
		limit++
	}
	written, err := io.Copy(destination, io.LimitReader(source, limit))
	if err != nil {
		return normalizeAuthenticatedReadError(err)
	}
	if written != expectedSize {
		return commonerrors.ErrAccessDenied
	}
	return nil
}

func authenticatedReadSnapshotExtension(realPath string) string {
	extension := filepath.Ext(realPath)
	if len(extension) > 32 {
		return ""
	}
	for _, char := range extension {
		if char == '.' || char >= '0' && char <= '9' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' {
			continue
		}
		return ""
	}
	return extension
}

func sameAuthenticatedReadTarget(original, current authenticatedReadTarget) bool {
	if original.Info == nil || current.Info == nil || original.ScopeInfo == nil || current.ScopeInfo == nil {
		return false
	}
	if !publicShareRealPathWithin(original.SourceReal, current.SourceReal) || !publicShareRealPathWithin(current.SourceReal, original.SourceReal) ||
		!publicShareRealPathWithin(original.ScopeReal, current.ScopeReal) || !publicShareRealPathWithin(current.ScopeReal, original.ScopeReal) ||
		!publicSharePathWithin(original.CanonicalPath, current.CanonicalPath) || !publicSharePathWithin(current.CanonicalPath, original.CanonicalPath) {
		return false
	}
	return os.SameFile(original.ScopeInfo, current.ScopeInfo) && os.SameFile(original.Info, current.Info)
}

func authenticatedReadTargetName(target authenticatedReadTarget, fallback string) string {
	name := pathpkg.Base(target.LogicalPath)
	if name == "" || name == "." || name == "/" {
		return fallback
	}
	return name
}

func normalizeAuthenticatedReadError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, commonerrors.ErrAccessDenied), os.IsPermission(err):
		return commonerrors.ErrAccessDenied
	case errors.Is(err, commonerrors.ErrNotExist), os.IsNotExist(err):
		return commonerrors.ErrNotExist
	default:
		return fmt.Errorf("authenticated read target is unavailable")
	}
}

func currentAuthenticatedReadUser(initial *users.User, token string) (*users.User, error) {
	if initial == nil {
		return nil, commonerrors.ErrAccessDenied
	}
	minimalToken := false
	userID := initial.ID
	if token != "" {
		if config == nil || config.Auth.Key == "" || store.Access == nil || auth.IsRevokedApiToken(store.Access, token) {
			return nil, commonerrors.ErrAccessDenied
		}
		var claims users.AuthToken
		parsed, err := jwt.ParseWithClaims(token, &claims, func(*jwt.Token) (interface{}, error) {
			return []byte(config.Auth.Key), nil
		})
		if err != nil || !parsed.Valid || parsed.Method.Alg() != jwt.SigningMethodHS256.Alg() || claims.RegisteredClaims.ExpiresAt == nil {
			return nil, commonerrors.ErrAccessDenied
		}
		minimalToken = claims.BelongsTo == 0
		tokenUserID := claims.BelongsTo
		if minimalToken {
			var found bool
			tokenUserID, found = store.Access.GetUserIDFromToken(token)
			if !found {
				return nil, commonerrors.ErrAccessDenied
			}
		}
		if userID != 0 && tokenUserID != userID {
			return nil, commonerrors.ErrAccessDenied
		}
		userID = tokenUserID
	}
	if userID == 0 {
		return initial, nil
	}
	current, err := store.Users.Get(userID)
	if err != nil {
		return nil, err
	}
	if minimalToken {
		return current, nil
	}
	effective := *current
	effective.Permissions = users.IntersectPermissions(current.Permissions, initial.Permissions)
	return &effective, nil
}

func resolveAuthenticatedEntryTarget(user *users.User, source, requestedPath string) (authenticatedReadTarget, error) {
	var target authenticatedReadTarget
	safePath, err := sanitizeAuthenticatedReadPath(requestedPath)
	if err != nil {
		return target, err
	}
	if safePath == "/" {
		return resolveAuthenticatedReadTarget(user, source, safePath)
	}
	idx, userScope, err := authenticatedReadScope(user, source)
	if err != nil {
		return target, err
	}
	logicalPath := normalizePublicShareIndexPath(utils.JoinPathAsUnix(userScope, safePath))
	if !publicSharePathWithin(userScope, logicalPath) || !store.Access.PermittedFresh(idx.Path, logicalPath, user.Username) {
		return target, commonerrors.ErrAccessDenied
	}
	parentPath := pathpkg.Dir(safePath)
	if parentPath == "." {
		parentPath = "/"
	}
	parent, err := resolveAuthenticatedBrowseTarget(user, source, parentPath)
	if err != nil {
		return target, err
	}
	if !parent.Info.IsDir() {
		return target, commonerrors.ErrAccessDenied
	}
	entryPath := normalizePublicShareIndexPath(pathpkg.Join(parent.CanonicalPath, pathpkg.Base(safePath)))
	if !publicSharePathWithin(userScope, entryPath) || !store.Access.PermittedFresh(idx.Path, entryPath, user.Username) {
		return target, commonerrors.ErrAccessDenied
	}
	realPath := filepath.Join(parent.RealPath, filepath.FromSlash(pathpkg.Base(safePath)))
	if !publicShareRealPathWithin(parent.SourceReal, realPath) || !publicShareRealPathWithin(parent.ScopeReal, realPath) {
		return target, commonerrors.ErrAccessDenied
	}
	info, err := os.Lstat(realPath)
	if err != nil {
		return target, normalizeAuthenticatedReadError(err)
	}
	entryRelative, err := filepath.Rel(parent.SourceReal, realPath)
	if err != nil || filepath.IsAbs(entryRelative) {
		return target, commonerrors.ErrAccessDenied
	}
	entryRelative = publicShareCanonicalCaseRelative(parent.SourceReal, entryRelative)
	entryPath = normalizePublicShareIndexPath(filepath.ToSlash(entryRelative))
	if !publicSharePathWithin(userScope, entryPath) || !store.Access.PermittedFresh(idx.Path, entryPath, user.Username) {
		return target, commonerrors.ErrAccessDenied
	}
	scopedPath, err := publicShareScopedPath(userScope, entryPath)
	if err != nil {
		return target, err
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
		CanonicalPath: entryPath,
		EntryPath:     entryPath,
		ScopedPath:    scopedPath,
		RealPath:      realPath,
		Info:          info,
	}, nil
}

func resolveAuthenticatedWriteTarget(user *users.User, source, requestedPath string) (authenticatedReadTarget, error) {
	target, err := resolveAuthenticatedEntryTarget(user, source, requestedPath)
	if err == nil || (!os.IsNotExist(err) && !errors.Is(err, commonerrors.ErrNotExist)) {
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
	if !publicSharePathWithin(userScope, logicalPath) || !store.Access.PermittedFresh(idx.Path, logicalPath, user.Username) {
		return target, commonerrors.ErrAccessDenied
	}

	parentPath := pathpkg.Dir(safePath)
	if parentPath == "." {
		parentPath = "/"
	}
	parent, err := resolveAuthenticatedBrowseTarget(user, source, parentPath)
	if err != nil {
		return target, err
	}
	if !parent.Info.IsDir() {
		return target, commonerrors.ErrAccessDenied
	}

	baseName := pathpkg.Base(safePath)
	canonicalPath := normalizePublicShareIndexPath(pathpkg.Join(parent.CanonicalPath, baseName))
	if !publicSharePathWithin(userScope, canonicalPath) || !store.Access.PermittedFresh(idx.Path, canonicalPath, user.Username) {
		return target, commonerrors.ErrAccessDenied
	}
	realPath := filepath.Join(parent.RealPath, filepath.FromSlash(baseName))
	if _, lstatErr := os.Lstat(realPath); lstatErr == nil || !os.IsNotExist(lstatErr) {
		if lstatErr == nil {
			return target, commonerrors.ErrAccessDenied
		}
		return target, lstatErr
	}
	scopedPath, err := publicShareScopedPath(userScope, canonicalPath)
	if err != nil {
		return target, err
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

func checksumAuthenticatedReadTarget(target authenticatedReadTarget, algorithm string) (string, error) {
	var digest hash.Hash
	switch algorithm {
	case "md5":
		digest = md5.New()
	case "sha1":
		digest = sha1.New()
	case "sha256":
		digest = sha256.New()
	case "sha512":
		digest = sha512.New()
	default:
		return "", commonerrors.ErrInvalidOption
	}
	file, _, err := openAuthenticatedReadTarget(target)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := io.Copy(digest, file); err != nil {
		return "", normalizeAuthenticatedReadError(err)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func readAuthenticatedTextContent(target authenticatedReadTarget) (string, error) {
	const maxSize = 20 * 1024 * 1024
	if target.Info == nil || target.Info.Size() >= maxSize {
		return "", nil
	}
	file, info, err := openAuthenticatedReadTarget(target)
	if err != nil {
		return "", err
	}
	defer file.Close()
	isText, err := isTextFileSample(file)
	if err != nil {
		return "", normalizeAuthenticatedReadError(err)
	}
	if !isText {
		return "", nil
	}
	if _, seekErr := file.Seek(0, io.SeekStart); seekErr != nil {
		return "", normalizeAuthenticatedReadError(seekErr)
	}
	content, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return "", normalizeAuthenticatedReadError(err)
	}
	if int64(len(content)) > maxSize || info.Size() >= maxSize {
		return "", nil
	}
	if len(content) == 0 {
		return "empty-file-x6OlSil", nil
	}
	return string(content), nil
}
