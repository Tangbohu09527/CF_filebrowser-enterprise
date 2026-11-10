package utils

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// TrashDirectory is server-owned storage, never a user-visible Source entry.
const TrashDirectory = ".filebrowser-trash"

// IsReservedStoragePath also rejects Windows aliases and nested Source mappings.
func IsReservedStoragePath(value string) bool {
	for _, part := range strings.Split(strings.ReplaceAll(value, "\\", "/"), "/") {
		part, _, _ = strings.Cut(part, ":")
		if strings.EqualFold(strings.TrimRight(part, " ."), TrashDirectory) {
			return true
		}
	}
	return false
}

// CheckUserStoragePath protects the reserved directory through symlink aliases
// and not-yet-created destinations whose existing parent is such an alias.
func CheckUserStoragePath(value string) error {
	if IsReservedStoragePath(filepath.Clean(value)) {
		return os.ErrPermission
	}
	current := filepath.Clean(value)
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			if IsReservedStoragePath(resolved) {
				return os.ErrPermission
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

// CheckUserStorageTree refuses recursive copy/move/delete of an ancestor that
// contains server-owned storage (including a nested configured Source). It reads
// only directory entries and symlink metadata, never file contents.
func CheckUserStorageTree(value string) error {
	if err := CheckUserStoragePath(value); err != nil {
		return err
	}
	return filepath.WalkDir(value, func(filename string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if IsReservedStoragePath(filename) {
			return os.ErrPermission
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return CheckUserStoragePath(filename)
		}
		return nil
	})
}
