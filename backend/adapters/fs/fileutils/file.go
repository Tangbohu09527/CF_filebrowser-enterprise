package fileutils

import (
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/gtsteffaniak/go-logger/logger"
)

var PermFile os.FileMode
var PermDir os.FileMode

// SetFsPermissions sets create modes from Unix chmod(2)-style values (for example
// values produced by strconv.ParseUint(s, 8, 32)). setuid, setgid, and sticky
// bits must be converted for Go's os.FileMode; a plain cast from Unix octal is
// incorrect for those bits.
func SetFsPermissions(unixFileMode, unixDirMode uint32) {
	PermFile = unixModeToFileMode(unixFileMode)
	PermDir = unixModeToFileMode(unixDirMode)
}

// EffectiveDirPerm returns [PermDir] if [SetFsPermissions] was called, otherwise 0o755. On Unix,
// [os.Mkdir] with perm 0 fails with permission denied, so use this (or [PermFile]) for creates when
// the process has not set globals yet.
func EffectiveDirPerm() os.FileMode {
	if PermDir == 0 {
		return 0o755
	}
	return PermDir
}

// EffectiveFilePerm returns [PermFile] if set, otherwise 0o644.
func EffectiveFilePerm() os.FileMode {
	if PermFile == 0 {
		return 0o644
	}
	return PermFile
}

func unixModeToFileMode(u uint32) os.FileMode {
	m := os.FileMode(u & 0777)
	if u&0o4000 != 0 {
		m |= os.ModeSetuid
	}
	if u&0o2000 != 0 {
		m |= os.ModeSetgid
	}
	if u&0o1000 != 0 {
		m |= os.ModeSticky
	}
	return m
}

// MoveFile moves a file from src to dst.
// By default, the rename system call is used. If src and dst point to different volumes,
// the file copy is used as a fallback.
func MoveFile(src, dst string) error {
	return moveFileWithOps(src, dst, moveFileOps{
		rename:    os.Rename,
		copy:      io.Copy,
		removeAll: os.RemoveAll,
	})
}

type moveFileOps struct {
	rename    func(string, string) error
	copy      func(io.Writer, io.Reader) (int64, error)
	removeAll func(string) error
}

func moveFileWithOps(src, dst string, ops moveFileOps) error {
	err := ops.rename(src, dst)
	if err == nil {
		return nil
	}
	if !isCrossDeviceError(err) {
		return err
	}

	tempPath, err := copyToMoveTemp(src, dst, ops.copy)
	if err != nil {
		return err
	}

	if err := ops.rename(tempPath, dst); err != nil {
		return errors.Join(err, cleanupMoveTemp(tempPath))
	}

	if err := ops.removeAll(src); err != nil {
		return err
	}

	return nil
}

const windowsErrorNotSameDevice = syscall.Errno(17)

func isCrossDeviceError(err error) bool {
	if errors.Is(err, syscall.EXDEV) {
		return true
	}

	// Windows returns ERROR_NOT_SAME_DEVICE instead of Go's synthesized EXDEV.
	return runtime.GOOS == "windows" && errors.Is(err, windowsErrorNotSameDevice)
}

func copyToMoveTemp(source, dest string, copyFn func(io.Writer, io.Reader) (int64, error)) (string, error) {
	info, err := os.Stat(source)
	if err != nil {
		return "", err
	}

	if info.IsDir() {
		return copyDirectoryToMoveTemp(source, dest, info, copyFn)
	}

	return copyRegularFileToMoveTemp(source, dest, info, copyFn)
}

func copyRegularFileToMoveTemp(source, dest string, info os.FileInfo, copyFn func(io.Writer, io.Reader) (int64, error)) (string, error) {
	temp, err := os.CreateTemp(filepath.Dir(dest), moveTempPattern(dest))
	if err != nil {
		return "", err
	}
	tempPath := temp.Name()

	if err := copyRegularFileForMove(source, temp, info, copyFn); err != nil {
		return "", errors.Join(err, cleanupMoveTemp(tempPath))
	}

	return tempPath, nil
}

func copyDirectoryToMoveTemp(source, dest string, info os.FileInfo, copyFn func(io.Writer, io.Reader) (int64, error)) (string, error) {
	tempPath, err := os.MkdirTemp(filepath.Dir(dest), moveTempPattern(dest))
	if err != nil {
		return "", err
	}

	if err := copyDirectoryForMove(source, tempPath, copyFn); err != nil {
		return "", errors.Join(err, cleanupMoveTemp(tempPath))
	}
	if err := os.Chmod(tempPath, info.Mode().Perm()); err != nil {
		logger.Debugf("Could not set directory permissions for %s: %v", tempPath, err)
	}

	return tempPath, nil
}

func copyDirectoryForMove(source, dest string, copyFn func(io.Writer, io.Reader) (int64, error)) error {
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(source, entry.Name())
		destPath := filepath.Join(dest, entry.Name())
		info, err := os.Stat(srcPath)
		if err != nil {
			return err
		}

		if entry.IsDir() {
			if err := os.Mkdir(destPath, info.Mode().Perm()|0o700); err != nil {
				return err
			}
			if err := copyDirectoryForMove(srcPath, destPath, copyFn); err != nil {
				return err
			}
			if err := os.Chmod(destPath, info.Mode().Perm()); err != nil {
				logger.Debugf("Could not set directory permissions for %s: %v", destPath, err)
			}
			continue
		}

		destFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
		if err != nil {
			return err
		}
		if err := copyRegularFileForMove(srcPath, destFile, info, copyFn); err != nil {
			return err
		}
	}

	return nil
}

func copyRegularFileForMove(source string, dest *os.File, info os.FileInfo, copyFn func(io.Writer, io.Reader) (int64, error)) error {
	src, err := os.Open(source)
	if err != nil {
		return errors.Join(err, dest.Close())
	}

	written, copyErr := copyFn(dest, src)
	srcCloseErr := src.Close()
	if copyErr == nil && info.Mode().IsRegular() && written != info.Size() {
		copyErr = io.ErrUnexpectedEOF
	}
	if copyErr == nil {
		if err := dest.Chmod(info.Mode().Perm()); err != nil {
			logger.Debugf("Could not set file permissions for %s: %v", dest.Name(), err)
		}
	}

	var syncErr error
	if copyErr == nil {
		syncErr = dest.Sync()
	}
	destCloseErr := dest.Close()

	return errors.Join(copyErr, srcCloseErr, syncErr, destCloseErr)
}

func moveTempPattern(dest string) string {
	return "." + filepath.Base(dest) + ".move-*"
}

func cleanupMoveTemp(tempPath string) error {
	return os.RemoveAll(tempPath)
}

// CopyFile copies a file or directory from source to dest and returns an error if any.
func CopyFile(source, dest string) error {
	// Check if the source exists and whether it's a file or directory.
	info, err := os.Stat(source)
	if err != nil {
		return err
	}

	if info.IsDir() {
		// If the source is a directory, copy it recursively.
		return copyDirectory(source, dest)
	}

	// If the source is a file, copy the file.
	return copySingleFile(source, dest)
}

// copySingleFile handles copying a single file.
func copySingleFile(source, dest string) error {
	// Get source file info to preserve permissions
	srcInfo, err := os.Stat(source)
	if err != nil {
		return err
	}
	sourcePerms := srcInfo.Mode().Perm()

	// Open the source file.
	src, err := os.Open(source)
	if err != nil {
		return err
	}
	defer src.Close()

	// Create the destination directory if needed.
	err = os.MkdirAll(filepath.Dir(dest), PermDir)
	if err != nil {
		return err
	}

	// Create the destination file with source permissions
	dst, err := os.OpenFile(dest, os.O_RDWR|os.O_CREATE|os.O_TRUNC, sourcePerms)
	if err != nil {
		return err
	}
	defer dst.Close()

	// Copy the contents of the file.
	_, err = io.Copy(dst, src)
	if err != nil {
		return err
	}

	// Preserve source file permissions
	// Handle chmod errors gracefully (e.g., in rootless containers where chmod may be restricted)
	err = os.Chmod(dest, sourcePerms)
	if err != nil {
		// Log but don't fail - chmod may be restricted in some environments
		// The file was copied successfully, so we continue
		logger.Debugf("Could not set file permissions for %s (this may be expected in restricted environments): %v", dest, err)
	}

	return nil
}

// copyDirectory handles copying directories recursively.
func copyDirectory(source, dest string) error {
	// Create the destination directory.
	err := os.MkdirAll(dest, PermDir)
	if err != nil {
		return err
	}

	// Read the contents of the source directory.
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}

	// Iterate over each entry in the directory.
	for _, entry := range entries {
		srcPath := filepath.Join(source, entry.Name())
		destPath := filepath.Join(dest, entry.Name())

		if entry.IsDir() {
			// Recursively copy subdirectories.
			err = copyDirectory(srcPath, destPath)
			if err != nil {
				return err
			}
		} else {
			// Copy files.
			err = copySingleFile(srcPath, destPath)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// CommonPrefix returns the common directory path of provided files.
func CommonPrefix(sep byte, paths ...string) string {
	// Handle special cases.
	switch len(paths) {
	case 0:
		return ""
	case 1:
		return path.Clean(paths[0])
	}

	// Treat string as []byte, not []rune as is often done in Go.
	c := []byte(path.Clean(paths[0]))

	// Add a trailing sep to handle the case where the common prefix directory
	// is included in the path list.
	c = append(c, sep)

	// Ignore the first path since it's already in c.
	for _, v := range paths[1:] {
		// Clean up each path before testing it.
		v = path.Clean(v) + string(sep)

		// Find the first non-common byte and truncate c.
		if len(v) < len(c) {
			c = c[:len(v)]
		}
		for i := 0; i < len(c); i++ {
			if v[i] != c[i] {
				c = c[:i]
				break
			}
		}
	}

	// Remove trailing non-separator characters and the final separator.
	for i := len(c) - 1; i >= 0; i-- {
		if c[i] == sep {
			c = c[:i]
			break
		}
	}

	return string(c)
}

func ClearCacheDir(cacheDir string) {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		logger.Errorf("failed clear cache dir: %v", err)
	}

	for _, entry := range entries {
		path := filepath.Join(cacheDir, entry.Name())
		err = os.RemoveAll(path)
		if err != nil {
			logger.Errorf("failed clear cache dir: %v", err)
		}
	}

}

// ClearDirectoryContents removes all files and subdirectories inside dir; dir itself remains.
// If dir does not exist, returns nil.
func ClearDirectoryContents(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	return nil
}
