//go:build darwin

package http

import "golang.org/x/sys/unix"

func renameWebDAVNoReplace(oldPath, newPath string) error {
	return unix.RenamexNp(oldPath, newPath, unix.RENAME_EXCL)
}
