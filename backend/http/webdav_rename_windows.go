//go:build windows

package http

import "golang.org/x/sys/windows"

func renameWebDAVNoReplace(oldPath, newPath string) error {
	oldPathPointer, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newPathPointer, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	return windows.MoveFile(oldPathPointer, newPathPointer)
}
