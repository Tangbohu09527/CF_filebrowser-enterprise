package fileutils

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestMoveFileRenameSuccessPreservesContents(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "source.txt")
	dst := filepath.Join(root, "destination.txt")
	want := "first line\nsecond line\n"

	writeMoveFileTestFile(t, src, want)

	if err := MoveFile(src, dst); err != nil {
		t.Fatalf("MoveFile() error = %v", err)
	}

	assertMoveFileTestPathDoesNotExist(t, src)
	assertMoveFileTestFileContent(t, dst, want)
}

func TestMoveFileNonEXDEVRenameErrorDoesNotFallback(t *testing.T) {
	oldPermFile, oldPermDir := PermFile, PermDir
	SetFsPermissions(0o644, 0o755)
	t.Cleanup(func() {
		PermFile = oldPermFile
		PermDir = oldPermDir
	})

	root := t.TempDir()
	srcDir := filepath.Join(root, "source")
	src := srcDir + string(os.PathSeparator) + "."
	srcFile := filepath.Join(srcDir, "source.txt")
	dstParent := filepath.Join(root, "missing")
	dst := filepath.Join(dstParent, "destination")
	want := "source must remain unchanged"

	if err := os.Mkdir(srcDir, 0o700); err != nil {
		t.Fatalf("os.Mkdir(%q) error = %v", srcDir, err)
	}
	writeMoveFileTestFile(t, srcFile, want)
	requireMoveFileTestNonEXDEVRenameError(t, src, dst)
	if err := os.RemoveAll(src); err == nil {
		t.Fatalf("os.RemoveAll(%q) unexpectedly succeeded", src)
	}

	if err := MoveFile(src, dst); err == nil {
		t.Error("MoveFile() error = nil, want the non-EXDEV rename error")
	}

	assertMoveFileTestFileContent(t, srcFile, want)
	assertMoveFileTestPathDoesNotExist(t, dstParent)
}

func TestMoveFileFailedFallbackPreservesExistingDestination(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "source")
	dst := filepath.Join(root, "destination")

	if err := os.Mkdir(src, 0o700); err != nil {
		t.Fatalf("os.Mkdir(%q) error = %v", src, err)
	}
	if err := os.Mkdir(dst, 0o700); err != nil {
		t.Fatalf("os.Mkdir(%q) error = %v", dst, err)
	}

	srcFirst := filepath.Join(src, "a-existing.txt")
	srcConflict := filepath.Join(src, "z-conflict")
	dstFirst := filepath.Join(dst, "a-existing.txt")
	dstConflict := filepath.Join(dst, "z-conflict")
	dstSentinel := filepath.Join(dstConflict, "keep.txt")

	writeMoveFileTestFile(t, srcFirst, "replacement content")
	writeMoveFileTestFile(t, srcConflict, "source conflict content")
	writeMoveFileTestFile(t, dstFirst, "original destination content")
	if err := os.Mkdir(dstConflict, 0o700); err != nil {
		t.Fatalf("os.Mkdir(%q) error = %v", dstConflict, err)
	}
	writeMoveFileTestFile(t, dstSentinel, "destination sentinel")

	requireMoveFileTestNonEXDEVRenameError(t, src, dst)

	// CopyFile overwrites the first entry before the later type conflict fails.
	if err := MoveFile(src, dst); err == nil {
		t.Fatal("MoveFile() error = nil, want an error")
	}

	assertMoveFileTestFileContent(t, srcFirst, "replacement content")
	assertMoveFileTestFileContent(t, srcConflict, "source conflict content")
	assertMoveFileTestFileContent(t, dstFirst, "original destination content")
	assertMoveFileTestFileContent(t, dstSentinel, "destination sentinel")

	info, err := os.Stat(dstConflict)
	if err != nil {
		t.Errorf("os.Stat(%q) error = %v", dstConflict, err)
	} else if !info.IsDir() {
		t.Errorf("destination conflict path mode = %v, want directory", info.Mode())
	}
}

func TestMoveFileMissingSourcePreservesExistingFile(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "missing-source.txt")
	dst := filepath.Join(root, "destination.txt")

	writeMoveFileTestFile(t, dst, "existing destination content")

	requireMoveFileTestNonEXDEVRenameError(t, src, dst)

	if err := MoveFile(src, dst); err == nil {
		t.Fatal("MoveFile() error = nil, want an error")
	}

	assertMoveFileTestPathDoesNotExist(t, src)
	assertMoveFileTestFileContent(t, dst, "existing destination content")
}

func requireMoveFileTestNonEXDEVRenameError(t *testing.T, src, dst string) {
	t.Helper()

	err := os.Rename(src, dst)
	if err == nil {
		t.Fatalf("os.Rename(%q, %q) unexpectedly succeeded", src, dst)
	}
	if errors.Is(err, syscall.EXDEV) {
		t.Fatalf("os.Rename(%q, %q) error = %v, want a non-EXDEV error", src, dst, err)
	}
}

func writeMoveFileTestFile(t *testing.T, name, content string) {
	t.Helper()

	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", name, err)
	}
}

func assertMoveFileTestFileContent(t *testing.T, name, want string) {
	t.Helper()

	got, err := os.ReadFile(name)
	if err != nil {
		t.Errorf("os.ReadFile(%q) error = %v", name, err)
		return
	}
	if string(got) != want {
		t.Errorf("content of %q = %q, want %q", name, got, want)
	}
}

func assertMoveFileTestPathDoesNotExist(t *testing.T, name string) {
	t.Helper()

	if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("os.Stat(%q) error = %v, want os.ErrNotExist", name, err)
	}
}
