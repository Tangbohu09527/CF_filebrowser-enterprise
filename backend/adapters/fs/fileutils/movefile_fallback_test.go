package fileutils

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestMoveFileEXDEVFallbackCommitsCopiedFile(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "source.txt")
	dst := filepath.Join(root, "destination.txt")

	writeMoveFileTestFile(t, src, "replacement content")
	writeMoveFileTestFile(t, dst, "original destination content")

	ops, renameState := moveFileTestEXDEVOps(io.Copy, os.RemoveAll)
	if err := moveFileWithOps(src, dst, ops); err != nil {
		t.Fatalf("moveFileWithOps() error = %v", err)
	}

	if renameState.calls != 2 {
		t.Errorf("rename calls = %d, want 2", renameState.calls)
	}
	if got := filepath.Dir(renameState.commitSource); got != filepath.Dir(dst) {
		t.Errorf("commit source directory = %q, want %q", got, filepath.Dir(dst))
	}
	if renameState.commitDestination != dst {
		t.Errorf("commit destination = %q, want %q", renameState.commitDestination, dst)
	}
	if !strings.HasPrefix(filepath.Base(renameState.commitSource), "."+filepath.Base(dst)+".move-") {
		t.Errorf("commit source = %q, want a random MoveFile temporary name", renameState.commitSource)
	}
	assertMoveFileTestPathDoesNotExist(t, src)
	assertMoveFileTestFileContent(t, dst, "replacement content")
	assertMoveFileTestNoTemporaryPath(t, dst)
}

func TestMoveFileNonEXDEVDoesNotCallFallbackOps(t *testing.T) {
	testCases := map[string]error{
		"permission":     os.ErrPermission,
		"invalid path":   syscall.EINVAL,
		"missing source": os.ErrNotExist,
		"target busy":    syscall.EBUSY,
	}

	for name, renameErr := range testCases {
		t.Run(name, func(t *testing.T) {
			renameCalls := 0
			err := moveFileWithOps("source", "destination", moveFileOps{
				rename: func(string, string) error {
					renameCalls++
					return renameErr
				},
				copy: func(io.Writer, io.Reader) (int64, error) {
					t.Fatal("copy called for a non-EXDEV rename error")
					return 0, nil
				},
				removeAll: func(string) error {
					t.Fatal("removeAll called for a non-EXDEV rename error")
					return nil
				},
			})
			if !errors.Is(err, renameErr) {
				t.Fatalf("moveFileWithOps() error = %v, want %v", err, renameErr)
			}
			if renameCalls != 1 {
				t.Errorf("rename calls = %d, want 1", renameCalls)
			}
		})
	}
}

func TestMoveFileEXDEVCopyFailurePreservesExistingDestination(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "source.txt")
	dst := filepath.Join(root, "destination.txt")
	copyErr := errors.New("injected copy failure")
	removeCalled := false

	writeMoveFileTestFile(t, src, "replacement content")
	writeMoveFileTestFile(t, dst, "original destination content")

	ops, renameState := moveFileTestEXDEVOps(func(dst io.Writer, _ io.Reader) (int64, error) {
		n, err := dst.Write([]byte("partial content"))
		if err != nil {
			return int64(n), err
		}
		return int64(n), copyErr
	}, func(string) error {
		removeCalled = true
		return nil
	})

	err := moveFileWithOps(src, dst, ops)
	if !errors.Is(err, copyErr) {
		t.Fatalf("moveFileWithOps() error = %v, want %v", err, copyErr)
	}
	if renameState.calls != 1 {
		t.Errorf("rename calls = %d, want 1", renameState.calls)
	}
	if removeCalled {
		t.Error("removeAll called after copy failure")
	}
	assertMoveFileTestFileContent(t, src, "replacement content")
	assertMoveFileTestFileContent(t, dst, "original destination content")
	assertMoveFileTestNoTemporaryPath(t, dst)
}

func TestMoveFileEXDEVShortCopyPreservesExistingDestination(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "source.txt")
	dst := filepath.Join(root, "destination.txt")
	removeCalled := false

	writeMoveFileTestFile(t, src, "replacement content")
	writeMoveFileTestFile(t, dst, "original destination content")

	ops, renameState := moveFileTestEXDEVOps(func(dst io.Writer, _ io.Reader) (int64, error) {
		n, err := dst.Write([]byte("partial"))
		return int64(n), err
	}, func(string) error {
		removeCalled = true
		return nil
	})
	err := moveFileWithOps(src, dst, ops)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("moveFileWithOps() error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
	if renameState.calls != 1 {
		t.Errorf("rename calls = %d, want 1", renameState.calls)
	}
	if removeCalled {
		t.Error("removeAll called after a short copy")
	}
	assertMoveFileTestFileContent(t, src, "replacement content")
	assertMoveFileTestFileContent(t, dst, "original destination content")
	assertMoveFileTestNoTemporaryPath(t, dst)
}

func TestMoveFileEXDEVCommitFailurePreservesExistingDestination(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "source.txt")
	dst := filepath.Join(root, "destination.txt")
	commitErr := errors.New("injected commit failure")
	renameCalls := 0
	removeCalled := false

	writeMoveFileTestFile(t, src, "replacement content")
	writeMoveFileTestFile(t, dst, "original destination content")

	err := moveFileWithOps(src, dst, moveFileOps{
		rename: func(oldPath, newPath string) error {
			renameCalls++
			if renameCalls == 1 {
				return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: syscall.EXDEV}
			}
			return commitErr
		},
		copy: io.Copy,
		removeAll: func(string) error {
			removeCalled = true
			return nil
		},
	})
	if !errors.Is(err, commitErr) {
		t.Fatalf("moveFileWithOps() error = %v, want %v", err, commitErr)
	}
	if renameCalls != 2 {
		t.Errorf("rename calls = %d, want 2", renameCalls)
	}
	if removeCalled {
		t.Error("removeAll called after commit failure")
	}
	assertMoveFileTestFileContent(t, src, "replacement content")
	assertMoveFileTestFileContent(t, dst, "original destination content")
	assertMoveFileTestNoTemporaryPath(t, dst)
}

func TestMoveFileEXDEVRemoveFailureIsReturned(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "source.txt")
	dst := filepath.Join(root, "destination.txt")
	removeErr := errors.New("injected remove failure")

	writeMoveFileTestFile(t, src, "replacement content")
	writeMoveFileTestFile(t, dst, "original destination content")

	ops, renameState := moveFileTestEXDEVOps(io.Copy, func(string) error {
		return removeErr
	})
	err := moveFileWithOps(src, dst, ops)
	if !errors.Is(err, removeErr) {
		t.Fatalf("moveFileWithOps() error = %v, want %v", err, removeErr)
	}

	if renameState.calls != 2 {
		t.Errorf("rename calls = %d, want 2", renameState.calls)
	}
	assertMoveFileTestFileContent(t, src, "replacement content")
	assertMoveFileTestFileContent(t, dst, "replacement content")
	assertMoveFileTestNoTemporaryPath(t, dst)
}

func TestMoveFileEXDEVFallbackMovesDirectory(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "source")
	dst := filepath.Join(root, "destination")
	srcFile := filepath.Join(src, "nested", "source.txt")

	if err := os.MkdirAll(filepath.Dir(srcFile), 0o700); err != nil {
		t.Fatalf("os.MkdirAll(%q) error = %v", filepath.Dir(srcFile), err)
	}
	writeMoveFileTestFile(t, srcFile, "directory content")

	ops, renameState := moveFileTestEXDEVOps(io.Copy, os.RemoveAll)
	if err := moveFileWithOps(src, dst, ops); err != nil {
		t.Fatalf("moveFileWithOps() error = %v", err)
	}

	if renameState.calls != 2 {
		t.Errorf("rename calls = %d, want 2", renameState.calls)
	}
	assertMoveFileTestPathDoesNotExist(t, src)
	assertMoveFileTestFileContent(t, filepath.Join(dst, "nested", "source.txt"), "directory content")
	assertMoveFileTestNoTemporaryPath(t, dst)
}

func TestMoveFileEXDEVDirectoryCopyFailurePreservesExistingDestination(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "source")
	dst := filepath.Join(root, "destination")
	copyErr := errors.New("injected directory copy failure")
	copyCalls := 0
	removeCalled := false

	if err := os.Mkdir(src, 0o700); err != nil {
		t.Fatalf("os.Mkdir(%q) error = %v", src, err)
	}
	if err := os.Mkdir(dst, 0o700); err != nil {
		t.Fatalf("os.Mkdir(%q) error = %v", dst, err)
	}
	writeMoveFileTestFile(t, filepath.Join(src, "a.txt"), "first source file")
	writeMoveFileTestFile(t, filepath.Join(src, "b.txt"), "second source file")
	writeMoveFileTestFile(t, filepath.Join(dst, "keep.txt"), "original destination content")

	ops, renameState := moveFileTestEXDEVOps(func(dst io.Writer, src io.Reader) (int64, error) {
		copyCalls++
		if copyCalls == 2 {
			n, err := dst.Write([]byte("partial"))
			if err != nil {
				return int64(n), err
			}
			return int64(n), copyErr
		}
		return io.Copy(dst, src)
	}, func(string) error {
		removeCalled = true
		return nil
	})
	err := moveFileWithOps(src, dst, ops)
	if !errors.Is(err, copyErr) {
		t.Fatalf("moveFileWithOps() error = %v, want %v", err, copyErr)
	}
	if renameState.calls != 1 {
		t.Errorf("rename calls = %d, want 1", renameState.calls)
	}
	if removeCalled {
		t.Error("removeAll called after directory copy failure")
	}
	assertMoveFileTestFileContent(t, filepath.Join(src, "a.txt"), "first source file")
	assertMoveFileTestFileContent(t, filepath.Join(src, "b.txt"), "second source file")
	assertMoveFileTestFileContent(t, filepath.Join(dst, "keep.txt"), "original destination content")
	assertMoveFileTestNoTemporaryPath(t, dst)
}

func TestMoveFileRecognizesWindowsCrossDeviceError(t *testing.T) {
	err := &os.LinkError{Op: "rename", Old: "source", New: "destination", Err: windowsErrorNotSameDevice}
	want := runtime.GOOS == "windows"
	if got := isCrossDeviceError(err); got != want {
		t.Errorf("isCrossDeviceError() = %t, want %t on %s", got, want, runtime.GOOS)
	}
}

type moveFileTestRenameState struct {
	calls             int
	commitSource      string
	commitDestination string
}

func moveFileTestEXDEVOps(copyFn func(io.Writer, io.Reader) (int64, error), removeAll func(string) error) (moveFileOps, *moveFileTestRenameState) {
	renameState := &moveFileTestRenameState{}
	return moveFileOps{
		rename: func(oldPath, newPath string) error {
			renameState.calls++
			if renameState.calls == 1 {
				return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: syscall.EXDEV}
			}
			renameState.commitSource = oldPath
			renameState.commitDestination = newPath
			return os.Rename(oldPath, newPath)
		},
		copy:      copyFn,
		removeAll: removeAll,
	}, renameState
}

func assertMoveFileTestNoTemporaryPath(t *testing.T, dst string) {
	t.Helper()

	entries, err := os.ReadDir(filepath.Dir(dst))
	if err != nil {
		t.Fatalf("os.ReadDir(%q) error = %v", filepath.Dir(dst), err)
	}
	prefix := "." + filepath.Base(dst) + ".move-"
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			t.Errorf("MoveFile temporary path remains: %q", filepath.Join(filepath.Dir(dst), entry.Name()))
		}
	}
}
