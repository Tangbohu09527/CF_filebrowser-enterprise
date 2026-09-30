//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func closeTestLocks(locks []syscall.Handle) {
	for _, handle := range locks {
		_ = syscall.CloseHandle(handle)
	}
}

func TestWindowsCacheLocksPreventDirectoryReplacement(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := newPrivateCache(parent)
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(root, "payload", "plugin")
	if err := os.MkdirAll(child, 0700); err != nil {
		t.Fatal(err)
	}
	locks, err := lockParents(child)
	if err != nil {
		closeTestLocks(locks)
		t.Fatal(err)
	}
	defer func() { closeTestLocks(locks) }()
	// READ_ATTRIBUTES alone (0x80) lets these real renames succeed. The
	// production handle must request directory read access and omit SHARE_DELETE.
	for _, path := range []string{child, filepath.Dir(child), root, parent} {
		if err := os.Rename(path, path+"-replaced"); err == nil {
			t.Fatal("held cache directory or ancestor was replaced")
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatal("failed replacement did not preserve the original directory")
		}
	}
	closeTestLocks(locks)
	locks = nil
	if err := os.Rename(root, root+"-released"); err != nil {
		t.Fatal("directory lock was not released:", err)
	}
}

// A real NTFS mount point does not require administrator privileges or Developer
// Mode. This is the same native fixture technique used by the inbound store.
func makeSetupTestJunction(t *testing.T, path, target string) {
	t.Helper()
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	p, _ := syscall.UTF16PtrFromString(path)
	handle, err := syscall.CreateFile(p, syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, 0x02200000, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)
	substitute, _ := syscall.UTF16FromString(`\??\` + target)
	display, _ := syscall.UTF16FromString(target)
	pathBytes := 2 * (len(substitute) + len(display))
	buffer := make([]byte, 16+pathBytes)
	binary.LittleEndian.PutUint32(buffer, 0xA0000003)
	binary.LittleEndian.PutUint16(buffer[4:], uint16(8+pathBytes))
	binary.LittleEndian.PutUint16(buffer[10:], uint16(2*(len(substitute)-1)))
	binary.LittleEndian.PutUint16(buffer[12:], uint16(2*len(substitute)))
	binary.LittleEndian.PutUint16(buffer[14:], uint16(2*(len(display)-1)))
	for index, value := range append(substitute, display...) {
		binary.LittleEndian.PutUint16(buffer[16+index*2:], value)
	}
	var returned uint32
	if err := syscall.DeviceIoControl(handle, 0x000900A4, &buffer[0], uint32(len(buffer)), nil, 0, &returned, nil); err != nil {
		t.Fatal("unprivileged junction creation failed:", err)
	}
}

func TestWindowsCacheLocksRejectReparseAncestor(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.MkdirAll(filepath.Join(target, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(base, "junction")
	makeSetupTestJunction(t, junction, target)
	info, err := os.Lstat(junction)
	if err != nil || !isReparse(info) {
		t.Fatal("fixture is not a real reparse point")
	}
	for _, path := range []string{junction, filepath.Join(junction, "child")} {
		locks, err := lockParents(path)
		closeTestLocks(locks)
		if err == nil {
			t.Fatal("reparse directory or ancestor was accepted")
		}
	}
	if _, err := os.Stat(filepath.Join(target, "child")); err != nil {
		t.Fatal("rejected path changed the target:", err)
	}
}

func TestWindowsPayloadLocksPreventWriteDeleteAndReplacement(t *testing.T) {
	root, err := newPrivateCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "plugin")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "inbound.py")
	approved := []byte("approved immutable fixture")
	if err := os.WriteFile(path, approved, 0600); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(root, "replacement")
	if err := os.WriteFile(replacement, []byte("replacement fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	locks, err := lockPayloads(root, []string{"plugin/inbound.py"})
	if err != nil {
		closeTestLocks(locks)
		t.Fatal(err)
	}
	defer func() { closeTestLocks(locks) }()
	for name, operation := range map[string]func() error{
		"write":              func() error { return os.WriteFile(path, []byte("changed"), 0600) },
		"rename":             func() error { return os.Rename(path, path+"-renamed") },
		"delete":             func() error { return os.Remove(path) },
		"replace":            func() error { return os.Rename(replacement, path) },
		"parent replacement": func() error { return os.Rename(directory, directory+"-renamed") },
	} {
		if err := operation(); err == nil {
			t.Fatal("locked payload allowed " + name)
		}
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, approved) {
			t.Fatal("payload readback failed after refused " + name)
		}
	}
	closeTestLocks(locks)
	locks = nil
	if err := os.WriteFile(path, []byte("after release"), 0600); err != nil {
		t.Fatal("payload lock did not release:", err)
	}
}

func TestWindowsPayloadLocksRejectHardlinkAndReleasePartialHandles(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(second, filepath.Join(root, "second-link")); err != nil {
		t.Fatal("ordinary NTFS hardlink fixture failed:", err)
	}
	locks, err := lockPayloads(root, []string{"first", "second"})
	defer func() { closeTestLocks(locks) }()
	if err == nil {
		t.Fatal("hardlinked payload accepted")
	}
	if err := os.WriteFile(first, []byte("changed"), 0600); err == nil {
		t.Fatal("failure did not return the already acquired file lock")
	}
	closeTestLocks(locks)
	locks = nil
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("after release"), 0600); err != nil {
			t.Fatal("partial handles did not release:", err)
		}
	}
}
