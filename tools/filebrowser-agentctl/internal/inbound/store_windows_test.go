//go:build windows

package inbound

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"
)

func setTestDirectorySDDL(t *testing.T, directory, sddl string) {
	t.Helper()
	p, err := syscall.UTF16PtrFromString(directory)
	if err != nil {
		t.Fatal(err)
	}
	h, err := syscall.CreateFile(p, 0x00040000|readControl, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, backupSemantics|openReparsePoint, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(h)
	text, _ := syscall.UTF16PtrFromString(sddl)
	var sd uintptr
	ok, _, _ := convertSDDL.Call(uintptr(unsafe.Pointer(text)), 1, uintptr(unsafe.Pointer(&sd)), 0)
	if ok == 0 {
		t.Fatal("convert test descriptor")
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	var present, defaulted uint32
	var dacl uintptr
	ok, _, _ = getSecurityDACL.Call(sd, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted)))
	if ok == 0 || present == 0 {
		t.Fatal("test descriptor has no DACL")
	}
	r, _, _ := setSecurityInfo.Call(uintptr(h), 1, 0x80000004, 0, 0, dacl, 0)
	if r != 0 {
		t.Fatalf("set owner-controlled test DACL: %d", r)
	}
}

func ensureTestPrivateStore(t *testing.T, directory string) {
	t.Helper()
	sid, err := currentStoreSID()
	if err != nil {
		t.Fatal(err)
	}
	setTestDirectorySDDL(t, directory, "D:P(A;OICI;FA;;;"+sid+")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
}

func TestWindowsStoreNTFSACL(t *testing.T) {
	dir := privateStoreDir(t)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, err := s.Create()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Abort()
	if err = validatePrivateACL(syscall.Handle(p.File.Fd()), s.backend.userSID); err != nil {
		t.Fatal("created file lacks protected private DACL")
	}
	_, _ = p.File.WriteString("private bytes")
	name, err := p.Publish()
	if err != nil {
		t.Fatal(err)
	}
	f, err := s.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = validatePrivateACL(syscall.Handle(f.Fd()), s.backend.userSID); err != nil {
		t.Fatal("published file lacks protected private DACL")
	}
	unsafeDir := privateStoreDir(t)
	sid, err := currentStoreSID()
	if err != nil {
		t.Fatal(err)
	}
	setTestDirectorySDDL(t, unsafeDir, "D:P(A;OICI;FA;;;"+sid+")(A;OICI;GR;;;WD)")
	if store, err := OpenStore(unsafeDir); err == nil {
		store.Close()
		t.Fatal("accepted Everyone read ACE")
	}
	// Recheck an already authorized directory before every new operation.
	setTestDirectorySDDL(t, dir, "D:P(A;OICI;FA;;;"+sid+")(A;OICI;GR;;;WD)")
	if staging, err := s.Create(); err == nil {
		staging.Abort()
		t.Fatal("accepted directory after ACL became public")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = validatePrivateACL(syscall.Handle(f.Fd()), sid); err != nil {
		t.Fatal("Store.Close weakened published file DACL")
	}
}

func TestWindowsStoreLocksDirectoryAndAncestor(t *testing.T) {
	ancestor := t.TempDir()
	dir := filepath.Join(ancestor, "task")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ensureTestPrivateStore(t, dir)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(dir, filepath.Join(ancestor, "moved-task")); err == nil {
		t.Fatal("authorized directory could be replaced")
	}
	if err = os.Rename(ancestor, ancestor+"-moved"); err == nil {
		t.Fatal("authorized ancestor could be replaced")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(dir, filepath.Join(ancestor, "moved-task")); err != nil {
		t.Fatalf("store did not release directory lock: %v", err)
	}
}

func makeTestJunction(t *testing.T, path, target string) {
	t.Helper()
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	p, _ := syscall.UTF16PtrFromString(path)
	h, err := syscall.CreateFile(p, syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, backupSemantics|openReparsePoint, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(h)
	sub, _ := syscall.UTF16FromString(`\??\` + target)
	printName, _ := syscall.UTF16FromString(target)
	pathBytes := len(sub)*2 + len(printName)*2
	buffer := make([]byte, 16+pathBytes)
	binary.LittleEndian.PutUint32(buffer, 0xA0000003)
	binary.LittleEndian.PutUint16(buffer[4:], uint16(8+pathBytes))
	binary.LittleEndian.PutUint16(buffer[10:], uint16((len(sub)-1)*2))
	binary.LittleEndian.PutUint16(buffer[12:], uint16(len(sub)*2))
	binary.LittleEndian.PutUint16(buffer[14:], uint16((len(printName)-1)*2))
	for i, u := range append(sub, printName...) {
		binary.LittleEndian.PutUint16(buffer[16+i*2:], u)
	}
	var returned uint32
	if err = syscall.DeviceIoControl(h, 0x000900A4, &buffer[0], uint32(len(buffer)), nil, 0, &returned, nil); err != nil {
		t.Fatalf("create unprivileged test junction: %v", err)
	}
}

func TestWindowsStoreRejectsJunctionAndADS(t *testing.T) {
	base := t.TempDir()
	target := privateStoreDir(t)
	junction := filepath.Join(base, "junction")
	makeTestJunction(t, junction, target)
	if err := os.Mkdir(filepath.Join(target, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	ensureTestPrivateStore(t, filepath.Join(target, "child"))
	for _, bad := range []string{junction, junction + `\child`, target + ":alternate", `\\server\share\task`, target + `\..\task`} {
		if s, err := OpenStore(bad); err == nil {
			s.Close()
			t.Errorf("accepted unsafe path %q", bad)
		}
	}
}

func TestWindowsStoreRejectsPublishedReparsePoint(t *testing.T) {
	dir := privateStoreDir(t)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, err := s.Create()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = p.File.WriteString("verified")
	name, err := p.Publish()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err = os.Rename(path, filepath.Join(dir, "retained-original")); err != nil {
		t.Fatal(err)
	}
	makeTestJunction(t, path, t.TempDir())
	if f, err := s.Open(name); err == nil {
		f.Close()
		t.Fatal("resolved a replaced junction")
	}
}
