//go:build linux

package inbound

import (
	"os"
	"path/filepath"
	"testing"
)

func ensureTestPrivateStore(t *testing.T, directory string) {
	t.Helper()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxStoreRejectsPermissionsAndSymlinks(t *testing.T) {
	dir := privateStoreDir(t)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if s, err := OpenStore(dir); err == nil {
		s.Close()
		t.Fatal("accepted public directory")
	}
	ensureTestPrivateStore(t, dir)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if s, err := OpenStore(link); err == nil {
		s.Close()
		t.Fatal("accepted symlink directory")
	}
}

func TestLinuxStoreAnonymousStagingNeverDeletesUnknown(t *testing.T) {
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
	_, _ = p.File.WriteString("partial content")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("anonymous staging became visible")
	}
	unknown := filepath.Join(dir, p.name)
	if err = os.WriteFile(unknown, []byte("unknown bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = p.Abort(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(unknown)
	if err != nil || string(data) != "unknown bytes" {
		t.Fatal("cleanup deleted unknown file")
	}
}
