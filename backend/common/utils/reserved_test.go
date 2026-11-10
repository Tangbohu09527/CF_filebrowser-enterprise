package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReservedStorageAliasesAndRecursiveAncestors(t *testing.T) {
	for _, name := range []string{"/.filebrowser-trash/item/content", "/.FILEBROWSER-TRASH/item", "C:\\data\\.filebrowser-trash. \\x", "/.filebrowser-trash:stream"} {
		if !IsReservedStoragePath(name) {
			t.Fatalf("reserved alias accepted: %q", name)
		}
	}
	base := t.TempDir()
	ordinary := filepath.Join(base, "ordinary")
	if err := os.Mkdir(ordinary, 0755); err != nil {
		t.Fatal(err)
	}
	if err := CheckUserStorageTree(ordinary); err != nil {
		t.Fatalf("ordinary tree refused: %v", err)
	}
	protected := filepath.Join(base, "nested-source", TrashDirectory)
	if err := os.MkdirAll(protected, 0700); err != nil {
		t.Fatal(err)
	}
	if err := CheckUserStorageTree(base); !os.IsPermission(err) {
		t.Fatalf("ancestor accepted: %v", err)
	}
	if err := CheckUserStorageTree(ordinary); err != nil {
		t.Fatalf("sibling tree refused: %v", err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(protected, alias); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("Windows symlink privilege unavailable: %v", err)
		}
		t.Fatal(err)
	}
	for _, name := range []string{alias, filepath.Join(alias, "missing", "file.txt")} {
		if err := CheckUserStoragePath(name); !os.IsPermission(err) {
			t.Fatalf("symlink alias accepted: %v", err)
		}
	}
}
