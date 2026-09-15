//go:build !windows

package indexing

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
)

func TestFreshAggregateEntryKeepsSparseAllocationAndRejectsHardlinkGuess(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sparse.bin")
	file, createErr := os.Create(path)
	if createErr != nil {
		t.Fatal(createErr)
	}
	truncateErr := file.Truncate(8 << 20)
	closeErr := file.Close()
	if truncateErr != nil || closeErr != nil {
		t.Fatalf("prepare sparse file: truncate=%v close=%v", truncateErr, closeErr)
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	idx := &Index{Source: settings.Source{Path: root}}
	allocated, _, _, statOK := getFileDetails(info.Sys(), "", false)
	size, indexed, supported := idx.FreshAggregateEntry("/sparse.bin", info)
	if !statOK || !supported || !indexed || uint64(size) != allocated || size >= info.Size() {
		t.Fatalf("sparse allocation replaced by logical/rounded size: size=%d logical=%d", size, info.Size())
	}
	idx.Config.UseLogicalSize = true
	size, indexed, supported = idx.FreshAggregateEntry("/sparse.bin", info)
	if !supported || !indexed || size != info.Size() {
		t.Fatal("logical aggregate did not preserve real bytes")
	}
	if linkErr := os.Link(path, filepath.Join(root, "alias.bin")); linkErr != nil {
		t.Fatal(linkErr)
	}
	linked, linkedErr := os.Stat(path)
	if linkedErr != nil {
		t.Fatal(linkedErr)
	}
	if _, _, supported = idx.FreshAggregateEntry("/sparse.bin", linked); supported {
		t.Fatal("hardlink aggregate was guessed without scanner deduplication state")
	}
}
