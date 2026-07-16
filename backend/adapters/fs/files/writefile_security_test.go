package files

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/fileutils"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
)

var errInjectedRead = errors.New("injected read failure")

type faultReader struct {
	content   []byte
	failAfter int
	offset    int
}

func (r *faultReader) Read(p []byte) (int, error) {
	if r.offset >= r.failAfter {
		return 0, errInjectedRead
	}

	n := copy(p, r.content[r.offset:r.failAfter])
	r.offset += n
	if r.offset >= r.failAfter {
		return n, errInjectedRead
	}
	return n, nil
}

func TestWriteFileDataIntegrity(t *testing.T) {
	originalPermFile := fileutils.PermFile
	originalPermDir := fileutils.PermDir
	fileutils.SetFsPermissions(0o644, 0o755)
	t.Cleanup(func() {
		fileutils.PermFile = originalPermFile
		fileutils.PermDir = originalPermDir
	})

	t.Run("existing_file_read_error_preserves_original", func(t *testing.T) {
		root := setupWriteFileSecurityTest(t, "writefile-security-existing")
		const targetName = "existing.txt"
		targetPath := filepath.Join(root, targetName)
		original := []byte("original")
		if err := os.WriteFile(targetPath, original, 0o644); err != nil {
			t.Fatalf("create original file: %v", err)
		}

		reader := &faultReader{
			content:   []byte("partial replacement must not be committed"),
			failAfter: len("partial replacement"),
		}
		writeErr := WriteFile("writefile-security-existing", "/"+targetName, reader)
		actual, readErr := os.ReadFile(targetPath)
		if readErr != nil {
			t.Fatalf("read final file: %v", readErr)
		}
		t.Logf("WriteFile error: %v; reader emitted: %d bytes; disk final content: %q", writeErr, reader.offset, actual)

		if !errors.Is(writeErr, errInjectedRead) {
			t.Errorf("expected injected read error, got %v", writeErr)
		}
		if !bytes.Equal(actual, original) {
			t.Errorf("existing file changed after failed write: got %q, want %q", actual, original)
		}
	})

	t.Run("new_file_read_error_leaves_no_file", func(t *testing.T) {
		root := setupWriteFileSecurityTest(t, "writefile-security-new")
		const targetName = "new.txt"
		targetPath := filepath.Join(root, targetName)
		reader := &faultReader{
			content:   []byte("partial new file must not be committed"),
			failAfter: len("partial new file"),
		}

		writeErr := WriteFile("writefile-security-new", "/"+targetName, reader)
		actual, readErr := os.ReadFile(targetPath)
		entries := readDirectoryEntryNames(t, root)
		if readErr == nil {
			t.Logf("WriteFile error: %v; reader emitted: %d bytes; disk final content: %q; directory entries: %q", writeErr, reader.offset, actual, entries)
		} else {
			t.Logf("WriteFile error: %v; reader emitted: %d bytes; disk final file absent: %v; directory entries: %q", writeErr, reader.offset, readErr, entries)
		}

		if !errors.Is(writeErr, errInjectedRead) {
			t.Errorf("expected injected read error, got %v", writeErr)
		}
		if !os.IsNotExist(readErr) {
			t.Errorf("failed new-file write left a formal file: read error=%v, content=%q", readErr, actual)
		}
	})

	t.Run("successful_overwrite_is_complete_without_temporary_files", func(t *testing.T) {
		root := setupWriteFileSecurityTest(t, "writefile-security-success")
		const targetName = "success.txt"
		targetPath := filepath.Join(root, targetName)
		if err := os.WriteFile(targetPath, []byte("original"), 0o644); err != nil {
			t.Fatalf("create original file: %v", err)
		}

		replacement := []byte("complete replacement content\x00including every byte")
		writeErr := WriteFile("writefile-security-success", "/"+targetName, bytes.NewReader(replacement))
		actual, readErr := os.ReadFile(targetPath)
		if readErr != nil {
			t.Fatalf("read final file: %v", readErr)
		}
		entries := readDirectoryEntryNames(t, root)
		t.Logf("WriteFile error: %v; disk final content: %q; directory entries: %q", writeErr, actual, entries)

		if writeErr != nil {
			t.Errorf("successful overwrite returned error: %v", writeErr)
		}
		if !bytes.Equal(actual, replacement) {
			t.Errorf("successful overwrite content mismatch: got %q, want %q", actual, replacement)
		}
		if len(entries) != 1 || entries[0] != targetName {
			t.Errorf("successful overwrite left unexpected temporary files: entries=%q", entries)
		}
	})

	t.Run("incomplete_declared_content_is_not_committed", func(t *testing.T) {
		root := setupWriteFileSecurityTest(t, "writefile-security-byte-count")
		const targetName = "counted.txt"
		targetPath := filepath.Join(root, targetName)
		reader := &faultReader{
			content:   []byte("declared content must be complete"),
			failAfter: len("declared"),
		}

		writeErr := WriteFile("writefile-security-byte-count", "/"+targetName, reader)
		actual, readErr := os.ReadFile(targetPath)
		if readErr == nil {
			t.Logf("declared: %d bytes; reader emitted: %d bytes; WriteFile error: %v; disk final content: %q", len(reader.content), reader.offset, writeErr, actual)
		} else {
			t.Logf("declared: %d bytes; reader emitted: %d bytes; WriteFile error: %v; disk final file absent: %v", len(reader.content), reader.offset, writeErr, readErr)
		}

		if reader.offset != reader.failAfter {
			t.Errorf("reader emitted %d bytes, want fault point %d", reader.offset, reader.failAfter)
		}
		if reader.offset >= len(reader.content) {
			t.Errorf("test reader unexpectedly emitted complete declared content: emitted=%d declared=%d", reader.offset, len(reader.content))
		}
		if !errors.Is(writeErr, errInjectedRead) {
			t.Errorf("expected injected read error, got %v", writeErr)
		}
		if !os.IsNotExist(readErr) {
			t.Errorf("incomplete %d-of-%d byte write was committed: read error=%v, content=%q", reader.offset, len(reader.content), readErr, actual)
		}
	})
}

func setupWriteFileSecurityTest(t *testing.T, sourceName string) string {
	t.Helper()
	root := t.TempDir()
	indexing.SetTestIndex(sourceName, root)
	idx := indexing.GetIndex(sourceName)
	if idx == nil {
		t.Fatalf("test index %q was not registered", sourceName)
	}
	idx.Config.ResolvedRules.IndexingDisabled = true
	t.Cleanup(indexing.ClearTestIndices)
	return root
}

func readDirectoryEntryNames(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatalf("read directory %q: %v", path, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
