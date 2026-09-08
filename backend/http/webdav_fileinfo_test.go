package http

import (
	"os"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/fileutils"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
)

func TestPermissionWebDAVSecurity_FileInfoModes(t *testing.T) {
	previousFilePerm, previousDirPerm := fileutils.PermFile, fileutils.PermDir
	t.Cleanup(func() {
		fileutils.PermFile, fileutils.PermDir = previousFilePerm, previousDirPerm
	})

	for _, tc := range []struct {
		name     string
		filePerm os.FileMode
		dirPerm  os.FileMode
		wantFile os.FileMode
		wantDir  os.FileMode
	}{
		{name: "uninitialized modes use existing defaults", wantFile: 0o644, wantDir: 0o755},
		{name: "private configured modes are retained", filePerm: 0o600, dirPerm: 0o700, wantFile: 0o600, wantDir: 0o700},
		{name: "group configured modes are retained", filePerm: 0o640, dirPerm: 0o750, wantFile: 0o640, wantDir: 0o750},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fileutils.PermFile, fileutils.PermDir = tc.filePerm, tc.dirPerm
			file := &fileInfoWrapper{ItemInfo: iteminfo.ItemInfo{Type: "text/plain"}}
			dir := &fileInfoWrapper{ItemInfo: iteminfo.ItemInfo{Type: "directory"}}
			// x/net/webdav COPY uses this mode to create the destination. Check
			// the mode directly so root or Windows cannot hide a mode-0000 file.
			if got := file.Mode(); got != tc.wantFile {
				t.Errorf("file mode: got %v, want %v", got, tc.wantFile)
			}
			if got := dir.Mode(); got != os.ModeDir|tc.wantDir {
				t.Errorf("directory mode: got %v, want %v", got, os.ModeDir|tc.wantDir)
			}
		})
	}
}
