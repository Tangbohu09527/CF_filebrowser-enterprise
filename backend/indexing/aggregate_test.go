package indexing

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
)

func TestFreshAggregateEntryUsesCurrentScannerRules(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file.bin")
	if writeErr := os.WriteFile(path, []byte("aggregate"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	tests := []struct {
		name, path string
		rules      settings.ResolvedRulesConfig
		indexed    bool
	}{
		{name: "plain", path: "/file.bin", indexed: true},
		{name: "excluded file", path: "/file.bin", rules: settings.ResolvedRulesConfig{FilePaths: map[string]settings.ConditionalRule{"/file.bin": {}}}},
		{name: "visible excluded ancestor", path: "/excluded/file.bin", rules: settings.ResolvedRulesConfig{FolderPaths: map[string]settings.ConditionalRule{"/excluded/": {Viewable: true}}}},
		{name: "conditional ancestor", path: "/privateFolder/child/file.bin", rules: settings.ResolvedRulesConfig{FolderEndsWith: []settings.ConditionalRule{{FolderEndsWith: "Folder"}}}},
		{name: "hidden ancestor", path: "/.hidden/file.bin", rules: settings.ResolvedRulesConfig{IgnoreAllHidden: true}},
		{name: "scanner hides file without rules", path: "/.hidden", rules: settings.ResolvedRulesConfig{NoRules: true}},
		{name: "scanner hides ancestor without rules", path: "/.hidden/file.bin", rules: settings.ResolvedRulesConfig{NoRules: true}},
		{name: "root excluded", path: "/other/file.bin", rules: settings.ResolvedRulesConfig{IncludeRootItems: map[string]struct{}{"/allowed/": {}}}},
		{name: "root included", path: "/allowed/file.bin", rules: settings.ResolvedRulesConfig{IncludeRootItems: map[string]struct{}{"/allowed/": {}}}, indexed: true},
		{name: "index disabled", path: "/file.bin", rules: settings.ResolvedRulesConfig{IndexingDisabled: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			idx := &Index{Source: settings.Source{Path: root, Config: settings.SourceConfig{UseLogicalSize: true, ResolvedRules: test.rules}}}
			size, indexed, supported := idx.FreshAggregateEntry(test.path, info)
			if !supported || indexed != test.indexed || (indexed && size != info.Size()) || (!indexed && size != 0) {
				t.Fatalf("aggregate decision: size=%d indexed=%t supported=%t", size, indexed, supported)
			}
		})
	}
}
