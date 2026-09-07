package indexing

import (
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
)

// FreshAggregateEntry reports scanner size semantics without reading aggregate
// caches or changing the index. The caller must authorize and verify the entry.
// Unsupported entries require a conservative fallback, never a partial total.
func (idx *Index) FreshAggregateEntry(indexPath string, info os.FileInfo) (size int64, indexed, supported bool) {
	if idx == nil || info == nil || !strings.HasPrefix(indexPath, "/") || len(indexPath) > 4096 {
		return 0, false, false
	}
	components := strings.Split(strings.Trim(indexPath, "/"), "/")
	if len(components) > 64 {
		return 0, false, false
	}
	for _, part := range components {
		if part == "." || part == ".." {
			return 0, false, false
		}
	}
	if indexPath != "/" && !idx.shouldInclude(components[0]) {
		return 0, false, true
	}
	current := idx.MakeIndexPath(indexPath, info.IsDir())
	isDir := info.IsDir()
	for {
		realPath := utils.JoinPathAsUnix(idx.Path, current)
		isSymlink := current == idx.MakeIndexPath(indexPath, info.IsDir()) && info.Mode()&os.ModeSymlink != 0
		if (isDir && omitList[filepath.Base(strings.TrimSuffix(current, "/"))]) ||
			idx.ShouldSkip(isDir, current, IsHidden(realPath), isSymlink, true) {
			return 0, false, true
		}
		if current == "/" {
			break
		}
		current = utils.GetParentDirectoryPath(current)
		if current == "" || current == "." {
			current = "/"
		}
		current = idx.MakeIndexPath(current, true)
		isDir = true
	}
	if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
		return 0, false, false
	}
	if info.IsDir() {
		return 0, true, true
	}
	value, ok := freshAggregateFileSize(info, idx.Config.UseLogicalSize)
	if !ok || value > math.MaxInt64 {
		return 0, false, false
	}
	return int64(value), true, true
}
