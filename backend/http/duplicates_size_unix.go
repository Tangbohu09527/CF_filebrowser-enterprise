//go:build !windows

package http

import (
	"math"
	"os"
	"syscall"
)

// duplicateIndexedFileSize matches the Unix scanner using only the authorized stat.
func duplicateIndexedFileSize(info os.FileInfo, logical bool) (int64, bool) {
	if info == nil || !info.Mode().IsRegular() || info.Size() < 0 {
		return 0, false
	}
	if logical {
		return info.Size(), true
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil || stat.Blocks < 0 || stat.Blocks > math.MaxInt64/512 {
		return 0, false
	}
	return int64(stat.Blocks) * 512, true
}
