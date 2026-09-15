//go:build windows

package indexing

import "os"

func freshAggregateFileSize(info os.FileInfo, logical bool) (uint64, bool) {
	// Matches the existing Windows scanner (which has no hardlink deduplication).
	return getFileSizeByMode(info.Size(), logical), info.Size() >= 0
}
