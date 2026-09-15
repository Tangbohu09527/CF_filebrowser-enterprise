//go:build !windows

package indexing

import "os"

func freshAggregateFileSize(info os.FileInfo, logical bool) (uint64, bool) {
	// The scanner uses allocated blocks on Unix. Do not replace sparse-file
	// allocation with the shallow API's 4 KiB rounding or guess hardlink totals.
	size, links, _, ok := getFileDetails(info.Sys(), "", logical)
	return size, ok && links == 1
}
