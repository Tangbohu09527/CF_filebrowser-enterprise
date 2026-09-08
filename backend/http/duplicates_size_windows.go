//go:build windows

package http

import (
	"math"
	"os"
)

// duplicateIndexedFileSize matches the existing Windows scanner's 4 KiB rounding.
func duplicateIndexedFileSize(info os.FileInfo, logical bool) (int64, bool) {
	if info == nil || !info.Mode().IsRegular() || info.Size() < 0 {
		return 0, false
	}
	if !logical && info.Size() > math.MaxInt64-4095 {
		return 0, false
	}
	return authenticatedListingFileSize(info.Size(), logical), true
}
