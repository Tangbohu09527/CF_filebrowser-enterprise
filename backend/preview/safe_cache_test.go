package preview

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
	"github.com/stretchr/testify/require"
)

func TestSafeCacheKeyIdentity(t *testing.T) {
	modTime := time.Date(2026, time.July, 17, 8, 30, 0, 123, time.UTC)
	root := t.TempDir()
	baseRealPath := filepath.Join(root, "folder", "same.png")
	require.NoError(t, os.MkdirAll(filepath.Dir(baseRealPath), 0755))
	require.NoError(t, os.WriteFile(baseRealPath, make([]byte, 4096), 0644))
	otherRealPath := filepath.Join(root, "other", "same.png")
	require.NoError(t, os.MkdirAll(filepath.Dir(otherRealPath), 0755))
	require.NoError(t, os.WriteFile(otherRealPath, make([]byte, 4096), 0644))
	base := iteminfo.ExtendedFileInfo{
		FileInfo: iteminfo.FileInfo{
			ItemInfo: iteminfo.ItemInfo{
				Name:    "same.png",
				Type:    "image/png",
				Size:    4096,
				ModTime: modTime,
			},
			Path: "/folder/same.png",
		},
		Source:   "source-a",
		RealPath: baseRealPath,
	}

	baseKey, err := SafeCacheKey(base, "small", 10)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(baseKey, safeDerivedPreviewCacheNamespace+":"))

	canonicalEquivalent := base
	canonicalEquivalent.Path = `\folder\.\same.png`
	canonicalEquivalent.RealPath = filepath.Join(filepath.Dir(base.RealPath), ".", "same.png")
	equivalentKey, err := SafeCacheKey(canonicalEquivalent, "small", 10)
	require.NoError(t, err)
	require.Equal(t, baseKey, equivalentKey)

	tests := []struct {
		name        string
		mutate      func(*iteminfo.ExtendedFileInfo)
		previewSize string
		percentage  int
	}{
		{name: "source", mutate: func(file *iteminfo.ExtendedFileInfo) { file.Source = "source-b" }, previewSize: "small", percentage: 10},
		{name: "index path", mutate: func(file *iteminfo.ExtendedFileInfo) { file.Path = "/other/same.png" }, previewSize: "small", percentage: 10},
		{name: "real path", mutate: func(file *iteminfo.ExtendedFileInfo) {
			file.RealPath = otherRealPath
		}, previewSize: "small", percentage: 10},
		{name: "size", mutate: func(file *iteminfo.ExtendedFileInfo) { file.Size++ }, previewSize: "small", percentage: 10},
		{name: "modification time", mutate: func(file *iteminfo.ExtendedFileInfo) { file.ModTime = file.ModTime.Add(time.Nanosecond) }, previewSize: "small", percentage: 10},
		{name: "preview size", mutate: func(file *iteminfo.ExtendedFileInfo) {}, previewSize: "large", percentage: 10},
		{name: "seek percentage", mutate: func(file *iteminfo.ExtendedFileInfo) {}, previewSize: "small", percentage: 11},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			test.mutate(&changed)
			key, err := SafeCacheKey(changed, test.previewSize, test.percentage)
			require.NoError(t, err)
			require.NotEqual(t, baseKey, key)
		})
	}

	albumArtCopy := base
	albumArtCopy.Type = "audio/mpeg"
	albumArtCopy.Metadata = &iteminfo.MediaMetadata{AlbumArt: []byte("cover")}
	otherSource := albumArtCopy
	otherSource.Source = "source-b"
	albumKey, err := SafeCacheKey(albumArtCopy, "small", 0)
	require.NoError(t, err)
	otherSourceKey, err := SafeCacheKey(otherSource, "small", 0)
	require.NoError(t, err)
	require.NotEqual(t, albumKey, otherSourceKey, "identical album art in different sources must not share safe cache entries")
}

func TestSafeCacheKeyDetectsSameSizeSameModTimeReplacement(t *testing.T) {
	realPath := filepath.Join(t.TempDir(), "same.bmp")
	contentA := []byte("content-a")
	contentB := []byte("content-b")
	require.Len(t, contentB, len(contentA))
	require.NoError(t, os.WriteFile(realPath, contentA, 0644))
	modTime := time.Date(2026, time.July, 17, 9, 0, 0, 0, time.UTC)
	require.NoError(t, os.Chtimes(realPath, modTime, modTime))

	file := iteminfo.ExtendedFileInfo{
		FileInfo: iteminfo.FileInfo{
			ItemInfo: iteminfo.ItemInfo{
				Name:    filepath.Base(realPath),
				Type:    "image/bmp",
				Size:    int64(len(contentA)),
				ModTime: modTime,
			},
			Path: "/same.bmp",
		},
		Source:   "source-a",
		RealPath: realPath,
		Metadata: &iteminfo.MediaMetadata{AlbumArt: []byte("must-not-mask-non-audio-source-content")},
	}

	keyA, err := SafeCacheKey(file, "small", 0)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(realPath, contentB, 0644))
	require.NoError(t, os.Chtimes(realPath, modTime, modTime))
	stat, err := os.Stat(realPath)
	require.NoError(t, err)
	require.Equal(t, file.Size, stat.Size())
	require.True(t, file.ModTime.Equal(stat.ModTime()))

	keyB, err := SafeCacheKey(file, "small", 0)
	require.NoError(t, err)
	require.NotEqual(t, keyA, keyB)
}

func TestSafeCacheKeyUsesCanonicalIdentityAndSnapshotContent(t *testing.T) {
	root := t.TempDir()
	canonicalPath := filepath.Join(root, "source", "same.bmp")
	require.NoError(t, os.MkdirAll(filepath.Dir(canonicalPath), 0755))
	require.NoError(t, os.WriteFile(canonicalPath, []byte("canonical-content"), 0644))
	modTime := time.Date(2026, time.July, 19, 10, 0, 0, 0, time.UTC)
	file := iteminfo.ExtendedFileInfo{
		FileInfo: iteminfo.FileInfo{
			ItemInfo: iteminfo.ItemInfo{
				Name:    "same.bmp",
				Type:    "image/bmp",
				Size:    int64(len("snapshot-content-a")),
				ModTime: modTime,
			},
			Path: "/folder/same.bmp",
		},
		Source:   "source-a",
		RealPath: canonicalPath,
	}

	snapshotA := filepath.Join(root, "random-a", "snapshot.bmp")
	snapshotB := filepath.Join(root, "random-b", "snapshot.bmp")
	require.NoError(t, os.MkdirAll(filepath.Dir(snapshotA), 0755))
	require.NoError(t, os.MkdirAll(filepath.Dir(snapshotB), 0755))
	require.NoError(t, os.WriteFile(snapshotA, []byte("snapshot-content-a"), 0644))
	require.NoError(t, os.WriteFile(snapshotB, []byte("snapshot-content-a"), 0644))

	file.PreviewSourcePath = snapshotA
	keyA, err := SafeCacheKey(file, "small", 0)
	require.NoError(t, err)
	file.PreviewSourcePath = snapshotB
	keyB, err := SafeCacheKey(file, "small", 0)
	require.NoError(t, err)
	require.Equal(t, keyA, keyB, "random snapshot paths must not change the canonical cache identity")

	require.NoError(t, os.WriteFile(snapshotB, []byte("snapshot-content-b"), 0644))
	keyC, err := SafeCacheKey(file, "small", 0)
	require.NoError(t, err)
	require.NotEqual(t, keyA, keyC, "snapshot content changes must invalidate the safe cache")
}

func TestSafeCacheKeyDisablesLargeSourceCache(t *testing.T) {
	realPath := filepath.Join(t.TempDir(), "large.bin")
	require.NoError(t, os.WriteFile(realPath, nil, 0644))
	require.NoError(t, os.Truncate(realPath, iteminfo.LargeFileSizeThreshold+1))

	file := iteminfo.ExtendedFileInfo{
		FileInfo: iteminfo.FileInfo{
			ItemInfo: iteminfo.ItemInfo{
				Name:    filepath.Base(realPath),
				Size:    iteminfo.LargeFileSizeThreshold + 1,
				ModTime: time.Now(),
			},
			Path: "/large.bin",
		},
		Source:   "source-a",
		RealPath: realPath,
	}

	_, err := SafeCacheKey(file, "small", 0)
	require.ErrorIs(t, err, ErrSafeCacheDisabled)
}

func TestSafeCacheKeyRejectsIncompleteIdentity(t *testing.T) {
	base := iteminfo.ExtendedFileInfo{
		FileInfo: iteminfo.FileInfo{
			ItemInfo: iteminfo.ItemInfo{Size: 1, ModTime: time.Now()},
			Path:     "/file.png",
		},
		Source:   "source",
		RealPath: filepath.Join(t.TempDir(), "file.png"),
	}

	for _, test := range []struct {
		name   string
		mutate func(*iteminfo.ExtendedFileInfo)
	}{
		{name: "source", mutate: func(file *iteminfo.ExtendedFileInfo) { file.Source = "" }},
		{name: "index path", mutate: func(file *iteminfo.ExtendedFileInfo) { file.Path = "" }},
		{name: "real path", mutate: func(file *iteminfo.ExtendedFileInfo) { file.RealPath = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := base
			test.mutate(&file)
			_, err := SafeCacheKey(file, "small", 0)
			require.Error(t, err)
		})
	}
}
