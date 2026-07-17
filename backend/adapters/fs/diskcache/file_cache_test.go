package diskcache

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/fileutils"
	"github.com/stretchr/testify/require"
)

func TestFileCache(t *testing.T) {
	ctx := context.Background()
	const (
		key            = "key"
		value          = "some text"
		newValue       = "new text"
		cacheRoot      = "cache"
		cachedFilePath = "a/62/a62f2225bf70bfaccbc7f1ef2a397836717377de"
	)

	// Set up file permissions before creating cache
	fileutils.SetFsPermissions(0644, 0755)

	// Create temporary directory for the cache
	cacheDir, err := os.MkdirTemp("", cacheRoot)
	require.NoError(t, err)
	defer os.RemoveAll(cacheDir) // Clean up

	cache, err := NewFileCache(cacheDir)
	require.NoError(t, err)

	// store new key
	// Note: NewFileCache creates a "diskcache" subdirectory, so the actual path includes it
	err = cache.Store(ctx, key, []byte(value))
	require.NoError(t, err)
	checkValue(t, ctx, cache, filepath.Join(cacheDir, "diskcache", cachedFilePath), key, value)
	requireNoCacheTemps(t, cache.getFileName(key))

	// update existing key
	err = cache.Store(ctx, key, []byte(newValue))
	require.NoError(t, err)
	checkValue(t, ctx, cache, filepath.Join(cacheDir, "diskcache", cachedFilePath), key, newValue)
	requireNoCacheTemps(t, cache.getFileName(key))

	// delete key
	err = cache.Delete(ctx, key)
	require.NoError(t, err)
	exists := fileExists(filepath.Join(cacheDir, "diskcache", cachedFilePath))
	require.False(t, exists)
}

func TestFileCacheConcurrentLoadAndStoreOnlyReturnsCompleteValues(t *testing.T) {
	fileutils.SetFsPermissions(0644, 0755)
	cacheDir := t.TempDir()
	cache, err := NewFileCache(cacheDir)
	require.NoError(t, err)

	const key = "concurrent-key"
	values := [][]byte{
		bytes.Repeat([]byte("a"), 128*1024),
		bytes.Repeat([]byte("b"), 256*1024),
	}
	require.NoError(t, cache.Store(context.Background(), key, values[0]))

	start := make(chan struct{})
	errorsCh := make(chan error, 16)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 40; i++ {
			if err := cache.Store(context.Background(), key, values[i%len(values)]); err != nil {
				errorsCh <- fmt.Errorf("store iteration %d: %w", i, err)
				return
			}
		}
	}()

	const readers = 4
	for reader := 0; reader < readers; reader++ {
		wg.Add(1)
		go func(reader int) {
			defer wg.Done()
			<-start
			for i := 0; i < 120; i++ {
				value, found, err := cache.Load(context.Background(), key)
				if err != nil {
					errorsCh <- fmt.Errorf("reader %d iteration %d: %w", reader, i, err)
					return
				}
				if !found {
					errorsCh <- fmt.Errorf("reader %d iteration %d: cache entry disappeared", reader, i)
					return
				}
				if !bytes.Equal(value, values[0]) && !bytes.Equal(value, values[1]) {
					errorsCh <- fmt.Errorf("reader %d iteration %d: read partial value of %d bytes", reader, i, len(value))
					return
				}
			}
		}(reader)
	}

	close(start)
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		require.NoError(t, err)
	}
	requireNoCacheTemps(t, cache.getFileName(key))
}

func TestFileCacheStoreCleansTempFileWhenReplaceFails(t *testing.T) {
	fileutils.SetFsPermissions(0644, 0755)
	cache, err := NewFileCache(t.TempDir())
	require.NoError(t, err)

	const key = "replace-failure"
	fileName := cache.getFileName(key)
	require.NoError(t, os.MkdirAll(fileName, fileutils.PermDir))

	err = cache.Store(context.Background(), key, []byte("cache value"))
	require.Error(t, err)
	requireNoCacheTemps(t, fileName)

	info, statErr := os.Stat(fileName)
	require.NoError(t, statErr)
	require.True(t, info.IsDir(), "failed replacement must not remove the existing target")
}

func checkValue(t *testing.T, ctx context.Context, cache *FileCache, fileFullPath string, key, wantValue string) {
	t.Helper()
	// check actual file content
	b, err := os.ReadFile(fileFullPath)
	require.NoError(t, err)
	require.Equal(t, wantValue, string(b))

	// check cache content
	b, ok, err := cache.Load(ctx, key)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, wantValue, string(b))
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func requireNoCacheTemps(t *testing.T, fileName string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(fileName), "."+filepath.Base(fileName)+".tmp-*"))
	require.NoError(t, err)
	require.Empty(t, matches)
}
