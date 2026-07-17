package access

import (
	"fmt"
	"strings"

	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
)

func permittedFreshCacheKeyForTest(sourcePath, indexPath, username string) string {
	if !strings.HasPrefix(indexPath, "/") {
		indexPath = "/" + indexPath
	}
	indexPath = utils.AddTrailingSlashIfNotExists(indexPath)

	version := 0
	if cachedVersion, ok := versionCache.Get("version:" + sourcePath); ok {
		version = cachedVersion
	}
	return fmt.Sprintf("perm:%s:%d:%s:%s", sourcePath, version, indexPath, username)
}

// SetPermissionCacheValueForTest installs a deterministic stale-cache sentinel.
func SetPermissionCacheValueForTest(sourcePath, indexPath, username string, permitted bool) {
	permissionCache.Set(permittedFreshCacheKeyForTest(sourcePath, indexPath, username), permitted)
}

// PermissionCacheValueForTest reads the cache entry used by Permitted.
func PermissionCacheValueForTest(sourcePath, indexPath, username string) (bool, bool) {
	return permissionCache.Get(permittedFreshCacheKeyForTest(sourcePath, indexPath, username))
}
