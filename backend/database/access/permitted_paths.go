package access

import "strings"

// PermittedPathsFresh checks a bounded set against one current ACL/group state.
// It does not consult permission/rule caches or hold the lock during filesystem IO.
func (s *Storage) PermittedPathsFresh(sourcePath string, paths []string, username string) bool {
	if s == nil || sourcePath == "" || username == "" || len(paths) == 0 || len(paths) > 8192 {
		return false
	}
	for _, path := range paths {
		if len(path) == 0 || len(path) > 4096 || !strings.HasPrefix(path, "/") {
			return false
		}
	}
	s.mux.RLock()
	defer s.mux.RUnlock()
	for _, path := range paths {
		if !s.permittedFreshLocked(sourcePath, path, username) {
			return false
		}
	}
	return true
}
