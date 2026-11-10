package share

import (
	"strings"
	"sync"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/crud"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/go-logger/logger"
)

// StorageBackend is the interface to implement for a share storage.
type StorageBackend interface {
	All() ([]*Link, error)
	FindByUserID(id uint) ([]*Link, error)
	GetByHash(hash string) (*Link, error)
	GetCommonShareByHash(hash string) (*CommonShare, error)
	GetPermanent(path, source string, id uint) (*Link, error)
	GetBySourcePath(path, source string) ([]*Link, error)
	Gets(path, source string, id uint) ([]*Link, error)
	Save(s *Link) error
	Delete(hash string) error
}

// crudBackend implements crud.CrudBackend[Link] for share storage.
type crudBackend struct {
	back StorageBackend
}

func (c *crudBackend) GetByID(id any) (*Link, error) {
	hash, ok := id.(string)
	if !ok {
		return nil, errors.ErrInvalidDataType
	}
	return c.back.GetByHash(hash)
}

func (c *crudBackend) GetAll() ([]*Link, error) {
	return c.back.All()
}

func (c *crudBackend) Save(obj *Link) error {
	return c.back.Save(obj)
}

func (c *crudBackend) DeleteByID(id any) error {
	hash, ok := id.(string)
	if !ok {
		return errors.ErrInvalidDataType
	}
	return c.back.Delete(hash)
}

// Storage is a share storage using generics.
type Storage struct {
	Generic     *crud.Storage[Link]
	back        StorageBackend
	shareByHash map[string]*Link             // key: link hash
	shareByPath map[string]map[string]string // key: pathKey(Source, Path), value: set of hashes (hash -> "")
	mu          sync.RWMutex
	mutationMu  sync.Mutex
	users       *users.Storage
}

// pathKey returns the cache key for shareByPath (source + path).
func pathKey(source, path string) string {
	return source + ":" + path
}

// setCacheLocked updates both shareByHash and shareByPath for the given link.
// Caller must hold s.mu.
func (s *Storage) setCacheLocked(link *Link) {
	if link == nil {
		return
	}
	s.deleteFromCacheLocked(link.Hash)
	adjustedPath := utils.AddTrailingSlashIfNotExists(link.Path)
	adjustedSource := utils.AddTrailingSlashIfNotExists(link.Source)
	s.shareByHash[link.Hash] = link
	key := pathKey(adjustedSource, adjustedPath)
	if s.shareByPath[key] == nil {
		s.shareByPath[key] = make(map[string]string)
	}
	s.shareByPath[key][link.Hash] = ""
}

// setCache updates both caches for the given link. It acquires s.mu.
func (s *Storage) setCache(link *Link) {
	s.mu.Lock()
	s.setCacheLocked(link)
	s.mu.Unlock()
}

// deleteFromCacheLocked removes the link (by hash) from both caches.
// Caller must hold s.mu.
func (s *Storage) deleteFromCacheLocked(hash string) {
	link, ok := s.shareByHash[hash]
	if !ok {
		return
	}
	adjustedPath := utils.AddTrailingSlashIfNotExists(link.Path)
	adjustedSource := utils.AddTrailingSlashIfNotExists(link.Source)
	key := pathKey(adjustedSource, adjustedPath)
	if inner, ok := s.shareByPath[key]; ok {
		delete(inner, hash)
		if len(inner) == 0 {
			delete(s.shareByPath, key)
		}
	}
	delete(s.shareByHash, hash)
}

// deleteFromCache removes the link (by hash) from both caches. It acquires s.mu.
func (s *Storage) deleteFromCache(hash string) {
	s.mu.Lock()
	s.deleteFromCacheLocked(hash)
	s.mu.Unlock()
}

// setCacheAfterMove updates both caches when a link's Source or Path changed. It acquires s.mu.
func (s *Storage) setCacheAfterMove(link *Link, oldSource, oldPath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if link == nil {
		return
	}
	adjustedOldPath := utils.AddTrailingSlashIfNotExists(oldPath)
	adjustedOldSource := utils.AddTrailingSlashIfNotExists(oldSource)
	oldKey := pathKey(adjustedOldSource, adjustedOldPath)
	if inner, ok := s.shareByPath[oldKey]; ok {
		delete(inner, link.Hash)
		if len(inner) == 0 {
			delete(s.shareByPath, oldKey)
		}
	}
	s.setCacheLocked(link)
}

// NewStorage creates a share links storage from a backend and populates the
// in-memory cache from the database so all reads can be served from cache.
func NewStorage(back StorageBackend, usersStore *users.Storage) *Storage {
	s := &Storage{
		Generic:     crud.NewStorage[Link](&crudBackend{back: back}),
		back:        back,
		shareByHash: make(map[string]*Link),
		shareByPath: make(map[string]map[string]string),
		users:       usersStore,
	}
	s.loadShareCache()
	return s
}

// loadShareCache fills shareByHash and shareByPath from the backend and removes expired links from the DB.
// Call once at startup so all reads can be served from cache.
func (s *Storage) loadShareCache() {
	links, err := s.back.All()
	if err != nil && err != errors.ErrNotExist {
		return
	}
	if links == nil {
		links = []*Link{}
	}
	s.mu.Lock()
	for _, link := range links {
		if link == nil {
			continue
		}
		if link.Expire != 0 && link.Expire <= time.Now().Unix() && !link.KeepAfterExpiration {
			_ = s.back.Delete(link.Hash)
			continue
		}
		link.InitUserDownloads()
		s.setCacheLocked(link)
	}
	s.mu.Unlock()
}

// LoadShareCacheFromDB repopulates the in-memory cache from the database.
// Call at startup (e.g. from InitializeDb) to ensure shares are loaded after the store is ready.
func (s *Storage) LoadShareCacheFromDB() {
	s.loadShareCache()
}

// All returns all non-expired shares from the cache (populated at startup and by writes).
func (s *Storage) All() ([]*Link, error) {
	s.mu.Lock()
	result := make([]*Link, 0, len(s.shareByHash))
	for _, l := range s.shareByHash {
		if l == nil {
			continue
		}
		if l.Expire != 0 && l.Expire <= time.Now().Unix() && !l.KeepAfterExpiration {
			_ = s.back.Delete(l.Hash)
			s.deleteFromCacheLocked(l.Hash)
			continue
		}
		result = append(result, l.Clone())
	}
	s.mu.Unlock()
	return result, nil
}

// FindByUserID returns non-expired shares for the user from the cache.
func (s *Storage) FindByUserID(id uint) ([]*Link, error) {
	s.mu.Lock()
	result := make([]*Link, 0)
	for _, l := range s.shareByHash {
		if l == nil || l.UserID != id {
			continue
		}
		if l.Expire != 0 && l.Expire <= time.Now().Unix() && !l.KeepAfterExpiration {
			_ = s.back.Delete(l.Hash)
			s.deleteFromCacheLocked(l.Hash)
			continue
		}
		result = append(result, l.Clone())
	}
	s.mu.Unlock()
	return result, nil
}

// GetByHash wraps StorageBackend.GetByHash and handles expiry.
func (s *Storage) GetByHash(hash string) (*Link, error) {
	// Return detached metadata with the stable runtime download state.
	s.mu.Lock()
	defer s.mu.Unlock()
	if link, ok := s.shareByHash[hash]; ok && link != nil {
		if link.Expire != 0 && link.Expire <= time.Now().Unix() {
			_ = s.back.Delete(hash)
			s.deleteFromCacheLocked(hash)
			return nil, errors.ErrNotExist
		}
		return link.Clone(), nil
	}

	link, err := s.back.GetByHash(hash)
	if err != nil {
		return nil, err
	}
	if link.Expire != 0 && link.Expire <= time.Now().Unix() {
		_ = s.back.Delete(hash)
		return nil, errors.ErrNotExist
	}

	// Initialize UserDownloads map
	link.InitUserDownloads()

	s.setCacheLocked(link)
	return link.Clone(), nil
}

// GetPermanent wraps StorageBackend.GetPermanent
func (s *Storage) GetPermanent(path, source string, id uint) (*Link, error) {
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	l, err := s.back.GetPermanent(path, source, id)
	if err == nil && l != nil {
		if cached, cachedErr := s.GetByHash(l.Hash); cachedErr == nil {
			return cached, nil
		}
		l.InitUserDownloads()
		s.setCache(l.Clone())
		return l.Clone(), nil
	}
	return l, err
}

// Gets returns shares for the given path, source, and user from the cache.
func (s *Storage) Gets(sourcePath, source string, id uint) ([]*Link, error) {
	s.mu.Lock()
	adjustedPath := utils.AddTrailingSlashIfNotExists(sourcePath)
	adjustedSource := utils.AddTrailingSlashIfNotExists(source)
	key := pathKey(adjustedSource, adjustedPath)
	hashes := s.shareByPath[key]
	result := make([]*Link, 0, len(hashes))
	for h := range hashes {
		l := s.shareByHash[h]
		if l == nil || l.UserID != id {
			continue
		}
		if l.Expire != 0 && l.Expire <= time.Now().Unix() && !l.KeepAfterExpiration {
			_ = s.back.Delete(l.Hash)
			s.deleteFromCacheLocked(l.Hash)
			continue
		}
		result = append(result, l.Clone())
	}
	s.mu.Unlock()
	return result, nil
}

// GetBySourcePath returns shares for the given path and source from the cache.
func (s *Storage) GetBySourcePath(path, source string) ([]*Link, error) {
	s.mu.Lock()
	adjustedPath := utils.AddTrailingSlashIfNotExists(path)
	adjustedSource := utils.AddTrailingSlashIfNotExists(source)
	key := pathKey(adjustedSource, adjustedPath)
	hashes := s.shareByPath[key]
	result := make([]*Link, 0, len(hashes))
	for h := range hashes {
		l := s.shareByHash[h]
		if l == nil {
			continue
		}
		if l.Expire != 0 && l.Expire <= time.Now().Unix() && !l.KeepAfterExpiration {
			_ = s.back.Delete(l.Hash)
			s.deleteFromCacheLocked(l.Hash)
			continue
		}
		result = append(result, l.Clone())
	}
	s.mu.Unlock()
	return result, nil
}

// IsShared returns whether the given path and source have any shares in the cache.
func (s *Storage) IsShared(path, source string, id uint) bool {
	links, _ := s.GetBySourcePath(path, source)
	for _, l := range links {
		if l.UserID == id {
			return true
		}
	}
	return len(links) > 0
}

// UpdateShares updates all shares that match oldSource and oldPath to point to newSource and newPath.
// Handles both exact matches and subdirectories, regardless of trailing slashes.
func (s *Storage) UpdateShares(oldSource, oldPath, newSource, newPath string) (int, error) {
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	links, err := s.All()
	if err != nil && err != errors.ErrNotExist {
		logger.Error("failed to list shares", "error", err)
		return 0, err
	}

	// Normalize paths for comparison (remove trailing slashes)
	oldPath = utils.AddTrailingSlashIfNotExists(oldPath)
	newPath = utils.AddTrailingSlashIfNotExists(newPath)

	updated := 0
	for _, l := range links {
		if l == nil || l.Source != oldSource {
			continue
		}
		pos := strings.Index(utils.AddTrailingSlashIfNotExists(l.Path), oldPath)
		if pos < 0 {
			continue
		}

		candidate := l.Clone()
		candidate.Source = newSource
		candidate.Path = newPath

		if err := s.back.Save(candidate.persistenceSnapshot()); err != nil {
			logger.Error("failed to save updated share", "hash", l.Hash, "error", err)
			return updated, err
		}

		s.setCacheAfterMove(candidate, l.Source, l.Path)
		updated++
	}
	return updated, nil
}

// UpdateSharePath updates the path for a specific share identified by hash
func (s *Storage) UpdateSharePath(hash, newPath string) error {
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	link, err := s.GetByHash(hash)
	if err != nil {
		return err
	}

	oldPath := link.Path
	candidate := link.Clone()
	candidate.Path = newPath

	if err := s.back.Save(candidate.persistenceSnapshot()); err != nil {
		logger.Error("failed to save updated share", "hash", hash, "error", err)
		return err
	}

	s.setCacheAfterMove(candidate, link.Source, oldPath)

	logger.Debug("share path updated", "hash", hash, "fromPath", oldPath, "toPath", newPath)
	return nil
}

// Save wraps StorageBackend.Save
func (s *Storage) Save(l *Link) error {
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	l.InitUserDownloads()
	candidate := l.Clone()
	if err := s.back.Save(candidate.persistenceSnapshot()); err != nil {
		return err
	}
	s.setCache(candidate)
	return nil
}

// SaveDownloads persists shared runtime counts with the current metadata. An
// in-flight request may still hold the metadata snapshot from before a move.
func (s *Storage) SaveDownloads(l *Link) error {
	if l == nil {
		return errors.ErrInvalidDataType
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	s.mu.RLock()
	defer s.mu.RUnlock()
	current := s.shareByHash[l.Hash]
	if current == nil || current.downloadsOwner() != l.downloadsOwner() {
		return errors.ErrNotExist
	}
	return s.back.Save(current.persistenceSnapshot())
}

// Delete wraps StorageBackend.Delete
func (s *Storage) Delete(hash string) error {
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if err := s.back.Delete(hash); err != nil {
		return err
	}
	s.deleteFromCache(hash)
	return nil
}

// Flush is a no-op: every share write (Save, Delete, UpdateShares, UpdateSharePath) already
// updates the database, so the cache and DB stay in sync without flushing.
func (s *Storage) Flush() error {
	return nil
}

// GetCommonShareByHash retrieves only the CommonShare attributes for a given hash
func (s *Storage) GetCommonShareByHash(hash string) (*CommonShare, error) {
	return s.back.GetCommonShareByHash(hash)
}
