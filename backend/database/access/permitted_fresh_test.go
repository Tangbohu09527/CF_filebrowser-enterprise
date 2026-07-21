package access_test

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asdine/storm/v3"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	accesspkg "github.com/gtsteffaniak/filebrowser/backend/database/access"
	boltusers "github.com/gtsteffaniak/filebrowser/backend/database/storage/bolt"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func newPermittedFreshTestStorage(t *testing.T, username string) (*accesspkg.Storage, string) {
	t.Helper()

	db, err := storm.Open(filepath.Join(t.TempDir(), "access.db"))
	if err != nil {
		t.Fatalf("open Storm test database: %v", err)
	}
	accesspkg.ClearCache()
	originalSourceMap := settings.Config.Server.SourceMap
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close Storm test database: %v", err)
		}
		settings.Config.Server.SourceMap = originalSourceMap
		accesspkg.ClearCache()
	})

	sourcePath := "permitted-fresh-" + strings.ReplaceAll(t.Name(), "/", "-")
	settings.Config.Server.SourceMap = map[string]*settings.Source{
		sourcePath: {
			Path: sourcePath,
			Name: sourcePath,
			Config: settings.SourceConfig{
				DenyByDefault: false,
			},
		},
	}

	userStore := users.NewStorage(boltusers.NewUsersBackend(db))
	user := &users.User{
		Username: username,
		NonAdminEditable: users.NonAdminEditable{
			Password: "test",
		},
	}
	if err := userStore.Save(user, false, false); err != nil {
		t.Fatalf("save access test user: %v", err)
	}

	return accesspkg.NewStorage(db, userStore), sourcePath
}

func TestPermittedFreshRevocationLifecycleAndCacheIsolation(t *testing.T) {
	const (
		indexPath = "/documents/report.txt"
		username  = "share-owner"
	)
	storage, sourcePath := newPermittedFreshTestStorage(t, username)

	if !storage.Permitted(sourcePath, indexPath, username) {
		t.Fatal("initial cached permission should allow access")
	}
	if cached, ok := accesspkg.PermissionCacheValueForTest(sourcePath, indexPath, username); !ok || !cached {
		t.Fatalf("expected initial allowed permission in cache, got value=%v present=%v", cached, ok)
	}

	if err := storage.DenyUser(sourcePath, indexPath, username); err != nil {
		t.Fatalf("deny user: %v", err)
	}
	// Model an allowed result computed before revocation but inserted after cache invalidation.
	accesspkg.SetPermissionCacheValueForTest(sourcePath, indexPath, username, true)
	if storage.PermittedFresh(sourcePath, indexPath, username) {
		t.Fatal("fresh permission check used stale allowed cache after revocation")
	}
	if cached, ok := accesspkg.PermissionCacheValueForTest(sourcePath, indexPath, username); !ok || !cached {
		t.Fatalf("fresh permission check changed stale-cache sentinel, got value=%v present=%v", cached, ok)
	}

	removed, err := storage.RemoveDenyUser(sourcePath, indexPath, username)
	if err != nil {
		t.Fatalf("remove user denial: %v", err)
	}
	if !removed {
		t.Fatal("expected user denial to be removed")
	}
	if !storage.PermittedFresh(sourcePath, indexPath, username) {
		t.Fatal("fresh permission check did not recover immediately after reauthorization")
	}
	if cached, ok := accesspkg.PermissionCacheValueForTest(sourcePath, indexPath, username); ok {
		t.Fatalf("fresh allowed result was written to permission cache: %v", cached)
	}

	accesspkg.SetPermissionCacheValueForTest(sourcePath, indexPath, username, false)
	if !storage.PermittedFresh(sourcePath, indexPath, username) {
		t.Fatal("fresh permission check used stale denied cache after reauthorization")
	}
	if cached, ok := accesspkg.PermissionCacheValueForTest(sourcePath, indexPath, username); !ok || cached {
		t.Fatalf("fresh permission check changed denied-cache sentinel, got value=%v present=%v", cached, ok)
	}
}

func TestHasPermittedDescendantFresh(t *testing.T) {
	const username = "search-scope-user"
	storage, sourcePath := newPermittedFreshTestStorage(t, username)

	if err := storage.DenyUser(sourcePath, "/documents", username); err != nil {
		t.Fatalf("deny search scope: %v", err)
	}
	if storage.HasPermittedDescendantFresh(sourcePath, "/documents", username) {
		t.Fatal("denied scope unexpectedly had a permitted descendant")
	}
	if err := storage.AllowUser(sourcePath, "/outside/report.txt", username); err != nil {
		t.Fatalf("allow unrelated path: %v", err)
	}
	if storage.HasPermittedDescendantFresh(sourcePath, "/documents", username) {
		t.Fatal("unrelated allow rule was treated as a permitted descendant")
	}
	if err := storage.AllowUser(sourcePath, "/documents/report.txt", username); err != nil {
		t.Fatalf("allow child path: %v", err)
	}
	if !storage.HasPermittedDescendantFresh(sourcePath, "/documents", username) {
		t.Fatal("explicitly allowed child was not detected")
	}
	removed, err := storage.RemoveAllowUser(sourcePath, "/documents/report.txt", username)
	if err != nil || !removed {
		t.Fatalf("remove child allow: removed=%t err=%v", removed, err)
	}
	if err := storage.AddUserToGroup("search-readers", username); err != nil {
		t.Fatalf("add user to group: %v", err)
	}
	if err := storage.AllowGroup(sourcePath, "/documents/team/report.txt", "search-readers"); err != nil {
		t.Fatalf("allow descendant for group: %v", err)
	}
	if !storage.HasPermittedDescendantFresh(sourcePath, "/documents", username) {
		t.Fatal("group-allowed child was not detected")
	}
}

func TestPermittedFreshConcurrentRuleUpdates(t *testing.T) {
	const (
		indexPath = "/documents/concurrent.txt"
		username  = "share-owner"
		readers   = 4
		updates   = 64
	)
	storage, sourcePath := newPermittedFreshTestStorage(t, username)

	start := make(chan struct{})
	readerReady := make(chan struct{}, readers)
	stopReaders := make(chan struct{})
	writerErr := make(chan error, 1)
	var reads atomic.Uint64
	var workers sync.WaitGroup

	workers.Add(readers)
	for range readers {
		go func() {
			defer workers.Done()
			<-start
			storage.PermittedFresh(sourcePath, indexPath, username)
			reads.Add(1)
			readerReady <- struct{}{}
			for {
				select {
				case <-stopReaders:
					return
				default:
					storage.PermittedFresh(sourcePath, indexPath, username)
					reads.Add(1)
					runtime.Gosched()
				}
			}
		}()
	}

	workers.Add(1)
	go func() {
		defer workers.Done()
		defer close(stopReaders)
		<-start
		for range readers {
			<-readerReady
		}
		for i := 0; i < updates; i++ {
			if err := storage.DenyUser(sourcePath, indexPath, username); err != nil {
				writerErr <- fmt.Errorf("deny user on update %d: %w", i, err)
				return
			}
			removed, err := storage.RemoveDenyUser(sourcePath, indexPath, username)
			if err != nil {
				writerErr <- fmt.Errorf("remove denial on update %d: %w", i, err)
				return
			}
			if !removed {
				writerErr <- fmt.Errorf("denial was not removed on update %d", i)
				return
			}
		}
	}()

	close(start)
	done := make(chan struct{})
	go func() {
		workers.Wait()
		close(done)
	}()

	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		t.Fatal("concurrent fresh permission reads and rule updates did not complete")
	}

	select {
	case err := <-writerErr:
		t.Fatal(err)
	default:
	}
	if reads.Load() < readers {
		t.Fatalf("expected every reader to execute, got %d reads", reads.Load())
	}
	if !storage.PermittedFresh(sourcePath, indexPath, username) {
		t.Fatal("final permission should be allowed after the last denial is removed")
	}
}
