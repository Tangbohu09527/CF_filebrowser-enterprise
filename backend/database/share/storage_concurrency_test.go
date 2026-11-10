package share

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func TestShareMoveDoesNotMutatePublishedMetadata(t *testing.T) {
	for _, move := range []struct {
		name string
		run  func(*Storage) error
	}{
		{"all", func(s *Storage) error {
			_, err := s.UpdateShares("source", "/old", "destination", "/new")
			return err
		}},
		{"path", func(s *Storage) error { return s.UpdateSharePath("share", "/new/") }},
	} {
		t.Run(move.name, func(t *testing.T) {
			backend := newShareConcurrencyBackend(t, testMovingShare())
			storage := NewStorage(backend, nil)
			published, err := storage.GetByHash("share")
			if err != nil {
				t.Fatal(err)
			}
			if moveErr := move.run(storage); moveErr != nil {
				t.Fatal(moveErr)
			}
			if published.Path != "/old/" || published.Source != "source" {
				t.Fatalf("move mutated an in-flight reader: source=%q path=%q", published.Source, published.Path)
			}
			updated, err := storage.GetByHash("share")
			if err != nil || updated.Path != "/new/" {
				t.Fatalf("new reader did not see move: link=%+v err=%v", updated, err)
			}
			oldLinks, err := storage.GetBySourcePath("/old/", "source")
			if err != nil || len(oldLinks) != 0 {
				t.Fatalf("old path remains indexed: links=%d err=%v", len(oldLinks), err)
			}
			newLinks, err := storage.GetBySourcePath(updated.Path, updated.Source)
			if err != nil || len(newLinks) != 1 {
				t.Fatalf("new path is not indexed: links=%d err=%v", len(newLinks), err)
			}
		})
	}
}

func TestShareMoveFailurePreservesCachedMetadata(t *testing.T) {
	backend := newShareConcurrencyBackend(t, testMovingShare())
	storage := NewStorage(backend, nil)
	backend.saveErr = fmt.Errorf("persistence unavailable")
	if _, err := storage.UpdateShares("source", "/old", "destination", "/new"); err == nil {
		t.Fatal("move unexpectedly succeeded")
	}
	link, err := storage.GetByHash("share")
	if err != nil || link.Path != "/old/" || link.Source != "source" {
		t.Fatalf("failed move changed cached metadata: link=%+v err=%v", link, err)
	}
}

func TestShareMoveRetainsInFlightDownloadCounts(t *testing.T) {
	initial := testMovingShare()
	initial.Downloads = 3
	initial.UserDownloads = map[string]int{"alice": 2}
	backend := newShareConcurrencyBackend(t, initial)
	storage := NewStorage(backend, nil)
	inFlight, err := storage.GetByHash("share")
	if err != nil {
		t.Fatal(err)
	}
	if _, moveErr := storage.UpdateShares("source", "/old", "destination", "/new"); moveErr != nil {
		t.Fatal(moveErr)
	}
	inFlight.IncrementDownload()
	inFlight.IncrementUserDownload("alice")
	current, err := storage.GetByHash("share")
	if err != nil {
		t.Fatal(err)
	}
	downloads := current.GetDownloadCount()
	if downloads != 4 || current.GetUserDownloadCount("alice") != 3 {
		t.Fatalf("move lost in-flight download counts: total=%d user=%d", downloads, current.GetUserDownloadCount("alice"))
	}
	if saveErr := storage.SaveDownloads(inFlight); saveErr != nil {
		t.Fatal(saveErr)
	}
	reloaded := NewStorage(backend, nil)
	persisted, err := reloaded.GetByHash("share")
	if err != nil || persisted.Downloads != 4 || persisted.GetUserDownloadCount("alice") != 3 {
		t.Fatalf("download counts did not survive persistence: link=%+v err=%v", persisted, err)
	}
	if persisted.Path != "/new/" || persisted.Source != "destination" {
		t.Fatalf("in-flight count save reverted move: source=%q path=%q", persisted.Source, persisted.Path)
	}
}

func TestShareSnapshotsDoNotExposeCachedMetadata(t *testing.T) {
	initial := testMovingShare()
	initial.AllowedUsernames = []string{"alice"}
	initial.SidebarLinks = []users.SidebarLink{{Name: "original"}}
	initial.UserDownloads = map[string]int{"alice": 1}
	storage := NewStorage(newShareConcurrencyBackend(t, initial), nil)
	getters := []struct {
		name string
		get  func() (*Link, error)
	}{
		{"hash", func() (*Link, error) { return storage.GetByHash("share") }},
		{"all", func() (*Link, error) { links, err := storage.All(); return links[0], err }},
		{"user", func() (*Link, error) { links, err := storage.FindByUserID(1); return links[0], err }},
		{"path", func() (*Link, error) { links, err := storage.GetBySourcePath("/old/", "source"); return links[0], err }},
		{"gets", func() (*Link, error) { links, err := storage.Gets("/old/", "source", 1); return links[0], err }},
		{"permanent", func() (*Link, error) { return storage.GetPermanent("/old/", "source", 1) }},
	}
	for _, getter := range getters {
		t.Run(getter.name, func(t *testing.T) {
			link, err := getter.get()
			if err != nil {
				t.Fatal(err)
			}
			link.Path = "/local"
			link.Source = "local"
			link.AllowedUsernames[0] = "changed"
			link.SidebarLinks[0].Name = "changed"
			link.UserDownloads["alice"] = 99
			cached, err := storage.GetByHash("share")
			if err != nil || cached.Path != "/old/" || cached.Source != "source" || cached.AllowedUsernames[0] != "alice" || cached.SidebarLinks[0].Name != "original" || cached.GetUserDownloadCount("alice") != 1 {
				t.Fatalf("getter exposed cached metadata or counter map: link=%+v err=%v", cached, err)
			}
		})
	}
	input := testMovingShare()
	if err := storage.Save(input); err != nil {
		t.Fatal(err)
	}
	input.Path = "/changed-after-save"
	cached, err := storage.GetByHash("share")
	if err != nil || cached.Path != "/old/" {
		t.Fatalf("Save retained caller metadata: link=%+v err=%v", cached, err)
	}
}

func TestShareZeroValueAndLegacyJSONCounts(t *testing.T) {
	var link Link
	if err := json.Unmarshal([]byte(`{"hash":"legacy","source":"source","path":"/old/","downloads":2,"userDownloads":{"alice":1},"downloadsLimit":3,"perUserDownloadLimit":true}`), &link); err != nil {
		t.Fatal(err)
	}
	if !link.ConsumeDownload("alice") || !link.Clone().ConsumeDownload("alice") || link.ConsumeDownload("alice") {
		t.Fatal("metadata clones did not share legacy per-user limit")
	}
	if link.GetDownloadCount() != 4 || link.GetUserDownloadCount("alice") != 3 {
		t.Fatal("legacy counts were not retained")
	}
	editing := link.Clone()
	editing.ResetDownloadCounts()
	if editing.Downloads != 0 || len(editing.UserDownloads) != 0 {
		t.Fatal("reset left stale counts in the initiating edit response")
	}
	if link.GetDownloadCount() != 0 || link.GetUserDownloadCount("alice") != 0 {
		t.Fatal("reset did not update shared runtime counts")
	}
	var zero Link
	zero.InitUserDownloads()
	zero.IncrementDownload()
	zero.IncrementUserDownload("alice")
	if zero.GetDownloadCount() != 1 || zero.GetUserDownloadCount("alice") != 1 {
		t.Fatal("zero-value Link methods are not usable")
	}
}

func TestShareConcurrentMoveAndRead(t *testing.T) {
	storage := NewStorage(newShareConcurrencyBackend(t, testMovingShare()), nil)
	var workers sync.WaitGroup
	start := make(chan struct{})
	for worker := 0; worker < 4; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			<-start
			for iteration := 0; iteration < 100; iteration++ {
				if worker < 2 {
					if _, err := storage.UpdateShares("source", "/old", "source", "/old"); err != nil {
						t.Error(err)
						return
					}
					if err := storage.UpdateSharePath("share", "/old/"); err != nil {
						t.Error(err)
						return
					}
					continue
				}
				link, err := storage.GetByHash("share")
				if err != nil {
					t.Error(err)
					return
				}
				if link.Source != "source" || link.Path != "/old/" {
					t.Errorf("unexpected metadata: source=%q path=%q", link.Source, link.Path)
					return
				}
				if _, err := storage.All(); err != nil {
					t.Error(err)
					return
				}
			}
		}(worker)
	}
	close(start)
	workers.Wait()
}

func TestShareConcurrentMovePreservesDownloadLimits(t *testing.T) {
	for _, perUser := range []bool{false, true} {
		t.Run(fmt.Sprintf("per-user-%t", perUser), func(t *testing.T) {
			initial := testMovingShare()
			initial.DownloadsLimit = 50
			initial.PerUserDownloadLimit = perUser
			backend := newShareConcurrencyBackend(t, initial)
			storage := NewStorage(backend, nil)
			inFlight, err := storage.GetByHash("share")
			if err != nil {
				t.Fatal(err)
			}
			var workers sync.WaitGroup
			for worker := 0; worker < 5; worker++ {
				workers.Add(1)
				go func(worker int) {
					defer workers.Done()
					for iteration := 0; iteration < 30; iteration++ {
						if worker == 0 {
							if _, moveErr := storage.UpdateShares("source", "/old", "source", "/old"); moveErr != nil {
								t.Error(moveErr)
							}
						} else if inFlight.ConsumeDownload("alice") {
							if saveErr := storage.SaveDownloads(inFlight); saveErr != nil {
								t.Error(saveErr)
							}
						}
					}
				}(worker)
			}
			workers.Wait()
			if saveErr := storage.SaveDownloads(inFlight); saveErr != nil {
				t.Fatal(saveErr)
			}
			current, err := storage.GetByHash("share")
			if err != nil || current.GetDownloadCount() != 50 || current.ConsumeDownload("alice") {
				t.Fatalf("concurrent moves lost global count/limit: count=%d err=%v", current.GetDownloadCount(), err)
			}
			if perUser && current.GetUserDownloadCount("alice") != 50 {
				t.Fatalf("concurrent moves lost per-user count: %d", current.GetUserDownloadCount("alice"))
			}
			reloaded, err := NewStorage(backend, nil).GetByHash("share")
			if err != nil || reloaded.GetDownloadCount() != 50 || (perUser && !reloaded.HasReachedUserLimit("alice")) {
				t.Fatalf("persisted counts lost download limit: link=%+v err=%v", reloaded, err)
			}
		})
	}
}

func testMovingShare() *Link {
	return &Link{Hash: "share", UserID: 1, CommonShare: CommonShare{Source: "source", Path: "/old/"}}
}

// Serialize each backend write so tests exercise the same detached persistence
// boundary as the database, rather than keeping pointers supplied by Storage.
type shareConcurrencyBackend struct {
	mu      sync.Mutex
	links   map[string][]byte
	saveErr error
}

func newShareConcurrencyBackend(t *testing.T, initial *Link) *shareConcurrencyBackend {
	t.Helper()
	backend := &shareConcurrencyBackend{links: make(map[string][]byte)}
	if err := backend.Save(initial); err != nil {
		t.Fatal(err)
	}
	return backend
}

func (b *shareConcurrencyBackend) All() ([]*Link, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := make([]*Link, 0, len(b.links))
	for _, raw := range b.links {
		var link Link
		if err := json.Unmarshal(raw, &link); err != nil {
			return nil, err
		}
		result = append(result, &link)
	}
	return result, nil
}

func (b *shareConcurrencyBackend) GetByHash(hash string) (*Link, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	raw, ok := b.links[hash]
	if !ok {
		return nil, errors.ErrNotExist
	}
	var link Link
	return &link, json.Unmarshal(raw, &link)
}

func (b *shareConcurrencyBackend) Save(link *Link) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.saveErr != nil {
		return b.saveErr
	}
	raw, err := json.Marshal(link)
	if err == nil {
		b.links[link.Hash] = raw
	}
	return err
}

func (b *shareConcurrencyBackend) Delete(hash string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.links, hash)
	return nil
}

func (b *shareConcurrencyBackend) FindByUserID(uint) ([]*Link, error) { return b.All() }
func (b *shareConcurrencyBackend) GetCommonShareByHash(hash string) (*CommonShare, error) {
	link, err := b.GetByHash(hash)
	if err != nil {
		return nil, err
	}
	return &link.CommonShare, nil
}
func (b *shareConcurrencyBackend) GetPermanent(string, string, uint) (*Link, error) {
	return b.GetByHash("share")
}
func (b *shareConcurrencyBackend) GetBySourcePath(string, string) ([]*Link, error) { return b.All() }
func (b *shareConcurrencyBackend) Gets(string, string, uint) ([]*Link, error)      { return b.All() }
