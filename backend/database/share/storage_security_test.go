package share

import (
	"errors"
	"testing"
)

func TestUpdateSharesPreservesDescendantsAndCacheAtomicity(t *testing.T) {
	t.Run("moving a parent preserves the share descendant suffix", func(t *testing.T) {
		backend := newSecurityShareBackend(&Link{Hash: "descendant", CommonShare: CommonShare{Source: "source", Path: "/a/private"}})
		storage := NewStorage(backend, nil)

		updated, err := storage.UpdateShares("source", "/a", "source", "/b")
		if err != nil || updated != 1 {
			t.Fatalf("UpdateShares: updated=%d err=%v", updated, err)
		}
		stored, err := storage.GetByHash("descendant")
		if err != nil {
			t.Fatal(err)
		}
		if stored.Path != "/b/private/" {
			t.Fatalf("descendant share path: got %q, want %q", stored.Path, "/b/private/")
		}
		if old, err := storage.Gets("/a/private", "source", 0); err == nil && len(old) != 0 {
			t.Fatalf("old cache key still returns moved share: %+v", old)
		}
	})

	t.Run("path substring is not treated as a descendant", func(t *testing.T) {
		backend := newSecurityShareBackend(&Link{Hash: "substring", CommonShare: CommonShare{Source: "source", Path: "/x/a/private"}})
		storage := NewStorage(backend, nil)

		updated, err := storage.UpdateShares("source", "/a", "source", "/b")
		if err != nil || updated != 0 {
			t.Fatalf("UpdateShares: updated=%d err=%v", updated, err)
		}
		stored, err := storage.GetByHash("substring")
		if err != nil {
			t.Fatal(err)
		}
		if stored.Path != "/x/a/private" {
			t.Fatalf("non-descendant share moved to %q", stored.Path)
		}
	})

	t.Run("failed persistence does not mutate the cache", func(t *testing.T) {
		backend := newSecurityShareBackend(&Link{Hash: "failure", CommonShare: CommonShare{Source: "source", Path: "/a/private"}})
		storage := NewStorage(backend, nil)
		backend.saveErr = errors.New("save failed")

		if _, err := storage.UpdateShares("source", "/a", "source", "/b"); err == nil {
			t.Fatal("UpdateShares unexpectedly succeeded")
		}
		stored, err := storage.GetByHash("failure")
		if err != nil {
			t.Fatal(err)
		}
		if stored.Path != "/a/private" {
			t.Fatalf("failed update mutated cached path to %q", stored.Path)
		}
	})
}

func TestStaleShareUpdateCannotRecreateDeletedHash(t *testing.T) {
	backend := newSecurityShareBackend(&Link{Hash: "deleted", CommonShare: CommonShare{Source: "source", Path: "/public"}})
	storage := NewStorage(backend, nil)
	existing, err := storage.GetByHash("deleted")
	if err != nil {
		t.Fatal(err)
	}
	candidate := existing.Clone()
	candidate.Title = "stale update"

	if err := storage.Delete(existing.Hash); err != nil {
		t.Fatal(err)
	}
	if err := storage.UpdateIfUnchanged(existing, candidate); err == nil {
		t.Fatal("stale update recreated a deleted share")
	}
	if recreated, err := storage.GetByHash(existing.Hash); err == nil {
		t.Fatalf("deleted share was recreated: %+v", recreated)
	}
}

type securityShareBackend struct {
	links   map[string]*Link
	saveErr error
}

func newSecurityShareBackend(links ...*Link) *securityShareBackend {
	backend := &securityShareBackend{links: make(map[string]*Link, len(links))}
	for _, link := range links {
		backend.links[link.Hash] = link.Clone()
	}
	return backend
}

func (b *securityShareBackend) All() ([]*Link, error) {
	links := make([]*Link, 0, len(b.links))
	for _, link := range b.links {
		links = append(links, link.Clone())
	}
	return links, nil
}

func (b *securityShareBackend) FindByUserID(id uint) ([]*Link, error) {
	links := make([]*Link, 0)
	for _, link := range b.links {
		if link.UserID == id {
			links = append(links, link.Clone())
		}
	}
	return links, nil
}

func (b *securityShareBackend) GetByHash(hash string) (*Link, error) {
	link, ok := b.links[hash]
	if !ok {
		return nil, errors.New("not found")
	}
	return link.Clone(), nil
}

func (b *securityShareBackend) GetCommonShareByHash(hash string) (*CommonShare, error) {
	link, err := b.GetByHash(hash)
	if err != nil {
		return nil, err
	}
	common := link.CommonShare
	return &common, nil
}

func (b *securityShareBackend) GetPermanent(path, source string, id uint) (*Link, error) {
	for _, link := range b.links {
		if link.Path == path && link.Source == source && link.UserID == id && link.Expire == 0 {
			return link.Clone(), nil
		}
	}
	return nil, errors.New("not found")
}

func (b *securityShareBackend) GetBySourcePath(path, source string) ([]*Link, error) {
	return b.Gets(path, source, 0)
}

func (b *securityShareBackend) Gets(path, source string, id uint) ([]*Link, error) {
	links := make([]*Link, 0)
	for _, link := range b.links {
		if link.Path == path && link.Source == source && (id == 0 || link.UserID == id) {
			links = append(links, link.Clone())
		}
	}
	return links, nil
}

func (b *securityShareBackend) Save(link *Link) error {
	if b.saveErr != nil {
		return b.saveErr
	}
	b.links[link.Hash] = link.Clone()
	return nil
}

func (b *securityShareBackend) Delete(hash string) error {
	delete(b.links, hash)
	return nil
}
