package inbound

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"regexp"
	"sync"
)

var errStore = errors.New("task working directory is unavailable or unsafe")
var internalName = regexp.MustCompile(`^work-[0-9a-f]{32}$`)

// Store retains the authorized directory for the dispatch lifetime. Names are
// internal capabilities; an original attachment filename is never a local path.
type Store struct {
	mu      sync.Mutex
	backend *storeBackend
	files   map[string]fileIdentity
	staging map[*Staging]struct{}
	closed  bool
}

type Staging struct {
	File     *os.File
	store    *Store
	name     string
	identity fileIdentity
	done     bool
}

// OpenStore requires an existing private task directory. It does not create or
// repair directories or permissions supplied by the host integration.
func OpenStore(directory string) (*Store, error) {
	b, err := openStoreBackend(directory)
	if err != nil {
		return nil, errStore
	}
	return &Store{backend: b, files: make(map[string]fileIdentity), staging: make(map[*Staging]struct{})}, nil
}

func randomName(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errStore
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}

func (s *Store) Create() (*Staging, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.backend.verify() != nil {
		return nil, errStore
	}
	name, err := randomName("pending-")
	if err != nil {
		return nil, err
	}
	f, id, err := s.backend.create(name)
	if err != nil {
		return nil, errStore
	}
	p := &Staging{File: f, store: s, name: name, identity: id}
	s.staging[p] = struct{}{}
	return p, nil
}

// Publish syncs and closes the staging writer after publishing the verified
// object without replacement. Call only after checking length and digest.
func (p *Staging) Publish() (string, error) {
	return p.PublishContext(context.Background())
}

// PublishContext keeps sync and publication inside the dispatch deadline. A
// cancellation during a native filesystem call never exposes its result.
func (p *Staging) PublishContext(ctx context.Context) (string, error) {
	s := p.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.done || s.closed || ctx.Err() != nil || s.backend.verify() != nil {
		return "", errStore
	}
	if err := p.File.Sync(); err != nil {
		return "", errStore
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	name, err := randomName("work-")
	if err != nil {
		return "", err
	}
	if err = s.backend.publish(p.File, p.name, name, p.identity); err != nil {
		return "", errStore
	}
	if ctx.Err() != nil {
		// The writer still holds its original object handle. Deletion on
		// Windows targets that handle, even though its name has changed.
		_ = s.backend.abort(p.File, name, p.identity)
		_ = p.File.Close()
		p.done = true
		delete(s.staging, p)
		return "", ctx.Err()
	}
	p.done = true
	delete(s.staging, p)
	s.files[name] = p.identity
	// Closing a successfully published regular file cannot create a partial
	// result; durable content was synced before the atomic publication.
	_ = p.File.Close()
	return name, nil
}

func (p *Staging) Abort() error {
	s := p.store
	s.mu.Lock()
	defer s.mu.Unlock()
	return p.abortLocked()
}

func (p *Staging) abortLocked() error {
	if p.done {
		return nil
	}
	err := p.store.backend.abort(p.File, p.name, p.identity)
	p.done = true
	delete(p.store.staging, p)
	_ = p.File.Close()
	if err != nil {
		return errStore
	}
	return nil
}

// Open resolves only names published by this Store and checks file identity.
// The caller receives a real readable file, never a path to pass to a shell.
func (s *Store) Open(name string) (*os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.files[name]
	if s.closed || !ok || !internalName.MatchString(name) || s.backend.verify() != nil {
		return nil, errStore
	}
	f, err := s.backend.open(name, id)
	if err != nil {
		return nil, errStore
	}
	return f, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	var first error
	for p := range s.staging {
		if err := p.abortLocked(); err != nil && first == nil {
			first = err
		}
	}
	s.closed = true
	if err := s.backend.close(); err != nil && first == nil {
		first = errStore
	}
	return first
}
