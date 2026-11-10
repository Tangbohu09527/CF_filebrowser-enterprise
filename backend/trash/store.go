// Package trash implements durable, explicit, single-file recycling inside a
// Source's data directory. It never uses the database, cache directory, or /tmp.
package trash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
)

var (
	ErrConflict  = errors.New("trash operation conflicts with existing data")
	ErrInvalid   = errors.New("invalid trash operation")
	ErrUncertain = errors.New("trash operation requires reconciliation")
	sourceLocks  sync.Map
)

const marker = "filebrowser-trash-v1\n"

// Item records Source-relative paths. HTTP clients receive paths relative to
// their current scope only after fresh authorization against the original path.
type Item struct {
	OperationID        string    `json:"operation_id"`
	State              string    `json:"state"`
	Source             string    `json:"source"`
	SourceKey          string    `json:"-"`
	OriginalPath       string    `json:"path"`
	Name               string    `json:"name"`
	Size               int64     `json:"size"`
	SHA256             string    `json:"sha256"`
	ActorID            uint      `json:"actor_id"`
	Actor              string    `json:"actor"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	RestoreOperationID string    `json:"restore_operation_id,omitempty"`
	RestoredPath       string    `json:"restored_path,omitempty"`
	RestoreActorID     uint      `json:"restore_actor_id,omitempty"`
	RestoreActor       string    `json:"restore_actor,omitempty"`
	ErrorCode          string    `json:"error_code,omitempty"`
}

// diskRecord preserves the trusted source identity without exposing disk paths.
type diskRecord struct {
	Item
	SourceKey string `json:"source_key"`
}

type Store struct {
	root   *os.Root
	key    string
	unlock func()
	// Hooks are deliberately private and used by package tests to inject faults.
	beforeSave func(*Item) error
	move       func(*os.Root, string, string) error
}

func ValidID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validFile(value string) bool {
	return value != "." && fs.ValidPath(value) && !strings.Contains(value, "\\") && !strings.Contains(value, ":") && !utils.IsReservedStoragePath(value)
}

// Open serializes operations for one Source within the FileBrowser process.
// FileBrowser is the sole writer; independent instances must not share a Source.
func Open(sourcePath string) (*Store, error) {
	canonical, err := filepath.EvalSymlinks(sourcePath)
	if err != nil {
		return nil, err
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil || utils.IsReservedStoragePath(canonical) {
		return nil, ErrInvalid
	}
	root, err := os.OpenRoot(canonical)
	if err != nil {
		return nil, err
	}
	lock, _ := sourceLocks.LoadOrStore(root.Name(), &sync.Mutex{})
	mu, ok := lock.(*sync.Mutex)
	if !ok {
		root.Close()
		return nil, ErrInvalid
	}
	mu.Lock()
	return &Store{root: root, key: sourcePath, unlock: mu.Unlock, move: moveNoReplace}, nil
}

func (s *Store) Close() error { defer s.unlock(); return s.root.Close() }

func syncDir(root *os.Root, name string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := root.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// safeParent pins each directory and rejects symlinks, including symlinks that
// resolve within the Source. os.Root additionally prevents escaping the Source.
func safeParent(root *os.Root, filename string) (*os.Root, string, error) {
	if !fs.ValidPath(filename) || strings.ContainsAny(filename, "\\:") {
		return nil, "", ErrInvalid
	}
	current, err := root.OpenRoot(".")
	if err != nil {
		return nil, "", err
	}
	parent := path.Dir(filename)
	if parent != "." {
		for _, component := range strings.Split(parent, "/") {
			info, statErr := current.Lstat(component)
			if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				current.Close()
				if statErr != nil {
					return nil, "", statErr
				}
				return nil, "", ErrInvalid
			}
			next, openErr := current.OpenRoot(component)
			current.Close()
			if openErr != nil {
				return nil, "", openErr
			}
			current = next
		}
	}
	return current, path.Base(filename), nil
}

func (s *Store) initialize(create bool) error {
	info, err := s.root.Lstat(utils.TrashDirectory)
	if os.IsNotExist(err) && create {
		if err = s.root.Mkdir(utils.TrashDirectory, 0700); err != nil {
			return err
		}
		f, createErr := s.root.OpenFile(path.Join(utils.TrashDirectory, "version"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if createErr != nil {
			return createErr
		}
		_, writeErr := io.WriteString(f, marker)
		if writeErr == nil {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
		if err = syncDir(s.root, utils.TrashDirectory); err != nil {
			return err
		}
		return syncDir(s.root, ".")
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalid
	}
	// Refuse to adopt an existing user-created directory or symlink as storage.
	f, err := s.root.Open(path.Join(utils.TrashDirectory, "version"))
	if err != nil {
		return ErrInvalid
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(len(marker)+1)))
	if err != nil || string(data) != marker {
		return ErrInvalid
	}
	return nil
}

func recordDir(id string) string   { return path.Join(utils.TrashDirectory, id) }
func contentPath(id string) string { return path.Join(recordDir(id), "content") }

func (s *Store) save(item *Item) error {
	if s.beforeSave != nil {
		if err := s.beforeSave(item); err != nil {
			return err
		}
	}
	item.UpdatedAt = time.Now().UTC()
	data, err := json.Marshal(diskRecord{Item: *item, SourceKey: s.key})
	if err != nil {
		return err
	}
	return s.writeRecord(path.Join(recordDir(item.OperationID), "record.json"), data)
}

func (s *Store) writeRecord(filename string, data []byte) error {
	directory, name, err := safeParent(s.root, filename)
	if err != nil {
		return err
	}
	defer directory.Close()
	next := strings.TrimSuffix(name, ".json") + ".next"
	file, err := directory.OpenFile(next, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = directory.Rename(next, name); err != nil {
		return err
	}
	return syncDir(directory, ".")
}

func (s *Store) load(id string) (*Item, error) {
	if !ValidID(id) {
		return nil, ErrInvalid
	}
	if err := s.initialize(false); err != nil {
		return nil, err
	}
	directory, name, err := safeParent(s.root, path.Join(recordDir(id), "record.json"))
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	info, err := directory.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return nil, ErrInvalid
	}
	file, err := directory.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var record diskRecord
	if err := json.NewDecoder(io.LimitReader(file, 64*1024)).Decode(&record); err != nil {
		return nil, ErrInvalid
	}
	item := &record.Item
	item.SourceKey = record.SourceKey
	if item.OperationID != id || record.SourceKey != s.key || !validFile(item.OriginalPath) || item.Size < 0 || len(item.SHA256) != 64 {
		return nil, ErrInvalid
	}
	if item.RestoredPath != "" && !validFile(item.RestoredPath) {
		return nil, ErrInvalid
	}
	return item, nil
}

// Peek reads metadata for authorization, without reconciling or touching bytes.
func (s *Store) Peek(id string) (*Item, error) { return s.load(id) }

func (s *Store) checksum(filename string) (string, os.FileInfo, error) {
	directory, name, err := safeParent(s.root, filename)
	if err != nil {
		return "", nil, err
	}
	defer directory.Close()
	info, err := directory.Lstat(name)
	if err != nil {
		return "", nil, err
	}
	if !info.Mode().IsRegular() {
		return "", nil, ErrInvalid
	}
	f, err := directory.Open(name)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", nil, ErrUncertain
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, f); err != nil {
		return "", nil, err
	}
	if runtime.GOOS != "windows" {
		if err = f.Sync(); err != nil {
			return "", nil, err
		}
	}
	after, err := directory.Lstat(name)
	if err != nil || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return "", nil, ErrUncertain
	}
	return hex.EncodeToString(hash.Sum(nil)), info, nil
}

func (s *Store) matches(filename string, item *Item) bool {
	checksum, info, err := s.checksum(filename)
	return err == nil && info.Size() == item.Size && checksum == item.SHA256
}

func (s *Store) sameSnapshot(filename string, before os.FileInfo) bool {
	after, err := s.root.Lstat(filename)
	return err == nil && before != nil && after.Mode().IsRegular() && os.SameFile(before, after) &&
		before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

func (s *Store) requireReconciliation(item *Item, code string) (*Item, error) {
	item.State, item.ErrorCode = "manual_reconciliation", code
	if err := s.save(item); err != nil {
		return nil, ErrUncertain
	}
	if err := s.settleRestoreAttempt(item); err != nil {
		return nil, ErrUncertain
	}
	return item, ErrUncertain
}

// Get reconciles a durable pending intent against both filesystem names. It
// never replays a move, and never treats a conflicting/unknown result as success.
func (s *Store) Get(id string) (*Item, error) {
	item, err := s.load(id)
	if err != nil {
		return nil, err
	}
	if item.State != "pending_trash" && item.State != "pending_restore" {
		return item, s.settleRestoreAttempt(item)
	}
	oldPath, newPath := item.OriginalPath, contentPath(id)
	completedState, unchangedState := "trashed", "failed"
	if item.State == "pending_restore" {
		oldPath, newPath = contentPath(id), item.RestoredPath
		completedState, unchangedState = "restored", "trashed"
	}
	oldInfo, oldErr := s.root.Lstat(oldPath)
	newInfo, newErr := s.root.Lstat(newPath)
	switch {
	case os.IsNotExist(oldErr) && newErr == nil && s.matches(newPath, item):
		item.State, item.ErrorCode = completedState, ""
	case oldErr == nil && os.IsNotExist(newErr) && s.matches(oldPath, item):
		item.State, item.ErrorCode = unchangedState, "not_moved"
	case oldErr == nil && newErr == nil && os.SameFile(oldInfo, newInfo) && s.matches(newPath, item):
		// The portable link/unlink fallback was interrupted. Preserve both names;
		// an operator can resolve it without any implicit overwrite or deletion.
		item.State, item.ErrorCode = "manual_reconciliation", "both_names_exist"
	default:
		item.State, item.ErrorCode = "manual_reconciliation", "integrity_or_path_conflict"
	}
	if err := s.save(item); err != nil {
		return nil, ErrUncertain
	}
	return item, s.settleRestoreAttempt(item)
}

func (s *Store) Trash(item Item) (*Item, error) {
	if !ValidID(item.OperationID) || !validFile(item.OriginalPath) {
		return nil, ErrInvalid
	}
	existing, err := s.Get(item.OperationID)
	if err == nil {
		if existing.OriginalPath != item.OriginalPath || existing.ActorID != item.ActorID || existing.Actor != item.Actor || existing.Source != item.Source {
			return nil, ErrConflict
		}
		return existing, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	checksum, info, err := s.checksum(item.OriginalPath)
	if err != nil {
		return nil, err
	}
	if err = s.initialize(true); err != nil {
		return nil, err
	}
	if err = s.root.Mkdir(recordDir(item.OperationID), 0700); err != nil {
		return nil, ErrConflict
	}
	if err = syncDir(s.root, utils.TrashDirectory); err != nil {
		return nil, err
	}
	item.State, item.SHA256, item.Size = "pending_trash", checksum, info.Size()
	item.SourceKey, item.Name, item.CreatedAt = s.key, path.Base(item.OriginalPath), time.Now().UTC()
	if err = s.save(&item); err != nil {
		return nil, err
	}
	if err = s.move(s.root, item.OriginalPath, contentPath(item.OperationID)); err != nil {
		// An interrupted portable unlink may already have linked the data. Leave
		// intent pending for Get to distinguish it from a definite pre-move error.
		if _, statErr := s.root.Lstat(contentPath(item.OperationID)); statErr == nil {
			return nil, ErrUncertain
		}
		item.State, item.ErrorCode = "failed", "move_rejected"
		if saveErr := s.save(&item); saveErr != nil {
			return nil, ErrUncertain
		}
		return &item, fmt.Errorf("move rejected: %w", err)
	}
	if err = s.syncMove(item.OriginalPath, contentPath(item.OperationID)); err != nil {
		return nil, ErrUncertain
	}
	if !s.sameSnapshot(contentPath(item.OperationID), info) {
		return s.requireReconciliation(&item, "source_changed")
	}
	item.State = "trashed"
	if err = s.save(&item); err != nil {
		return nil, ErrUncertain
	}
	return &item, nil
}

func (s *Store) syncMove(oldPath, newPath string) error {
	if err := syncDir(s.root, path.Dir(oldPath)); err != nil {
		return err
	}
	return syncDir(s.root, path.Dir(newPath))
}

func (s *Store) Restore(id, restoreID, destination string, actorID uint, actor string) (*Item, error) {
	if !ValidID(restoreID) || !validFile(destination) {
		return nil, ErrInvalid
	}
	item, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	previous, attemptErr := s.GetRestoreAttempt(id, restoreID)
	if attemptErr == nil {
		if previous.Path != destination || previous.ActorID != actorID || previous.Actor != actor {
			return nil, ErrConflict
		}
		return item, nil
	}
	if !os.IsNotExist(attemptErr) {
		return nil, attemptErr
	}
	if item.State != "trashed" {
		return nil, ErrConflict
	}
	attempt := &RestoreAttempt{OperationID: restoreID, TrashOperationID: id, State: "pending_restore", Path: destination, ActorID: actorID, Actor: actor, CreatedAt: time.Now().UTC()}
	if err = s.saveRestoreAttempt(attempt); err != nil {
		return nil, err
	}
	item.RestoreOperationID, item.RestoredPath = restoreID, destination
	item.RestoreActorID, item.RestoreActor, item.ErrorCode = actorID, actor, ""
	if _, err = s.root.Lstat(destination); err == nil {
		return s.rejectRestore(item, "target_exists", ErrConflict)
	} else if !os.IsNotExist(err) {
		return s.rejectRestore(item, "target_unavailable", err)
	}
	parent, _, err := safeParent(s.root, destination)
	if err != nil {
		return s.rejectRestore(item, "invalid_destination", err)
	}
	parent.Close()
	payloadHash, payloadInfo, checksumErr := s.checksum(contentPath(id))
	if checksumErr != nil || payloadInfo.Size() != item.Size || payloadHash != item.SHA256 {
		return s.requireReconciliation(item, "integrity_conflict")
	}
	item.State = "pending_restore"
	if err = s.save(item); err != nil {
		return nil, ErrUncertain
	}
	if err = s.move(s.root, contentPath(id), destination); err != nil {
		if os.IsExist(err) {
			return s.rejectRestore(item, "target_exists", ErrConflict)
		}
		if _, statErr := s.root.Lstat(destination); statErr == nil {
			return nil, ErrUncertain
		}
		return s.rejectRestore(item, "move_rejected", fmt.Errorf("restore rejected: %w", err))
	}
	if err = s.syncMove(contentPath(id), destination); err != nil {
		return nil, ErrUncertain
	}
	if !s.sameSnapshot(destination, payloadInfo) {
		return s.requireReconciliation(item, "source_changed")
	}
	item.State = "restored"
	if err = s.save(item); err != nil {
		return nil, ErrUncertain
	}
	return item, s.settleRestoreAttempt(item)
}

// IDs enumerates only the dedicated journal directory, never the Source tree.
func (s *Store) IDs() ([]string, error) {
	if err := s.initialize(false); err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	f, err := s.root.Open(utils.TrashDirectory)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, entry := range entries {
		if entry.IsDir() && ValidID(entry.Name()) {
			ids = append(ids, entry.Name())
		}
	}
	return ids, nil
}
