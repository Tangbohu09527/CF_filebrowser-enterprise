package trash

import (
	"os"
	"time"
)

const (
	PurgeManual    = "manual"
	PurgeAutomatic = "automatic"
)

// OccupiedBytes reports the logical size of a payload still in the recycle
// directory. Historical journal records and the original path are excluded.
func (s *Store) OccupiedBytes(item *Item) (int64, error) {
	if item == nil || !ValidID(item.OperationID) || item.SourceKey != s.key {
		return 0, ErrInvalid
	}
	directory, name, err := safeParent(s.root, contentPath(item.OperationID))
	if err != nil {
		return 0, err
	}
	defer directory.Close()
	info, err := directory.Lstat(name)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, ErrInvalid
	}
	return info.Size(), nil
}

// Purge removes only the private payload of a completed recycle operation.
// The trash operation ID is also the idempotency key for permanent removal.
func (s *Store) Purge(id string, actorID uint, actor, method string) (*Item, error) {
	if actor == "" || (method != PurgeManual && method != PurgeAutomatic) {
		return nil, ErrInvalid
	}
	item, err := s.Get(id)
	if err != nil || item.State == "purged" {
		return item, err
	}
	if item.State != "trashed" {
		return nil, ErrConflict
	}
	return s.purge(item, actorID, actor, method)
}

// PurgeExpired rechecks the current retention policy while holding the same
// Source lock used by policy changes and restores. Comparisons are inclusive.
func (s *Store) PurgeExpired(id string, now time.Time) (*Item, error) {
	item, err := s.Get(id)
	if err != nil || item.State != "trashed" {
		return item, err
	}
	policy, err := s.RetentionPolicy()
	if err != nil {
		return nil, err
	}
	deadline := policy.Deadline(item)
	if deadline == nil || now.Before(*deadline) {
		return item, nil
	}
	return s.purge(item, 0, "retention", PurgeAutomatic)
}

func (s *Store) purge(item *Item, actorID uint, actor, method string) (*Item, error) {
	filename := contentPath(item.OperationID)
	directory, name, err := safeParent(s.root, filename)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	checksum, info, err := s.checksum(filename)
	if err != nil {
		return nil, err
	}
	if info.Size() != item.Size || checksum != item.SHA256 {
		return nil, ErrConflict
	}

	item.State = "pending_purge"
	item.PurgeActorID, item.PurgeActor, item.PurgeMethod = actorID, actor, method
	if err = s.save(item); err != nil {
		return nil, ErrUncertain
	}
	// The dedicated Source lock keeps all FileBrowser writers out of the
	// private store. Check the entry again after syncing the durable intent.
	snapshot, err := directory.Lstat(name)
	if err != nil || !snapshot.Mode().IsRegular() || !os.SameFile(info, snapshot) ||
		snapshot.Size() != info.Size() || !snapshot.ModTime().Equal(info.ModTime()) {
		return s.requireReconciliation(item, "purge_payload_changed")
	}
	if err = directory.Remove(name); err != nil {
		return nil, ErrUncertain
	}
	return s.finishPurge(directory, item)
}

func (s *Store) finishPurge(directory *os.Root, item *Item) (*Item, error) {
	if err := syncDir(directory, "."); err != nil {
		return nil, ErrUncertain
	}
	now := time.Now().UTC()
	item.State, item.ErrorCode, item.PurgedAt = "purged", "", &now
	if err := s.save(item); err != nil {
		return nil, ErrUncertain
	}
	return item, nil
}

func (s *Store) reconcilePurge(item *Item) (*Item, error) {
	directory, name, err := safeParent(s.root, contentPath(item.OperationID))
	if err != nil {
		return nil, ErrUncertain
	}
	defer directory.Close()
	info, err := directory.Lstat(name)
	switch {
	case os.IsNotExist(err):
		return s.finishPurge(directory, item)
	case err != nil:
		return nil, ErrUncertain
	case !info.Mode().IsRegular() || info.Size() != item.Size:
		return s.requireReconciliation(item, "purge_payload_changed")
	default:
		// The unlink did not happen. Let a new authorized request or the
		// current retention policy decide whether to retry.
		item.State = "trashed"
		item.PurgeActorID, item.PurgeActor, item.PurgeMethod = 0, "", ""
		if err := s.save(item); err != nil {
			return nil, ErrUncertain
		}
		return item, nil
	}
}
