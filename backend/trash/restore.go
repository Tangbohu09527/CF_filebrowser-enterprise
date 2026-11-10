package trash

import (
	"encoding/json"
	"io"
	"os"
	"path"
	"time"
)

// RestoreAttempt is retained for every restore ID, including rejected targets.
// Later attempts cannot reuse an earlier ID or erase its historical result.
type RestoreAttempt struct {
	OperationID      string    `json:"operation_id"`
	TrashOperationID string    `json:"trash_operation_id"`
	State            string    `json:"state"`
	Path             string    `json:"path"`
	ActorID          uint      `json:"actor_id"`
	Actor            string    `json:"actor"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	ErrorCode        string    `json:"error_code,omitempty"`
}

func restoreRecordPath(id, restoreID string) string {
	return path.Join(recordDir(id), "restore-"+restoreID+".json")
}

func (s *Store) loadRestoreAttempt(id, restoreID string) (*RestoreAttempt, error) {
	if !ValidID(id) || !ValidID(restoreID) {
		return nil, ErrInvalid
	}
	directory, name, err := safeParent(s.root, restoreRecordPath(id, restoreID))
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
	f, err := directory.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var attempt RestoreAttempt
	if err = json.NewDecoder(io.LimitReader(f, 64*1024)).Decode(&attempt); err != nil {
		return nil, ErrInvalid
	}
	if attempt.OperationID != restoreID || attempt.TrashOperationID != id || !validFile(attempt.Path) {
		return nil, ErrInvalid
	}
	return &attempt, nil
}

func (s *Store) saveRestoreAttempt(attempt *RestoreAttempt) error {
	attempt.UpdatedAt = time.Now().UTC()
	data, err := json.Marshal(attempt)
	if err != nil {
		return err
	}
	return s.writeRecord(restoreRecordPath(attempt.TrashOperationID, attempt.OperationID), data)
}

func (s *Store) settleRestoreAttempt(item *Item) error {
	if item.RestoreOperationID == "" {
		return nil
	}
	attempt, err := s.loadRestoreAttempt(item.OperationID, item.RestoreOperationID)
	if os.IsNotExist(err) {
		attempt = &RestoreAttempt{OperationID: item.RestoreOperationID, TrashOperationID: item.OperationID, Path: item.RestoredPath, ActorID: item.RestoreActorID, Actor: item.RestoreActor, CreatedAt: item.UpdatedAt}
	} else if err != nil {
		return err
	}
	state := item.State
	if state == "trashed" {
		state = "failed"
	}
	if attempt.State == state && attempt.ErrorCode == item.ErrorCode {
		return nil
	}
	attempt.State, attempt.ErrorCode = state, item.ErrorCode
	if err = s.saveRestoreAttempt(attempt); err != nil {
		return ErrUncertain
	}
	return nil
}

// GetRestoreAttempt queries one historical intent after the caller has
// authorized the original item and, separately, this attempt's target path.
func (s *Store) GetRestoreAttempt(id, restoreID string) (*RestoreAttempt, error) {
	item, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	attempt, err := s.loadRestoreAttempt(id, restoreID)
	if err != nil {
		return nil, err
	}
	if attempt.State == "pending_restore" && item.RestoreOperationID != restoreID {
		// Its intent never became the authoritative pending item, so execution
		// could not have started. No filesystem operation is replayed here.
		attempt.State, attempt.ErrorCode = "failed", "not_moved"
		if err = s.saveRestoreAttempt(attempt); err != nil {
			return nil, ErrUncertain
		}
	}
	return attempt, nil
}

func (s *Store) rejectRestore(item *Item, code string, cause error) (*Item, error) {
	item.State, item.ErrorCode = "trashed", code
	if err := s.save(item); err != nil {
		return nil, ErrUncertain
	}
	if err := s.settleRestoreAttempt(item); err != nil {
		return nil, ErrUncertain
	}
	return item, cause
}
