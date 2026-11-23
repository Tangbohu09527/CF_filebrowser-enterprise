package bolt

import (
	"errors"
	"time"

	storm "github.com/asdine/storm/v3"
)

// ChunkUploadDisposition keeps a move or cancellation result available across restarts.
type ChunkUploadDisposition struct {
	Key       string `storm:"id"`
	State     string
	ExpiresAt int64 `storm:"index"`
}

type ChunkUploads struct {
	db *storm.DB
}

func (s *ChunkUploads) State(key string) (string, error) {
	var disposition ChunkUploadDisposition
	err := s.db.One("Key", key, &disposition)
	if errors.Is(err, storm.ErrNotFound) || (err == nil && disposition.ExpiresAt <= time.Now().Unix()) {
		return "", nil
	}
	return disposition.State, err
}

func (s *ChunkUploads) SetState(key, state string, ttl time.Duration) error {
	now := time.Now()
	var expired []ChunkUploadDisposition
	err := s.db.Range("ExpiresAt", int64(0), now.Unix(), &expired, storm.Limit(16))
	if err != nil && !errors.Is(err, storm.ErrNotFound) {
		return err
	}
	for i := range expired {
		if err := s.db.DeleteStruct(&expired[i]); err != nil && !errors.Is(err, storm.ErrNotFound) {
			return err
		}
	}
	return s.db.Save(&ChunkUploadDisposition{Key: key, State: state, ExpiresAt: now.Add(ttl).Unix()})
}
