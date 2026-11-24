package trash

import (
	"encoding/json"
	"io"
	"os"
	"path"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
)

const (
	DefaultRetentionDays = 30
	MaxRetentionDays     = 3650
)

type RetentionPolicy struct {
	Days      int        `json:"days"`
	Enabled   bool       `json:"enabled"`
	EnabledAt *time.Time `json:"enabled_since,omitempty"`
}

func (p RetentionPolicy) valid() bool {
	return p.Days >= 1 && p.Days <= MaxRetentionDays &&
		(p.EnabledAt != nil && !p.EnabledAt.IsZero() || p.EnabledAt == nil && !p.Enabled)
}

// Deadline gives files already in the bin at first enablement the same full
// retention period as files moved to the bin after that date.
func (p RetentionPolicy) Deadline(item *Item) *time.Time {
	if item == nil || item.State != "trashed" || !p.Enabled || !p.valid() {
		return nil
	}
	started := item.CreatedAt
	if started.Before(*p.EnabledAt) {
		started = *p.EnabledAt
	}
	deadline := started.UTC().AddDate(0, 0, p.Days)
	return &deadline
}

func (s *Store) RetentionPolicy() (RetentionPolicy, error) {
	defaultPolicy := RetentionPolicy{Days: DefaultRetentionDays}
	if err := s.initialize(false); err != nil {
		if os.IsNotExist(err) {
			return defaultPolicy, nil
		}
		return RetentionPolicy{}, err
	}
	filename := path.Join(utils.TrashDirectory, "retention.json")
	directory, name, err := safeParent(s.root, filename)
	if err != nil {
		return RetentionPolicy{}, err
	}
	defer directory.Close()
	info, err := directory.Lstat(name)
	if os.IsNotExist(err) {
		return defaultPolicy, nil
	}
	if err != nil {
		return RetentionPolicy{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 {
		return RetentionPolicy{}, ErrInvalid
	}
	file, err := directory.Open(name)
	if err != nil {
		return RetentionPolicy{}, err
	}
	defer file.Close()
	var policy RetentionPolicy
	decoder := json.NewDecoder(io.LimitReader(file, 4096))
	if err := decoder.Decode(&policy); err != nil || !policy.valid() {
		return RetentionPolicy{}, ErrInvalid
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return RetentionPolicy{}, ErrInvalid
	}
	return policy, nil
}

func (s *Store) SetRetentionPolicy(enabled bool, days int, now time.Time) (RetentionPolicy, error) {
	if days < 1 || days > MaxRetentionDays || now.IsZero() {
		return RetentionPolicy{}, ErrInvalid
	}
	policy, err := s.RetentionPolicy()
	if err != nil {
		return RetentionPolicy{}, err
	}
	policy.Enabled, policy.Days = enabled, days
	if enabled && policy.EnabledAt == nil {
		firstEnabled := now.UTC()
		policy.EnabledAt = &firstEnabled
	}
	data, err := json.Marshal(policy)
	if err != nil {
		return RetentionPolicy{}, err
	}
	if err = s.initialize(true); err != nil {
		return RetentionPolicy{}, err
	}
	if err = s.writeRecord(path.Join(utils.TrashDirectory, "retention.json"), data); err != nil {
		return RetentionPolicy{}, err
	}
	return policy, nil
}
