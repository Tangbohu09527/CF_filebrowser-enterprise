package bolt

import (
	"fmt"

	storm "github.com/asdine/storm/v3"

	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/database/access"
	"github.com/gtsteffaniak/filebrowser/backend/database/audit"
	"github.com/gtsteffaniak/filebrowser/backend/database/dbindex"
	"github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

// Storage is a storage powered by a Backend which makes the necessary
// verifications when fetching and saving data to ensure consistency.
type BoltStore struct {
	Users    *users.Storage
	Share    *share.Storage
	Auth     *auth.Storage
	Settings *settings.Storage
	Access   *access.Storage
	Indexing *dbindex.Storage
	Audit    audit.Store
}

// NewStorage creates a storage.Storage based on Bolt DB.
func NewStorage(db *storm.DB) (*BoltStore, error) {
	if err := MigrateDatabase(db); err != nil {
		return nil, fmt.Errorf("migrate storage database: %w", err)
	}
	auditStore := newAuditStore(db)
	if _, err := auditStore.RecoverPending(); err != nil {
		return nil, fmt.Errorf("recover audit storage: %w", err)
	}
	userStore := users.NewStorage(usersBackend{db: db})
	authStore, err := auth.NewStorage(authBackend{db: db}, userStore)
	if err != nil {
		return nil, err
	}
	return &BoltStore{
		Users:    userStore,
		Share:    share.NewStorage(shareBackend{db: db}, userStore),
		Auth:     authStore,
		Settings: settings.NewStorage(settingsBackend{db: db}),
		Access:   access.NewStorage(db, userStore),
		Indexing: dbindex.NewStorage(indexingBackend{db: db}),
		Audit:    auditStore,
	}, nil
}
