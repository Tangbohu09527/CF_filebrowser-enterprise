package users

import (
	stderrors "errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/database/crud"
)

var ErrAPIPermissionRequired = stderrors.New("API permission is required to store a token")

// StorageBackend is the interface to implement for a users storage.
type StorageBackend interface {
	GetBy(interface{}) (*User, error)
	Gets() ([]*User, error)
	Save(u *User, changePass bool, disableScopeChange bool) error
	Update(u *User, adminActor bool, fields ...string) error
	DeleteByID(uint) error
	DeleteByUsername(string) error
}

// Store is an interface for user storage.
type Store interface {
	Get(id interface{}) (user *User, err error)
	Gets() ([]*User, error)
	Update(user *User, adminActor bool, fields ...string) error
	Save(user *User, changePass bool, disableScopeChange bool) error
	Delete(id interface{}) error
	LastUpdate(id uint) int64
	AddApiToken(userID uint, name string, tokenString string, metadata AuthToken) error
	DeleteApiToken(userID uint, name string) error
}

// crudBackend implements crud.CrudBackend[User] for users storage.
type crudBackend struct {
	back StorageBackend
}

func (c *crudBackend) GetByID(id any) (*User, error) {
	switch v := id.(type) {
	case string, uint:
		return c.back.GetBy(v)
	default:
		return nil, errors.ErrInvalidDataType
	}
}

func (c *crudBackend) GetAll() ([]*User, error) {
	return c.back.Gets()
}

func (c *crudBackend) Save(obj *User) error {
	// Use default values for changePass and disableScopeChange
	return c.back.Save(obj, false, false)
}

func (c *crudBackend) DeleteByID(id any) error {
	switch v := id.(type) {
	case string:
		return c.back.DeleteByUsername(v)
	case uint:
		return c.back.DeleteByID(v)
	default:
		return errors.ErrInvalidDataType
	}
}

// Storage is a users storage using generics.
type Storage struct {
	Generic  *crud.Storage[User]
	back     StorageBackend
	updated  map[uint]int64
	mux      sync.RWMutex
	tokenMux sync.Mutex
}

// NewStorage creates a users storage from a backend.
func NewStorage(back StorageBackend) *Storage {
	return &Storage{
		Generic: crud.NewStorage[User](&crudBackend{back: back}),
		back:    back,
		updated: map[uint]int64{},
	}
}

// Get allows you to get a user by its name or username. The provided
// id must be a string for username lookup or a uint for id lookup. If id
// is neither, a ErrInvalidDataType will be returned.
func (s *Storage) Get(id interface{}) (user *User, err error) {
	user, err = s.back.GetBy(id)
	if err != nil {
		return
	}
	return user, err
}

// Gets gets a list of all users.
func (s *Storage) Gets() ([]*User, error) {
	users, err := s.back.Gets()
	if err != nil {
		return nil, err
	}
	return users, err
}

// Update updates a user in the database.
func (s *Storage) Update(user *User, adminIActor bool, fields ...string) error {
	if userUpdateIncludesPermissions(fields) {
		s.tokenMux.Lock()
		defer s.tokenMux.Unlock()

		current, err := s.Get(user.ID)
		if err != nil {
			return err
		}
		if !user.Permissions.Api && (len(current.Tokens) != 0 || len(current.ApiKeys) != 0) {
			updated := *user
			updated.Tokens = make(map[string]AuthToken)
			updated.ApiKeys = make(map[string]AuthToken)
			user = &updated
			fields = appendUserUpdateFields(fields, "Tokens", "ApiKeys")
		}
	}
	return s.update(user, adminIActor, fields...)
}

func (s *Storage) update(user *User, adminIActor bool, fields ...string) error {
	err := s.back.Update(user, adminIActor, fields...)
	if err != nil {
		return err
	}

	s.mux.Lock()
	s.updated[user.ID] = time.Now().Unix()
	s.mux.Unlock()
	return nil
}

func userUpdateIncludesPermissions(fields []string) bool {
	if len(fields) == 0 {
		return true
	}
	for _, field := range fields {
		if strings.EqualFold(field, "Permissions") || strings.EqualFold(field, "All") {
			return true
		}
	}
	return false
}

func appendUserUpdateFields(fields []string, additional ...string) []string {
	if len(fields) == 0 {
		return fields
	}
	for _, field := range additional {
		present := false
		for _, existing := range fields {
			if strings.EqualFold(existing, field) {
				present = true
				break
			}
		}
		if !present {
			fields = append(fields, field)
		}
	}
	return fields
}

func (s *Storage) AddApiToken(userID uint, name string, tokenString string, metadata AuthToken) error {
	s.tokenMux.Lock()
	defer s.tokenMux.Unlock()
	user, err := s.Get(userID)
	if err != nil {
		return err
	}
	if !user.Permissions.Api {
		return ErrAPIPermissionRequired
	}
	if _, exists := user.Tokens[name]; exists {
		return fmt.Errorf("key already exists with same name %v ", name)
	}
	if _, exists := user.ApiKeys[name]; exists {
		return fmt.Errorf("key already exists with same name %v ", name)
	}
	updated := *user
	updated.Tokens = cloneAuthTokens(user.Tokens)
	metadata.Token = tokenString
	updated.Tokens[name] = metadata
	err = s.update(&updated, true, "Tokens")
	if err != nil {
		return err
	}

	return nil
}

func (s *Storage) DeleteApiToken(userID uint, name string) error {
	_, err := s.DeleteApiTokens(userID, name)
	return err
}

func (s *Storage) ApiTokenSecrets(userID uint, name string) ([]string, error) {
	s.tokenMux.Lock()
	defer s.tokenMux.Unlock()
	user, err := s.Get(userID)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, 4)
	secrets := make([]string, 0, 4)
	for _, tokens := range []map[string]AuthToken{user.Tokens, user.ApiKeys} {
		token, ok := tokens[name]
		if !ok {
			continue
		}
		for _, secret := range []string{token.Token, token.Key} {
			if secret == "" {
				continue
			}
			if _, exists := seen[secret]; !exists {
				seen[secret] = struct{}{}
				secrets = append(secrets, secret)
			}
		}
	}
	return secrets, nil
}

func (s *Storage) DeleteApiTokens(userID uint, name string) (bool, error) {
	s.tokenMux.Lock()
	defer s.tokenMux.Unlock()
	user, err := s.Get(userID)
	if err != nil {
		return false, err
	}
	_, modern := user.Tokens[name]
	_, legacy := user.ApiKeys[name]
	if !modern && !legacy {
		return false, nil
	}
	updated := *user
	updated.Tokens = cloneAuthTokens(user.Tokens)
	updated.ApiKeys = cloneAuthTokens(user.ApiKeys)
	delete(updated.Tokens, name)
	delete(updated.ApiKeys, name)
	err = s.update(&updated, true, "Tokens", "ApiKeys")
	if err != nil {
		return false, err
	}
	return true, nil
}

func cloneAuthTokens(tokens map[string]AuthToken) map[string]AuthToken {
	cloned := make(map[string]AuthToken, len(tokens))
	for name, token := range tokens {
		cloned[name] = token
	}
	return cloned
}

// Save saves the user in a storage.
func (s *Storage) Save(user *User, changePass, disableScopeChange bool) error {
	return s.back.Save(user, changePass, disableScopeChange)
}

// Delete allows you to delete a user by its name or username. The provided
// id must be a string for username lookup or a uint for id lookup. If id
// is neither, a ErrInvalidDataType will be returned.
func (s *Storage) Delete(id interface{}) error {
	switch id := id.(type) {
	case string:
		return s.back.DeleteByUsername(id)
	case uint:
		return s.back.DeleteByID(id)
	default:
		return errors.ErrInvalidDataType
	}
}

// LastUpdate gets the timestamp for the last update of an user.
func (s *Storage) LastUpdate(id uint) int64 {
	s.mux.RLock()
	defer s.mux.RUnlock()
	if val, ok := s.updated[id]; ok {
		return val
	}
	return 0
}
