package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	storm "github.com/asdine/storm/v3"
	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/fileutils"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/storage/bolt"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/go-logger/logger"
)

var userStore *users.Storage

func InitializeDb(path string) (*bolt.BoltStore, bool, error) {
	logger.Debugf("Initializing database: %v", path)
	exists, err := dbExists(path)
	if err != nil {
		panic(err)
	}
	if !exists && !utf8.ValidString(settings.Config.Auth.Key) {
		return nil, false, errors.New("configured JWT signing key cannot be persisted losslessly")
	}
	db, err := storm.Open(path)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			logger.Fatal("the database is locked, please close all other instances of filebrowser before starting.")
		}
		logger.Fatalf("could not open database: %v", err)
	}
	// Validate the signing key before NewStorage initializes authentication records
	// or any version/settings write can alter an existing database.
	if err = restoreSigningKey(db, exists); err != nil {
		_ = db.Close()
		return nil, exists, err
	}
	store, err := bolt.NewStorage(db)
	if err != nil {
		_ = db.Close()
		return nil, exists, err
	}
	// Load access rules from DB on startup
	// ignoring errors because
	_ = store.Access.LoadFromDB()
	// Load share cache from DB so shareByHash/shareByPath are populated at startup
	store.Share.LoadShareCacheFromDB()
	userStore = store.Users
	err = bolt.Save(db, "version", 2)
	if err != nil {
		_ = db.Close()
		return nil, exists, err
	}
	if !exists {
		if settings.Env.IsPlaywright || settings.Env.IsDevMode {
			settings.Env.IsFirstLoad = false
		} else {
			settings.Env.IsFirstLoad = true
		}
		quickSetup(store)
	}

	return store, exists, err
}

func restoreSigningKey(db *storm.DB, exists bool) error {
	if !exists {
		return nil
	}
	persisted, err := bolt.ReadSettings(db)
	if err != nil {
		return errors.New("could not read persisted JWT signing key from existing database")
	}
	configured := settings.Config.Auth.Key
	if persisted.Auth.Key == "" {
		if configured == "" {
			return errors.New("existing database has no JWT signing key; restore an explicit trusted key before startup")
		}
		// An explicit trusted recovery key is runtime-only. Never rewrite the
		// old settings or silently invent a replacement credential.
		return nil
	}
	if configured != "" && configured != persisted.Auth.Key {
		return errors.New("configured JWT signing key conflicts with existing database; restore the matching key before startup")
	}
	// File/environment configuration remains authoritative for every other field.
	// Nonempty legacy values are restored verbatim, without format conversion.
	settings.Config.Auth.Key = persisted.Auth.Key
	return nil
}

func dbExists(path string) (bool, error) {
	stat, err := os.Stat(path)
	if err == nil {
		return stat.Size() != 0, nil
	}

	if os.IsNotExist(err) {
		d := filepath.Dir(path)
		_, err = os.Stat(d)
		if os.IsNotExist(err) {
			if err = os.MkdirAll(d, fileutils.PermDir); err != nil {
				return false, err
			}
			return false, nil
		}
	}

	return false, err
}

func quickSetup(store *bolt.BoltStore) {
	if settings.Config.Auth.Key == "" {
		// Preserve the original 512 bits of entropy as lossless JSON/YAML text.
		key, err := utils.RandomHex(64)
		utils.CheckErr("generate JWT signing key", err)
		settings.Config.Auth.Key = key
	}
	err := store.Settings.Save(&settings.Config)
	utils.CheckErr("store.Settings.Save", err)
	err = store.Settings.SaveServer(&settings.Config.Server)
	utils.CheckErr("store.Settings.SaveServer", err)
	passwordAuth := settings.Config.Auth.Methods.PasswordAuth.Enabled
	noAuth := settings.Config.Auth.Methods.NoAuth
	if passwordAuth || noAuth {
		user := &users.User{}
		settings.ApplyUserDefaults(user)
		user.Username = settings.Config.Auth.AdminUsername
		if settings.Config.Auth.AdminPassword == "" {
			settings.Config.Auth.AdminPassword = "admin"
		}
		user.Password = settings.Config.Auth.AdminPassword
		user.LockPassword = false
		user.Permissions = settings.AdminPerms()
		user.ShowFirstLogin = settings.Env.IsFirstLoad && user.Permissions.Admin
		logger.Debugf("Creating user as admin: %v", user.Username)
		err = store.Users.Save(user, true, true)
		utils.CheckErr("store.Users.Save", err)
	}
}

// create new user
func CreateUser(userInfo users.User, permissions users.Permissions) error {
	newUser := &userInfo
	newUser.ShowFirstLogin = settings.Env.IsFirstLoad && newUser.Permissions.Admin
	if userInfo.LoginMethod == "password" {
		if userInfo.Password == "" {
			return fmt.Errorf("password is required to create a password login user")
		}
	} else {
		hashpass, err := utils.HashPwd(userInfo.Username)
		if err != nil {
			return err
		}
		userInfo.Password = hashpass
	}
	// must have username
	if userInfo.Username == "" {
		return fmt.Errorf("username is required to create a user")
	}
	settings.ApplyUserDefaults(newUser)
	newUser.Permissions = permissions
	newUser.Version = users.CurrentUserMigrationVersion
	logger.Debugf("Creating user: %v %v", userInfo.Username, userInfo.Scopes)
	// create new home directories
	err := userStore.Save(newUser, true, false)
	if err != nil {
		return err
	}
	return nil
}
