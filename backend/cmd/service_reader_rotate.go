package cmd

// Password rotation is an operator-only continuation of a previously created
// locked reader. It cannot create an account, change its scope or repair an
// unknown state. Invoke only against an exclusively stopped, backed-up store.
import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"

	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/storage"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func rotateServiceReaderPassword(expected users.User, password []byte, get func(any) (*users.User, error), save func(*users.User, bool, bool) error) (uint, error) {
	stored, err := get(expected.Username)
	if err != nil || stored == nil {
		return 0, fmt.Errorf("existing reader unavailable; no changes made")
	}
	if stored.ID == 0 || stored.Username != expected.Username || !stored.ServiceScopeLocked || stored.LoginMethod != users.LoginMethodPassword || stored.LockPassword || stored.Permissions != expected.Permissions || !reflect.DeepEqual(stored.Scopes, expected.Scopes) {
		return 0, fmt.Errorf("existing reader identity, permissions or scope differ; no changes made")
	}
	before := *stored
	beforeJSON, err := json.Marshal(before)
	if err != nil {
		return 0, fmt.Errorf("existing reader metadata unavailable")
	}
	updated := *stored
	updated.Password = string(password)
	if err = save(&updated, true, true); err != nil {
		return 0, fmt.Errorf("reader password rotation did not complete; inspect before retry")
	}
	actual, err := get(expected.Username)
	if err != nil || actual == nil || utils.CheckPwd(string(password), actual.Password) != nil {
		return 0, fmt.Errorf("reader password changed but verification failed; inspect before retry")
	}
	restored := *actual
	restored.Password = before.Password
	afterJSON, err := json.Marshal(restored)
	if err != nil || !bytes.Equal(beforeJSON, afterJSON) || !reflect.DeepEqual(before, restored) {
		return 0, fmt.Errorf("reader metadata changed during rotation; inspect before retry")
	}
	return actual.ID, nil
}

func runServiceReaderRotateCLI(configFile string, options serviceReaderOptions, input io.Reader, output io.Writer) error {
	if !options.PasswordStdin {
		return fmt.Errorf("--password-stdin is required")
	}
	password, err := readServiceReaderPassword(input)
	if err != nil {
		return err
	}
	defer clear(password)
	settings.Initialize(configFile)
	info, err := os.Lstat(settings.Config.Server.Database)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return fmt.Errorf("existing regular database required; stop the service and verify backup first")
	}
	expected, err := serviceReaderDefinition(options, password)
	if err != nil {
		return err
	}
	loaded, existed, err := storage.InitializeDb(settings.Config.Server.Database)
	if err != nil || !existed {
		return fmt.Errorf("existing database unavailable")
	}
	id, err := rotateServiceReaderPassword(expected, password, loaded.Users.Get, loaded.Users.Save)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(map[string]any{"schema": "cf-service-reader-password-rotation/v1", "rotated": true, "created": false, "account_id": id, "username": options.Username, "source": options.Source, "scope": options.Scope, "scope_locked": true, "other_fields_unchanged": true, "password_saved": false})
}
