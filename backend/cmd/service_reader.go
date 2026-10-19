package cmd

// The operator-only CLI creates a new narrowly scoped account via normal user
// storage. It never signs tokens, alters existing accounts, or starts the server.
import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	commonerrors "github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/database/storage"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

var serviceReaderName = regexp.MustCompile(`^[a-z][a-z0-9-]{2,63}$`)

type serviceReaderOptions struct {
	Username, Source, Scope string
	PasswordStdin           bool
}

func readServiceReaderPassword(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, 4097))
	if err != nil {
		return nil, fmt.Errorf("password input unavailable")
	}
	data = bytes.TrimSuffix(data, []byte("\n"))
	data = bytes.TrimSuffix(data, []byte("\r"))
	if len(data) < 32 || len(data) > 256 {
		clear(data)
		return nil, fmt.Errorf("password stdin must contain 32 to 256 bytes")
	}
	for _, value := range data {
		if value < 33 || value > 126 {
			clear(data)
			return nil, fmt.Errorf("password stdin must be one printable non-space ASCII line")
		}
	}
	return data, nil
}
func serviceReaderDefinition(options serviceReaderOptions, password []byte) (users.User, error) {
	var result users.User
	if !options.PasswordStdin || !serviceReaderName.MatchString(options.Username) || options.Username == "anonymous" {
		return result, fmt.Errorf("new reader username and --password-stdin required")
	}
	if options.Source == "" || options.Scope == "" || options.Scope == "/" || !strings.HasPrefix(options.Scope, "/") || path.Clean(options.Scope) != options.Scope || strings.ContainsAny(options.Scope, "\\\x00\r\n") {
		return result, fmt.Errorf("explicit non-root canonical source scope required")
	}
	for _, r := range options.Scope {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return result, fmt.Errorf("invalid service scope")
		}
	}
	source, ok := settings.Config.Server.NameToSource[options.Source]
	if !ok || source == nil {
		return result, fmt.Errorf("source unavailable")
	}
	sourceRoot, err := filepath.EvalSymlinks(source.Path)
	if err != nil {
		return result, fmt.Errorf("source unavailable")
	}
	selected, err := filepath.EvalSymlinks(filepath.Join(sourceRoot, filepath.FromSlash(strings.TrimPrefix(options.Scope, "/"))))
	if err != nil {
		return result, fmt.Errorf("scope must already exist")
	}
	relative, err := filepath.Rel(sourceRoot, selected)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return result, fmt.Errorf("scope outside source")
	}
	info, err := os.Stat(selected)
	if err != nil || !info.IsDir() {
		return result, fmt.Errorf("scope must be an existing directory")
	}
	result = users.User{Username: options.Username, LoginMethod: users.LoginMethodPassword, ServiceScopeLocked: true,
		Scopes:           []users.SourceScope{{Name: source.Path, Scope: options.Scope}},
		NonAdminEditable: users.NonAdminEditable{Password: string(password)},
		Permissions:      users.Permissions{Api: true, Browse: true, Download: true}}
	return result, nil
}
func persistNewServiceReader(user users.User, get func(any) (*users.User, error), create func(users.User, users.Permissions) error) error {
	_, err := get(user.Username)
	if err == nil {
		return fmt.Errorf("reader already exists; no changes made")
	}
	if !errors.Is(err, commonerrors.ErrNotExist) {
		return fmt.Errorf("reader existence could not be verified")
	}
	if err = create(user, user.Permissions); err != nil {
		return fmt.Errorf("service reader creation did not complete; inspect before retry")
	}
	stored, err := get(user.Username)
	if err != nil || !stored.ServiceScopeLocked || stored.Permissions != user.Permissions || len(stored.Scopes) != 1 || stored.Scopes[0] != user.Scopes[0] {
		return fmt.Errorf("reader created but verification failed; inspect before retry")
	}
	return nil
}
func runServiceReaderCLI(configFile string, options serviceReaderOptions, input io.Reader, output io.Writer) error {
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
	user, err := serviceReaderDefinition(options, password)
	if err != nil {
		return err
	}
	loaded, existed, err := storage.InitializeDb(settings.Config.Server.Database)
	if err != nil || !existed {
		return fmt.Errorf("existing database unavailable")
	}
	if err = persistNewServiceReader(user, loaded.Users.Get, storage.CreateUser); err != nil {
		return err
	}
	// The process exits after this subcommand. It must never share an open DB with
	// a running service; the deployment runner enforces stop/backup/restart.
	return json.NewEncoder(output).Encode(map[string]any{"schema": "cf-service-reader/v1", "created": true, "username": user.Username, "source": options.Source, "scope": options.Scope, "scope_locked": true, "permissions": user.Permissions})
}
