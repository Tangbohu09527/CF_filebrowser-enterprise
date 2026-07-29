package cmd

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/fileutils"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/go-logger/logger"
)

var createBackup = false

func validateUserInfo(newDB bool) {
	// update source info for users if names/sources/paths might have changed
	usersList, err := store.Users.Gets()
	if err != nil {
		logger.Fatalf("could not load users: %v", err)
	}
	for _, user := range usersList {
		changePass := false
		updateUser := false
		if updateUserScopes(user) {
			updateUser = true
		}
		if migrateUser(user) {
			updateUser = true
		}
		if updatePreviewSettings(user) {
			updateUser = true
		}
		if updateLoginType(user) {
			updateUser = true
		}
		if updateShowFirstLogin(user) {
			updateUser = true
		}
		if updateSidebarLinks(user) {
			updateUser = true
		}
		adminUser := settings.Config.Auth.AdminUsername
		adminPass := settings.Config.Auth.AdminPassword
		if user.Username == adminUser && adminPass != "" && user.LoginMethod == users.LoginMethodPassword {
			logger.Info("Resetting admin user to default username and password.")
			user.Permissions.Admin = true
			user.Password = settings.Config.Auth.AdminPassword
			updateUser = true
			changePass = true
		}
		if updateUser {
			skipCreateBackup := os.Getenv("FILEBROWSER_DISABLE_AUTOMATIC_BACKUP") == "true" || newDB
			if createBackup && !skipCreateBackup {
				logger.Warning("Incompatible user settings detected, creating backup of database before converting.")
				err = fileutils.CopyFile(settings.Config.Server.Database, fmt.Sprintf("%s.bak", settings.Config.Server.Database))
				if err != nil {
					logger.Fatalf("Unable to create automatic backup of database due to error: %v", err)
				}
			}
			fields := []string{"Scopes", "SidebarLinks", "Tokens", "ApiKeys", "Permissions", "Preview", "ShowFirstLogin", "LoginMethod", "ShowToolsInSidebar", "Version"}
			if changePass {
				fields = append(fields, "Password")
			}
			err := store.Users.Update(user, true, fields...)
			if err != nil {
				logger.Errorf("could not update user: %v", err)
			}
		}
	}
}

func updateUserScopes(user *users.User) bool {
	newScopes := []users.SourceScope{}
	seen := make(map[string]struct{})

	// Build map of existing scopes keyed by canonical source path (DB may use path or display name).
	existing := make(map[string]users.SourceScope)
	for _, s := range user.Scopes {
		if info, ok := users.ResolveSourceKey(s.Name); ok {
			existing[info.Path] = s
		}
	}

	// Preserve order by using Config.Server.Sources
	for _, src := range settings.Config.Server.Sources {
		existingScope, ok := existing[src.Path]
		if ok {
			// If scope is empty and there's a default, apply default
			if existingScope.Scope == "" {
				existingScope.Scope = src.Config.DefaultUserScope
			}
		} else if src.Config.DefaultEnabled {
			existingScope.Scope = src.Config.DefaultUserScope
		} else {
			continue
		}
		newScopes = append(newScopes, users.SourceScope{
			Name:  src.Path,
			Scope: existingScope.Scope,
		})
		seen[src.Path] = struct{}{}
	}

	// Preserve explicit or legacy scopes not already merged (e.g. non-defaultEnabled sources, removed sources).
	for _, s := range user.Scopes {
		if info, ok := users.ResolveSourceKey(s.Name); ok {
			if _, already := seen[info.Path]; already {
				continue
			}
		}
		newScopes = append(newScopes, s)
	}
	changed := !reflect.DeepEqual(user.Scopes, newScopes)
	user.Scopes = newScopes
	return changed
}

// updateShowToolsInSidebar applies the v2-to-v3 sidebar default.
func updateShowToolsInSidebar(user *users.User) bool {
	if user.Version >= 3 {
		return false
	}
	user.ShowToolsInSidebar = true
	user.Version = 3
	return true
}

func updateReadPermissions(user *users.User) bool {
	if user.Version >= 4 {
		return false
	}
	user.Permissions = users.NormalizeLegacyPermissions(user.Permissions)
	user.Version = 4
	return true
}

func migrateUser(user *users.User) bool {
	updated := false
	for user.Version < users.CurrentUserMigrationVersion {
		previousVersion := user.Version
		switch {
		case user.Version < 1:
			updatePermissions(user)
		case user.Version < 2:
			updateTokens(user)
		case user.Version < 3:
			updateShowToolsInSidebar(user)
		case user.Version < 4:
			updateReadPermissions(user)
		case user.Version < 5:
			updateTokenHashes(user)
		}
		if user.Version == previousVersion {
			break
		}
		updated = true
	}
	return updated
}

func updateShowFirstLogin(user *users.User) bool {
	if user.ShowFirstLogin && !settings.Env.IsFirstLoad {
		user.ShowFirstLogin = false
		return true
	}
	return false
}

// func to convert legacy user with perm key to permissions
func updatePermissions(user *users.User) bool {
	if user.Version >= 1 {
		return false
	}
	user.Permissions.Api = user.Permissions.Api || user.Perm.Api
	user.Permissions.Admin = user.Permissions.Admin || user.Perm.Admin
	user.Permissions.Modify = user.Permissions.Modify || user.Perm.Modify
	user.Permissions.Share = user.Permissions.Share || user.Perm.Share
	user.Permissions.Realtime = user.Permissions.Realtime || user.Perm.Realtime
	user.Permissions.Delete = user.Permissions.Delete || user.Perm.Delete
	user.Permissions.Create = user.Permissions.Create || user.Perm.Create
	user.Permissions.Download = user.Permissions.Download || user.Perm.Download
	user.Perm = users.Permissions{}
	if user.Permissions.Modify {
		user.Permissions.Create = true
		user.Permissions.Delete = true
	}
	user.Version = 1
	createBackup = true
	return true
}

func updateLoginType(user *users.User) bool {
	if user.LoginMethod == "" {
		user.LoginMethod = users.LoginMethodPassword
		return true
	}
	return false
}

func updatePreviewSettings(user *users.User) bool {
	// if user hasn't been updated yet
	if user.LoginMethod == "" {
		user.Preview.Image = true
		user.Preview.PopUp = true
		return true
	}
	return false
}

// updateSidebarLinks checks if user has stale source links and rebuilds them if needed
func updateSidebarLinks(user *users.User) bool {
	// Count source links and check if any are still valid
	sourceLinksCount := 0
	validSourceLinksCount := 0

	for _, link := range user.SidebarLinks {
		if strings.HasPrefix(link.Category, "source") {
			sourceLinksCount++
			if link.SourceName == "" {
				continue
			}
			if _, ok := users.ResolveSourceKey(link.SourceName); ok {
				validSourceLinksCount++
			}
		}
	}

	// If user has no source links, don't update anything
	if sourceLinksCount == 0 {
		return false
	}

	// If user has source links but NONE are valid, rebuild from their scopes
	if validSourceLinksCount == 0 {
		// Remove all existing source links
		newLinks := []users.SidebarLink{}
		for _, link := range user.SidebarLinks {
			if !strings.HasPrefix(link.Category, "source") {
				newLinks = append(newLinks, link)
			}
		}

		for _, scope := range user.Scopes {
			info, ok := users.ResolveSourceKey(scope.Name)
			if !ok {
				continue
			}
			newLinks = append(newLinks, users.SidebarLink{
				Name:       info.Name,
				Category:   "source",
				Target:     "/",
				Icon:       "",
				SourceName: info.Path,
			})
		}

		user.SidebarLinks = newLinks
		return true
	}

	return false
}

func updateTokens(user *users.User) bool {
	if user.Version >= 2 {
		return false
	}
	if user.ApiKeys != nil {
		if user.Tokens == nil {
			user.Tokens = make(map[string]users.AuthToken)
		}
		for name, token := range user.ApiKeys {
			if _, exists := user.Tokens[name]; exists {
				continue
			}
			if token.Token == "" {
				token.Token = token.Key
			}
			user.Tokens[name] = token
		}
	}
	user.Version = 2
	return true
}

func updateTokenHashes(user *users.User) bool {
	if user.Version >= 5 {
		return false
	}
	migrateTokenMap := func(tokens map[string]users.AuthToken) {
		for name, token := range tokens {
			secret := token.Token
			if secret == "" {
				secret = token.Key
			}
			if token.TokenHash == "" && secret == "" {
				continue
			}

			tokenHash := token.TokenHash
			tokenPrefix := token.TokenPrefix
			if secret != "" {
				if tokenHash == "" {
					tokenHash = utils.HashSHA256(secret)
				}
				if tokenPrefix == "" {
					tokenPrefix = secret
					if len(tokenPrefix) > 8 {
						tokenPrefix = tokenPrefix[:8]
					}
				}
			}

			issuedAt := token.IssuedAt
			if token.RegisteredClaims.IssuedAt != nil {
				issuedAt = token.RegisteredClaims.IssuedAt.Unix()
			}
			expiresAt := token.ExpiresAt
			if token.RegisteredClaims.ExpiresAt != nil {
				expiresAt = token.RegisteredClaims.ExpiresAt.Unix()
			}
			tokens[name] = users.AuthToken{
				TokenHash:   tokenHash,
				TokenPrefix: tokenPrefix,
				IssuedAt:    issuedAt,
				ExpiresAt:   expiresAt,
				Permissions: token.Permissions,
			}
		}
	}

	migrateTokenMap(user.Tokens)
	migrateTokenMap(user.ApiKeys)
	user.Version = 5
	return true
}
