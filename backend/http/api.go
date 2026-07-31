package http

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

// createApiTokenHandler creates an API token for the user.
// @Summary Create API Token
// @Description Create an API token with specified name, duration, and permissions.
// @Tags Auth
// @Accept json
// @Produce json
// @Param name query string true "Name of the API token"
// @Param days query string true "Duration of the API token in days"
// @Param permissions query string true "Permissions for the API token (comma-separated)"
// @Param minimal query bool false "Create a stateful token that uses current user permissions"
// @Success 200 {object} HttpResponse "Token created successfully, response contains json object with token"
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 404 {object} map[string]string "Not found"
// @Failure 409 {object} map[string]string "Conflict"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/auth/token [post]
func createApiTokenHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	name := r.URL.Query().Get("name")
	durationStr := r.URL.Query().Get("days")
	permissionsStr := r.URL.Query().Get("permissions")
	minimal := permissionsStr == ""
	if minimalStr := r.URL.Query().Get("minimal"); minimalStr != "" {
		parsedMinimal, err := strconv.ParseBool(minimalStr)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid minimal value: %w", err)
		}
		minimal = parsedMinimal
	}

	if !d.user.Permissions.Api {
		return http.StatusForbidden, fmt.Errorf("user does not have permission to create api tokens")
	}
	if d.apiToken {
		return http.StatusForbidden, fmt.Errorf("api tokens cannot create other tokens")
	}

	if name == "" || strings.HasPrefix(name, "WEB_TOKEN") {
		return http.StatusBadRequest, fmt.Errorf("api token name must be valid")
	}
	if durationStr == "" {
		return http.StatusBadRequest, fmt.Errorf("api token duration must be valid")
	}

	// For full tokens (minimal=false), permissions are required in the claim
	// For minimal tokens (minimal=true), permissions are not in the token
	var permissions users.Permissions
	if !minimal {
		permissionNames := parsePermissionNames(permissionsStr)
		requested := users.Permissions{
			Api:      permissionNames["api"],
			Admin:    permissionNames["admin"],
			Modify:   permissionNames["modify"],
			Delete:   permissionNames["delete"],
			Create:   permissionNames["create"],
			Share:    permissionNames["share"],
			Realtime: permissionNames["realtime"],
			Browse:   permissionNames["browse"],
			Preview:  permissionNames["preview"],
			Download: permissionNames["download"],
		}
		permissions = users.IntersectPermissions(d.user.Permissions, requested)
	}

	// Convert the duration string to an int64
	durationInt, err := strconv.ParseInt(durationStr, 10, 64) // Base 10 and bit size of 64
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("invalid duration value: %w", err)
	}

	// Here we assume the duration is in seconds; convert to time.Duration
	duration := time.Duration(durationInt) * time.Hour * 24
	tokenString, authToken, err := auth.MakeSignedTokenAPI(d.user, name, duration, permissions, minimal)
	if err != nil {
		if strings.Contains(err.Error(), "key already exists with same name") {
			return http.StatusConflict, err
		}
		return http.StatusInternalServerError, err
	}

	// Store API token metadata in user's Tokens map
	err = store.Users.AddApiToken(d.user.ID, name, tokenString, authToken)
	if err != nil {
		if errors.Is(err, users.ErrAPIPermissionRequired) {
			return http.StatusForbidden, err
		}
		if strings.Contains(err.Error(), "key already exists with same name") {
			return http.StatusConflict, err
		}
		return http.StatusInternalServerError, err
	}

	// Store token hash → user ID mapping in access storage for fast lookups
	err = store.Access.AddApiToken(tokenString, d.user.ID)
	if err != nil {
		if rollbackErr := store.Users.DeleteApiToken(d.user.ID, name); rollbackErr != nil {
			return http.StatusInternalServerError, fmt.Errorf("store api token mapping: %w (metadata rollback failed: %v)", err, rollbackErr)
		}
		return http.StatusInternalServerError, err
	}

	response := HttpResponse{
		Message: "here is your token!",
		Token:   tokenString,
	}
	w.Header().Set("Cache-Control", "no-store")
	return renderJSON(w, r, response)
}

func parsePermissionNames(value string) map[string]bool {
	permissions := make(map[string]bool)
	for _, name := range strings.Split(value, ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			permissions[name] = true
		}
	}
	return permissions
}

// deleteApiTokenHandler deletes an API token for the user.
// @Summary Delete API token
// @Description Delete an API token with specified name.
// @Tags Auth
// @Accept json
// @Produce json
// @Param name query string true "Name of the API token to delete"
// @Success 200 {object} HttpResponse "API token deleted successfully"
// @Failure 404 {object} map[string]string "Not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/auth/token [delete]
func deleteApiTokenHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	name := r.URL.Query().Get("name")
	if !d.user.Permissions.Api {
		return http.StatusForbidden, fmt.Errorf("user does not have permission to delete api tokens")
	}

	tokenHashes, err := store.Users.ApiTokenHashes(d.user.ID, name)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("load api token metadata: %w", err)
	}
	if len(tokenHashes) == 0 {
		return http.StatusNotFound, fmt.Errorf("api token not found")
	}

	for _, tokenHash := range tokenHashes {
		revokeErr := auth.RevokeApiTokenHash(store.Access, tokenHash)
		if revokeErr != nil {
			return http.StatusInternalServerError, fmt.Errorf("revoke api token: %w", revokeErr)
		}
	}

	deleted, err := store.Users.DeleteApiTokens(d.user.ID, name)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("delete revoked api token metadata: %w", err)
	}
	if !deleted {
		return http.StatusNotFound, fmt.Errorf("api token metadata changed during deletion")
	}

	response := HttpResponse{
		Message: "successfully deleted api token from user",
	}
	return renderJSON(w, r, response)
}

type AuthTokenFrontend struct {
	ID                 string            `json:"id"`
	Name               string            `json:"name"`
	Type               string            `json:"type"`
	Fingerprint        string            `json:"fingerprint"`
	TokenPrefix        string            `json:"tokenPrefix"`
	IssuedAt           int64             `json:"issuedAt"`
	ExpiresAt          int64             `json:"expiresAt"`
	PermissionsVersion int               `json:"permissionsVersion,omitempty"`
	Permissions        users.Permissions `json:"Permissions,omitempty"`
}

func authTokenFrontendType(token users.AuthToken) string {
	if token.TokenHash != "" {
		if token.Permissions == (users.Permissions{}) {
			return "minimal"
		}
		return "full"
	}
	switch {
	case token.BelongsTo == 0:
		return "minimal"
	case token.Name != "" && token.PermissionsVersion == users.CurrentPermissionsVersion:
		return "full"
	default:
		return "legacy"
	}
}

func authTokenFrontend(name string, token users.AuthToken, current users.Permissions) AuthTokenFrontend {
	digest := authTokenHash(token)
	fingerprint := digest
	if len(fingerprint) > 16 {
		fingerprint = fingerprint[:16]
	}
	tokenType := authTokenFrontendType(token)
	permissions := token.Permissions
	if tokenType == "minimal" {
		permissions = current
	}
	return AuthTokenFrontend{
		ID:                 digest,
		Name:               name,
		Type:               tokenType,
		Fingerprint:        "sha256:" + fingerprint,
		TokenPrefix:        token.TokenPrefix,
		IssuedAt:           authTokenIssuedUnix(token),
		ExpiresAt:          authTokenExpiresUnix(token),
		PermissionsVersion: token.PermissionsVersion,
		Permissions:        permissions,
	}
}

func authTokenHash(token users.AuthToken) string {
	hashes := token.TokenHashes()
	if len(hashes) == 0 {
		return ""
	}
	return hashes[0]
}

// authTokenIssuedUnix returns iat from JWT claims when set, otherwise the persisted int64 (e.g. loaded from DB).
func authTokenIssuedUnix(t users.AuthToken) int64 {
	if t.RegisteredClaims.IssuedAt != nil {
		return t.RegisteredClaims.IssuedAt.Unix()
	}
	return t.IssuedAt
}

// authTokenExpiresUnix returns exp from JWT claims when set, otherwise the persisted int64.
func authTokenExpiresUnix(t users.AuthToken) int64 {
	if t.RegisteredClaims.ExpiresAt != nil {
		return t.RegisteredClaims.ExpiresAt.Unix()
	}
	return t.ExpiresAt
}

// listApiTokensHandler lists all API tokens or retrieves details for a specific token.
// @Summary List API tokens
// @Description List all API tokens or retrieve details for a specific token.
// @Tags Auth
// @Accept json
// @Produce json
// @Success 200 {array} AuthTokenFrontend "List of API tokens"
// @Failure 404 {object} map[string]string "Not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/auth/token/list [get]
func listApiTokensHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if !d.user.Permissions.Api {
		return http.StatusForbidden, fmt.Errorf("user does not have permission to list api tokens")
	}
	if len(d.user.Tokens) == 0 && len(d.user.ApiKeys) == 0 {
		return http.StatusNotFound, fmt.Errorf("no api tokens found")
	}
	AuthTokensFrontend := make([]AuthTokenFrontend, 0, len(d.user.Tokens)+len(d.user.ApiKeys))
	seen := make(map[string]struct{}, len(d.user.Tokens)+len(d.user.ApiKeys))
	for _, tokens := range []map[string]users.AuthToken{d.user.Tokens, d.user.ApiKeys} {
		for name, token := range tokens {
			entry := authTokenFrontend(name, token, d.user.Permissions)
			if _, duplicate := seen[entry.ID]; duplicate {
				continue
			}
			seen[entry.ID] = struct{}{}
			AuthTokensFrontend = append(AuthTokensFrontend, entry)
		}
	}

	sort.Slice(AuthTokensFrontend, func(i, j int) bool {
		return AuthTokensFrontend[i].Name < AuthTokensFrontend[j].Name
	})

	return renderJSON(w, r, AuthTokensFrontend)
}

// getApiTokenHandler gets a specific API token.
// @Summary Get API token
// @Description Get a specific API token.
// @Tags Auth
// @Accept json
// @Produce json
// @Param name query string true "Name of the API token to retrieve"
// @Success 200 {object} AuthTokenFrontend "API token details"
// @Failure 404 {object} map[string]string "Not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/auth/token [get]
func getApiTokenHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	name := r.URL.Query().Get("name")
	if !d.user.Permissions.Api {
		return http.StatusForbidden, fmt.Errorf("user does not have permission to list api tokens")
	}
	tokenInfo, ok := d.user.Tokens[name]
	if !ok {
		tokenInfo, ok = d.user.ApiKeys[name]
		if !ok {
			return http.StatusNotFound, fmt.Errorf("api token not found")
		}
	}
	AuthTokenFrontendResponse := authTokenFrontend(name, tokenInfo, d.user.Permissions)
	return renderJSON(w, r, AuthTokenFrontendResponse)
}
