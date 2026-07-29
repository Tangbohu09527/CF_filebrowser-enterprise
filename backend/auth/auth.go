package auth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/access"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

// Auther is the authentication interface.
type Auther interface {
	// Auth is called to authenticate a request.
	Auth(r *http.Request, userStore *users.Storage) (*users.User, error)
}

const FB_ISSUER = "FileBrowser Quantum" // don't change

const (
	TokenTypeHeader  = "fb_token_type"
	TokenNonceHeader = "fb_nonce"
	TokenTypeWeb     = "web"
	TokenTypeAPI     = "api"
)

// IsRevokedApiToken checks if a token is in the revoked list.
func IsRevokedApiToken(accessStore *access.Storage, token string) bool {
	if accessStore == nil {
		return true
	}
	return accessStore.IsTokenRevoked(token)
}

// RevokeApiToken adds a token to the revoked list.
func RevokeApiToken(accessStore *access.Storage, token string) error {
	if accessStore == nil {
		return fmt.Errorf("access storage not available")
	}
	return accessStore.RevokeToken(token)
}

// RevokeApiTokenHash revokes an API token without requiring its bearer secret.
func RevokeApiTokenHash(accessStore *access.Storage, tokenHash string) error {
	if accessStore == nil {
		return fmt.Errorf("access storage not available")
	}
	return accessStore.RevokeTokenHash(tokenHash)
}

func MakeSignedTokenAPI(user *users.User, name string, duration time.Duration, perms users.Permissions, minimal bool) (string, users.AuthToken, error) {
	if _, ok := user.Tokens[name]; ok {
		return "", users.AuthToken{}, fmt.Errorf("key already exists with same name %v ", name)
	}
	now := time.Now()
	expires := now.Add(duration)
	// Create minimal token with only JWT standard claims
	claim := users.AuthToken{
		MinimalAuthToken: users.MinimalAuthToken{
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(expires),
				Issuer:    FB_ISSUER,
			},
		},
	}
	if !minimal {
		claim.Permissions = perms
		claim.BelongsTo = user.ID
		if !strings.HasPrefix(name, "WEB_TOKEN") {
			claim.PermissionsVersion = users.CurrentPermissionsVersion
			claim.Name = name
		}
	}
	tokenType := TokenTypeAPI
	if !minimal && strings.HasPrefix(name, "WEB_TOKEN") {
		tokenType = TokenTypeWeb
	}
	nonce, err := utils.RandomHex(16)
	if err != nil {
		return "", users.AuthToken{}, fmt.Errorf("generate token nonce: %w", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	token.Header[TokenTypeHeader] = tokenType
	token.Header[TokenNonceHeader] = nonce
	tokenString, err := token.SignedString([]byte(settings.Config.Auth.Key))
	if err != nil {
		return "", users.AuthToken{}, err
	}
	return tokenString, claim, nil

}
