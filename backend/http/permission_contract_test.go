package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	storm "github.com/asdine/storm/v3"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/database/storage/bolt"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func TestCreateAPITokenPermissionsUseExactNames(t *testing.T) {
	setupPermissionContractHTTPTest(t)

	user := savePermissionContractUser(t, "exact-token-permissions", users.Permissions{
		Api:      true,
		Admin:    true,
		Modify:   true,
		Share:    true,
		Realtime: true,
		Delete:   true,
		Create:   true,
		Browse:   true,
		Preview:  true,
		Download: true,
	})

	_, stored := issuePermissionContractToken(
		t,
		user,
		"exact-token-permissions-token",
		"notapi,administrator,modify-extra,shareholder,realtime2,undelete,recreate,browse-all,preview-only,downloadable",
	)

	if stored.Permissions != (users.Permissions{}) {
		t.Fatalf("near-match permission names must not grant permissions: got %+v", stored.Permissions)
	}
}

func TestNewFullTokenStoresVersionedReadPermissionSnapshot(t *testing.T) {
	setupPermissionContractHTTPTest(t)

	user := savePermissionContractUser(t, "versioned-full-token", users.Permissions{
		Api:      true,
		Browse:   true,
		Preview:  true,
		Download: true,
	})
	wantSnapshot := users.Permissions{
		Browse:   true,
		Preview:  true,
		Download: true,
	}

	tokenString, stored := issuePermissionContractToken(
		t,
		user,
		"versioned-full-token-snapshot",
		"browse,preview,download",
	)

	if stored.Permissions != wantSnapshot {
		t.Fatalf("persisted full token permissions: got %+v, want %+v", stored.Permissions, wantSnapshot)
	}
	if stored.TokenHash == "" || stored.Token != "" || stored.Key != "" {
		t.Fatalf("persisted full token is not hash-only: %+v", stored)
	}

	var claim users.AuthToken
	parsed, err := jwt.ParseWithClaims(tokenString, &claim, func(*jwt.Token) (interface{}, error) {
		return []byte(settings.Config.Auth.Key), nil
	})
	if err != nil {
		t.Fatalf("parse full token claim: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("new full token claim is invalid")
	}
	if claim.PermissionsVersion != users.CurrentPermissionsVersion {
		t.Fatalf("claim permissions version: got %d, want %d", claim.PermissionsVersion, users.CurrentPermissionsVersion)
	}
	if claim.Name != "versioned-full-token-snapshot" {
		t.Fatalf("full token generation marker: claim=%q", claim.Name)
	}
	if claim.Permissions != wantSnapshot {
		t.Fatalf("full token claim permissions: got %+v, want %+v", claim.Permissions, wantSnapshot)
	}
	if effective := authenticatePermissionContractToken(t, tokenString); effective != wantSnapshot {
		t.Fatalf("full token effective permissions: got %+v, want %+v", effective, wantSnapshot)
	}
}

func TestNewFullTokenInvalidPermissionsVersionFailsClosed(t *testing.T) {
	setupPermissionContractHTTPTest(t)

	user := savePermissionContractUser(t, "invalid-version-full-token", users.Permissions{
		Api:      true,
		Admin:    true,
		Modify:   true,
		Share:    true,
		Realtime: true,
		Delete:   true,
		Create:   true,
		Browse:   true,
		Preview:  true,
		Download: true,
	})
	granted := user.Permissions
	tests := []struct {
		name            string
		claimName       string
		claimVersion    int
		metadataVersion int
	}{
		{name: "missing", claimName: "invalid-version-missing", claimVersion: 0, metadataVersion: users.CurrentPermissionsVersion},
		{name: "missing marker and version", claimName: "", claimVersion: 0, metadataVersion: users.CurrentPermissionsVersion},
		{name: "older", claimName: "invalid-version-older", claimVersion: users.CurrentPermissionsVersion - 1, metadataVersion: users.CurrentPermissionsVersion},
		{name: "future", claimName: "invalid-version-future", claimVersion: users.CurrentPermissionsVersion + 1, metadataVersion: users.CurrentPermissionsVersion},
		{name: "legacy metadata on new claim", claimName: "invalid-version-metadata", claimVersion: users.CurrentPermissionsVersion, metadataVersion: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			storageName := "invalid-version-" + strings.ReplaceAll(tc.name, " ", "-")
			tokenString := storeFullTokenWithVersions(
				t,
				user,
				storageName,
				tc.claimName,
				tc.claimVersion,
				tc.metadataVersion,
				granted,
			)
			assertPermissionContractTokenRejected(t, tokenString)
		})
	}
}

func TestWebTokenKeepsLegacyClaimShape(t *testing.T) {
	setupPermissionContractHTTPTest(t)

	user := &users.User{
		ID:       42,
		Username: "web-token-user",
		Permissions: users.Permissions{
			Browse:   true,
			Preview:  true,
			Download: true,
		},
	}
	_, claim, err := auth.MakeSignedTokenAPI(user, "WEB_TOKEN_permission-contract", time.Hour, user.Permissions, false)
	if err != nil {
		t.Fatalf("create WEB_TOKEN: %v", err)
	}
	if claim.ID != "" {
		t.Fatalf("WEB_TOKEN jti changed: got %q, want empty", claim.ID)
	}
	if claim.Name != "" {
		t.Fatalf("WEB_TOKEN name claim changed: got %q, want empty", claim.Name)
	}
	if claim.PermissionsVersion != 0 {
		t.Fatalf("WEB_TOKEN permissionsVersion changed: got %d, want 0", claim.PermissionsVersion)
	}
	if claim.BelongsTo != user.ID || claim.Permissions != user.Permissions {
		t.Fatalf("WEB_TOKEN legacy claims changed: got %+v", claim)
	}
}

func TestExplicitEmptyFullTokenKeepsEmptyPermissionSnapshot(t *testing.T) {
	setupPermissionContractHTTPTest(t)

	user := savePermissionContractUser(t, "empty-full-token", users.Permissions{
		Api:      true,
		Admin:    true,
		Modify:   true,
		Share:    true,
		Realtime: true,
		Delete:   true,
		Create:   true,
		Browse:   true,
		Preview:  true,
		Download: true,
	})
	tokenString, stored := issuePermissionContractTokenWithMode(t, user, "empty-full-token-snapshot", "", false)

	if stored.Permissions != (users.Permissions{}) {
		t.Fatalf("empty full token snapshot: got %+v, want no permissions", stored.Permissions)
	}
	var claim users.AuthToken
	parsed, err := jwt.ParseWithClaims(tokenString, &claim, func(*jwt.Token) (interface{}, error) {
		return []byte(settings.Config.Auth.Key), nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("parse empty full token claim: valid=%v err=%v", parsed != nil && parsed.Valid, err)
	}
	if claim.BelongsTo != user.ID || claim.PermissionsVersion != users.CurrentPermissionsVersion || claim.Name != "empty-full-token-snapshot" {
		t.Fatalf("empty full token signed identity is invalid: %+v", claim)
	}
	if effective := authenticatePermissionContractToken(t, tokenString); effective != (users.Permissions{}) {
		t.Fatalf("empty full token effective permissions: got %+v, want no permissions", effective)
	}
}

func TestLegacyFullTokenFailsClosedAndIntersectsReadPermissions(t *testing.T) {
	setupPermissionContractHTTPTest(t)

	tests := []struct {
		name           string
		current        users.Permissions
		legacyDownload bool
		wantBrowse     bool
		wantPreview    bool
		wantDownload   bool
	}{
		{
			name: "legacy grants are constrained by current user",
			current: users.Permissions{
				Api:      true,
				Browse:   false,
				Preview:  true,
				Download: false,
			},
			legacyDownload: true,
			wantBrowse:     false,
			wantPreview:    false,
			wantDownload:   false,
		},
		{
			name: "legacy download denial remains denied",
			current: users.Permissions{
				Api:      true,
				Browse:   true,
				Preview:  true,
				Download: true,
			},
			legacyDownload: false,
			wantBrowse:     false,
			wantPreview:    false,
			wantDownload:   false,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			user := savePermissionContractUser(t, "legacy-full-token-"+string(rune('a'+i)), tc.current)
			tokenString := storeLegacyFullToken(t, user, "legacy-full-token", tc.legacyDownload)

			effective := authenticatePermissionContractToken(t, tokenString)
			if effective.Browse != tc.wantBrowse {
				t.Errorf("effective browse: got %v, want %v", effective.Browse, tc.wantBrowse)
			}
			if effective.Preview != tc.wantPreview {
				t.Errorf("effective preview: got %v, want %v", effective.Preview, tc.wantPreview)
			}
			if effective.Download != tc.wantDownload {
				t.Errorf("effective download: got %v, want %v", effective.Download, tc.wantDownload)
			}
		})
	}
}

func TestMinimalTokenUsesCurrentUserPermissions(t *testing.T) {
	setupPermissionContractHTTPTest(t)

	user := savePermissionContractUser(t, "minimal-token-current-permissions", users.Permissions{
		Api:      true,
		Browse:   true,
		Preview:  false,
		Download: true,
	})
	tokenString, metadata := issuePermissionContractTokenWithMode(
		t,
		user,
		"minimal-token-current-permissions-token",
		"browse",
		true,
	)
	if metadata.BelongsTo != 0 || metadata.PermissionsVersion != 0 {
		t.Fatalf("minimal token stored full-token metadata: %+v", metadata)
	}

	current := users.Permissions{
		Api:      true,
		Browse:   false,
		Preview:  true,
		Download: false,
	}
	user.Permissions = current
	if err := store.Users.Update(user, true, "Permissions"); err != nil {
		t.Fatalf("update current user permissions: %v", err)
	}

	effective := authenticatePermissionContractToken(t, tokenString)
	if effective != current {
		t.Fatalf("minimal token permissions: got %+v, want current user permissions %+v", effective, current)
	}
}

func TestUserRequestPermissionPresence(t *testing.T) {
	tests := []struct {
		name                string
		body                string
		fallback            users.Permissions
		browsePresent       bool
		previewPresent      bool
		downloadPresent     bool
		applyCreateDefaults bool
		want                users.Permissions
	}{
		{
			name: "missing read permissions use defaults",
			body: `{"which":[],"data":{"permissions":{}}}`,
			fallback: users.Permissions{
				Browse:   true,
				Preview:  true,
				Download: true,
			},
			applyCreateDefaults: true,
			want: users.Permissions{
				Browse:   true,
				Preview:  true,
				Download: true,
			},
		},
		{
			name: "missing browse and preview use fallback",
			body: `{"which":["permissions"],"data":{"permissions":{"download":true}}}`,
			fallback: users.Permissions{
				Browse:  true,
				Preview: false,
			},
			downloadPresent: true,
			want: users.Permissions{
				Browse:   true,
				Preview:  false,
				Download: true,
			},
		},
		{
			name: "explicit false revokes browse and preview",
			body: `{"which":["permissions"],"data":{"permissions":{"browse":false,"preview":false,"download":true}}}`,
			fallback: users.Permissions{
				Browse:  true,
				Preview: true,
			},
			browsePresent:   true,
			previewPresent:  true,
			downloadPresent: true,
			want: users.Permissions{
				Browse:   false,
				Preview:  false,
				Download: true,
			},
		},
		{
			name: "presence is tracked independently per field",
			body: `{"which":["permissions"],"data":{"permissions":{"browse":false,"download":true}}}`,
			fallback: users.Permissions{
				Browse:  true,
				Preview: true,
			},
			browsePresent:   true,
			downloadPresent: true,
			want: users.Permissions{
				Browse:   false,
				Preview:  true,
				Download: true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var request UserRequest
			if err := json.Unmarshal([]byte(tc.body), &request); err != nil {
				t.Fatalf("decode UserRequest: %v", err)
			}

			if got := request.permissionPresence.Browse != nil; got != tc.browsePresent {
				t.Fatalf("browse presence: got %v, want %v", got, tc.browsePresent)
			}
			if request.permissionPresence.Browse != nil && *request.permissionPresence.Browse {
				t.Fatal("explicit browse value: got true, want false")
			}
			if got := request.permissionPresence.Preview != nil; got != tc.previewPresent {
				t.Fatalf("preview presence: got %v, want %v", got, tc.previewPresent)
			}
			if request.permissionPresence.Preview != nil && *request.permissionPresence.Preview {
				t.Fatal("explicit preview value: got true, want false")
			}
			if got := request.permissionPresence.Download != nil; got != tc.downloadPresent {
				t.Fatalf("download presence: got %v, want %v", got, tc.downloadPresent)
			}

			got := applyPermissionPresence(request.User.Permissions, tc.fallback, request.permissionPresence)
			if tc.applyCreateDefaults {
				got = applyNewUserPermissionDefaults(request.User.Permissions, tc.fallback, request.permissionPresence)
			}
			if got != tc.want {
				t.Fatalf("merged permissions: got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestUserPutPermissionPresenceContract(t *testing.T) {
	setupPermissionContractHTTPTest(t)

	tests := []struct {
		name    string
		initial users.Permissions
		body    string
		want    users.Permissions
	}{
		{
			name: "legacy client preserves omitted read permissions",
			initial: users.Permissions{
				Api:      true,
				Admin:    true,
				Modify:   true,
				Share:    true,
				Realtime: true,
				Delete:   true,
				Create:   true,
				Browse:   true,
				Preview:  false,
				Download: true,
			},
			body: `{"which":["permissions"],"data":{"permissions":{}}}`,
			want: users.Permissions{
				Browse:   true,
				Preview:  false,
				Download: false,
			},
		},
		{
			name: "explicit false revokes browse while omitted preview is preserved",
			initial: users.Permissions{
				Browse:   true,
				Preview:  true,
				Download: true,
			},
			body: `{"which":["permissions"],"data":{"permissions":{"browse":false,"download":true}}}`,
			want: users.Permissions{
				Browse:   false,
				Preview:  true,
				Download: true,
			},
		},
	}

	actor := &users.User{
		ID:          9999,
		LoginMethod: users.LoginMethodProxy,
		Permissions: users.Permissions{Admin: true},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target := savePermissionContractUser(t, "permission-presence-target-"+string(rune('a'+i)), tc.initial)
			request := httptest.NewRequest(
				http.MethodPut,
				"/api/users?id="+strconv.FormatUint(uint64(target.ID), 10),
				strings.NewReader(tc.body),
			)
			response := httptest.NewRecorder()

			status, err := userPutHandler(response, request, &requestContext{user: actor})
			if err != nil {
				t.Fatalf("update user permissions: %v", err)
			}
			if status != http.StatusNoContent {
				t.Fatalf("update user permissions status: got %d, want %d", status, http.StatusNoContent)
			}

			stored, err := store.Users.Get(target.ID)
			if err != nil {
				t.Fatalf("load updated user: %v", err)
			}
			if stored.Permissions != tc.want {
				t.Fatalf("stored permissions: got %+v, want %+v", stored.Permissions, tc.want)
			}
		})
	}
}

func setupPermissionContractHTTPTest(t *testing.T) {
	t.Helper()

	db, err := storm.Open(filepath.Join(t.TempDir(), "permission-contract.db"))
	if err != nil {
		t.Fatalf("open permission contract database: %v", err)
	}
	testStore, err := bolt.NewStorage(db)
	if err != nil {
		_ = db.Close()
		t.Fatalf("create permission contract storage: %v", err)
	}

	previousStore := store
	previousConfig := config
	previousAuth := settings.Config.Auth
	testAuth := settings.Auth{Key: "permission-contract-test-key"}
	store = testStore
	config = &settings.Settings{Auth: testAuth}
	settings.Config.Auth = testAuth

	t.Cleanup(func() {
		store = previousStore
		config = previousConfig
		settings.Config.Auth = previousAuth
		if err := db.Close(); err != nil {
			t.Errorf("close permission contract database: %v", err)
		}
	})
}

func savePermissionContractUser(t *testing.T, username string, permissions users.Permissions) *users.User {
	t.Helper()

	user := &users.User{
		Username:    username,
		Permissions: permissions,
	}
	if err := store.Users.Save(user, false, false); err != nil {
		t.Fatalf("save permission contract user: %v", err)
	}
	return user
}

func issuePermissionContractToken(t *testing.T, user *users.User, name, permissionNames string) (string, users.AuthToken) {
	t.Helper()
	return issuePermissionContractTokenRequest(t, user, name, permissionNames, nil)
}

func issuePermissionContractTokenWithMode(t *testing.T, user *users.User, name, permissionNames string, minimal bool) (string, users.AuthToken) {
	t.Helper()
	return issuePermissionContractTokenRequest(t, user, name, permissionNames, &minimal)
}

func issuePermissionContractTokenRequest(t *testing.T, user *users.User, name, permissionNames string, minimal *bool) (string, users.AuthToken) {
	t.Helper()

	query := url.Values{
		"name": {name},
		"days": {"1"},
	}
	if permissionNames != "" {
		query.Set("permissions", permissionNames)
	}
	if minimal != nil {
		query.Set("minimal", strconv.FormatBool(*minimal))
	}
	request := httptest.NewRequest(http.MethodPost, "/api/auth/token?"+query.Encode(), nil)
	response := httptest.NewRecorder()
	status, err := createApiTokenHandler(response, request, &requestContext{user: user})
	if err != nil {
		t.Fatalf("create full token: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("create full token status: got %d, want %d", status, http.StatusOK)
	}
	if cacheControl := response.Header().Get("Cache-Control"); cacheControl != "no-store" {
		t.Fatalf("create full token cache control: got %q, want %q", cacheControl, "no-store")
	}

	var payload HttpResponse
	if decodeErr := json.NewDecoder(response.Body).Decode(&payload); decodeErr != nil {
		t.Fatalf("decode full token response: %v", decodeErr)
	}
	if payload.Token == "" {
		t.Fatal("create full token returned an empty token")
	}

	storedUser, err := store.Users.Get(user.ID)
	if err != nil {
		t.Fatalf("load full token owner: %v", err)
	}
	metadata, ok := storedUser.Tokens[name]
	if !ok {
		t.Fatalf("full token metadata %q was not persisted", name)
	}
	return payload.Token, metadata
}

func storeLegacyFullToken(t *testing.T, user *users.User, name string, download bool) string {
	t.Helper()

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":       auth.FB_ISSUER,
		"iat":       now.Unix(),
		"exp":       now.Add(time.Hour).Unix(),
		"belongsTo": user.ID,
		"Permissions": map[string]bool{
			"api":      true,
			"download": download,
		},
	}
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(settings.Config.Auth.Key))
	if err != nil {
		t.Fatalf("sign legacy full token: %v", err)
	}
	metadata := users.AuthToken{
		Token:     tokenString,
		BelongsTo: user.ID,
		Permissions: users.Permissions{
			Api:      true,
			Download: download,
		},
	}
	storeLegacyAuthToken(t, user, name, metadata)
	return tokenString
}

func storeFullTokenWithVersions(
	t *testing.T,
	user *users.User,
	storageName string,
	claimName string,
	claimVersion int,
	metadataVersion int,
	permissions users.Permissions,
) string {
	t.Helper()

	now := time.Now()
	claim := users.AuthToken{
		MinimalAuthToken: users.MinimalAuthToken{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    auth.FB_ISSUER,
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		},
		Name:               claimName,
		BelongsTo:          user.ID,
		PermissionsVersion: claimVersion,
		Permissions:        permissions,
	}
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claim).SignedString([]byte(settings.Config.Auth.Key))
	if err != nil {
		t.Fatalf("sign versioned full token: %v", err)
	}
	metadata := claim
	metadata.PermissionsVersion = metadataVersion
	if claimName != "" && metadataVersion == users.CurrentPermissionsVersion {
		if err := store.Users.AddApiToken(user.ID, storageName, tokenString, metadata); err != nil {
			t.Fatalf("persist hash-only versioned token metadata: %v", err)
		}
		return tokenString
	}
	metadata.Token = tokenString
	storeLegacyAuthToken(t, user, storageName, metadata)
	return tokenString
}

func storeLegacyAuthToken(t *testing.T, user *users.User, name string, metadata users.AuthToken) {
	t.Helper()

	storedUser, err := store.Users.Get(user.ID)
	if err != nil {
		t.Fatalf("load legacy token owner: %v", err)
	}
	updated := *storedUser
	updated.Tokens = make(map[string]users.AuthToken, len(storedUser.Tokens)+1)
	for storedName, storedToken := range storedUser.Tokens {
		updated.Tokens[storedName] = storedToken
	}
	updated.Tokens[name] = metadata
	if err := store.Users.Update(&updated, true, "Tokens"); err != nil {
		t.Fatalf("persist legacy token metadata: %v", err)
	}
}

func assertPermissionContractTokenRejected(t *testing.T, tokenString string) {
	t.Helper()

	called := false
	probe := withUserHelper(func(_ http.ResponseWriter, _ *http.Request, _ *requestContext) (int, error) {
		called = true
		return http.StatusOK, nil
	})
	request := httptest.NewRequest(http.MethodGet, "/api/permission-contract-probe", nil)
	request.Header.Set("Authorization", "Bearer "+tokenString)
	response := httptest.NewRecorder()
	status, err := probe(response, request, &requestContext{})
	if status != http.StatusUnauthorized || err == nil {
		t.Fatalf("invalid full token: got status=%d err=%v, want status=%d with error", status, err, http.StatusUnauthorized)
	}
	if called {
		t.Fatal("invalid full token reached the protected handler")
	}
}

func authenticatePermissionContractToken(t *testing.T, tokenString string) users.Permissions {
	t.Helper()

	var effective users.Permissions
	probe := withUserHelper(func(_ http.ResponseWriter, _ *http.Request, data *requestContext) (int, error) {
		effective = data.user.Permissions
		return http.StatusOK, nil
	})
	request := httptest.NewRequest(http.MethodGet, "/api/permission-contract-probe", nil)
	request.Header.Set("Authorization", "Bearer "+tokenString)
	response := httptest.NewRecorder()
	status, err := probe(response, request, &requestContext{})
	if err != nil {
		t.Fatalf("authenticate permission contract token: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("authenticate permission contract token status: got %d, want %d", status, http.StatusOK)
	}
	return effective
}
