package http

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func TestAPITokenSecurityLifecycle(t *testing.T) {
	t.Run("new token metadata is persisted hash only", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-hash-only", users.Permissions{Api: true, Browse: true})
		secret, _ := issuePermissionContractToken(t, user, "hash-only", "api,browse")

		persistedUser, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal(err)
		}
		metadata, ok := persistedUser.Tokens["hash-only"]
		if !ok {
			t.Fatal("hash-only token metadata was not persisted")
		}
		encoded, err := json.Marshal(metadata)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("persisted token metadata contains bearer secret: %s", encoded)
		}

		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		allowed := map[string]struct{}{
			"tokenHash":   {},
			"tokenPrefix": {},
			"issuedAt":    {},
			"expiresAt":   {},
			"Permissions": {},
		}
		for field := range fields {
			if _, ok := allowed[field]; !ok {
				t.Errorf("persisted token metadata contains unexpected field %q: %s", field, encoded)
			}
		}
		for field := range allowed {
			if _, ok := fields[field]; !ok {
				t.Errorf("persisted token metadata is missing %q: %s", field, encoded)
			}
		}

		var tokenHash, tokenPrefix string
		var issuedAt, expiresAt int64
		var permissions users.Permissions
		if err := json.Unmarshal(fields["tokenHash"], &tokenHash); err != nil {
			t.Errorf("decode token hash: %v", err)
		}
		if err := json.Unmarshal(fields["tokenPrefix"], &tokenPrefix); err != nil {
			t.Errorf("decode token prefix: %v", err)
		}
		if err := json.Unmarshal(fields["issuedAt"], &issuedAt); err != nil {
			t.Errorf("decode issued time: %v", err)
		}
		if err := json.Unmarshal(fields["expiresAt"], &expiresAt); err != nil {
			t.Errorf("decode expiry time: %v", err)
		}
		if err := json.Unmarshal(fields["Permissions"], &permissions); err != nil {
			t.Errorf("decode permissions: %v", err)
		}
		if tokenHash != utils.HashSHA256(secret) {
			t.Errorf("persisted token hash = %q, want SHA-256 of bearer", tokenHash)
		}
		if tokenPrefix == "" || tokenPrefix == secret || !strings.HasPrefix(secret, tokenPrefix) {
			t.Errorf("persisted token prefix %q is not a redacted bearer prefix", tokenPrefix)
		}
		if issuedAt <= 0 || expiresAt <= issuedAt {
			t.Errorf("persisted token lifetime is invalid: issuedAt=%d expiresAt=%d", issuedAt, expiresAt)
		}
		if want := (users.Permissions{Api: true, Browse: true}); permissions != want {
			t.Errorf("persisted permissions = %+v, want %+v", permissions, want)
		}
		currentPermissions := users.Permissions{Api: true, Admin: true, Browse: true, Download: true}
		if frontend := authTokenFrontend("hash-only", metadata, currentPermissions); frontend.Permissions != permissions {
			t.Errorf("full token management permissions = %+v, want stored snapshot %+v", frontend.Permissions, permissions)
		}
	})

	t.Run("secret is returned only at creation", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-secret-once", users.Permissions{Api: true, Browse: true})
		secret, _ := issuePermissionContractToken(t, user, "secret-once", "api,browse")
		storedUser, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal(err)
		}

		listRecorder := httptest.NewRecorder()
		status, err := listApiTokensHandler(listRecorder, httptest.NewRequest(http.MethodGet, "/api/auth/token/list", nil), &requestContext{user: storedUser})
		if err != nil || status != http.StatusOK {
			t.Fatalf("list tokens: status=%d err=%v", status, err)
		}
		assertTokenManagementResponseRedacted(t, listRecorder.Body.Bytes(), secret, true)

		getRecorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/api/auth/token?name=secret-once", nil)
		status, err = getApiTokenHandler(getRecorder, request, &requestContext{user: storedUser})
		if err != nil || status != http.StatusOK {
			t.Fatalf("get token: status=%d err=%v", status, err)
		}
		assertTokenManagementResponseRedacted(t, getRecorder.Body.Bytes(), secret, false)
	})

	t.Run("management responses expose stable token types without secrets", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-management-types", users.Permissions{
			Api: true, Browse: true, Preview: true, Download: true,
		})
		fullSecret, _ := issuePermissionContractTokenWithMode(t, user, "typed-full", "api,browse", false)
		minimalSecret, _ := issuePermissionContractTokenWithMode(t, user, "typed-minimal", "", true)
		legacySecret := storeLegacyFullToken(t, user, "typed-legacy", true)

		storedUser, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal(err)
		}
		listRecorder := httptest.NewRecorder()
		status, err := listApiTokensHandler(listRecorder, httptest.NewRequest(http.MethodGet, "/api/auth/token/list", nil), &requestContext{user: storedUser})
		if err != nil || status != http.StatusOK {
			t.Fatalf("list typed tokens: status=%d err=%v", status, err)
		}
		for _, secret := range []string{fullSecret, minimalSecret, legacySecret} {
			if strings.Contains(listRecorder.Body.String(), secret) {
				t.Fatalf("typed token list exposed bearer %q", secret)
			}
		}

		var listed []map[string]any
		if err := json.Unmarshal(listRecorder.Body.Bytes(), &listed); err != nil {
			t.Fatalf("decode typed token list: %v", err)
		}
		if len(listed) != 3 {
			t.Fatalf("typed token list entries: got %d, want 3", len(listed))
		}
		wantTypes := map[string]string{
			"typed-full":    "full",
			"typed-minimal": "minimal",
			"typed-legacy":  "legacy",
		}
		listTypes := make(map[string]string, len(listed))
		for _, entry := range listed {
			name, _ := entry["name"].(string)
			tokenType, _ := entry["type"].(string)
			if tokenType != wantTypes[name] {
				t.Errorf("listed token %q type: got %q, want %q", name, tokenType, wantTypes[name])
			}
			if _, present := entry["token"]; present {
				t.Errorf("listed token %q retained token field", name)
			}
			if _, present := entry["key"]; present {
				t.Errorf("listed token %q retained key field", name)
			}
			listTypes[name] = tokenType
		}

		for name, wantType := range wantTypes {
			request := httptest.NewRequest(http.MethodGet, "/api/auth/token?name="+url.QueryEscape(name), nil)
			getRecorder := httptest.NewRecorder()
			status, err = getApiTokenHandler(getRecorder, request, &requestContext{user: storedUser})
			if err != nil || status != http.StatusOK {
				t.Fatalf("get typed token %q: status=%d err=%v", name, status, err)
			}
			var entry map[string]any
			if err := json.Unmarshal(getRecorder.Body.Bytes(), &entry); err != nil {
				t.Fatalf("decode typed token %q: %v", name, err)
			}
			if got, _ := entry["type"].(string); got != wantType || got != listTypes[name] {
				t.Errorf("token %q type is unstable: list=%q get=%q want=%q", name, listTypes[name], got, wantType)
			}
			for _, secret := range []string{fullSecret, minimalSecret, legacySecret} {
				if strings.Contains(getRecorder.Body.String(), secret) {
					t.Fatalf("typed token get %q exposed bearer %q", name, secret)
				}
			}
			if _, present := entry["token"]; present {
				t.Errorf("token get %q retained token field", name)
			}
			if _, present := entry["key"]; present {
				t.Errorf("token get %q retained key field", name)
			}
		}
	})

	t.Run("renew rejects API tokens", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-renew-parent", users.Permissions{Api: true, Download: true})
		parent, _ := issuePermissionContractToken(t, user, "narrow-renew-parent", "api")
		request := httptest.NewRequest(http.MethodPost, "/api/auth/renew", nil)
		request.Header.Set("Authorization", "Bearer "+parent)
		recorder := httptest.NewRecorder()

		status, err := withUserHelper(renewHandler)(recorder, request, &requestContext{})
		if status != http.StatusForbidden || err == nil {
			t.Fatalf("API token renew: got status=%d err=%v body=%q, want forbidden", status, err, recorder.Body.String())
		}
	})

	t.Run("narrow full token cannot create a minimal token", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-minimal-parent", users.Permissions{Api: true, Download: true})
		parent, _ := issuePermissionContractToken(t, user, "narrow-minimal-parent", "api")
		query := url.Values{"name": {"forbidden-minimal-child"}, "days": {"1"}, "minimal": {"true"}}
		request := httptest.NewRequest(http.MethodPost, "/api/auth/token?"+query.Encode(), nil)
		request.Header.Set("Authorization", "Bearer "+parent)
		recorder := httptest.NewRecorder()

		status, err := withUserHelper(createApiTokenHandler)(recorder, request, &requestContext{})
		if status != http.StatusForbidden || err == nil {
			t.Fatalf("minimal child creation: got status=%d err=%v body=%q, want forbidden", status, err, recorder.Body.String())
		}
		stored, loadErr := store.Users.Get(user.ID)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if _, exists := stored.Tokens["forbidden-minimal-child"]; exists {
			t.Fatal("narrow API token persisted a wider minimal child")
		}
	})

	t.Run("api token cannot create a full child token", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-full-child-parent", users.Permissions{Api: true, Browse: true})
		parent, _ := issuePermissionContractToken(t, user, "full-child-parent", "api,browse")
		query := url.Values{"name": {"forbidden-full-child"}, "days": {"30"}, "permissions": {"api,browse"}}
		request := httptest.NewRequest(http.MethodPost, "/api/auth/token?"+query.Encode(), nil)
		request.Header.Set("Authorization", "Bearer "+parent)
		status, err := withUserHelper(createApiTokenHandler)(httptest.NewRecorder(), request, &requestContext{})
		if status != http.StatusForbidden || err == nil {
			t.Fatalf("full child creation: status=%d err=%v, want forbidden", status, err)
		}
		stored, loadErr := store.Users.Get(user.ID)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if _, exists := stored.Tokens["forbidden-full-child"]; exists {
			t.Fatal("API token persisted a full child token")
		}
	})

	t.Run("api token is not echoed into a session cookie", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-cookie-parent", users.Permissions{Api: true, Browse: true})
		parent, _ := issuePermissionContractToken(t, user, "cookie-parent", "api,browse")
		request := httptest.NewRequest(http.MethodGet, "/api/auth/token/list", nil)
		request.Header.Set("Authorization", "Bearer "+parent)
		recorder := httptest.NewRecorder()
		status, err := withUserHelper(listApiTokensHandler)(recorder, request, &requestContext{})
		if err != nil || status != http.StatusOK {
			t.Fatalf("list through auth middleware: status=%d err=%v", status, err)
		}
		for _, cookie := range recorder.Header().Values("Set-Cookie") {
			if strings.Contains(cookie, parent) {
				t.Fatalf("API bearer was echoed in Set-Cookie: %q", cookie)
			}
		}
	})

	t.Run("session cookie is secure and host-only on TLS", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "https://files.example.test/api/probe", nil)
		request.TLS = &tls.ConnectionState{}
		request.Header.Set("X-Forwarded-Host", "attacker.example.test")
		recorder := httptest.NewRecorder()
		setSessionCookie(recorder, request, "session-secret", time.Now().Add(time.Hour))
		cookies := recorder.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("session cookies: got %d, want 1", len(cookies))
		}
		cookie := cookies[0]
		if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
			t.Fatalf("session cookie flags: %+v", cookie)
		}
		if cookie.Domain != "" {
			t.Fatalf("session cookie must be host-only, got Domain=%q", cookie.Domain)
		}
	})

	t.Run("new web token carries a signed marker and authenticates", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-marked-web-session", users.Permissions{Browse: true})
		tokenString, _, err := auth.MakeSignedTokenAPI(user, "WEB_TOKEN_marked", time.Hour, user.Permissions, false)
		if err != nil {
			t.Fatal(err)
		}

		var claims users.AuthToken
		parsed, err := jwt.ParseWithClaims(tokenString, &claims, func(*jwt.Token) (interface{}, error) {
			return []byte(settings.Config.Auth.Key), nil
		})
		if err != nil || !parsed.Valid {
			t.Fatalf("parse marked web token: valid=%v err=%v", parsed != nil && parsed.Valid, err)
		}
		if got := parsed.Header["fb_token_type"]; got != "web" {
			t.Fatalf("web token marker: got %#v, want %q", got, "web")
		}

		request := httptest.NewRequest(http.MethodGet, "/api/marked-web-probe", nil)
		request.Header.Set("Authorization", "Bearer "+tokenString)
		called := false
		status, err := withUserHelper(func(_ http.ResponseWriter, _ *http.Request, data *requestContext) (int, error) {
			called = data.user != nil && data.user.ID == user.ID && !data.apiToken
			return http.StatusOK, nil
		})(httptest.NewRecorder(), request, &requestContext{})
		if err != nil || status != http.StatusOK || !called {
			t.Fatalf("marked web token authentication: status=%d err=%v called=%v", status, err, called)
		}
	})

	t.Run("concurrent same-name creation leaves one managed token", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-concurrent-name", users.Permissions{Api: true, Browse: true})
		const attempts = 8
		start := make(chan struct{})
		statuses := make(chan int, attempts)
		errorsSeen := make(chan error, attempts)
		var wait sync.WaitGroup
		for range attempts {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				query := url.Values{"name": {"single-name"}, "days": {"1"}, "permissions": {"api,browse"}}
				status, err := createApiTokenHandler(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/auth/token?"+query.Encode(), nil), &requestContext{user: user})
				statuses <- status
				errorsSeen <- err
			}()
		}
		close(start)
		wait.Wait()
		close(statuses)
		close(errorsSeen)
		successes := 0
		conflicts := 0
		for status := range statuses {
			switch status {
			case http.StatusOK:
				successes++
			case http.StatusConflict:
				conflicts++
			default:
				t.Errorf("concurrent token creation returned status %d", status)
			}
		}
		for err := range errorsSeen {
			if err != nil && !strings.Contains(err.Error(), "key already exists") {
				t.Errorf("concurrent token creation error: %v", err)
			}
		}
		if successes != 1 || conflicts != attempts-1 {
			t.Fatalf("concurrent same-name results: success=%d conflict=%d", successes, conflicts)
		}
		stored, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal(err)
		}
		tokenMetadata := stored.Tokens["single-name"]
		if len(stored.Tokens) != 1 || tokenMetadata.TokenHash == "" || tokenMetadata.Token != "" || tokenMetadata.Key != "" {
			t.Fatalf("concurrent token metadata is not singular and manageable: %+v", stored.Tokens)
		}
	})

	t.Run("named full token without matching metadata fails closed", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-orphan", users.Permissions{Api: true, Download: true})
		tokenString, _, err := auth.MakeSignedTokenAPI(user, "orphan-full-token", time.Hour, user.Permissions, false)
		if err != nil {
			t.Fatal(err)
		}
		assertPermissionContractTokenRejected(t, tokenString)
	})

	t.Run("minimal token without matching metadata fails closed", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-orphan-minimal", users.Permissions{Api: true, Browse: true})
		tokenString, _, err := auth.MakeSignedTokenAPI(user, "orphan-minimal-token", time.Hour, users.Permissions{}, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Access.AddApiToken(tokenString, user.ID); err != nil {
			t.Fatal(err)
		}
		assertPermissionContractTokenRejected(t, tokenString)
	})

	t.Run("untracked legacy full token cannot fall back to a web session", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-orphan-legacy-full", users.Permissions{
			Api: true, Browse: true, Preview: true, Download: true,
		})
		now := time.Now()
		claims := jwt.MapClaims{
			"iss":       auth.FB_ISSUER,
			"iat":       now.Unix(),
			"exp":       now.Add(time.Hour).Unix(),
			"belongsTo": user.ID,
			"Permissions": map[string]bool{
				"api": true,
			},
		}
		tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(settings.Config.Auth.Key))
		if err != nil {
			t.Fatal(err)
		}
		assertPermissionContractTokenRejected(t, tokenString)
	})

	t.Run("issued token bearers are unique within one JWT timestamp", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		firstUser := savePermissionContractUser(t, "token-unique-first", users.Permissions{Api: true})
		secondUser := savePermissionContractUser(t, "token-unique-second", users.Permissions{Api: true})

		assertUniqueInSameSecond := func(t *testing.T, firstName, secondName string, firstOwner, secondOwner *users.User, minimal bool) {
			t.Helper()
			for attempt := 0; attempt < 100; attempt++ {
				first, firstClaims, err := auth.MakeSignedTokenAPI(firstOwner, firstName, time.Hour, firstOwner.Permissions, minimal)
				if err != nil {
					t.Fatal(err)
				}
				second, secondClaims, err := auth.MakeSignedTokenAPI(secondOwner, secondName, time.Hour, secondOwner.Permissions, minimal)
				if err != nil {
					t.Fatal(err)
				}
				if firstClaims.RegisteredClaims.IssuedAt.Unix() != secondClaims.RegisteredClaims.IssuedAt.Unix() {
					continue
				}
				if first == second {
					t.Fatal("two token issuances produced the same bearer")
				}
				return
			}
			t.Fatal("could not observe two issuances in the same JWT timestamp")
		}

		t.Run("minimal tokens for different users", func(t *testing.T) {
			assertUniqueInSameSecond(t, "minimal-first", "minimal-second", firstUser, secondUser, true)
		})
		t.Run("web sessions for one user", func(t *testing.T) {
			assertUniqueInSameSecond(t, "WEB_TOKEN_first", "WEB_TOKEN_second", firstUser, firstUser, false)
		})
	})

	t.Run("delete uses fresh token metadata and preserves a later token", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-delete-fresh-state", users.Permissions{Api: true, Browse: true})
		first, _ := issuePermissionContractToken(t, user, "delete-first", "api,browse")
		stale, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal(err)
		}
		second, _ := issuePermissionContractToken(t, user, "created-after-delete-snapshot", "api,browse")

		request := httptest.NewRequest(http.MethodDelete, "/api/auth/token?name=delete-first", nil)
		status, err := deleteApiTokenHandler(httptest.NewRecorder(), request, &requestContext{user: stale})
		if err != nil || status != http.StatusOK {
			t.Fatalf("delete first token: status=%d err=%v", status, err)
		}
		if !auth.IsRevokedApiToken(store.Access, first) {
			t.Fatal("deleted token was not revoked")
		}
		reloaded, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored, ok := reloaded.Tokens["created-after-delete-snapshot"]; !ok || !stored.MatchesTokenHash(utils.HashSHA256(second)) {
			t.Fatalf("later token metadata was lost: %+v", reloaded.Tokens)
		}
		request = httptest.NewRequest(http.MethodGet, "/api/probe", nil)
		request.Header.Set("Authorization", "Bearer "+second)
		status, err = withUserHelper(nil)(httptest.NewRecorder(), request, &requestContext{})
		if err != nil || status != http.StatusOK {
			t.Fatalf("later token no longer authenticates: status=%d err=%v", status, err)
		}
	})

	t.Run("revoked token remains anonymous in optional auth", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-optional-revoked", users.Permissions{Api: true, Browse: true})
		tokenString, _ := issuePermissionContractToken(t, user, "optional-revoked", "api,browse")
		if err := auth.RevokeApiToken(store.Access, tokenString); err != nil {
			t.Fatal(err)
		}

		var gotUser *users.User
		var gotToken string
		handler := withOrWithoutUserHelper(func(_ http.ResponseWriter, _ *http.Request, data *requestContext) (int, error) {
			gotUser = data.user
			gotToken = data.token
			return http.StatusOK, nil
		})
		request := httptest.NewRequest(http.MethodGet, "/public/optional-auth-probe", nil)
		request.Header.Set("Authorization", "Bearer "+tokenString)
		status, err := handler(httptest.NewRecorder(), request, &requestContext{})
		if err != nil || status != http.StatusOK {
			t.Fatalf("optional auth: status=%d err=%v", status, err)
		}
		if gotUser == nil || gotUser.Username != "anonymous" || gotToken != "" {
			t.Fatalf("revoked optional identity: user=%+v token=%q, want anonymous with empty token", gotUser, gotToken)
		}
	})

	t.Run("orphan minimal token clears optional auth state", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-optional-orphan", users.Permissions{Api: true, Browse: true})
		tokenString, _ := issuePermissionContractTokenWithMode(t, user, "optional-orphan", "", true)
		if err := store.Users.DeleteApiToken(user.ID, "optional-orphan"); err != nil {
			t.Fatal(err)
		}

		var gotUser *users.User
		var gotToken string
		gotAPIToken := true
		handler := withOrWithoutUserHelper(func(_ http.ResponseWriter, _ *http.Request, data *requestContext) (int, error) {
			gotUser = data.user
			gotToken = data.token
			gotAPIToken = data.apiToken
			return http.StatusOK, nil
		})
		request := httptest.NewRequest(http.MethodGet, "/public/optional-auth-probe", nil)
		request.Header.Set("Authorization", "Bearer "+tokenString)
		status, err := handler(httptest.NewRecorder(), request, &requestContext{})
		if err != nil || status != http.StatusOK {
			t.Fatalf("optional auth: status=%d err=%v", status, err)
		}
		if gotUser == nil || gotUser.Username != "anonymous" || gotToken != "" || gotAPIToken {
			t.Fatalf("orphan optional identity: user=%+v token=%q apiToken=%v, want anonymous with cleared credential state", gotUser, gotToken, gotAPIToken)
		}
	})

	t.Run("authorization header takes precedence over query credential", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/api/probe?auth=query.token.value", nil)
		request.Header.Set("Authorization", "Bearer header.token.value")
		got, err := extractToken(request)
		if err != nil {
			t.Fatal(err)
		}
		if got != "header.token.value" {
			t.Fatalf("extractToken returned %q, want Authorization header token", got)
		}
	})

	t.Run("authorization header takes precedence over external jwt query", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-external-jwt-priority", users.Permissions{Api: true, Browse: true})
		parent, _ := issuePermissionContractToken(t, user, "external-jwt-priority", "api,browse")
		config.Auth.Methods.JwtAuth = settings.JwtAuthConfig{
			AuthCommon: settings.AuthCommon{Enabled: true, UserIdentifier: "sub"},
			Header:     "X-JWT-Assertion",
			Secret:     "external-jwt-test-secret",
			Algorithm:  "HS256",
		}
		request := httptest.NewRequest(http.MethodGet, "/api/probe?jwt=invalid.external.jwt", nil)
		request.Header.Set("Authorization", "Bearer "+parent)
		called := false
		status, err := withUserHelper(func(_ http.ResponseWriter, _ *http.Request, data *requestContext) (int, error) {
			called = data.user != nil && data.user.ID == user.ID
			return http.StatusOK, nil
		})(httptest.NewRecorder(), request, &requestContext{})
		if err != nil || status != http.StatusOK || !called {
			t.Fatalf("Authorization versus ?jwt=: status=%d err=%v called=%v", status, err, called)
		}
	})

	t.Run("configured Authorization external JWT preserves explicit auth precedence", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		const externalSecret = "configured-authorization-external-secret"
		externalUser := &users.User{
			Username:    "configured-authorization-external-user",
			LoginMethod: users.LoginMethodJwt,
			Permissions: users.Permissions{Browse: true},
		}
		if err := store.Users.Save(externalUser, false, false); err != nil {
			t.Fatal(err)
		}
		internalUser := savePermissionContractUser(t, "configured-authorization-internal-user", users.Permissions{Api: true, Browse: true})
		internalToken, _ := issuePermissionContractToken(t, internalUser, "configured-authorization-internal", "api,browse")

		config.Auth.Methods.JwtAuth = settings.JwtAuthConfig{
			AuthCommon: settings.AuthCommon{Enabled: true, UserIdentifier: "sub"},
			Header:     "Authorization",
			Secret:     externalSecret,
			Algorithm:  "HS256",
		}
		now := time.Now()
		externalToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": externalUser.Username,
			"iat": now.Unix(),
			"exp": now.Add(time.Hour).Unix(),
		}).SignedString([]byte(externalSecret))
		if err != nil {
			t.Fatal(err)
		}

		t.Run("raw configured header authenticates external JWT", func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/external-authorization-probe", nil)
			request.Header.Set("Authorization", externalToken)
			var gotUserID uint
			status, err := withUserHelper(func(_ http.ResponseWriter, _ *http.Request, data *requestContext) (int, error) {
				gotUserID = data.user.ID
				return http.StatusOK, nil
			})(httptest.NewRecorder(), request, &requestContext{})
			if err != nil || status != http.StatusOK || gotUserID != externalUser.ID {
				t.Fatalf("configured external Authorization: status=%d err=%v userID=%d want=%d", status, err, gotUserID, externalUser.ID)
			}
		})

		t.Run("FileBrowser bearer is not replaced by external query", func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/internal-authorization-probe?jwt="+url.QueryEscape(externalToken), nil)
			request.Header.Set("Authorization", "Bearer "+internalToken)
			var gotUserID uint
			status, err := withUserHelper(func(_ http.ResponseWriter, _ *http.Request, data *requestContext) (int, error) {
				gotUserID = data.user.ID
				return http.StatusOK, nil
			})(httptest.NewRecorder(), request, &requestContext{})
			if err != nil || status != http.StatusOK || gotUserID != internalUser.ID {
				t.Fatalf("FileBrowser Authorization versus ?jwt=: status=%d err=%v userID=%d want=%d", status, err, gotUserID, internalUser.ID)
			}
		})
	})

	t.Run("legacy token missing read claims fails closed", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "legacy-token-fail-closed", users.Permissions{
			Api: true, Browse: true, Preview: true, Download: true,
		})
		tokenString := storeLegacyFullToken(t, user, "legacy-token-fail-closed", true)
		effective := authenticatePermissionContractToken(t, tokenString)
		if effective.Browse || effective.Preview {
			t.Fatalf("legacy token synthesized missing read permissions: %+v", effective)
		}
	})

	t.Run("delete reports unavailable revocation storage", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-delete-failure", users.Permissions{Api: true})
		_, _ = issuePermissionContractToken(t, user, "delete-failure", "api")
		storedUser, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal(err)
		}
		store.Access = nil
		request := httptest.NewRequest(http.MethodDelete, "/api/auth/token?name=delete-failure", nil)
		status, err := deleteApiTokenHandler(httptest.NewRecorder(), request, &requestContext{user: storedUser})
		if status != http.StatusInternalServerError || err == nil {
			t.Fatalf("delete with unavailable revocation storage: status=%d err=%v", status, err)
		}
	})

	t.Run("authentication fails closed without revocation storage", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-nil-revocation-store", users.Permissions{Api: true})
		tokenString, _ := issuePermissionContractToken(t, user, "nil-revocation-store", "api")
		store.Access = nil
		request := httptest.NewRequest(http.MethodGet, "/api/probe", nil)
		request.Header.Set("Authorization", "Bearer "+tokenString)
		called := false
		status, err := withUserHelper(func(http.ResponseWriter, *http.Request, *requestContext) (int, error) {
			called = true
			return http.StatusOK, nil
		})(httptest.NewRecorder(), request, &requestContext{})
		if status != http.StatusUnauthorized || err == nil || called {
			t.Fatalf("nil revocation store: status=%d err=%v called=%v", status, err, called)
		}
	})

	t.Run("delete revokes same-name modern and legacy tokens", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-legacy-collision", users.Permissions{Api: true})
		modern, _ := issuePermissionContractToken(t, user, "collision", "api")
		now := time.Now()
		legacyClaims := jwt.MapClaims{
			"iss": auth.FB_ISSUER, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"belongsTo": user.ID, "Permissions": map[string]bool{"api": true},
		}
		legacy, err := jwt.NewWithClaims(jwt.SigningMethodHS256, legacyClaims).SignedString([]byte(settings.Config.Auth.Key))
		if err != nil {
			t.Fatal(err)
		}
		stored, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal(err)
		}
		stored.ApiKeys = map[string]users.AuthToken{"collision": {Token: legacy, BelongsTo: user.ID, Permissions: users.Permissions{Api: true}}}
		if err := store.Users.Update(stored, true, "ApiKeys"); err != nil {
			t.Fatal(err)
		}
		if err := store.Access.AddApiToken(legacy, user.ID); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodDelete, "/api/auth/token?name=collision", nil)
		status, err := deleteApiTokenHandler(httptest.NewRecorder(), request, &requestContext{user: stored})
		if err != nil || status != http.StatusOK {
			t.Fatalf("delete collision: status=%d err=%v", status, err)
		}
		if !auth.IsRevokedApiToken(store.Access, modern) || !auth.IsRevokedApiToken(store.Access, legacy) {
			t.Fatal("delete did not revoke every bearer with the requested name")
		}
		reloaded, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := reloaded.Tokens["collision"]; ok {
			t.Fatal("modern token metadata remains after delete")
		}
		if _, ok := reloaded.ApiKeys["collision"]; ok {
			t.Fatal("legacy token metadata remains after delete")
		}
	})

	t.Run("delete revokes distinct Token and Key bearers", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-dual-secret-fields", users.Permissions{Api: true})
		primary, metadata, err := auth.MakeSignedTokenAPI(user, "dual-primary", time.Hour, users.Permissions{Api: true}, false)
		if err != nil {
			t.Fatal(err)
		}
		legacyKey, _, err := auth.MakeSignedTokenAPI(user, "dual-legacy-key", time.Hour, users.Permissions{Api: true}, false)
		if err != nil {
			t.Fatal(err)
		}
		metadata.Token = primary
		metadata.Key = legacyKey
		storeLegacyAuthToken(t, user, "dual-secret-fields", metadata)
		if err := store.Access.AddApiToken(primary, user.ID); err != nil {
			t.Fatal(err)
		}
		if err := store.Access.AddApiToken(legacyKey, user.ID); err != nil {
			t.Fatal(err)
		}

		request := httptest.NewRequest(http.MethodDelete, "/api/auth/token?name=dual-secret-fields", nil)
		status, err := deleteApiTokenHandler(httptest.NewRecorder(), request, &requestContext{user: user})
		if err != nil || status != http.StatusOK {
			t.Fatalf("delete dual-field token: status=%d err=%v", status, err)
		}
		if !auth.IsRevokedApiToken(store.Access, primary) {
			t.Fatal("Token bearer remained active after deletion")
		}
		if !auth.IsRevokedApiToken(store.Access, legacyKey) {
			t.Fatal("Key bearer remained active after deletion")
		}
		reloaded, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := reloaded.Tokens["dual-secret-fields"]; ok {
			t.Fatal("dual-field token metadata remains after delete")
		}
	})

	t.Run("lowercase permission update revokes existing tokens", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		target := savePermissionContractUser(t, "token-permission-revoke", users.Permissions{Api: true})
		tokenString, _ := issuePermissionContractToken(t, target, "permission-revoke", "api")
		actor := &users.User{ID: 9999, Permissions: users.Permissions{Admin: true}}
		body := `{"which":["permissions"],"data":{"permissions":{"api":false}}}`
		request := httptest.NewRequest(http.MethodPut, "/api/users?id="+strconv.FormatUint(uint64(target.ID), 10), strings.NewReader(body))
		status, err := userPutHandler(httptest.NewRecorder(), request, &requestContext{user: actor})
		if err != nil || status != http.StatusNoContent {
			t.Fatalf("remove API permission: status=%d err=%v", status, err)
		}
		if !auth.IsRevokedApiToken(store.Access, tokenString) {
			t.Fatal("lowercase permissions update left API token active")
		}
	})

	t.Run("stale request cannot create a token after API permission revocation", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-stale-create", users.Permissions{
			Api: true, Browse: true, Download: true,
		})
		staleUser := *user
		updatedUser := *user
		updatedUser.Permissions.Api = false
		if err := store.Users.Update(&updatedUser, true, "Permissions"); err != nil {
			t.Fatalf("revoke API permission: %v", err)
		}

		query := url.Values{
			"name":        {"created-from-stale-request"},
			"days":        {"1"},
			"minimal":     {"false"},
			"permissions": {"download"},
		}
		request := httptest.NewRequest(http.MethodPost, "/api/auth/token?"+query.Encode(), nil)
		status, createErr := createApiTokenHandler(httptest.NewRecorder(), request, &requestContext{user: &staleUser})
		if status != http.StatusForbidden || createErr == nil {
			t.Fatalf("stale token creation: status=%d err=%v", status, createErr)
		}
		reloaded, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := reloaded.Tokens["created-from-stale-request"]; exists {
			t.Fatal("stale request persisted token metadata after API permission revocation")
		}
	})
}

func assertTokenManagementResponseRedacted(t *testing.T, body []byte, secret string, list bool) {
	t.Helper()
	if strings.Contains(string(body), secret) {
		t.Fatalf("token management response exposed bearer: %s", body)
	}
	var entries []map[string]any
	if list {
		if err := json.Unmarshal(body, &entries); err != nil {
			t.Fatalf("decode token list: %v", err)
		}
	} else {
		var entry map[string]any
		if err := json.Unmarshal(body, &entry); err != nil {
			t.Fatalf("decode token details: %v", err)
		}
		entries = []map[string]any{entry}
	}
	if len(entries) != 1 {
		t.Fatalf("token management entries: got %d, want 1", len(entries))
	}
	entry := entries[0]
	if _, present := entry["token"]; present {
		t.Fatalf("token management response retained token field: %v", entry)
	}
	for _, field := range []string{"id", "name", "type", "fingerprint", "issuedAt", "expiresAt", "Permissions"} {
		if _, present := entry[field]; !present {
			t.Errorf("token management response missing %q: %v", field, entry)
		}
	}
}
