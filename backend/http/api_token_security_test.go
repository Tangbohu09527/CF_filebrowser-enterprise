package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func TestAPITokenSecurityLifecycle(t *testing.T) {
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

	t.Run("named full token without matching metadata fails closed", func(t *testing.T) {
		setupPermissionContractHTTPTest(t)
		user := savePermissionContractUser(t, "token-orphan", users.Permissions{Api: true, Download: true})
		tokenString, _, err := auth.MakeSignedTokenAPI(user, "orphan-full-token", time.Hour, user.Permissions, false)
		if err != nil {
			t.Fatal(err)
		}
		assertPermissionContractTokenRejected(t, tokenString)
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
	for _, field := range []string{"id", "name", "fingerprint", "issuedAt", "expiresAt", "Permissions"} {
		if _, present := entry[field]; !present {
			t.Errorf("token management response missing %q: %v", field, entry)
		}
	}
}
