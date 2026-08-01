package http

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	dbshare "github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"golang.org/x/crypto/bcrypt"
)

func TestPasswordShareRequiresPasswordInsteadOfStoredToken(t *testing.T) {
	setupTestEnv(t)

	const (
		password = "password-share-correct-password"
		wrong    = "password-share-wrong-password"
		key      = "password-share-auth-signing-key"
	)
	config.Auth.Key = key
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.URLEncoding.EncodeToString([]byte("password-share-token-payload"))
	mac := hmac.New(sha256.New, []byte(key))
	if _, err := mac.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	storedToken := payload + "." + base64.URLEncoding.EncodeToString(mac.Sum(nil))
	link := &dbshare.Link{
		PasswordHash: string(passwordHash),
		Token:        storedToken,
	}

	tests := []struct {
		name       string
		queryToken string
		headers    map[string]string
		wantStatus int
	}{
		{
			name:       "correct password succeeds",
			headers:    map[string]string{"X-SHARE-PASSWORD": password},
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing password is rejected",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong password is rejected",
			headers:    map[string]string{"X-SHARE-PASSWORD": wrong},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "stored query token cannot replace password",
			queryToken: storedToken,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "stored share token header cannot replace password",
			headers:    map[string]string{"X-SHARE-TOKEN": storedToken},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "stored bearer token cannot replace password",
			headers:    map[string]string{"Authorization": "Bearer " + storedToken},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "stored token in password header is rejected",
			headers:    map[string]string{"X-SHARE-PASSWORD": storedToken},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/public/api/resources", nil)
			query := request.URL.Query()
			if tc.queryToken != "" {
				query.Set("token", tc.queryToken)
			}
			request.URL.RawQuery = query.Encode()
			for name, value := range tc.headers {
				request.Header.Set(name, value)
			}

			status, authErr := authenticateShareRequest(request, link)
			if authErr != nil {
				t.Fatalf("authenticate password share: %v", authErr)
			}
			if status != tc.wantStatus {
				t.Errorf("status = %d, want %d", status, tc.wantStatus)
			}
		})
	}
}

func TestPasswordShareResponsesDoNotExposeStoredCredentials(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	harness := newPermissionShareSecurityHarness(t, sourcePath)

	const (
		shareHash     = "password-share-management-hash"
		storedToken   = "PASSWORD-SHARE-STORED-TOKEN-SECRET"
		plainPassword = "PASSWORD-SHARE-PLAINTEXT-SECRET"
	)
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	owner := harness.newOwner(t, "password-share-owner", users.Permissions{
		Share: true, Browse: true, Preview: true, Download: true,
	})
	link := harness.saveShare(t, owner, shareHash, "/public", nil)
	link.PasswordHash = string(passwordHash)
	link.Token = storedToken
	if err := store.Share.Save(link); err != nil {
		t.Fatalf("save password share credentials: %v", err)
	}

	t.Run("management list", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "https://files.example/api/share/list", nil)
		recorder := httptest.NewRecorder()
		status, handlerErr := shareListHandler(recorder, request, &requestContext{user: owner})
		if handlerErr != nil || status != http.StatusOK {
			t.Fatalf("list password share: status=%d err=%v body=%q", status, handlerErr, recorder.Body.String())
		}
		payload := decodeCredentialSafeJSON(t, recorder.Body.Bytes(), storedToken, string(passwordHash), plainPassword)
		shares, ok := payload.([]any)
		if !ok || len(shares) != 1 {
			t.Fatalf("management list payload = %#v, want one share", payload)
		}
		assertPasswordShareManagementURLsSafe(t, shares[0], storedToken, string(passwordHash), plainPassword)
	})

	t.Run("management get", func(t *testing.T) {
		query := url.Values{"path": {"/public"}, "source": {"source1"}}
		request := httptest.NewRequest(http.MethodGet, "https://files.example/api/share?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()
		status, handlerErr := shareGetHandler(recorder, request, &requestContext{user: owner})
		if handlerErr != nil || status != http.StatusOK {
			t.Fatalf("get password share: status=%d err=%v body=%q", status, handlerErr, recorder.Body.String())
		}
		payload := decodeCredentialSafeJSON(t, recorder.Body.Bytes(), storedToken, string(passwordHash), plainPassword)
		shares, ok := payload.([]any)
		if !ok || len(shares) != 1 {
			t.Fatalf("management get payload = %#v, want one share", payload)
		}
		assertPasswordShareManagementURLsSafe(t, shares[0], storedToken, string(passwordHash), plainPassword)
	})

	t.Run("public info DTO", func(t *testing.T) {
		publicInfo := link.CommonShare
		publicInfo.HasPassword = link.HasPassword()
		publicInfo.Source = ""
		publicInfo.Path = ""
		publicInfo.DownloadURL = ""
		publicInfo.ShareURL = "https://files.example/public/share/" + shareHash
		recorder := httptest.NewRecorder()
		status, renderErr := renderJSON(recorder, httptest.NewRequest(http.MethodGet, "/public/api/share/info", nil), publicInfo)
		if renderErr != nil || status != http.StatusOK {
			t.Fatalf("render public password share info: status=%d err=%v body=%q", status, renderErr, recorder.Body.String())
		}
		decodeCredentialSafeJSON(t, recorder.Body.Bytes(), storedToken, string(passwordHash), plainPassword)
	})
}

func decodeCredentialSafeJSON(t *testing.T, body []byte, secretValues ...string) any {
	t.Helper()
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode JSON response: %v; body=%q", err, body)
	}
	assertNoCredentialJSONFields(t, payload)
	for _, secret := range secretValues {
		if secret != "" && strings.Contains(string(body), secret) {
			t.Errorf("JSON response exposed credential value %q", secret)
		}
	}
	return payload
}

func assertNoCredentialJSONFields(t *testing.T, value any) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for name, child := range typed {
			normalized := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(name))
			switch normalized {
			case "passwordhash", "password", "token", "accesstoken", "cookie", "authorization":
				t.Errorf("JSON response exposed credential field %q", name)
			}
			assertNoCredentialJSONFields(t, child)
		}
	case []any:
		for _, child := range typed {
			assertNoCredentialJSONFields(t, child)
		}
	}
}

func assertPasswordShareManagementURLsSafe(t *testing.T, value any, secretValues ...string) {
	t.Helper()
	sharePayload, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("management share payload = %#v, want object", value)
	}
	for _, field := range []string{"shareURL", "downloadURL"} {
		rawURL, ok := sharePayload[field].(string)
		if !ok || rawURL == "" {
			t.Errorf("management share %s = %#v, want non-empty string", field, sharePayload[field])
			continue
		}
		parsed, err := url.Parse(rawURL)
		if err != nil {
			t.Errorf("parse management share %s %q: %v", field, rawURL, err)
			continue
		}
		if _, exists := parsed.Query()["token"]; exists {
			t.Errorf("management share %s contains a token query parameter", field)
		}
		for _, secret := range secretValues {
			if secret != "" && strings.Contains(rawURL, secret) {
				t.Errorf("management share %s exposed credential value %q", field, secret)
			}
		}
	}
}
