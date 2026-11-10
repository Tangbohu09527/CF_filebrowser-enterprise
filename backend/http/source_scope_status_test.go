package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
)

func TestSourceScopeReadDenialStatus(t *testing.T) {
	source := setupResourcePutTestEnv(t)
	configurePermissionReadAuth(t)
	if err := os.WriteFile(filepath.Join(source, "public", "allowed.txt"), []byte("allowed synthetic bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	outsidePath := filepath.Join(filepath.Dir(source), "outside")
	if err := os.Mkdir(outsidePath, 0755); err != nil {
		t.Fatal(err)
	}
	const deniedName = "outside-sentinel.txt"
	const deniedBytes = "synthetic out-of-scope file bytes"
	if err := os.WriteFile(filepath.Join(outsidePath, deniedName), []byte(deniedBytes), 0644); err != nil {
		t.Fatal(err)
	}
	outside := &settings.Source{
		Path: outsidePath,
		Name: "outside-source",
		Config: settings.SourceConfig{
			Private: true,
			ResolvedRules: settings.ResolvedRulesConfig{
				IndexingDisabled: true,
				NoRules:          true,
			},
		},
	}
	config.Server.SourceMap[outsidePath] = outside
	config.Server.NameToSource[outside.Name] = outside
	settings.InitializeUserResolvers()
	indexing.Initialize(outside, false, false)
	for _, name := range []string{"source1", outside.Name} {
		indexing.GetIndex(name).CreateMockData(1, 1)
	}

	user := saveAPITokenTestUser(t, "source-scoped-reader", source, users.Permissions{
		Api: true, Browse: true, Download: true,
	})
	identities := []struct{ name, token string }{
		{"ordinary web user", issuePermissionReadWebToken(t, user)},
		{"restricted full token", issuePermissionReadAPIToken(t, user, "source-scope-full-token", users.Permissions{Browse: true, Download: true})},
	}
	router := http.NewServeMux()
	router.HandleFunc("GET /api/resources", withUser(resourceGetHandler))
	router.HandleFunc("GET /api/resources/download", withUser(downloadHandler))
	assertNoOutsideData := func(t *testing.T, response *httptest.ResponseRecorder) {
		t.Helper()
		var failure HttpResponse
		if err := json.Unmarshal(response.Body.Bytes(), &failure); err != nil {
			t.Fatal(err)
		}
		for _, protected := range []string{deniedName, deniedBytes, outsidePath} {
			if strings.Contains(response.Body.String(), protected) || strings.Contains(failure.Message, protected) {
				t.Error("denied response leaked out-of-scope data or physical Source path")
			}
		}
	}
	for _, identity := range identities {
		t.Run(identity.name, func(t *testing.T) {
			for _, test := range []struct {
				name, sourceName, path string
				content                bool
				status                 int
			}{
				{"authorized metadata", "source1", "/public/allowed.txt", false, http.StatusOK},
				{"outside directory", outside.Name, "/", false, http.StatusForbidden},
				{"outside metadata", outside.Name, "/" + deniedName, false, http.StatusForbidden},
				{"outside content", outside.Name, "/" + deniedName, true, http.StatusForbidden},
				{"missing authorized file", "source1", "/not-present.txt", false, http.StatusNotFound},
				{"missing index stays server error", "not-configured-source", "/", false, http.StatusInternalServerError},
			} {
				t.Run(test.name, func(t *testing.T) {
					query := url.Values{"source": {test.sourceName}, "path": {test.path}, "skipExtendedAttrs": {"true"}}
					if test.content {
						query.Set("content", "true")
					}
					req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query.Encode(), nil)
					req.Header.Set("Authorization", "Bearer "+identity.token)
					response := httptest.NewRecorder()
					router.ServeHTTP(response, req)
					if response.Code != test.status {
						t.Errorf("status: got %d, want %d", response.Code, test.status)
					}
					if test.status == http.StatusOK {
						if !strings.Contains(response.Body.String(), "allowed.txt") {
							t.Fatal("authorized metadata missing")
						}
						return
					}
					assertNoOutsideData(t, response)
				})
			}
			for _, test := range []struct {
				name, sourceName, path string
				status                 int
			}{
				{"authorized download", "source1", "/public/allowed.txt", http.StatusOK},
				{"outside download", outside.Name, "/" + deniedName, http.StatusForbidden},
			} {
				t.Run(test.name, func(t *testing.T) {
					query := url.Values{"source": {test.sourceName}, "file": {test.path}}
					req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
					req.Header.Set("Authorization", "Bearer "+identity.token)
					response := httptest.NewRecorder()
					router.ServeHTTP(response, req)
					if response.Code != test.status {
						t.Errorf("status: got %d, want %d", response.Code, test.status)
					}
					if test.status == http.StatusOK {
						if response.Body.String() != "allowed synthetic bytes" {
							t.Fatal("authorized download content changed")
						}
					} else {
						assertNoOutsideData(t, response)
					}
				})
			}
		})
	}
}
