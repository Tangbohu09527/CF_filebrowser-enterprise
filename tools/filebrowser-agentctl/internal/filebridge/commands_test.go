package filebridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestEffectivePermissions(t *testing.T) {
	t.Parallel()
	account := Permissions{
		API: true, Admin: true, Modify: true, Share: true, Realtime: true,
		Delete: true, Create: true, Browse: true, Preview: true, Download: true,
	}
	fullToken := commandTestToken(t, map[string]any{
		"name":               "hermes-filebridge",
		"belongsTo":          7,
		"permissionsVersion": 4,
		"Permissions": Permissions{
			Browse: true, Download: true, Create: true,
		},
	})
	effective, exact, source := effectivePermissions(account, fullToken)
	if !exact || source != "account_and_full_token_intersection" {
		t.Fatalf("unexpected full token provenance: exact=%v source=%q", exact, source)
	}
	if !effective.Browse || !effective.Download || !effective.Create {
		t.Fatalf("expected granted file permissions: %+v", effective)
	}
	if effective.API || effective.Admin || effective.Modify || effective.Delete || effective.Share || effective.Realtime || effective.Preview {
		t.Fatalf("full token expanded permissions: %+v", effective)
	}

	minimalToken := commandTestToken(t, map[string]any{"iat": 1, "exp": 4102444800})
	effective, exact, source = effectivePermissions(account, minimalToken)
	if !exact || source != "stateful_token_account_permissions" || effective != account {
		t.Fatalf("unexpected minimal token result: exact=%v source=%q permissions=%+v", exact, source, effective)
	}

	legacyToken := commandTestToken(t, map[string]any{
		"belongsTo":   7,
		"Permissions": Permissions{Browse: true},
	})
	effective, exact, source = effectivePermissions(account, legacyToken)
	if exact || source != "conservative_unknown_token" || effective != (Permissions{}) {
		t.Fatalf("ambiguous token was not handled conservatively: exact=%v source=%q permissions=%+v", exact, source, effective)
	}
}

func TestCapabilitiesAndSourcesUseTokenAndLocalIntersections(t *testing.T) {
	t.Parallel()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/fb/api/users":
			writeCommandTestJSON(t, writer, map[string]any{
				"id": 17, "username": "hermes-agent",
				"permissions": Permissions{API: true, Browse: true, Download: true, Create: true, Admin: true},
				"scopes":      []Scope{{Name: "Enterprise", Scope: "/hermes"}, {Name: "Private", Scope: "/"}},
			})
		case "/fb/api/settings/sources":
			writeCommandTestJSON(t, writer, map[string]any{
				"Enterprise": map[string]any{"name": "Enterprise", "readOnly": false, "private": true, "status": "ready", "numFiles": 4},
				"Private":    map[string]any{"name": "Private", "readOnly": false, "status": "ready"},
			})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	token := commandTestToken(t, map[string]any{
		"name": "hermes-filebridge", "belongsTo": 17, "permissionsVersion": 4,
		"Permissions": Permissions{Browse: true, Download: true, Create: true},
	})
	runner := commandTestRunner(t, server.URL+"/fb/", token)
	input := Input{RequestID: "req-capabilities", OperationID: "op-capabilities"}
	capabilities := runner.Run(context.Background(), "capabilities", input, false)
	if !capabilities.OK {
		t.Fatalf("capabilities failed: %+v", capabilities.Error)
	}
	result := capabilities.Result.(CapabilitiesResult)
	if result.Username != "hermes-agent" || !result.CapabilitiesExact || result.PermissionSource != "account_and_full_token_intersection" {
		t.Fatalf("unexpected capabilities: %+v", result)
	}
	if result.Permissions.Admin || result.Permissions.API || !result.Permissions.Browse || len(result.Sources) != 1 || result.Sources[0].Name != "Enterprise" {
		t.Fatalf("capabilities were not intersected: %+v", result)
	}

	sources := runner.Run(context.Background(), "sources", input, false)
	if !sources.OK {
		t.Fatalf("sources failed: %+v", sources.Error)
	}
	sourceResult := sources.Result.(SourcesResult)
	if len(sourceResult.Sources) != 1 || sourceResult.Sources[0].Name != "Enterprise" || !sourceResult.Sources[0].Available {
		t.Fatalf("unexpected locally filtered sources: %+v", sourceResult)
	}
	if sourceResult.Sources[0].Info == nil || sourceResult.Sources[0].Info.NumFiles != 4 || sourceResult.Sources[0].Info.Private != true {
		t.Fatalf("unexpected stable source info: %+v", sourceResult.Sources[0].Info)
	}
}

func TestReadOnlyCommandContracts(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Has("auth") {
			t.Errorf("token appeared in query: %s", request.URL.RawQuery)
		}
		switch request.URL.Path {
		case "/fb/api/resources":
			resourcePath := request.URL.Query().Get("path")
			if resourcePath == "/allowed" {
				writeCommandTestJSON(t, writer, map[string]any{
					"name": "allowed", "type": "directory", "path": "/allowed",
					"files":   []map[string]any{{"name": "b.txt", "size": 5, "modified": "2026-01-02T03:04:05Z", "type": "text/plain"}},
					"folders": []map[string]any{{"name": "a", "type": "directory"}},
				})
				return
			}
			if resourcePath == "/allowed/b.txt" {
				response := map[string]any{"name": "b.txt", "size": 5, "modified": "2026-01-02T03:04:05Z", "type": "text/plain"}
				if request.URL.Query().Get("checksum") == "sha256" {
					response["checksums"] = map[string]string{"sha256": "abc123"}
				}
				writeCommandTestJSON(t, writer, response)
				return
			}
			http.NotFound(writer, request)
		case "/fb/api/tools/search":
			if request.URL.Query().Get("query") != "" || request.URL.Query().Get("terms") != "invoice" {
				t.Errorf("search did not use literal terms: %s", request.URL.RawQuery)
			}
			if request.Header.Get("SessionId") != "req-read-commands" {
				t.Errorf("unexpected SessionId: %q", request.Header.Get("SessionId"))
			}
			writeCommandTestJSON(t, writer, []map[string]any{
				{"path": "/first.txt", "source": "Enterprise", "type": "text/plain", "size": 1},
				{"path": "/second.txt", "source": "Enterprise", "type": "text/plain", "size": 2},
			})
		case "/fb/api/resources/download":
			writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = ioWriteString(writer, "hello")
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	runner := commandTestRunner(t, server.URL+"/fb/", commandTestToken(t, map[string]any{"iat": 1, "exp": 4102444800}))
	baseInput := Input{RequestID: "req-read-commands", OperationID: "op-read-commands", Source: "Enterprise"}

	listInput := baseInput
	listInput.Path = "/allowed"
	listResponse := runner.Run(context.Background(), "list", listInput, false)
	if !listResponse.OK {
		t.Fatalf("list failed: %+v", listResponse.Error)
	}
	listResult := listResponse.Result.(ListResult)
	if len(listResult.Files) != 1 || listResult.Files[0].Path != "/allowed/b.txt" || len(listResult.Folders) != 1 || listResult.Folders[0].Path != "/allowed/a" {
		t.Fatalf("unexpected list result: %+v", listResult)
	}

	searchInput := baseInput
	searchInput.Path = "/allowed"
	searchInput.Query = "invoice"
	searchInput.Limit = 1
	searchResponse := runner.Run(context.Background(), "search", searchInput, false)
	if !searchResponse.OK {
		t.Fatalf("search failed: %+v", searchResponse.Error)
	}
	searchResult := searchResponse.Result.(SearchResult)
	if len(searchResult.Items) != 1 || !searchResult.Truncated || searchResult.Items[0].Path != "/allowed/first.txt" {
		t.Fatalf("unexpected search result: %+v", searchResult)
	}

	statInput := baseInput
	statInput.Path = "/allowed/b.txt"
	statResponse := runner.Run(context.Background(), "stat", statInput, false)
	if !statResponse.OK || statResponse.Result.(StatResult).Item.Size != 5 {
		t.Fatalf("unexpected stat response: %+v", statResponse)
	}
	checksumResponse := runner.Run(context.Background(), "checksum", statInput, false)
	if !checksumResponse.OK || checksumResponse.Result.(StatResult).Checksums["sha256"] != "abc123" {
		t.Fatalf("unexpected checksum response: %+v", checksumResponse)
	}

	readResponse := runner.Run(context.Background(), "read", statInput, false)
	if !readResponse.OK {
		t.Fatalf("read failed: %+v", readResponse.Error)
	}
	readResult := readResponse.Result.(ReadResult)
	if readResult.Content != "hello" || readResult.Encoding != "utf-8" || !readResult.Untrusted || readResult.Bytes != 5 {
		t.Fatalf("unexpected read result: %+v", readResult)
	}
}

func commandTestRunner(t *testing.T, baseURL, token string) *Runner {
	t.Helper()
	config := &Config{
		BaseURL: baseURL,
		AllowedSources: map[string]SourcePolicy{
			"Enterprise": {ReadRoots: []string{"/allowed"}, WriteRoots: []string{"/write"}},
		},
	}
	if err := config.applyDefaultsAndValidate(true); err != nil {
		t.Fatalf("validate test config: %v", err)
	}
	return NewRunner(config, NewClient(config, token), &AuditLogger{writer: &bytes.Buffer{}})
}

func commandTestToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal token claims: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func writeCommandTestJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func ioWriteString(writer http.ResponseWriter, value string) (int, error) {
	return fmt.Fprint(writer, value)
}

func TestEndpointURLPreservesConfiguredBasePath(t *testing.T) {
	t.Parallel()
	parsed, err := validateBaseURL("https://example.test/filebrowser/", false)
	if err != nil {
		t.Fatal(err)
	}
	config := &Config{parsedBaseURL: parsed}
	client := &Client{config: config}
	got, err := url.Parse(client.endpointURL("api/resources", url.Values{"path": []string{"/a b"}}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "/filebrowser/api/resources" || got.Query().Get("path") != "/a b" {
		t.Fatalf("unexpected endpoint URL: %s", got)
	}
}

func TestCommandInputRejectsIrrelevantAndOversizedFields(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		t.Errorf("validation failure sent an HTTP request: %s", request.URL)
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	runner := commandTestRunner(t, server.URL, commandTestToken(t, map[string]any{"iat": 1, "exp": 4102444800}))

	response := runner.Run(context.Background(), "ping", Input{
		RequestID: "req-extra", OperationID: "op-extra", Source: "Enterprise",
	}, false)
	if response.OK || response.Error == nil || response.Error.Code != "invalid_input" {
		t.Fatalf("irrelevant field was accepted: %+v", response)
	}

	response = runner.Run(context.Background(), "search", Input{
		RequestID: "req-long", OperationID: "op-long", Source: "Enterprise", Path: "/allowed",
		Query: strings.Repeat("x", maxSearchQueryBytes+1),
	}, false)
	if response.OK || response.Error == nil || response.Error.Code != "invalid_input" {
		t.Fatalf("oversized query was accepted: %+v", response)
	}

	response = runner.Run(context.Background(), "upload-new", Input{
		RequestID: "req-approval", OperationID: "op-approval", Source: "Enterprise", Path: "/write/new.txt",
		LocalFile: "ignored-before-I/O",
	}, true)
	if response.OK || response.Error == nil || response.Error.Code != "invalid_input" {
		t.Fatalf("upload apply without approved bytes/hash was accepted: %+v", response)
	}

	response = runner.Run(context.Background(), "mkdir", Input{
		RequestID: "req-mkdir-op", Source: "Enterprise", Path: "/write/new",
	}, true)
	if response.OK || response.Error == nil || response.Error.Code != "invalid_input" {
		t.Fatalf("write apply without operation_id was accepted: %+v", response)
	}
}
