package filebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "header.payload.signature"

func TestPingDoesNotSendTokenToPublicHealthEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "" {
			t.Errorf("public health request received Authorization header: %q", got)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"message":"ok"}`))
	}))
	defer server.Close()

	config := newSecurityTestConfig(t, server.URL, true, nil)
	if _, err := NewClient(config, testToken).ping(context.Background(), "req-health"); err != nil {
		t.Fatalf("ping() error = %v", err)
	}
}

func TestTokenUsesAuthorizationHeaderWithoutQueryAuthentication(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if got, want := request.Header.Get("Authorization"), "Bearer "+testToken; got != want {
			t.Errorf("Authorization header = %q, want %q", got, want)
		}
		if strings.Contains(request.RequestURI, testToken) {
			t.Errorf("request URI contains token: %q", request.RequestURI)
		}
		for name, values := range request.URL.Query() {
			if strings.Contains(strings.ToLower(name), "token") || strings.Contains(strings.ToLower(name), "auth") {
				t.Errorf("authentication-like query parameter %q is not allowed", name)
			}
			for _, value := range values {
				if value == testToken || value == "Bearer "+testToken {
					t.Errorf("query parameter %q contains token", name)
				}
			}
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"name":"report.txt","type":"file","size":7}`))
	}))
	defer server.Close()

	config := newSecurityTestConfig(t, server.URL, true, nil)
	client := NewClient(config, testToken)
	if _, err := client.getResource(context.Background(), "req-header", "documents", "/read/report.txt", ""); err != nil {
		t.Fatalf("getResource() error = %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("request count = %d, want 1", got)
	}
}

func TestAuditAndErrorOutputDoNotContainToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"message":"` + strings.Repeat("A", 500) + testToken + `"}`))
	}))
	defer server.Close()

	config := newSecurityTestConfig(t, server.URL, true, nil)
	var auditOutput bytes.Buffer
	runner := NewRunner(config, NewClient(config, testToken), &AuditLogger{writer: &auditOutput})
	response := runner.Run(context.Background(), "ping", Input{
		RequestID:   "req-redaction",
		OperationID: "op-redaction",
	}, false)
	if response.OK || response.Error == nil || response.Error.Code != "unauthorized" {
		t.Fatalf("response = %#v, want unauthorized failure", response)
	}

	encodedResponse, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("json.Marshal(response) error = %v", err)
	}
	for name, output := range map[string]string{
		"audit log":  string(auditOutput.Bytes()),
		"JSON error": string(encodedResponse),
	} {
		if strings.Contains(output, testToken) {
			t.Errorf("%s leaked token: %q", name, output)
		}
		if strings.Contains(output, "header.pay") {
			t.Errorf("%s leaked a token prefix: %q", name, output)
		}
	}
}

func TestBaseURLTransportPolicy(t *testing.T) {
	tests := []struct {
		name               string
		baseURL            string
		allowLocalhostHTTP bool
		wantCode           string
	}{
		{name: "https", baseURL: "https://files.example.test/filebrowser", wantCode: ""},
		{name: "remote http", baseURL: "http://files.example.test", allowLocalhostHTTP: true, wantCode: "insecure_base_url"},
		{name: "localhost requires opt in", baseURL: "http://localhost:8080", wantCode: "insecure_base_url"},
		{name: "localhost development exception", baseURL: "http://localhost:8080", allowLocalhostHTTP: true, wantCode: ""},
		{name: "ipv4 loopback development exception", baseURL: "http://127.0.0.1:8080", allowLocalhostHTTP: true, wantCode: ""},
		{name: "ipv6 loopback development exception", baseURL: "http://[::1]:8080", allowLocalhostHTTP: true, wantCode: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateBaseURL(test.baseURL, test.allowLocalhostHTTP)
			if test.wantCode == "" {
				if err != nil {
					t.Fatalf("validateBaseURL() error = %v", err)
				}
				return
			}
			assertSecurityBridgeError(t, err, test.wantCode, 0, false)
		})
	}
}

func TestRemoteAllowlistSeparatesReadAndWriteRoots(t *testing.T) {
	config := newSecurityTestConfig(t, "https://files.example.test", false, nil)
	tests := []struct {
		name     string
		source   string
		path     string
		mode     accessMode
		wantPath string
		wantCode string
	}{
		{name: "read root", source: "documents", path: "/read", mode: readAccess, wantPath: "/read"},
		{name: "read child", source: "documents", path: "/read/reports/q1.txt", mode: readAccess, wantPath: "/read/reports/q1.txt"},
		{name: "read prefix boundary", source: "documents", path: "/readonly/report.txt", mode: readAccess, wantCode: "path_denied"},
		{name: "read cannot use write root", source: "documents", path: "/write/new.txt", mode: readAccess, wantCode: "path_denied"},
		{name: "write root", source: "documents", path: "/write", mode: writeAccess, wantPath: "/write"},
		{name: "write child", source: "documents", path: "/write/new.txt", mode: writeAccess, wantPath: "/write/new.txt"},
		{name: "write cannot use read root", source: "documents", path: "/read/report.txt", mode: writeAccess, wantCode: "path_denied"},
		{name: "unknown source", source: "private", path: "/read/report.txt", mode: readAccess, wantCode: "source_denied"},
		{name: "traversal", source: "documents", path: "/read/../write/new.txt", mode: readAccess, wantCode: "invalid_path"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := config.authorizeRemote(test.source, test.path, test.mode)
			if test.wantCode != "" {
				assertSecurityBridgeError(t, err, test.wantCode, 0, false)
				return
			}
			if err != nil {
				t.Fatalf("authorizeRemote() error = %v", err)
			}
			if got != test.wantPath {
				t.Fatalf("authorizeRemote() = %q, want %q", got, test.wantPath)
			}
		})
	}
}

func TestHTTPAuthorizationFailuresArePreserved(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		wantCode    string
		wantMessage string
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, wantCode: "unauthorized", wantMessage: "FileBrowser rejected the token"},
		{name: "forbidden", status: http.StatusForbidden, wantCode: "forbidden", wantMessage: "FileBrowser denied this operation"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				writer.WriteHeader(test.status)
			}))
			defer server.Close()

			config := newSecurityTestConfig(t, server.URL, true, nil)
			_, err := NewClient(config, testToken).ping(context.Background(), "req-authz")
			bridgeErr := assertSecurityBridgeError(t, err, test.wantCode, test.status, false)
			if bridgeErr.Message != test.wantMessage {
				t.Errorf("error message = %q, want %q", bridgeErr.Message, test.wantMessage)
			}
			if got := requests.Load(); got != 1 {
				t.Errorf("request count = %d, want 1", got)
			}
		})
	}
}

func TestRateLimitRetryCountIsBounded(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writer.Header().Set("Retry-After", "0")
		writer.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	const maxRetries = 2
	config := newSecurityTestConfig(t, server.URL, true, func(config *Config) {
		config.MaxRetries = maxRetries
		config.RetryDelayMillis = 1
		config.MaxRetryDelaySeconds = 1
	})
	_, err := NewClient(config, testToken).ping(context.Background(), "req-rate-limit")
	assertSecurityBridgeError(t, err, "rate_limited", http.StatusTooManyRequests, true)
	if got, want := requests.Load(), int32(maxRetries+1); got != want {
		t.Fatalf("request count = %d, want bounded count %d", got, want)
	}
}

func TestRequestTimeoutIsReportedAsRetryable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
			return
		case <-time.After(2 * time.Second):
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(`{"status":"late"}`))
		}
	}))
	defer server.Close()

	config := newSecurityTestConfig(t, server.URL, true, nil)
	client := NewClient(config, testToken)
	client.httpClient.Timeout = 25 * time.Millisecond
	started := time.Now()
	_, err := client.ping(context.Background(), "req-timeout")
	assertSecurityBridgeError(t, err, "timeout", 0, true)
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("timeout took %s, want less than 1s", elapsed)
	}
}

func TestDangerousCommandsAreRejectedBeforeConfigurationLoad(t *testing.T) {
	commands := []string{
		"delete", "share", "token", "tokens", "user", "users", "acl", "http", "request",
		"shell", "exec", "move", "rename", "overwrite",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			exitCode := RunCLI(
				context.Background(),
				[]string{"--config", t.TempDir() + "/missing.json", command},
				strings.NewReader(""),
				&stdout,
				&stderr,
			)
			if exitCode != 2 {
				t.Fatalf("RunCLI() exit code = %d, want 2", exitCode)
			}
			var response Response
			if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
				t.Fatalf("RunCLI() output is not JSON: %v; output = %q", err, stdout.String())
			}
			if response.OK || response.Command != command || response.Error == nil || response.Error.Code != "dangerous_command" {
				t.Errorf("RunCLI() response = %#v, want dangerous_command rejection", response)
			}
			if stderr.Len() != 0 {
				t.Errorf("RunCLI() stderr = %q, want empty", stderr.String())
			}
		})
	}
}

func TestJSONResponseEncodingIsStable(t *testing.T) {
	response := Response{
		SchemaVersion: SchemaVersion,
		OK:            false,
		Command:       "list",
		RequestID:     "req-fixed",
		OperationID:   "op-fixed",
		DryRun:        false,
		Error: &ErrorResponse{
			Code:       "forbidden",
			Message:    "FileBrowser denied this operation",
			HTTPStatus: http.StatusForbidden,
			Retryable:  false,
		},
	}
	var output bytes.Buffer
	writeResponse(&output, response)
	want := `{"schema_version":"filebrowser-agentctl/v1","ok":false,"command":"list","request_id":"req-fixed","operation_id":"op-fixed","dry_run":false,"error":{"code":"forbidden","message":"FileBrowser denied this operation","http_status":403,"retryable":false}}` + "\n"
	if got := output.String(); got != want {
		t.Fatalf("writeResponse() = %q, want %q", got, want)
	}
}

func newSecurityTestConfig(t *testing.T, baseURL string, allowLocalhostHTTP bool, modify func(*Config)) *Config {
	t.Helper()
	config := &Config{
		BaseURL: baseURL,
		AllowedSources: map[string]SourcePolicy{
			"documents": {
				ReadRoots:  []string{"/read"},
				WriteRoots: []string{"/write"},
			},
		},
	}
	if modify != nil {
		modify(config)
	}
	if err := config.applyDefaultsAndValidate(allowLocalhostHTTP); err != nil {
		t.Fatalf("applyDefaultsAndValidate() error = %v", err)
	}
	return config
}

func assertSecurityBridgeError(t *testing.T, err error, code string, httpStatus int, retryable bool) *BridgeError {
	t.Helper()
	var bridgeErr *BridgeError
	if !asBridgeError(err, &bridgeErr) {
		t.Fatalf("error = %v, want *BridgeError with code %q", err, code)
	}
	if bridgeErr.Code != code || bridgeErr.HTTPStatus != httpStatus || bridgeErr.Retryable != retryable {
		t.Fatalf("BridgeError = %#v, want code=%q http_status=%d retryable=%t", bridgeErr, code, httpStatus, retryable)
	}
	return bridgeErr
}
