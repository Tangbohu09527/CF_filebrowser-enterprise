package filebridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadTokenAcceptsOnlyConfiguredSources(t *testing.T) {
	t.Run("environment", func(t *testing.T) {
		t.Setenv("FILEBROWSER_AGENT_TOKEN", testToken)
		got, err := LoadToken(&Config{}, false, bufio.NewReader(strings.NewReader("")))
		if err != nil || got != testToken {
			t.Fatalf("LoadToken environment = %q, %v", got, err)
		}
	})

	t.Run("stdin", func(t *testing.T) {
		t.Setenv("FILEBROWSER_AGENT_TOKEN", "")
		reader := bufio.NewReader(strings.NewReader(testToken + "\n{\"request_id\":\"req-after-token\"}"))
		got, err := LoadToken(&Config{}, true, reader)
		if err != nil || got != testToken {
			t.Fatalf("LoadToken stdin = %q, %v", got, err)
		}
		input, err := readInput("-", reader)
		if err != nil || input.RequestID != "req-after-token" {
			t.Fatalf("JSON after stdin token was not preserved: %+v, %v", input, err)
		}
	})

	t.Run("restricted file", func(t *testing.T) {
		t.Setenv("FILEBROWSER_AGENT_TOKEN", "")
		tokenFile := filepath.Join(t.TempDir(), "agent.token")
		if err := os.WriteFile(tokenFile, []byte(testToken+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := LoadToken(&Config{TokenFile: tokenFile}, false, bufio.NewReader(strings.NewReader("")))
		if err != nil || got != testToken {
			t.Fatalf("LoadToken file = %q, %v", got, err)
		}
	})

	if runtime.GOOS != "windows" {
		t.Run("open file rejected", func(t *testing.T) {
			t.Setenv("FILEBROWSER_AGENT_TOKEN", "")
			tokenFile := filepath.Join(t.TempDir(), "agent.token")
			if err := os.WriteFile(tokenFile, []byte(testToken), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := LoadToken(&Config{TokenFile: tokenFile}, false, bufio.NewReader(strings.NewReader("")))
			transferTestRequireBridgeError(t, err, "insecure_token_file")
		})
	}
}

func TestCLIRejectsTokenArgumentAndJSONField(t *testing.T) {
	if _, err := parseCLI([]string{"--config", "config.json", "--token", testToken, "ping"}); err == nil {
		t.Fatal("--token command-line argument was accepted")
	}
	_, err := readInput("-", bufio.NewReader(strings.NewReader(`{"token":"`+testToken+`"}`)))
	transferTestRequireBridgeError(t, err, "invalid_input")
}

func TestRunCLIReadsJSONAndTokenFromStdin(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path != "/api/resources" {
			t.Errorf("unexpected path: %s", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer "+testToken {
			t.Errorf("unexpected Authorization header")
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"name":"report.txt","type":"text/plain","size":5}`))
	}))
	defer server.Close()

	configFile := filepath.Join(t.TempDir(), "agentctl.json")
	configJSON := map[string]any{
		"base_url": server.URL,
		"allowed_sources": map[string]any{
			"documents": map[string]any{"read_roots": []string{"/read"}, "write_roots": []string{"/write"}},
		},
	}
	data, err := json.Marshal(configJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configFile, data, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := RunCLI(
		context.Background(),
		[]string{"--config", configFile, "--allow-localhost-http", "--token-stdin", "stat"},
		strings.NewReader(testToken+"\n"+`{"request_id":"req-cli","operation_id":"op-cli","source":"documents","path":"/read/report.txt"}`),
		&stdout,
		&stderr,
	)
	if exitCode != 0 || requests != 1 {
		t.Fatalf("RunCLI exit=%d requests=%d stdout=%s stderr=%s", exitCode, requests, stdout.String(), stderr.String())
	}
	var response Response
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
	if !response.OK || response.Command != "stat" || response.RequestID != "req-cli" || response.OperationID != "op-cli" {
		t.Fatalf("unexpected response: %+v", response)
	}
	if strings.Contains(stdout.String(), testToken) || strings.Contains(stderr.String(), testToken) {
		t.Fatal("token leaked into CLI output")
	}
}

func TestBaseURLRejectsMutableOrCredentialComponents(t *testing.T) {
	for _, raw := range []string{
		"https://user:pass@example.test/",
		"https://example.test/?target=other",
		"https://example.test/#fragment",
		"https://example.test/a/../b/",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := validateBaseURL(raw, false); err == nil {
				t.Fatalf("unsafe base URL was accepted: %s", raw)
			}
		})
	}
}
