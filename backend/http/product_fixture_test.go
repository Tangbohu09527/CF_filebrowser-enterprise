package http

// This fixture starts only when explicitly selected and given a private output
// directory. It uses the real scoped HTTP/auth/audit routes and temporary DB/files.
import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProductMaterialsExternalFixture(t *testing.T) {
	output := os.Getenv("CF_PRODUCT_FIXTURE_DIR")
	if output == "" {
		t.Skip("external joint probe only")
	}
	output, err := filepath.Abs(output)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	env := newCoreFileAuditEnvironment(t)
	config.Server.ProductMaterialsUsers = []string{"core-file-audit-user"}
	server := httptest.NewTLSServer(newCoreFileAuditRouter(newAuditStoreStub()))
	defer server.Close()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	ca := filepath.Join(output, "fixture-ca.pem")
	token := filepath.Join(output, "fixture-token.txt")
	if err = os.WriteFile(ca, cert, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(token, []byte(env.token), 0600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(token)
	sum := sha256.Sum256(cert)
	config := map[string]any{"base_url": server.URL, "token_file": token, "ca_file": ca, "ca_sha256": hex.EncodeToString(sum[:]), "direct_connection": true, "audit_log": filepath.Join(output, "client-audit.jsonl"), "allowed_sources": map[string]any{"source1": map[string]any{"read_roots": []string{"/public"}, "write_roots": []string{"/public"}}}, "max_upload_bytes": 128 << 20, "max_download_bytes": 128 << 20, "max_checksum_bytes": 128 << 20, "timeout_seconds": 180}
	cfg := filepath.Join(output, "client-config.json")
	encoded, _ := json.Marshal(config)
	if err = os.WriteFile(cfg, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	ready, _ := json.Marshal(map[string]any{"url": server.URL, "source": "source1", "root": "/public", "config_path": cfg, "ca_file": ca, "source_path": env.sourcePath, "expires_utc": time.Now().UTC().Add(15 * time.Minute).Format(time.RFC3339)})
	if err = os.WriteFile(filepath.Join(output, "ready.json"), ready, 0600); err != nil {
		t.Fatal(err)
	}
	stop := filepath.Join(output, "stop")
	deadline := time.After(15 * time.Minute)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline:
			return
		case <-tick.C:
			if _, e := os.Stat(stop); e == nil {
				return
			}
		}
	}
}
