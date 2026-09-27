package inbound

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const syntheticAuthorization = "Bearer synthetic-inbound-private-capability"

func strptr(value string) *string { return &value }

func inboundTLS(t *testing.T, wrongHost bool, handler http.Handler) (*httptest.Server, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Isolated inbound test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	if wrongHost {
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.2")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certificate, err := tls.X509KeyPair(ca, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	caPath := filepath.Join(t.TempDir(), "test-ca.pem")
	if err := os.WriteFile(caPath, ca, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(ca)
	return server, caPath, hex.EncodeToString(h[:])
}

func inboundBinding(t *testing.T, server *httptest.Server, caFile, caHash string, body []byte) Binding {
	t.Helper()
	dir := t.TempDir()
	ensureTestPrivateStore(t, dir)
	h := sha256.Sum256(body)
	return Binding{DispatchID: "dispatch-1", TaskID: "task-1", ThreadID: "thread-1", EnterpriseIdentityID: "identity-1", WorkDir: dir, GatewayOrigin: server.URL, ExpiresAt: time.Now().Add(time.Minute), MaxBytes: 1 << 20, CAFile: caFile, CASHA256: caHash, Attachments: []Descriptor{{Schema: "cf-inbound-read/v1", MessageID: 1, AttachmentID: 2, ThreadID: "thread-1", EnterpriseIdentityID: "identity-1", URL: server.URL + "/inbound-media/12/content", Authorization: syntheticAuthorization, ExpiresAt: time.Now().Add(time.Minute), Size: int64(len(body)), SHA256: hex.EncodeToString(h[:]), MIMEType: "application/pdf", Filename: strptr("report.pdf"), DeclaredQuality: strptr("full"), OriginalComparison: "not_checked", DownloadPolicy: DownloadPolicy{MaxAttempts: 4, TotalTimeoutSeconds: 30, RetryableStatusCodes: []int{503}, RetryAfterSeconds: 1}}}}
}

func inboundEngine(t *testing.T, b Binding) *Engine {
	t.Helper()
	e, err := New(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

func assertFailure(t *testing.T, result Result, code string) {
	t.Helper()
	if result.OK || result.Verified || result.Handle != "" || result.Error == nil || (code != "" && result.Error.Code != code) {
		t.Fatalf("unexpected result: %+v", result)
	}
	encoded, _ := json.Marshal(result)
	if bytes.Contains(encoded, []byte(syntheticAuthorization)) || bytes.Contains(encoded, []byte("private-capability")) {
		t.Fatal("capability leaked in result")
	}
}

func assertNoWorkFiles(t *testing.T, b Binding) {
	t.Helper()
	files, err := os.ReadDir(b.WorkDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "pending-") || strings.HasPrefix(file.Name(), "work-") {
			t.Fatalf("failed download left file %q", file.Name())
		}
	}
}

func TestDownloadRealHTTPSPDFAndJPEG(t *testing.T) {
	for _, test := range []struct {
		name, mime string
		body       []byte
	}{{"PDF", "application/pdf", []byte("%PDF-1.7\nsynthetic bytes\n%%EOF")}, {"JPEG", "image/jpeg", []byte{0xff, 0xd8, 0xff, 0xe0, 0, 4, 0, 0, 0xff, 0xd9}}} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server, ca, hash := inboundTLS(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "GET" || r.URL.Path != "/inbound-media/12/content" || r.Header.Get("Authorization") != syntheticAuthorization {
					t.Error("unexpected request")
				}
				w.Header().Set("Content-Type", test.mime)
				_, _ = w.Write(test.body)
			}))
			b := inboundBinding(t, server, ca, hash, test.body)
			b.Attachments[0].MIMEType = test.mime
			b.Attachments[0].Filename = strptr("../../..\\other-task\\escape.pdf")
			e := inboundEngine(t, b)
			r := e.Download(context.Background(), 2)
			if !r.OK || !r.Verified || r.FormalArchive || r.BytesWritten != int64(len(test.body)) || r.SHA256 != b.Attachments[0].SHA256 || r.OriginalComparison != "not_checked" || (r.DeclaredQuality == nil || *r.DeclaredQuality != "full") || r.TaskID != "task-1" || r.DispatchID != "dispatch-1" {
				t.Fatalf("result: %+v", r)
			}
			f, err := e.Resolve(context.Background(), r.Handle)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(f)
			_ = f.Close()
			if err != nil || !bytes.Equal(got, test.body) {
				t.Fatal("handle did not resolve to verified bytes")
			}
			for range 3 {
				if duplicate := e.Download(context.Background(), 2); duplicate.Handle != r.Handle || !duplicate.OK {
					t.Fatal("repeat did not reuse copy")
				}
			}
			if calls.Load() != 1 {
				t.Fatal("repeat made another HTTP request")
			}
			encoded, _ := json.Marshal(r)
			if bytes.Contains(encoded, []byte(b.WorkDir)) || bytes.Contains(encoded, []byte("escape.pdf")) || bytes.Contains(encoded, []byte(syntheticAuthorization)) {
				t.Fatal("sensitive input echoed")
			}
			if _, err := e.Resolve(context.Background(), "inbound:unknown"); err == nil {
				t.Fatal("unknown handle accepted")
			}
			e.Close()
			if _, err := e.Resolve(context.Background(), r.Handle); err == nil {
				t.Fatal("ended dispatch resolved handle")
			}
		})
	}
}

func TestDownload503ThenSuccess(t *testing.T) {
	body := []byte("%PDF-success")
	var calls atomic.Int32
	server, ca, hash := inboundTLS(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write(body)
	}))
	b := inboundBinding(t, server, ca, hash, body)
	e := inboundEngine(t, b)
	start := time.Now()
	r := e.Download(context.Background(), 2)
	if !r.OK || calls.Load() != 2 || time.Since(start) < time.Second {
		t.Fatalf("retry result=%+v calls=%d", r, calls.Load())
	}
}

func TestDownloadConcurrentAndRepeatedShareFourAttempts(t *testing.T) {
	var calls atomic.Int32
	server, ca, hash := inboundTLS(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "invalid")
		w.WriteHeader(503)
	}))
	b := inboundBinding(t, server, ca, hash, []byte("test"))
	e := inboundEngine(t, b)
	var wg sync.WaitGroup
	results := make(chan Result, 12)
	for range 12 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- e.Download(context.Background(), 2) }()
	}
	wg.Wait()
	close(results)
	for r := range results {
		assertFailure(t, r, "temporarily_unavailable")
	}
	assertFailure(t, e.Download(context.Background(), 2), "temporarily_unavailable")
	if calls.Load() != 4 {
		t.Fatalf("attempt budget reset: %d", calls.Load())
	}
	assertNoWorkFiles(t, b)
}

func TestDownloadDeadlinesAndCancellation(t *testing.T) {
	for _, kind := range []string{"read-timeout", "retry-after-budget", "dispatch-cancel", "credential-expired", "dispatch-expired"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			entered := make(chan struct{}, 1)
			server, ca, hash := inboundTLS(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				select {
				case entered <- struct{}{}:
				default:
				}
				if kind == "retry-after-budget" {
					w.Header().Set("Retry-After", "300")
					w.WriteHeader(503)
					return
				}
				w.Header().Set("Content-Length", "100")
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			b := inboundBinding(t, server, ca, hash, make([]byte, 100))
			if kind == "credential-expired" {
				b.Attachments[0].ExpiresAt = time.Now().Add(-time.Second)
			}
			if kind == "dispatch-expired" {
				b.ExpiresAt = time.Now().Add(-time.Second)
				if _, err := New(context.Background(), b); err == nil {
					t.Fatal("expired dispatch initialized")
				}
				return
			}
			if kind == "read-timeout" {
				b.Attachments[0].ExpiresAt = time.Now().Add(150 * time.Millisecond)
			}
			e := inboundEngine(t, b)
			if kind == "dispatch-cancel" {
				go func() { <-entered; e.Close() }()
			}
			start := time.Now()
			r := e.Download(context.Background(), 2)
			assertFailure(t, r, "")
			if time.Since(start) > 3*time.Second {
				t.Fatal("deadline or cancellation ignored")
			}
			if kind == "credential-expired" && calls.Load() != 0 {
				t.Fatal("expired credential sent")
			}
			e.Close()
			assertNoWorkFiles(t, b)
			before := calls.Load()
			assertFailure(t, e.Download(context.Background(), 2), "")
			if calls.Load() != before {
				t.Fatal("terminal state retried")
			}
		})
	}
}

func TestDownloadNonRetryableAndIntegrity(t *testing.T) {
	for _, kind := range []string{"403", "404", "429", "500", "redirect", "truncated", "oversized", "wrong-hash", "encoded"} {
		t.Run(kind, func(t *testing.T) {
			body := []byte("%PDF-complete")
			var calls atomic.Int32
			var redirected atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
			defer target.Close()
			server, ca, hash := inboundTLS(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if status, err := strconv.Atoi(kind); err == nil {
					w.WriteHeader(status)
					return
				}
				switch kind {
				case "redirect":
					w.Header().Set("Location", target.URL)
					w.WriteHeader(302)
				case "truncated":
					w.Header().Set("Content-Length", strconv.Itoa(len(body)))
					_, _ = w.Write(body[:3])
				case "oversized":
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
					_, _ = w.Write(append(body, []byte("extra")...))
				case "encoded":
					w.Header().Set("Content-Encoding", "gzip")
					_, _ = w.Write(body)
				default:
					_, _ = w.Write(body)
				}
			}))
			b := inboundBinding(t, server, ca, hash, body)
			if kind == "wrong-hash" {
				b.Attachments[0].SHA256 = strings.Repeat("0", 64)
			}
			e := inboundEngine(t, b)
			r := e.Download(context.Background(), 2)
			assertFailure(t, r, "")
			assertFailure(t, e.Download(context.Background(), 2), "")
			if calls.Load() != 1 || redirected.Load() != 0 {
				t.Fatal("non-retryable response retried or redirected")
			}
			e.Close()
			assertNoWorkFiles(t, b)
		})
	}
}

func TestDownloadUnknownCAAndWrongHostname(t *testing.T) {
	for _, wrongHost := range []bool{false, true} {
		t.Run(strconv.FormatBool(wrongHost), func(t *testing.T) {
			var calls atomic.Int32
			server, ca, hash := inboundTLS(t, wrongHost, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
			b := inboundBinding(t, server, ca, hash, []byte("x"))
			if !wrongHost {
				b.CAFile = ""
				b.CASHA256 = ""
			}
			e := inboundEngine(t, b)
			assertFailure(t, e.Download(context.Background(), 2), "transport_failed")
			assertFailure(t, e.Download(context.Background(), 2), "transport_failed")
			if calls.Load() != 0 {
				t.Fatal("unverified TLS sent HTTP request")
			}
			assertNoWorkFiles(t, b)
		})
	}
}

func TestDownloadRejectsUntrustedDescriptorAndBinding(t *testing.T) {
	server, ca, hash := inboundTLS(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("invalid descriptor reached network") }))
	for _, kind := range []string{"identity", "thread", "schema", "policy", "attempts", "timeout", "backoff", "archive", "size", "maxbytes", "digest", "authorization", "url-origin", "url-path", "url-query", "url-escape", "url-user", "origin-http", "ca-hash", "duplicate", "empty-task"} {
		t.Run(kind, func(t *testing.T) {
			b := inboundBinding(t, server, ca, hash, []byte("x"))
			d := &b.Attachments[0]
			switch kind {
			case "identity":
				d.EnterpriseIdentityID = "another"
			case "thread":
				d.ThreadID = "another"
			case "schema":
				d.Schema = "cf-inbound-read/v2"
			case "policy":
				d.DownloadPolicy.RetryableStatusCodes = []int{403}
			case "attempts":
				d.DownloadPolicy.MaxAttempts = 5
			case "timeout":
				d.DownloadPolicy.TotalTimeoutSeconds = 31
			case "backoff":
				d.DownloadPolicy.RetryAfterSeconds = 0
			case "archive":
				d.FormalArchive = true
			case "size":
				d.Size = b.MaxBytes + 1
			case "maxbytes":
				b.MaxBytes = maxDownloadBytes + 1
			case "digest":
				d.SHA256 = strings.Repeat("A", 64)
			case "authorization":
				d.Authorization += "\r\nX-Leak: value"
			case "url-origin":
				d.URL = "https://other.invalid/inbound-media/12/content"
			case "url-path":
				d.URL = server.URL + "/api/resources"
			case "url-query":
				d.URL += "?token=secret"
			case "url-escape":
				d.URL = server.URL + "/inbound-media/%31%32/content"
			case "url-user":
				d.URL = strings.Replace(d.URL, "https://", "https://user@", 1)
			case "origin-http":
				b.GatewayOrigin = "http://127.0.0.1"
			case "ca-hash":
				b.CASHA256 = strings.Repeat("0", 64)
			case "duplicate":
				b.Attachments = append(b.Attachments, *d)
			case "empty-task":
				b.TaskID = ""
			}
			if e, err := New(context.Background(), b); err == nil {
				e.Close()
				t.Fatal("invalid descriptor/binding accepted")
			}
		})
	}
}

func TestDownloadHandleDetectsModifiedBytes(t *testing.T) {
	body := []byte("%PDF-original")
	server, ca, hash := inboundTLS(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
	b := inboundBinding(t, server, ca, hash, body)
	e := inboundEngine(t, b)
	r := e.Download(context.Background(), 2)
	if !r.OK {
		t.Fatalf("download: %+v", r)
	}
	path := filepath.Join(b.WorkDir, e.states[2].name)
	if err := os.WriteFile(path, []byte("%PDF-tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if f, err := e.Resolve(context.Background(), r.Handle); err == nil {
		f.Close()
		t.Fatal("modified work copy accepted")
	}
	assertFailure(t, e.Download(context.Background(), 2), "integrity_failed")
}

func TestDescriptorJSONRequiresContractFields(t *testing.T) {
	server, ca, hash := inboundTLS(t, false, http.NotFoundHandler())
	b := inboundBinding(t, server, ca, hash, []byte("%PDF"))
	b.Attachments[0].Filename = nil
	b.Attachments[0].DeclaredQuality = nil
	raw, err := json.Marshal(b.Attachments[0])
	if err != nil {
		t.Fatal(err)
	}
	var valid Descriptor
	if err := json.Unmarshal(raw, &valid); err != nil || valid.Filename != nil || valid.DeclaredQuality != nil {
		t.Fatal("Gateway nullable metadata not preserved")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for field := range fields {
		t.Run(field, func(t *testing.T) {
			copy := make(map[string]json.RawMessage, len(fields))
			for key, value := range fields {
				copy[key] = value
			}
			delete(copy, field)
			missing, _ := json.Marshal(copy)
			var got Descriptor
			if err := json.Unmarshal(missing, &got); err == nil {
				t.Fatal("missing contract field accepted")
			}
			if field != "filename" && field != "declared_quality" {
				copy[field] = json.RawMessage("null")
				null, _ := json.Marshal(copy)
				if err := json.Unmarshal(null, &got); err == nil {
					t.Fatal("null required contract field accepted")
				}
			}
		})
	}
	fields["unknown"] = json.RawMessage(`"synthetic-secret"`)
	unknown, _ := json.Marshal(fields)
	if err := json.Unmarshal(unknown, &valid); err == nil {
		t.Fatal("unknown descriptor field accepted")
	}
}

func TestDownloadAlreadyCancelledDoesNotSend(t *testing.T) {
	var calls atomic.Int32
	server, ca, hash := inboundTLS(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	b := inboundBinding(t, server, ca, hash, []byte("test"))
	e := inboundEngine(t, b)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assertFailure(t, e.Download(ctx, 2), "task_cancelled")
	if calls.Load() != 0 || e.states[2].done != nil {
		t.Fatal("cancelled call started a download")
	}
}

func TestDownloadPreservesNullQualityAndDifferentComparison(t *testing.T) {
	body := []byte("%PDF-file")
	server, ca, hash := inboundTLS(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
	b := inboundBinding(t, server, ca, hash, body)
	b.Attachments[0].DeclaredQuality = nil
	b.Attachments[0].OriginalComparison = "different"
	r := inboundEngine(t, b).Download(context.Background(), 2)
	if !r.OK || r.DeclaredQuality != nil || r.OriginalComparison != "different" {
		t.Fatalf("source claim was changed: %+v", r)
	}
	encoded, _ := json.Marshal(r)
	if !bytes.Contains(encoded, []byte(`"declared_quality":null`)) {
		t.Fatal("null claim not represented")
	}
}
