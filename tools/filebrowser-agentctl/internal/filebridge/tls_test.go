package filebridge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func trustFixture(t *testing.T, wrongName bool) ([]byte, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Synthetic server"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	if wrongName {
		leaf.IPAddresses = nil
		leaf.DNSNames = []string{"wrong.example.invalid"}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert
}

func saveTrust(t *testing.T, data []byte) TrustOptions {
	t.Helper()
	name := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	return TrustOptions{CAFile: name, CASHA256: hex.EncodeToString(h[:]), DirectConnection: true}
}

func TestTrustStrictBundle(t *testing.T) {
	ca, _ := trustFixture(t, false)
	for _, kind := range []string{"valid", "bad-hash", "missing-hash", "missing-file", "garbage", "private-block", "non-ca", "oversized", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			data := ca
			if kind == "garbage" {
				data = append([]byte("ignored text\n"), ca...)
			}
			if kind == "private-block" {
				data = append(append([]byte{}, ca...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-key")})...)
			}
			if kind == "oversized" {
				data = []byte(strings.Repeat("x", (1<<20)+1))
			}
			if kind == "non-ca" {
				_, leaf := trustFixture(t, false)
				data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})
			}
			opts := saveTrust(t, data)
			switch kind {
			case "bad-hash":
				opts.CASHA256 = strings.Repeat("0", 64)
			case "missing-hash":
				opts.CASHA256 = ""
			case "missing-file":
				opts.CAFile = filepath.Join(t.TempDir(), "absent")
			case "symlink":
				name := opts.CAFile + "-link"
				if err := os.Symlink(opts.CAFile, name); err != nil {
					t.Skip("OS does not permit test symlink")
				}
				opts.CAFile = name
			}
			pool, err := trustRoots(opts)
			if kind == "valid" {
				if err != nil || pool == nil {
					t.Fatal("valid bundle refused")
				}
			} else if err == nil {
				t.Fatal("invalid bundle accepted")
			}
		})
	}
}

func TestTrustRealTLSAcceptanceAndRejection(t *testing.T) {
	for _, kind := range []string{"trusted", "untrusted", "wrong-name", "invalid-hash"} {
		t.Run(kind, func(t *testing.T) {
			ca, cert := trustFixture(t, kind == "wrong-name")
			var called atomic.Int32
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called.Add(1)
				_, _ = io.WriteString(w, `{"message":"ok"}`)
			}))
			s.Config.ErrorLog = log.New(io.Discard, "", 0)
			s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
			s.StartTLS()
			defer s.Close()
			opts := saveTrust(t, ca)
			if kind == "untrusted" {
				other, _ := trustFixture(t, false)
				opts = saveTrust(t, other)
			}
			if kind == "invalid-hash" {
				opts.CASHA256 = strings.Repeat("0", 64)
			}
			cfg := &Config{BaseURL: s.URL, AllowedSources: map[string]SourcePolicy{"files": {ReadRoots: []string{"/"}}}}
			if err := cfg.applyDefaultsAndValidate(false); err != nil {
				t.Fatal(err)
			}
			// Direct construction cannot fall back to an insecure transport either.
			cfg.TrustOptions = opts
			_, err := NewClient(cfg, "private-test-token").ping(context.Background(), "test")
			if kind == "trusted" {
				if err != nil || called.Load() != 1 {
					t.Fatalf("trusted failed %v", err)
				}
			} else if err == nil || called.Load() != 0 {
				t.Fatal("certificate failure transmitted request")
			}
		})
	}
}

func TestTrustDoesNotModifyGlobalTransportOrProxy(t *testing.T) {
	before := http.DefaultTransport
	transport, err := filebridgeTransport(TrustOptions{DirectConnection: true})
	if err != nil {
		t.Fatal(err)
	}
	tr := transport.(*http.Transport)
	if tr.Proxy != nil || tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 || http.DefaultTransport != before {
		t.Fatal("unexpected global or TLS behavior")
	}
	other, err := filebridgeTransport(TrustOptions{})
	if err != nil || other.(*http.Transport).Proxy == nil {
		t.Fatal("default proxy compatibility changed")
	}
}
