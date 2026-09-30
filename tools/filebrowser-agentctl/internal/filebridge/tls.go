package filebridge

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// TrustOptions are operator configuration, never accepted in a tool request.
// A configured bundle replaces (does not augment) the system trust store.
// The PEM hash binds the file to the independently verified deployment input.
type TrustOptions struct {
	CAFile           string `json:"ca_file,omitempty"`
	CASHA256         string `json:"ca_sha256,omitempty"`
	DirectConnection bool   `json:"direct_connection,omitempty"`
}

var errTrustConfig = errors.New("invalid FileBridge trust configuration")

func trustRoots(options TrustOptions) (*x509.CertPool, error) {
	if options.CAFile == "" && options.CASHA256 == "" {
		return nil, nil // Existing clients continue to use normal system roots.
	}
	want, err := hex.DecodeString(options.CASHA256)
	if options.CAFile == "" || err != nil || len(want) != sha256.Size || strings.ToLower(options.CASHA256) != options.CASHA256 {
		return nil, errTrustConfig
	}
	info, err := os.Lstat(options.CAFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errTrustConfig
	}
	// Public CA files need not be secret, but cannot escape through links.
	absolute, err := filepath.Abs(options.CAFile)
	if err != nil {
		return nil, errTrustConfig
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || !sameClientPath(absolute, resolved) {
		return nil, errTrustConfig
	}
	file, err := os.Open(options.CAFile)
	if err != nil {
		return nil, errTrustConfig
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errTrustConfig
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 || len(data) == 0 {
		return nil, errTrustConfig
	}
	digest := sha256.Sum256(data)
	if !bytes.Equal(digest[:], want) {
		return nil, errTrustConfig
	}
	roots := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(data)) != 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errTrustConfig
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errTrustConfig
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errTrustConfig
		}
		roots.AddCert(cert)
		count++
		data = rest
	}
	if count == 0 {
		return nil, errTrustConfig
	}
	return roots, nil
}

func filebridgeTransport(options TrustOptions) (http.RoundTripper, error) {
	roots, err := trustRoots(options)
	if err != nil {
		return nil, err
	}
	// Do not inherit a process-global custom transport that might skip TLS checks.
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		},
		ForceAttemptHTTP2: true,
	}
	if options.DirectConnection {
		transport.Proxy = nil
	}
	return transport, nil
}

func sameClientPath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		// EvalSymlinks also expands legitimate 8.3 aliases on Windows. Compare
		// file identity, but independently reject every actual link component.
		for current := a; ; current = filepath.Dir(current) {
			info, err := os.Lstat(current)
			if err != nil || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
				return false
			}
			if filepath.Dir(current) == current {
				break
			}
		}
		left, leftErr := os.Lstat(a)
		right, rightErr := os.Stat(b)
		return leftErr == nil && rightErr == nil && os.SameFile(left, right)
	}
	return a == b
}
