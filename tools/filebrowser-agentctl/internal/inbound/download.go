// Package inbound downloads trusted Gateway descriptors into dispatch-owned work copies.
// It deliberately has no dependency on the FileBrowser client, configuration or tokens.
package inbound

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxDownloadBytes int64 = 64 << 20

var contentPath = regexp.MustCompile(`^/inbound-media/[1-9][0-9]*/content$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type DownloadPolicy struct {
	MaxAttempts          int   `json:"max_attempts"`
	TotalTimeoutSeconds  int   `json:"total_timeout_seconds"`
	RetryableStatusCodes []int `json:"retryable_status_codes"`
	RetryAfterSeconds    int   `json:"retry_after_seconds"`
}

type Descriptor struct {
	Schema               string         `json:"schema"`
	MessageID            int64          `json:"message_id"`
	AttachmentID         int64          `json:"attachment_id"`
	ThreadID             string         `json:"thread_id"`
	EnterpriseIdentityID string         `json:"enterprise_identity_id"`
	URL                  string         `json:"url"`
	Authorization        string         `json:"authorization"`
	ExpiresAt            time.Time      `json:"expires_at"`
	Size                 int64          `json:"size"`
	SHA256               string         `json:"sha256"`
	MIMEType             string         `json:"mime_type"`
	Filename             *string        `json:"filename"`
	DeclaredQuality      *string        `json:"declared_quality"`
	OriginalComparison   string         `json:"original_comparison"`
	FormalArchive        bool           `json:"formal_archive"`
	DownloadPolicy       DownloadPolicy `json:"download_policy"`
}

// Descriptor decoding is strict, including the presence of false/null fields.
// Gateway v1 allows null filename/quality; dropping those fields is different.
func (d *Descriptor) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fixedError("invalid_descriptor")
	}
	if len(fields) != 16 {
		return fixedError("invalid_descriptor")
	}
	for _, name := range []string{"schema", "message_id", "attachment_id", "thread_id", "enterprise_identity_id", "url", "authorization", "expires_at", "size", "sha256", "mime_type", "filename", "declared_quality", "original_comparison", "formal_archive", "download_policy"} {
		value, exists := fields[name]
		if !exists || (name != "filename" && name != "declared_quality" && bytes.Equal(bytes.TrimSpace(value), []byte("null"))) {
			return fixedError("invalid_descriptor")
		}
	}
	type plain Descriptor
	var parsed plain
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&parsed); err != nil {
		return fixedError("invalid_descriptor")
	}
	*d = Descriptor(parsed)
	return nil
}

// Binding is supplied once by the trusted dispatch host, never by a model tool call.
type Binding struct {
	DispatchID           string       `json:"dispatch_id"`
	TaskID               string       `json:"task_id"`
	ThreadID             string       `json:"thread_id"`
	EnterpriseIdentityID string       `json:"enterprise_identity_id"`
	WorkDir              string       `json:"work_dir"`
	GatewayOrigin        string       `json:"gateway_origin"`
	ExpiresAt            time.Time    `json:"expires_at"`
	MaxBytes             int64        `json:"max_bytes"`
	CAFile               string       `json:"ca_file,omitempty"`
	CASHA256             string       `json:"ca_sha256,omitempty"`
	Attachments          []Descriptor `json:"attachments"`
}

type Failure struct {
	Code string `json:"code"`
}
type Result struct {
	OK                 bool     `json:"ok"`
	Error              *Failure `json:"error,omitempty"`
	Handle             string   `json:"handle,omitempty"`
	BytesWritten       int64    `json:"bytes_written"`
	SHA256             string   `json:"sha256,omitempty"`
	Verified           bool     `json:"verified"`
	FormalArchive      bool     `json:"formal_archive"`
	DispatchID         string   `json:"dispatch_id,omitempty"`
	TaskID             string   `json:"task_id,omitempty"`
	DeclaredQuality    *string  `json:"declared_quality"`
	OriginalComparison string   `json:"original_comparison,omitempty"`
}

type attachmentState struct {
	descriptor Descriptor
	expires    time.Time
	done       chan struct{}
	runCtx     context.Context
	result     Result
	name       string
}

type Engine struct {
	binding Binding
	ctx     context.Context
	cancel  context.CancelFunc
	client  *http.Client
	store   *Store
	mu      sync.Mutex
	states  map[int64]*attachmentState
	handles map[string]*attachmentState
	closed  bool
	wg      sync.WaitGroup
}

func failure(code string) Result   { return Result{Error: &Failure{Code: code}} }
func fixedError(code string) error { return errors.New(code) }

func validOrigin(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(raw, "\\%\r\n\t ") {
		return false
	}
	if u.Host != strings.ToLower(u.Host) {
		return false
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return u.String() == raw
}

func validateDescriptor(d Descriptor, b Binding) bool {
	p := d.DownloadPolicy
	if d.Schema != "cf-inbound-read/v1" || d.MessageID <= 0 || d.AttachmentID <= 0 || d.ThreadID != b.ThreadID || d.EnterpriseIdentityID != b.EnterpriseIdentityID || d.ExpiresAt.IsZero() || d.Size < 1 || d.Size > b.MaxBytes || !digestPattern.MatchString(d.SHA256) || d.FormalArchive || p.MaxAttempts != 4 || p.TotalTimeoutSeconds != 30 || p.RetryAfterSeconds != 1 || len(p.RetryableStatusCodes) != 1 || p.RetryableStatusCodes[0] != 503 {
		return false
	}
	if d.OriginalComparison != "not_checked" && d.OriginalComparison != "match" && d.OriginalComparison != "different" {
		return false
	}
	if d.DeclaredQuality != nil && *d.DeclaredQuality != "full" && *d.DeclaredQuality != "standard" && *d.DeclaredQuality != "thumbnail" {
		return false
	}
	if d.Filename != nil && len(*d.Filename) > 1024 {
		return false
	}
	if d.MIMEType != "application/pdf" && d.MIMEType != "image/jpeg" && d.MIMEType != "image/png" && d.MIMEType != "application/octet-stream" {
		return false
	}
	if !strings.HasPrefix(d.Authorization, "Bearer ") || len(d.Authorization) <= 7 || len(d.Authorization) > 128 {
		return false
	}
	for _, c := range d.Authorization[7:] {
		if c <= 32 || c >= 127 {
			return false
		}
	}
	u, err := url.Parse(d.URL)
	return err == nil && u.Scheme+"://"+u.Host == b.GatewayOrigin && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawPath == "" && contentPath.MatchString(u.Path) && !strings.ContainsAny(d.URL, "\\%\r\n\t ")
}

func trustRoots(b Binding) (*x509.CertPool, error) {
	if b.CAFile == "" && b.CASHA256 == "" {
		return nil, nil
	}
	if b.CAFile == "" || !filepath.IsAbs(b.CAFile) || !digestPattern.MatchString(b.CASHA256) {
		return nil, fixedError("invalid_trust")
	}
	for current := b.CAFile; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return nil, fixedError("invalid_trust")
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	before, err := os.Lstat(b.CAFile)
	if err != nil || !before.Mode().IsRegular() {
		return nil, fixedError("invalid_trust")
	}
	f, err := os.Open(b.CAFile)
	if err != nil {
		return nil, fixedError("invalid_trust")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		return nil, fixedError("invalid_trust")
	}
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, fixedError("invalid_trust")
	}
	after, err := os.Lstat(b.CAFile)
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return nil, fixedError("invalid_trust")
	}
	h := sha256.Sum256(data)
	if hex.EncodeToString(h[:]) != b.CASHA256 {
		return nil, fixedError("invalid_trust")
	}
	pool := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fixedError("invalid_trust")
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fixedError("invalid_trust")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fixedError("invalid_trust")
		}
		pool.AddCert(cert)
		count++
		data = rest
	}
	if count == 0 {
		return nil, fixedError("invalid_trust")
	}
	return pool, nil
}

func New(parent context.Context, b Binding) (*Engine, error) {
	if b.MaxBytes == 0 {
		b.MaxBytes = maxDownloadBytes
	}
	if b.DispatchID == "" || b.TaskID == "" || b.ThreadID == "" || b.EnterpriseIdentityID == "" || b.WorkDir == "" || !validOrigin(b.GatewayOrigin) || b.ExpiresAt.IsZero() || b.MaxBytes < 1 || b.MaxBytes > maxDownloadBytes || len(b.Attachments) == 0 || len(b.Attachments) > 1024 {
		return nil, fixedError("invalid_binding")
	}
	now := time.Now()
	if !b.ExpiresAt.After(now) || parent.Err() != nil {
		return nil, fixedError("task_cancelled")
	}
	states := make(map[int64]*attachmentState, len(b.Attachments))
	for _, d := range b.Attachments {
		if !validateDescriptor(d, b) || states[d.AttachmentID] != nil {
			return nil, fixedError("invalid_descriptor")
		}
		// Anchor wall-clock expiry once to Go's monotonic clock.
		states[d.AttachmentID] = &attachmentState{descriptor: d, expires: now.Add(d.ExpiresAt.Sub(now))}
	}
	roots, err := trustRoots(b)
	if err != nil {
		return nil, err
	}
	store, err := OpenStore(b.WorkDir)
	if err != nil {
		return nil, fixedError("unsafe_work_directory")
	}
	ctx, cancel := context.WithDeadline(parent, now.Add(b.ExpiresAt.Sub(now)))
	// Fresh HTTP/1 connections disable Transport's implicit replay of failed reused
	// connections, so every wire attempt is counted by the loop below. No proxies.
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DialContext: (&net.Dialer{}).DialContext, MaxResponseHeaderBytes: 32 << 10}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Engine{binding: b, ctx: ctx, cancel: cancel, client: client, store: store, states: states, handles: make(map[string]*attachmentState)}, nil
}

func (e *Engine) Download(ctx context.Context, id int64) Result {
	e.mu.Lock()
	s := e.states[id]
	if e.closed || e.ctx.Err() != nil || ctx.Err() != nil {
		e.mu.Unlock()
		return failure("task_cancelled")
	}
	if s == nil {
		e.mu.Unlock()
		return failure("not_authorized")
	}
	if !time.Now().Before(s.expires) {
		e.mu.Unlock()
		return failure("not_authorized")
	}
	wasStarted := s.done != nil
	if s.done == nil {
		s.done = make(chan struct{})
		deadline := time.Now().Add(30 * time.Second)
		if s.expires.Before(deadline) {
			deadline = s.expires
		}
		runCtx, stop := context.WithDeadline(e.ctx, deadline)
		s.runCtx = runCtx
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			stopCaller := context.AfterFunc(ctx, stop)
			defer stopCaller()
			defer stop()
			result, name := e.download(runCtx, s.descriptor)
			e.mu.Lock()
			s.result, s.name = result, name
			if result.OK {
				e.handles[result.Handle] = s
			}
			close(s.done)
			e.mu.Unlock()
		}()
	}
	done := s.done
	runCtx := s.runCtx
	e.mu.Unlock()
	completed := func() Result {
		if ctx.Err() != nil || e.ctx.Err() != nil {
			return failure("task_cancelled")
		}
		if wasStarted && s.result.OK {
			f, err := e.Resolve(ctx, s.result.Handle)
			if err != nil {
				return failure("integrity_failed")
			}
			_ = f.Close()
		}
		return s.result
	}
	select {
	case <-ctx.Done():
		return failure("task_cancelled")
	case <-e.ctx.Done():
		return failure("task_cancelled")
	case <-done:
		return completed()
	case <-runCtx.Done():
		// File-system syscalls may be non-interruptible. The caller still receives
		// its bounded result, and PublishContext will reject any late publication.
		select {
		case <-done:
			return completed()
		default:
			return contextFailure(runCtx)
		}
	}
}

func contextFailure(ctx context.Context) Result {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return failure("deadline_exceeded")
	}
	return failure("task_cancelled")
}

func (e *Engine) download(ctx context.Context, d Descriptor) (Result, string) {
	for attempt := 1; attempt <= 4; attempt++ {
		if ctx.Err() != nil {
			return contextFailure(ctx), ""
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.URL, nil)
		if err != nil {
			return failure("invalid_descriptor"), ""
		}
		req.Header.Set("Authorization", d.Authorization)
		req.Header.Set("Accept-Encoding", "identity")
		response, err := e.client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return contextFailure(ctx), ""
			}
			return failure("transport_failed"), ""
		}
		if response.StatusCode == http.StatusServiceUnavailable {
			retryAfter := response.Header.Get("Retry-After")
			_ = response.Body.Close()
			if attempt == 4 {
				return failure("temporarily_unavailable"), ""
			}
			delay := time.Second
			if seconds, err := strconv.ParseUint(retryAfter, 10, 64); (err == nil && seconds > 30) || errors.Is(err, strconv.ErrRange) {
				return failure("deadline_exceeded"), ""
			} else if err == nil && seconds > 1 {
				delay = time.Duration(seconds) * time.Second
			} else if when, err := http.ParseTime(retryAfter); err == nil && time.Until(when) > delay {
				delay = time.Until(when)
			}
			if deadline, ok := ctx.Deadline(); ok && delay >= time.Until(deadline) {
				return failure("deadline_exceeded"), ""
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return contextFailure(ctx), ""
			case <-timer.C:
			}
			continue
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusNotFound {
				return failure("not_authorized"), ""
			}
			return failure("response_rejected"), ""
		}
		result, name := e.save(ctx, d, response)
		_ = response.Body.Close()
		return result, name
	}
	return failure("temporarily_unavailable"), ""
}

func (e *Engine) save(ctx context.Context, d Descriptor, response *http.Response) (Result, string) {
	if response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return failure("integrity_failed"), ""
	}
	if response.ContentLength >= 0 && response.ContentLength != d.Size {
		return failure("integrity_failed"), ""
	}
	if ctx.Err() != nil {
		return contextFailure(ctx), ""
	}
	staging, err := e.store.Create()
	if err != nil {
		return failure("storage_failed"), ""
	}
	defer staging.Abort()
	h := sha256.New()
	reader := io.LimitReader(response.Body, d.Size+1)
	buffer := make([]byte, 64<<10)
	var n int64
	for {
		if ctx.Err() != nil {
			return contextFailure(ctx), ""
		}
		nr, readErr := reader.Read(buffer)
		if nr > 0 {
			n += int64(nr)
			if n > d.Size || n > e.binding.MaxBytes {
				return failure("integrity_failed"), ""
			}
			if _, err := staging.File.Write(buffer[:nr]); err != nil {
				return failure("storage_failed"), ""
			}
			_, _ = h.Write(buffer[:nr])
		}
		if readErr != nil {
			if readErr != io.EOF {
				if ctx.Err() != nil {
					return contextFailure(ctx), ""
				}
				return failure("integrity_failed"), ""
			}
			break
		}
	}
	if n != d.Size || hex.EncodeToString(h.Sum(nil)) != d.SHA256 {
		return failure("integrity_failed"), ""
	}
	if ctx.Err() != nil {
		return contextFailure(ctx), ""
	}
	name, err := staging.PublishContext(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return contextFailure(ctx), ""
		}
		return failure("storage_failed"), ""
	}
	if ctx.Err() != nil {
		return contextFailure(ctx), ""
	}
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		return failure("storage_failed"), ""
	}
	return Result{OK: true, Handle: "inbound:" + hex.EncodeToString(random[:]), BytesWritten: n, SHA256: d.SHA256, Verified: true, FormalArchive: false, DispatchID: e.binding.DispatchID, TaskID: e.binding.TaskID, DeclaredQuality: d.DeclaredQuality, OriginalComparison: d.OriginalComparison}, name
}

// Resolve is exclusively for trusted processing tools. It returns an open read-only
// file after checking both store identity and bytes again; model output never gets a path.
func (e *Engine) Resolve(ctx context.Context, handle string) (*os.File, error) {
	e.mu.Lock()
	s := e.handles[handle]
	if e.closed || e.ctx.Err() != nil || ctx.Err() != nil || s == nil || !time.Now().Before(s.expires) {
		e.mu.Unlock()
		return nil, fixedError("not_authorized")
	}
	e.wg.Add(1)
	e.mu.Unlock()
	defer e.wg.Done()
	f, err := e.store.Open(s.name)
	if err != nil {
		return nil, fixedError("integrity_failed")
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	h := sha256.New()
	buffer := make([]byte, 64<<10)
	var n int64
	for {
		if e.ctx.Err() != nil || ctx.Err() != nil || !time.Now().Before(s.expires) {
			return nil, fixedError("task_cancelled")
		}
		nr, readErr := f.Read(buffer)
		n += int64(nr)
		if n > s.descriptor.Size {
			return nil, fixedError("integrity_failed")
		}
		if nr > 0 {
			_, _ = h.Write(buffer[:nr])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fixedError("integrity_failed")
		}
	}
	if n != s.descriptor.Size || hex.EncodeToString(h.Sum(nil)) != s.descriptor.SHA256 {
		return nil, fixedError("integrity_failed")
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, fixedError("integrity_failed")
	}
	if e.ctx.Err() != nil || ctx.Err() != nil || !time.Now().Before(s.expires) {
		return nil, fixedError("task_cancelled")
	}
	ok = true
	return f, nil
}

func (e *Engine) Close() {
	e.mu.Lock()
	e.closed = true
	e.cancel()
	e.mu.Unlock()
	e.wg.Wait()
	e.client.CloseIdleConnections()
	_ = e.store.Close()
}
