package filebridge

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	defaultTimeoutSeconds       = 30
	defaultMaxDownloadBytes     = 16 << 20
	defaultMaxInlineBytes       = 1 << 20
	defaultMaxChecksumBytes     = 64 << 20
	defaultMaxUploadBytes       = 256 << 20
	defaultSearchLimit          = 25
	defaultSearchMaxLimit       = 100
	defaultMaxRetries           = 2
	defaultRetryDelayMillis     = 100
	defaultMaxRetryDelaySeconds = 2
	maxConfigBytes              = 1 << 20
	maxTokenBytes               = 64 << 10
	maxSourceNameBytes          = 255
)

type Config struct {
	BaseURL              string                  `json:"base_url"`
	TokenFile            string                  `json:"token_file,omitempty"`
	AuditLog             string                  `json:"audit_log,omitempty"`
	AllowedSources       map[string]SourcePolicy `json:"allowed_sources"`
	LocalReadRoots       []string                `json:"local_read_roots,omitempty"`
	LocalWriteRoots      []string                `json:"local_write_roots,omitempty"`
	TimeoutSeconds       int                     `json:"timeout_seconds,omitempty"`
	MaxDownloadBytes     int64                   `json:"max_download_bytes,omitempty"`
	MaxInlineBytes       int64                   `json:"max_inline_bytes,omitempty"`
	MaxChecksumBytes     int64                   `json:"max_checksum_bytes,omitempty"`
	MaxUploadBytes       int64                   `json:"max_upload_bytes,omitempty"`
	SearchDefaultLimit   int                     `json:"search_default_limit,omitempty"`
	SearchMaxLimit       int                     `json:"search_max_limit,omitempty"`
	MaxRetries           int                     `json:"max_retries,omitempty"`
	RetryDelayMillis     int                     `json:"retry_delay_millis,omitempty"`
	MaxRetryDelaySeconds int                     `json:"max_retry_delay_seconds,omitempty"`
	configDir            string
	parsedBaseURL        *url.URL
	requestTimeout       time.Duration
	retryDelay           time.Duration
	maximumRetryDelay    time.Duration
}

type SourcePolicy struct {
	ReadRoots  []string `json:"read_roots"`
	WriteRoots []string `json:"write_roots"`
}

func LoadConfig(filename string, allowLocalhostHTTP bool) (*Config, error) {
	if strings.TrimSpace(filename) == "" {
		return nil, bridgeError("invalid_config", "--config is required")
	}
	abs, err := filepath.Abs(filename)
	if err != nil {
		return nil, bridgeError("invalid_config", "config path is invalid")
	}
	file, err := os.Open(abs)
	if err != nil {
		return nil, bridgeError("invalid_config", "cannot open config file")
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil || len(data) > maxConfigBytes {
		return nil, bridgeError("invalid_config", "config file exceeds the supported size")
	}
	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, bridgeError("invalid_config", "config must be one JSON object with known fields")
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, bridgeError("invalid_config", "config must contain exactly one JSON object")
	}
	cfg.configDir = filepath.Dir(abs)
	if err := cfg.applyDefaultsAndValidate(allowLocalhostHTTP); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaultsAndValidate(allowLocalhostHTTP bool) error {
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = defaultTimeoutSeconds
	}
	if c.MaxDownloadBytes == 0 {
		c.MaxDownloadBytes = defaultMaxDownloadBytes
	}
	if c.MaxInlineBytes == 0 {
		c.MaxInlineBytes = defaultMaxInlineBytes
	}
	if c.MaxChecksumBytes == 0 {
		c.MaxChecksumBytes = defaultMaxChecksumBytes
	}
	if c.MaxUploadBytes == 0 {
		c.MaxUploadBytes = defaultMaxUploadBytes
	}
	if c.SearchDefaultLimit == 0 {
		c.SearchDefaultLimit = defaultSearchLimit
	}
	if c.SearchMaxLimit == 0 {
		c.SearchMaxLimit = defaultSearchMaxLimit
	}
	if c.MaxRetries == 0 {
		c.MaxRetries = defaultMaxRetries
	}
	if c.RetryDelayMillis == 0 {
		c.RetryDelayMillis = defaultRetryDelayMillis
	}
	if c.MaxRetryDelaySeconds == 0 {
		c.MaxRetryDelaySeconds = defaultMaxRetryDelaySeconds
	}

	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 300 ||
		c.MaxDownloadBytes < 1 || c.MaxInlineBytes < 1 || c.MaxInlineBytes > c.MaxDownloadBytes ||
		c.MaxChecksumBytes < 1 || c.MaxUploadBytes < 1 || c.SearchDefaultLimit < 1 || c.SearchMaxLimit < 1 ||
		c.SearchDefaultLimit > c.SearchMaxLimit || c.SearchMaxLimit > 100 ||
		c.MaxRetries < 0 || c.MaxRetries > 5 || c.RetryDelayMillis < 1 || c.RetryDelayMillis > 5000 ||
		c.MaxRetryDelaySeconds < 1 || c.MaxRetryDelaySeconds > 30 {
		return bridgeError("invalid_config", "config limits are outside supported bounds")
	}
	if len(c.AllowedSources) == 0 {
		return bridgeError("invalid_config", "allowed_sources must not be empty")
	}
	for source, policy := range c.AllowedSources {
		if strings.TrimSpace(source) == "" || len(source) > maxSourceNameBytes || strings.ContainsAny(source, "\r\n\x00") {
			return bridgeError("invalid_config", "allowed source name is invalid")
		}
		var err error
		policy.ReadRoots, err = normalizeRemoteRoots(policy.ReadRoots)
		if err != nil {
			return bridgeError("invalid_config", fmt.Sprintf("read roots for source %q are invalid", source))
		}
		policy.WriteRoots, err = normalizeRemoteRoots(policy.WriteRoots)
		if err != nil {
			return bridgeError("invalid_config", fmt.Sprintf("write roots for source %q are invalid", source))
		}
		if len(policy.ReadRoots) == 0 && len(policy.WriteRoots) == 0 {
			return bridgeError("invalid_config", fmt.Sprintf("source %q has no allowed roots", source))
		}
		c.AllowedSources[source] = policy
	}

	base, err := validateBaseURL(c.BaseURL, allowLocalhostHTTP)
	if err != nil {
		return err
	}
	c.parsedBaseURL = base
	c.requestTimeout = time.Duration(c.TimeoutSeconds) * time.Second
	c.retryDelay = time.Duration(c.RetryDelayMillis) * time.Millisecond
	c.maximumRetryDelay = time.Duration(c.MaxRetryDelaySeconds) * time.Second
	c.TokenFile = resolveConfigRelative(c.configDir, c.TokenFile)
	c.AuditLog = resolveConfigRelative(c.configDir, c.AuditLog)
	for index, root := range c.LocalReadRoots {
		c.LocalReadRoots[index] = resolveConfigRelative(c.configDir, root)
	}
	for index, root := range c.LocalWriteRoots {
		c.LocalWriteRoots[index] = resolveConfigRelative(c.configDir, root)
	}
	return nil
}

func validateBaseURL(raw string, allowLocalhostHTTP bool) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.Scheme == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, bridgeError("invalid_base_url", "base_url must be an absolute URL without credentials, query, or fragment")
	}
	if parsed.Scheme != "https" {
		if parsed.Scheme != "http" || !allowLocalhostHTTP || !isLoopbackHost(parsed.Hostname()) {
			return nil, bridgeError("insecure_base_url", "base_url must use HTTPS; HTTP is allowed only for localhost with --allow-localhost-http")
		}
	}
	if parsed.Port() != "" {
		if _, err := net.LookupPort("tcp", parsed.Port()); err != nil {
			return nil, bridgeError("invalid_base_url", "base_url port is invalid")
		}
	}
	for _, segment := range strings.Split(strings.ReplaceAll(parsed.Path, "\\", "/"), "/") {
		if segment == ".." {
			return nil, bridgeError("invalid_base_url", "base_url path must not contain traversal")
		}
	}
	parsed.Path = path.Clean("/" + strings.TrimPrefix(parsed.Path, "/"))
	if parsed.Path == "." || parsed.Path == "/" {
		parsed.Path = "/"
	} else {
		parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/"
	}
	parsed.RawPath = ""
	return parsed, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func resolveConfigRelative(configDir, value string) string {
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(configDir, value)
}

func LoadToken(cfg *Config, tokenFromStdin bool, stdin *bufio.Reader) (string, error) {
	var token string
	if tokenFromStdin {
		line, err := stdin.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", bridgeError("token_unavailable", "could not read token from stdin")
		}
		token = strings.TrimSpace(line)
	} else if value := os.Getenv("FILEBROWSER_AGENT_TOKEN"); value != "" {
		token = strings.TrimSpace(value)
	} else if cfg.TokenFile != "" {
		value, err := readRestrictedTokenFile(cfg.TokenFile)
		if err != nil {
			return "", err
		}
		token = value
	}
	if token == "" {
		return "", bridgeError("token_unavailable", "token must come from FILEBROWSER_AGENT_TOKEN, stdin, or token_file")
	}
	if len(token) > maxTokenBytes || strings.ContainsAny(token, " \t\r\n\x00") || strings.Count(token, ".") != 2 {
		return "", bridgeError("invalid_token", "token format is invalid")
	}
	return token, nil
}

func readRestrictedTokenFile(filename string) (string, error) {
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", bridgeError("token_unavailable", "token_file must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", bridgeError("insecure_token_file", "token_file permissions must be 0600 or stricter")
	}
	file, err := os.Open(filename)
	if err != nil {
		return "", bridgeError("token_unavailable", "cannot open token_file")
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maxTokenBytes+1))
	if err != nil || len(value) > maxTokenBytes {
		return "", bridgeError("token_unavailable", "cannot read token_file")
	}
	return strings.TrimSpace(string(value)), nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("unexpected trailing JSON")
	}
	return nil
}
