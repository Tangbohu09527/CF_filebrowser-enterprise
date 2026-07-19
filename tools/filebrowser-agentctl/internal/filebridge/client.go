package filebridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxJSONResponseBytes = 16 << 20
	currentPermissionsV4 = 4
)

type Client struct {
	config     *Config
	token      string
	httpClient *http.Client
}

type requestOptions struct {
	method          string
	endpoint        string
	query           url.Values
	headers         http.Header
	body            io.Reader
	contentLength   int64
	retry429        bool
	requestID       string
	unauthenticated bool
}

func NewClient(config *Config, token string) *Client {
	return &Client{
		config: config,
		token:  token,
		httpClient: &http.Client{
			Timeout: config.requestTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *Client) do(ctx context.Context, options requestOptions) (*http.Response, error) {
	attempts := 1
	if options.retry429 {
		attempts += c.config.MaxRetries
	}
	for attempt := 0; attempt < attempts; attempt++ {
		requestURL := c.endpointURL(options.endpoint, options.query)
		request, err := http.NewRequestWithContext(ctx, options.method, requestURL, options.body)
		if err != nil {
			return nil, bridgeError("request_failed", "could not create HTTP request")
		}
		if !options.unauthenticated {
			request.Header.Set("Authorization", "Bearer "+c.token)
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("User-Agent", "filebrowser-agentctl/1")
		if options.requestID != "" {
			request.Header.Set("X-Request-ID", options.requestID)
		}
		for name, values := range options.headers {
			for _, value := range values {
				request.Header.Add(name, value)
			}
		}
		if options.contentLength >= 0 {
			request.ContentLength = options.contentLength
		}

		response, err := c.httpClient.Do(request)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || isTimeoutError(err) {
				return nil, &BridgeError{Code: "timeout", Message: "FileBrowser request timed out", Retryable: true}
			}
			return nil, &BridgeError{Code: "connection_failed", Message: "could not reach FileBrowser", Retryable: true}
		}
		if response.StatusCode != http.StatusTooManyRequests || attempt == attempts-1 {
			return response, nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		delay := retryAfter(response.Header.Get("Retry-After"), c.config.retryDelay)
		if delay > c.config.maximumRetryDelay {
			delay = c.config.maximumRetryDelay
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, &BridgeError{Code: "timeout", Message: "FileBrowser request timed out", Retryable: true}
		case <-timer.C:
		}
	}
	return nil, bridgeError("internal_error", "HTTP retry loop ended unexpectedly")
}

func (c *Client) endpointURL(endpoint string, query url.Values) string {
	reference := &url.URL{Path: strings.TrimPrefix(endpoint, "/")}
	resolved := c.config.parsedBaseURL.ResolveReference(reference)
	resolved.RawQuery = query.Encode()
	return resolved.String()
}

func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func retryAfter(value string, fallback time.Duration) time.Duration {
	if seconds, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		if delay := time.Until(when); delay > 0 {
			return delay
		}
	}
	return fallback
}

func (c *Client) expectJSON(response *http.Response, destination any) error {
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return c.statusError(response)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxJSONResponseBytes+1))
	if err := decoder.Decode(destination); err != nil {
		return bridgeError("invalid_server_response", "FileBrowser returned invalid JSON")
	}
	return nil
}

func (c *Client) expectEmpty(response *http.Response) error {
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return c.statusError(response)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return nil
}

func (c *Client) statusError(response *http.Response) error {
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	code := "http_error"
	message := "FileBrowser rejected the request"
	retryable := false
	switch response.StatusCode {
	case http.StatusBadRequest:
		code = "bad_request"
		message = "FileBrowser rejected the request as invalid"
	case http.StatusUnauthorized:
		code = "unauthorized"
		message = "FileBrowser rejected the token"
	case http.StatusForbidden:
		code = "forbidden"
		message = "FileBrowser denied this operation"
	case http.StatusNotFound:
		code = "not_found"
		message = "FileBrowser resource was not found"
	case http.StatusConflict:
		code = "conflict"
		message = "FileBrowser reported a target conflict"
	case http.StatusTooManyRequests:
		code = "rate_limited"
		message = "FileBrowser rate limit was reached"
		retryable = true
	default:
		if response.StatusCode >= 500 {
			code = "server_error"
			message = "FileBrowser returned a server error"
			retryable = true
		}
	}
	return &BridgeError{Code: code, Message: message, HTTPStatus: response.StatusCode, Retryable: retryable}
}

func (c *Client) ping(ctx context.Context, requestID string) (map[string]any, error) {
	response, err := c.do(ctx, requestOptions{
		method: http.MethodGet, endpoint: "health", query: make(url.Values),
		retry429: true, requestID: requestID, contentLength: -1, unauthenticated: true,
	})
	if err != nil {
		return nil, err
	}
	var health map[string]any
	if err := c.expectJSON(response, &health); err != nil {
		return nil, err
	}
	return map[string]any{"reachable": true, "healthy": true, "health": health}, nil
}

func (c *Client) getUser(ctx context.Context, requestID string) (wireUser, error) {
	query := url.Values{"id": []string{"self"}}
	response, err := c.do(ctx, requestOptions{
		method: http.MethodGet, endpoint: "api/users", query: query,
		retry429: true, requestID: requestID, contentLength: -1,
	})
	if err != nil {
		return wireUser{}, err
	}
	var user wireUser
	if err := c.expectJSON(response, &user); err != nil {
		return wireUser{}, err
	}
	if user.Username == "" || user.ID == 0 {
		return wireUser{}, bridgeError("invalid_server_response", "FileBrowser returned an incomplete user profile")
	}
	return user, nil
}

func (c *Client) capabilities(ctx context.Context, requestID string) (CapabilitiesResult, error) {
	user, err := c.getUser(ctx, requestID)
	if err != nil {
		return CapabilitiesResult{}, err
	}
	permissions, exact, source := effectivePermissions(user.Permissions, c.token)
	scopes := make([]Scope, 0, len(user.Scopes))
	for _, scope := range user.Scopes {
		if _, locallyAllowed := c.config.AllowedSources[scope.Name]; locallyAllowed {
			scopes = append(scopes, scope)
		}
	}
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].Name < scopes[j].Name })
	return CapabilitiesResult{
		Username: user.Username, UserID: user.ID, Permissions: permissions, Sources: scopes,
		CapabilitiesExact: exact, PermissionSource: source,
	}, nil
}

func effectivePermissions(account Permissions, token string) (Permissions, bool, string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Permissions{}, false, "conservative_unknown_token"
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Permissions{}, false, "conservative_unknown_token"
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(payload, &claims) != nil {
		return Permissions{}, false, "conservative_unknown_token"
	}
	var name string
	var version int
	var belongsTo uint
	_ = json.Unmarshal(claims["name"], &name)
	_ = json.Unmarshal(claims["permissionsVersion"], &version)
	_ = json.Unmarshal(claims["belongsTo"], &belongsTo)
	permissionsJSON := claims["Permissions"]
	if len(permissionsJSON) == 0 {
		permissionsJSON = claims["permissions"]
	}
	if name != "" && version == currentPermissionsV4 && len(permissionsJSON) != 0 {
		var tokenPermissions Permissions
		if json.Unmarshal(permissionsJSON, &tokenPermissions) == nil {
			return account.intersect(tokenPermissions), true, "account_and_full_token_intersection"
		}
	}
	if belongsTo == 0 && name == "" && version == 0 && len(permissionsJSON) == 0 {
		return account, true, "stateful_token_account_permissions"
	}
	return Permissions{}, false, "conservative_unknown_token"
}

func (c *Client) sources(ctx context.Context, requestID string) (SourcesResult, error) {
	user, err := c.getUser(ctx, requestID)
	if err != nil {
		return SourcesResult{}, err
	}
	response, err := c.do(ctx, requestOptions{
		method: http.MethodGet, endpoint: "api/settings/sources", query: make(url.Values),
		retry429: true, requestID: requestID, contentLength: -1,
	})
	if err != nil {
		return SourcesResult{}, err
	}
	var availableWire map[string]struct {
		Name            string `json:"name"`
		ReadOnly        bool   `json:"readOnly"`
		Private         bool   `json:"private"`
		Status          string `json:"status"`
		NumDirectories  uint64 `json:"numDirs"`
		NumFiles        uint64 `json:"numFiles"`
		UsedBytes       uint64 `json:"used"`
		TotalBytes      uint64 `json:"total"`
		LastIndexedUnix int64  `json:"lastIndexedUnixTime"`
	}
	if err := c.expectJSON(response, &availableWire); err != nil {
		return SourcesResult{}, err
	}
	result := SourcesResult{Sources: make([]SourceResult, 0, len(user.Scopes))}
	for _, scope := range user.Scopes {
		if _, locallyAllowed := c.config.AllowedSources[scope.Name]; !locallyAllowed {
			continue
		}
		wire, ok := availableWire[scope.Name]
		var info *SourceInfo
		if ok {
			info = &SourceInfo{
				Name: wire.Name, ReadOnly: wire.ReadOnly, Private: wire.Private, Status: wire.Status,
				NumDirectories: wire.NumDirectories, NumFiles: wire.NumFiles,
				UsedBytes: wire.UsedBytes, TotalBytes: wire.TotalBytes, LastIndexedUnix: wire.LastIndexedUnix,
			}
		}
		result.Sources = append(result.Sources, SourceResult{Name: scope.Name, Scope: scope.Scope, Available: ok, Info: info})
	}
	sort.Slice(result.Sources, func(i, j int) bool { return result.Sources[i].Name < result.Sources[j].Name })
	return result, nil
}

func (c *Client) getResource(ctx context.Context, requestID, source, resourcePath, checksum string) (wireResource, error) {
	query := url.Values{"source": []string{source}, "path": []string{resourcePath}, "skipExtendedAttrs": []string{"true"}}
	if checksum != "" {
		query.Set("checksum", checksum)
	}
	response, err := c.do(ctx, requestOptions{
		method: http.MethodGet, endpoint: "api/resources", query: query,
		retry429: true, requestID: requestID, contentLength: -1,
	})
	if err != nil {
		return wireResource{}, err
	}
	var resource wireResource
	if err := c.expectJSON(response, &resource); err != nil {
		return wireResource{}, err
	}
	return resource, nil
}

func (c *Client) search(ctx context.Context, requestID, source, scope, queryText string) ([]wireSearchResult, error) {
	query := url.Values{
		"source": []string{source},
		"scope":  []string{scope},
		"terms":  []string{queryText},
	}
	headers := make(http.Header)
	headers.Set("SessionId", requestID)
	response, err := c.do(ctx, requestOptions{
		method: http.MethodGet, endpoint: "api/tools/search", query: query, headers: headers,
		retry429: true, requestID: requestID, contentLength: -1,
	})
	if err != nil {
		return nil, err
	}
	var results []wireSearchResult
	if err := c.expectJSON(response, &results); err != nil {
		return nil, err
	}
	return results, nil
}

func (c *Client) downloadResponse(ctx context.Context, requestID, method, source, resourcePath string) (*http.Response, error) {
	query := url.Values{"source": []string{source}, "file": []string{resourcePath}}
	response, err := c.do(ctx, requestOptions{
		method: method, endpoint: "api/resources/download", query: query,
		retry429:  method == http.MethodGet || method == http.MethodHead,
		requestID: requestID, contentLength: -1,
	})
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		defer response.Body.Close()
		return nil, c.statusError(response)
	}
	return response, nil
}

func (c *Client) createDirectory(ctx context.Context, requestID, source, resourcePath string) error {
	query := url.Values{"source": []string{source}, "path": []string{resourcePath}, "isDir": []string{"true"}}
	response, err := c.do(ctx, requestOptions{
		method: http.MethodPost, endpoint: "api/resources", query: query,
		requestID: requestID, contentLength: 0,
	})
	if err != nil {
		return err
	}
	return c.expectEmpty(response)
}

func (c *Client) uploadNew(ctx context.Context, requestID, source, resourcePath string, body io.Reader, size int64) error {
	query := url.Values{"source": []string{source}, "path": []string{resourcePath}}
	headers := make(http.Header)
	headers.Set("Content-Type", "application/octet-stream")
	headers.Set("X-File-Chunk-Offset", "0")
	headers.Set("X-File-Total-Size", strconv.FormatInt(size, 10))
	response, err := c.do(ctx, requestOptions{
		method: http.MethodPost, endpoint: "api/resources", query: query, headers: headers,
		body: body, contentLength: size, requestID: requestID,
	})
	if err != nil {
		return err
	}
	return c.expectEmpty(response)
}

func isErrorCode(err error, code string) bool {
	var bridgeErr *BridgeError
	return asBridgeError(err, &bridgeErr) && bridgeErr.Code == code
}
