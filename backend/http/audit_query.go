package http

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
)

const (
	auditCursorDomain       = "audit-cursor:v1"
	auditCursorVersion      = 1
	auditCursorDirection    = "desc"
	minAuditCursorKeyBytes  = 32
	maxEncodedAuditCursor   = 2048
	auditQueryRedactedValue = "[REDACTED]"
)

var (
	errAuditQueryInvalid     = errors.New("invalid audit query")
	errAuditQueryUnavailable = errors.New("audit query unavailable")
)

type auditQueryResponse struct {
	Items      []auditQueryItem `json:"items"`
	NextCursor string           `json:"nextCursor"`
	HasMore    bool             `json:"hasMore"`
}

type auditQueryItem struct {
	TimestampUTC time.Time          `json:"timestampUtc"`
	RequestID    string             `json:"requestId"`
	UserID       *uint              `json:"userId,omitempty"`
	Username     string             `json:"username,omitempty"`
	AuthMethod   auditdb.AuthMethod `json:"authMethod"`
	TokenRef     string             `json:"tokenRef,omitempty"`
	ShareRef     string             `json:"shareRef,omitempty"`
	ClientIP     string             `json:"clientIp,omitempty"`
	Action       auditdb.Action     `json:"action"`
	Origin       auditdb.Origin     `json:"origin"`

	Source        string `json:"source,omitempty"`
	Path          string `json:"path,omitempty"`
	CanonicalPath string `json:"canonicalPath,omitempty"`

	TargetSource        string `json:"targetSource,omitempty"`
	TargetPath          string `json:"targetPath,omitempty"`
	TargetCanonicalPath string `json:"targetCanonicalPath,omitempty"`

	EffectivePermissions *auditdb.Permissions `json:"effectivePermissions,omitempty"`
	Result               auditdb.Result       `json:"result"`
	HTTPStatus           *int                 `json:"httpStatus,omitempty"`
	ErrorCode            string               `json:"errorCode,omitempty"`
	Metadata             *auditdb.MetadataV1  `json:"metadata,omitempty"`
}

type auditCursorPayload struct {
	Version   int    `json:"v"`
	Filter    string `json:"f"`
	AfterID   string `json:"a"`
	Direction string `json:"d"`
}

type auditQueryFilterBinding struct {
	Actor     string         `json:"actor,omitempty"`
	TokenRef  string         `json:"tokenRef,omitempty"`
	ShareRef  string         `json:"shareRef,omitempty"`
	Action    auditdb.Action `json:"action,omitempty"`
	Source    string         `json:"source,omitempty"`
	Path      string         `json:"path,omitempty"`
	RequestID string         `json:"requestId,omitempty"`
	Result    auditdb.Result `json:"result,omitempty"`
	From      string         `json:"from,omitempty"`
	To        string         `json:"to,omitempty"`
	Limit     int            `json:"limit"`
	Direction string         `json:"direction"`
}

func auditQueryHandler(w http.ResponseWriter, r *http.Request, _ *requestContext) (int, error) {
	options, encodedCursor, err := parseAuditQueryRequest(r)
	if err != nil {
		return http.StatusBadRequest, errAuditQueryInvalid
	}
	options, err = auditdb.NormalizeQueryOptions(options)
	if err != nil {
		return http.StatusBadRequest, errAuditQueryInvalid
	}
	if config == nil || len(config.Auth.Key) < minAuditCursorKeyBytes || store == nil || store.Audit == nil {
		return http.StatusInternalServerError, errAuditQueryUnavailable
	}

	filterDigest, err := auditQueryFilterDigest(options)
	if err != nil {
		return http.StatusInternalServerError, errAuditQueryUnavailable
	}
	if encodedCursor != "" {
		afterID, decodeErr := decodeAuditCursor(encodedCursor, []byte(config.Auth.Key), filterDigest)
		if decodeErr != nil {
			return http.StatusBadRequest, errAuditQueryInvalid
		}
		options.AfterID = afterID
	}

	result, err := store.Audit.Query(r.Context(), options)
	if err != nil {
		if errors.Is(err, auditdb.ErrInvalidQuery) {
			return http.StatusBadRequest, errAuditQueryInvalid
		}
		return http.StatusInternalServerError, errAuditQueryUnavailable
	}

	response := auditQueryResponse{
		Items:   make([]auditQueryItem, len(result.Events)),
		HasMore: result.HasMore,
	}
	for index := range result.Events {
		response.Items[index] = newAuditQueryItem(result.Events[index])
	}
	if result.HasMore {
		if result.NextID == "" {
			return http.StatusInternalServerError, errAuditQueryUnavailable
		}
		response.NextCursor, err = encodeAuditCursor([]byte(config.Auth.Key), filterDigest, result.NextID)
		if err != nil {
			return http.StatusInternalServerError, errAuditQueryUnavailable
		}
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	return renderJSON(w, r, response)
}

func parseAuditQueryRequest(r *http.Request) (auditdb.QueryOptions, string, error) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	redactAuditQueryURL(r, values, err)
	if err != nil {
		return auditdb.QueryOptions{}, "", errAuditQueryInvalid
	}

	supported := map[string]struct{}{
		"actor": {}, "tokenRef": {}, "shareRef": {}, "action": {}, "source": {}, "path": {},
		"requestID": {}, "result": {}, "from": {}, "to": {}, "limit": {}, "cursor": {},
	}
	for key, entries := range values {
		if _, ok := supported[key]; !ok || len(entries) != 1 {
			return auditdb.QueryOptions{}, "", errAuditQueryInvalid
		}
	}

	options := auditdb.QueryOptions{
		Actor:     values.Get("actor"),
		TokenRef:  values.Get("tokenRef"),
		ShareRef:  values.Get("shareRef"),
		Action:    auditdb.Action(values.Get("action")),
		Source:    values.Get("source"),
		Path:      values.Get("path"),
		RequestID: values.Get("requestID"),
		Result:    auditdb.Result(values.Get("result")),
		Limit:     auditdb.DefaultQueryLimit,
	}
	if rawLimit, exists := values["limit"]; exists {
		if rawLimit[0] == "" {
			return auditdb.QueryOptions{}, "", errAuditQueryInvalid
		}
		options.Limit, err = strconv.Atoi(rawLimit[0])
		if err != nil {
			return auditdb.QueryOptions{}, "", errAuditQueryInvalid
		}
	}
	if rawFrom := values.Get("from"); rawFrom != "" {
		parsed, parseErr := time.Parse(time.RFC3339, rawFrom)
		if parseErr != nil {
			return auditdb.QueryOptions{}, "", errAuditQueryInvalid
		}
		options.From = &parsed
	}
	if rawTo := values.Get("to"); rawTo != "" {
		parsed, parseErr := time.Parse(time.RFC3339, rawTo)
		if parseErr != nil {
			return auditdb.QueryOptions{}, "", errAuditQueryInvalid
		}
		options.To = &parsed
	}
	return options, values.Get("cursor"), nil
}

func redactAuditQueryURL(r *http.Request, values url.Values, parseErr error) {
	if parseErr != nil {
		r.URL.RawQuery = "invalid=" + url.QueryEscape(auditQueryRedactedValue)
		return
	}
	redacted := make(url.Values, len(values))
	for key, entries := range values {
		redacted[key] = make([]string, len(entries))
		for index := range entries {
			redacted[key][index] = auditQueryRedactedValue
		}
	}
	r.URL.RawQuery = redacted.Encode()
}

func auditQueryFilterDigest(options auditdb.QueryOptions) (string, error) {
	binding := auditQueryFilterBinding{
		Actor:     options.Actor,
		TokenRef:  options.TokenRef,
		ShareRef:  options.ShareRef,
		Action:    options.Action,
		Source:    options.Source,
		Path:      options.Path,
		RequestID: options.RequestID,
		Result:    options.Result,
		Limit:     options.Limit,
		Direction: auditCursorDirection,
	}
	if options.From != nil {
		binding.From = options.From.UTC().Format(time.RFC3339Nano)
	}
	if options.To != nil {
		binding.To = options.To.UTC().Format(time.RFC3339Nano)
	}
	serialized, err := json.Marshal(binding)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(serialized)
	return hex.EncodeToString(digest[:]), nil
}

func encodeAuditCursor(key []byte, filterDigest, afterID string) (string, error) {
	if len(key) < minAuditCursorKeyBytes || filterDigest == "" || auditdb.ValidateEventID(afterID) != nil {
		return "", errAuditQueryUnavailable
	}
	payload, err := json.Marshal(auditCursorPayload{
		Version:   auditCursorVersion,
		Filter:    filterDigest,
		AfterID:   afterID,
		Direction: auditCursorDirection,
	})
	if err != nil {
		return "", err
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signature := signAuditCursor(key, encodedPayload)
	return encodedPayload + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func decodeAuditCursor(encoded string, key []byte, filterDigest string) (string, error) {
	if len(key) < minAuditCursorKeyBytes || len(encoded) == 0 || len(encoded) > maxEncodedAuditCursor {
		return "", errAuditQueryInvalid
	}
	parts := strings.Split(encoded, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", errAuditQueryInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != parts[0] {
		return "", errAuditQueryInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != sha256.Size || base64.RawURLEncoding.EncodeToString(signature) != parts[1] {
		return "", errAuditQueryInvalid
	}
	if !hmac.Equal(signature, signAuditCursor(key, parts[0])) {
		return "", errAuditQueryInvalid
	}

	var decoded auditCursorPayload
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return "", errAuditQueryInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", errAuditQueryInvalid
	}
	if decoded.Version != auditCursorVersion || decoded.Direction != auditCursorDirection ||
		decoded.Filter != filterDigest || auditdb.ValidateEventID(decoded.AfterID) != nil {
		return "", errAuditQueryInvalid
	}
	return decoded.AfterID, nil
}

func signAuditCursor(key []byte, encodedPayload string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(auditCursorDomain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(encodedPayload))
	return mac.Sum(nil)
}

func newAuditQueryItem(event auditdb.Event) auditQueryItem {
	item := auditQueryItem{
		TimestampUTC:         event.TimestampUTC,
		RequestID:            event.RequestID,
		Username:             event.Username,
		AuthMethod:           event.AuthMethod,
		TokenRef:             event.TokenRef,
		ShareRef:             event.ShareRef,
		ClientIP:             event.ClientIP,
		Action:               event.Action,
		Origin:               event.Origin,
		Source:               event.Source,
		Path:                 event.Path,
		CanonicalPath:        event.CanonicalPath,
		TargetSource:         event.TargetSource,
		TargetPath:           event.TargetPath,
		TargetCanonicalPath:  event.TargetCanonicalPath,
		Result:               event.Result,
		ErrorCode:            event.ErrorCode,
		Metadata:             auditdb.MergeMetadataV1(nil, event.Metadata),
		EffectivePermissions: nil,
		HTTPStatus:           nil,
		UserID:               nil,
	}
	if event.UserID != nil {
		value := *event.UserID
		item.UserID = &value
	}
	if event.HTTPStatus != nil {
		value := *event.HTTPStatus
		item.HTTPStatus = &value
	}
	if event.EffectivePermissions != nil {
		value := *event.EffectivePermissions
		item.EffectivePermissions = &value
	}
	return item
}
