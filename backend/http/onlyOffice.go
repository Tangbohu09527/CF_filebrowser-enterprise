package http

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
	"github.com/gtsteffaniak/go-cache/cache"
	"github.com/gtsteffaniak/go-logger/logger"
	"golang.org/x/net/http/httpguts"
)

const (
	onlyOfficeStatusDocumentBeingEdited             = 1
	onlyOfficeStatusDocumentClosedWithChanges       = 2
	onlyOfficeStatusDocumentSavingError             = 3
	onlyOfficeStatusDocumentClosedWithNoChanges     = 4
	onlyOfficeStatusForceSaveWhileDocumentStillOpen = 6
	onlyOfficeStatusForceSaveError                  = 7

	onlyOfficeDownloadTimeout = 10 * time.Second
	onlyOfficeCapabilityTTL   = 30 * time.Minute
	onlyOfficeCallbackMaxBody = 1 << 20

	onlyOfficeDownloadAudience = "filebrowser-onlyoffice-download"
	onlyOfficeCallbackAudience = "filebrowser-onlyoffice-callback"
)

var errOnlyOfficeCallbackTooLarge = errors.New("OnlyOffice callback body is too large")
var errOnlyOfficeWriteAuthorizationChanged = errors.New("OnlyOffice write authorization changed")

type onlyOfficeCapabilityClaims struct {
	jwt.RegisteredClaims
	Purpose           string `json:"purpose"`
	Method            string `json:"method"`
	Source            string `json:"source"`
	Path              string `json:"path"`
	LogicalPath       string `json:"logicalPath,omitempty"`
	CanonicalPath     string `json:"canonicalPath,omitempty"`
	ShareHash         string `json:"shareHash,omitempty"`
	UserID            uint   `json:"userId"`
	RequesterID       uint   `json:"requesterId,omitempty"`
	RequesterUsername string `json:"requesterUsername"`
	DocumentKey       string `json:"documentKey"`
	Browse            bool   `json:"browse"`
	Download          bool   `json:"download"`
	CanEdit           bool   `json:"canEdit"`
}

type onlyOfficeCapabilityState struct {
	Purpose            string
	Source             string
	Path               string
	ShareHash          string
	ShareLink          *share.Link
	UserID             uint
	RequesterID        uint
	RequesterUsername  string
	ParentAPITokenHash string
	DocumentKey        string
	RealPath           string
	FileInfo           os.FileInfo
	ContentSHA256      [sha256.Size]byte
}

var onlyOfficeCapabilityCache = cache.NewCache[onlyOfficeCapabilityState](onlyOfficeCapabilityTTL)
var onlyOfficeCapabilityUseMu sync.Mutex
var onlyOfficeCallbackInFlight = make(map[string]struct{})

// onlyOfficeDownloadClient fetches saved documents from the OnlyOffice document server.
// A bounded timeout avoids hanging goroutines when the server is unreachable.
var onlyOfficeDownloadClient = &http.Client{
	Timeout: onlyOfficeDownloadTimeout,
}

func onlyOfficeCapabilityExpiry(d *requestContext) time.Time {
	expires := time.Now().Add(onlyOfficeCapabilityTTL)
	if d == nil || d.token == "" {
		return expires
	}
	var parent users.AuthToken
	if _, _, err := new(jwt.Parser).ParseUnverified(d.token, &parent); err == nil &&
		parent.RegisteredClaims.ExpiresAt != nil && parent.RegisteredClaims.ExpiresAt.Time.Before(expires) {
		expires = parent.RegisteredClaims.ExpiresAt.Time
	}
	return expires
}

func onlyOfficeFileState(realPath string) (onlyOfficeCapabilityState, error) {
	var state onlyOfficeCapabilityState
	if realPath == "" {
		return state, errors.New("document path is missing")
	}
	file, err := os.Open(realPath)
	if err != nil {
		return state, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() {
		return state, errors.New("document is not a regular file")
	}
	hasher := sha256.New()
	if _, err = io.Copy(hasher, file); err != nil {
		return state, err
	}
	after, err := file.Stat()
	if err != nil || !publicShareSameFileIdentity(info, after) {
		return state, errors.New("document changed while reading")
	}
	state.RealPath = realPath
	state.FileInfo = after
	state.ContentSHA256 = [sha256.Size]byte(hasher.Sum(nil))
	return state, nil
}

func issueOnlyOfficeCapability(d *requestContext, claims onlyOfficeCapabilityClaims, state onlyOfficeCapabilityState) (string, error) {
	if settings.Config.Auth.Key == "" {
		return "", errors.New("authentication signing key is not configured")
	}
	expires := onlyOfficeCapabilityExpiry(d)
	now := time.Now()
	if !expires.After(now) {
		return "", errors.New("parent credential has expired")
	}
	jti, err := utils.RandomHex(16)
	if err != nil {
		return "", err
	}
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{claims.Purpose},
		ExpiresAt: jwt.NewNumericDate(expires),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-time.Second)),
		Issuer:    "FileBrowser Quantum OnlyOffice",
		ID:        jti,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	signed, err := token.SignedString([]byte(settings.Config.Auth.Key))
	if err != nil {
		return "", err
	}
	state.Purpose = claims.Purpose
	state.Source = claims.Source
	state.Path = claims.Path
	state.ShareHash = claims.ShareHash
	if claims.ShareHash != "" {
		if d == nil || d.share == nil || d.share.Hash != claims.ShareHash {
			return "", errors.New("capability share state is unavailable")
		}
		state.ShareLink = d.share
	} else if d != nil && d.share != nil {
		return "", errors.New("capability share state is inconsistent")
	}
	state.UserID = claims.UserID
	state.RequesterID = claims.RequesterID
	state.RequesterUsername = claims.RequesterUsername
	if d != nil && d.apiToken && d.token != "" {
		state.ParentAPITokenHash = utils.HashSHA256(d.token)
	}
	state.DocumentKey = claims.DocumentKey
	onlyOfficeCapabilityCache.SetWithExp(jti, state, time.Until(expires))
	return signed, nil
}

func parseOnlyOfficeCapability(r *http.Request, purpose, method string) (*onlyOfficeCapabilityClaims, error) {
	query := r.URL.Query()
	for key := range query {
		if key != "capability" {
			return nil, errors.New("unexpected capability parameter")
		}
	}
	raw := query.Get("capability")
	if raw == "" || settings.Config.Auth.Key == "" {
		return nil, errors.New("missing capability")
	}
	claims := &onlyOfficeCapabilityClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected capability signing method")
		}
		return []byte(settings.Config.Auth.Key), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil || !token.Valid {
		return nil, errors.New("invalid or expired capability")
	}
	if claims.Issuer != "FileBrowser Quantum OnlyOffice" || claims.ID == "" ||
		claims.Purpose != purpose || claims.Method != method || r.Method != method ||
		!claims.VerifyAudience(purpose, true) || claims.Source == "" || claims.Path == "" ||
		claims.UserID == 0 || claims.RequesterUsername == "" || claims.DocumentKey == "" ||
		(claims.RequesterID == 0 && claims.RequesterUsername != "anonymous") {
		return nil, errors.New("capability scope mismatch")
	}
	return claims, nil
}

func onlyOfficeCapabilityStateForClaims(claims *onlyOfficeCapabilityClaims) (onlyOfficeCapabilityState, error) {
	state, ok := onlyOfficeCapabilityCache.Get(claims.ID)
	if !ok || state.Purpose != claims.Purpose || state.Source != claims.Source || state.Path != claims.Path ||
		state.ShareHash != claims.ShareHash || state.UserID != claims.UserID || state.DocumentKey != claims.DocumentKey ||
		state.RequesterID != claims.RequesterID || state.RequesterUsername != claims.RequesterUsername ||
		(claims.ShareHash == "") != (state.ShareLink == nil) ||
		state.FileInfo == nil || state.RealPath == "" || state.ContentSHA256 == ([sha256.Size]byte{}) {
		return onlyOfficeCapabilityState{}, errors.New("capability state is not available")
	}
	return state, nil
}

type OnlyOfficeCallback struct {
	Actions       []OnlyOfficeAction `json:"actions,omitempty"`
	ChangesURL    string             `json:"changesurl,omitempty"`
	FileType      string             `json:"filetype,omitempty"`
	ForceSaveType int                `json:"forcesavetype,omitempty"`
	FormsDataURL  string             `json:"formsdataurl,omitempty"`
	History       *OnlyOfficeHistory `json:"history,omitempty"`
	Key           string             `json:"key,omitempty"`
	Status        int                `json:"status,omitempty"`
	URL           string             `json:"url,omitempty"`
	UserData      string             `json:"userdata,omitempty"`
	Users         []string           `json:"users,omitempty"`
}

type OnlyOfficeAction struct {
	Type   int    `json:"type"`
	UserID string `json:"userid"`
}

type OnlyOfficeHistory struct {
	Changes       interface{} `json:"changes"`
	ServerVersion string      `json:"serverVersion"`
}

// OnlyOfficeJWTPayload represents the JWT payload structure for OnlyOffice callbacks
type OnlyOfficeJWTPayload struct {
	Key     string   `json:"key"`
	Status  int      `json:"status"`
	Users   []string `json:"users"`
	Actions []struct {
		Type   int    `json:"type"`
		UserID string `json:"userid"`
	} `json:"actions"`
}

// onlyofficeClientConfigGetHandler retrieves OnlyOffice client configuration
//
// @Summary Get OnlyOffice client configuration
// @Description Returns the configuration needed for OnlyOffice document editor client
// @Tags Office
// @Accept json
// @Produce json
// @Param source query string false "Source name"
// @Param path query string false "File path"
// @Param hash query string false "Share hash (for public shares)"
// @Success 200 {object} map[string]interface{} "OnlyOffice configuration"
// @Failure 400 {object} map[string]string "Missing or invalid parameters"
// @Failure 500 {object} map[string]string "Server error"
// @Router /api/office/config [get]
// @Security ApiKeyAuth
func onlyofficeClientConfigGetHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if d.share == nil && (d.user == nil || !d.user.Permissions.Browse || !d.user.Permissions.Download) {
		return http.StatusForbidden, errors.New("browse and download permissions are required")
	}
	if d.share != nil && (d.shareUser == nil || !d.share.EnableOnlyOffice || len(d.shareTargets) != 1 ||
		!d.shareAccess.allows(publicShareReadOriginalViewer)) {
		return http.StatusForbidden, errors.New("public share does not allow OnlyOffice")
	}
	if config.Integrations.OnlyOffice.Url == "" || config.Integrations.OnlyOffice.Secret == "" {
		return http.StatusInternalServerError, errors.New("only-office URL and callback signing secret must be configured")
	}
	onlyOfficeURLBase := onlyOfficeBaseURL(r)
	if onlyOfficeURLBase == "" {
		return http.StatusInternalServerError, errors.New("only-office callback origin is not valid")
	}

	// Extract clean parameters from request
	source := r.URL.Query().Get("source")
	providedPath := r.URL.Query().Get("path")
	hash := r.URL.Query().Get("hash")
	if d.share == nil && hash != "" {
		return http.StatusBadRequest, errors.New("hash is only valid for public share requests")
	}

	// Validate required parameters
	if (providedPath == "" || source == "") && hash == "" {
		logger.Errorf("OnlyOffice callback missing required parameters: source=%s, path=%s", source, providedPath)
		return http.StatusBadRequest, errors.New("missing required parameters: path + source/hash are required")
	}

	// Rule 1: Validate user-provided path to prevent path traversal
	cleanPath, err := utils.SanitizeUserPath(providedPath)
	if err != nil {
		return http.StatusBadRequest, err
	}
	providedPath = cleanPath

	themeMode := utils.Ternary(d.user.DarkMode, "dark", "light")
	var sourceInfo *settings.Source
	var ok bool
	if d.share != nil {
		sourceInfo, ok = config.Server.SourceMap[d.share.Source]
		if !ok {
			logger.Error("OnlyOffice: source not found")
			return http.StatusInternalServerError, fmt.Errorf("source not found")
		}
	} else {
		sourceInfo, ok = config.Server.NameToSource[source]
		if !ok {
			logger.Error("OnlyOffice: source not found")
			return http.StatusInternalServerError, fmt.Errorf("source not found")
		}
	}
	source = sourceInfo.Name
	path := providedPath
	if d.share == nil {
		// Build file info based on whether this is a share or regular request
		// Regular user request
		logger.Debugf("OnlyOffice user request: request path=%s", path)
		var fileInfo *iteminfo.ExtendedFileInfo
		fileInfo, err = files.FileInfoFaster(utils.FileOptions{
			Path:           path,
			Source:         source,
			Expand:         false,
			FollowSymlinks: true,
		}, store.Access, d.user, store.Share)
		if err != nil {
			logger.Errorf("OnlyOffice: failed to get file info for source=%s, path=%s: %v", source, path, err)
			return errToStatus(err), err
		}
		d.fileInfo = *fileInfo
	} else {
		// path is index path, so we build from share path
		path = utils.JoinPathAsUnix(d.share.Path, providedPath)
		if d.share.EnforceDarkLightMode == "dark" {
			themeMode = "dark"
		}
		if d.share.EnforceDarkLightMode == "light" {
			themeMode = "light"
		}

	}

	// Determine file type and editing permissions
	fileType := strings.TrimPrefix(filepath.Ext(d.fileInfo.Name), ".")

	// Determine modify permissions based on whether this is a share or regular request
	var modifyPerms bool
	if d.share != nil {
		modifyPerms = d.share.CapabilityVersion == share.CurrentCapabilityVersion &&
			d.shareUser.Permissions.Share && d.shareUser.Permissions.Modify &&
			d.share.CreatorCapabilities.Share && d.share.CreatorCapabilities.Modify && d.share.AllowModify
	} else {
		// Regular user request - check user permissions
		modifyPerms = d.user.Permissions.Modify
	}

	canEdit := iteminfo.CanEditOnlyOffice(modifyPerms, fileType)
	canEditMode := utils.Ternary(canEdit, "edit", "view")
	// Generate document ID for OnlyOffice
	documentId, err := getOnlyOfficeId(d.fileInfo.RealPath)
	if err != nil {
		logger.Errorf("OnlyOffice: failed to generate document ID for source=%s, path=%s: %v", source, path, err)
		return http.StatusNotFound, fmt.Errorf("failed to generate document ID: %v", err)
	}

	// Create and store log context for this OnlyOffice session
	sessionID := r.URL.Query().Get("sessionId")
	if sessionID == "" {
		sessionID = "unknown"
	}

	shareHash := ""
	if d.share != nil {
		shareHash = d.share.Hash
	}

	logContext := createOnlyOfficeLogContext(
		d.user.Username,
		sessionID,
		documentId,
		path,
		source,
		shareHash,
		d.user.Permissions.Admin,
	)
	storeOnlyOfficeLogContext(documentId, logContext)

	// Send initial log event with detailed path information
	sendOnlyOfficeLogEvent(logContext, "INFO", "config", fmt.Sprintf("OnlyOffice session started for document: %s ", path))

	state, err := onlyOfficeFileState(d.fileInfo.RealPath)
	if err != nil {
		return http.StatusNotFound, fmt.Errorf("document is no longer available")
	}
	capabilityPath := path
	capabilityUserID := d.user.ID
	logicalPath := ""
	canonicalPath := ""
	capabilityBrowse := d.user.Permissions.Browse
	capabilityDownload := d.user.Permissions.Download
	if d.share != nil {
		target := d.shareTargets[0]
		capabilityPath = target.ScopedPath
		capabilityUserID = d.shareUser.ID
		logicalPath = target.LogicalPath
		canonicalPath = target.CanonicalPath
		capabilityBrowse = d.shareAccess.browse
		capabilityDownload = d.shareAccess.download
	}
	baseCapability := onlyOfficeCapabilityClaims{
		Source:            source,
		Path:              capabilityPath,
		LogicalPath:       logicalPath,
		CanonicalPath:     canonicalPath,
		ShareHash:         shareHash,
		UserID:            capabilityUserID,
		RequesterID:       d.user.ID,
		RequesterUsername: d.user.Username,
		DocumentKey:       documentId,
		Browse:            capabilityBrowse,
		Download:          capabilityDownload,
		CanEdit:           canEdit && !config.Integrations.OnlyOffice.ViewOnly,
	}
	downloadClaims := baseCapability
	downloadClaims.Purpose = onlyOfficeDownloadAudience
	downloadClaims.Method = http.MethodGet
	downloadCapability, err := issueOnlyOfficeCapability(d, downloadClaims, state)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to create OnlyOffice download capability")
	}
	callbackClaims := baseCapability
	callbackClaims.Purpose = onlyOfficeCallbackAudience
	callbackClaims.Method = http.MethodPost
	callbackCapability, err := issueOnlyOfficeCapability(d, callbackClaims, state)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to create OnlyOffice callback capability")
	}

	// Build scoped URLs that do not contain the parent FileBrowser bearer.
	downloadURL := buildOnlyOfficeCapabilityURL(onlyOfficeURLBase, "/api/office/download", downloadCapability)
	callbackURL := buildOnlyOfficeCapabilityURL(onlyOfficeURLBase, "/api/office/callback", callbackCapability)

	// Build OnlyOffice client configuration
	clientConfig := map[string]interface{}{
		"document": map[string]interface{}{
			"fileType": fileType,
			"key":      documentId,
			"title":    d.fileInfo.Name,
			"url":      downloadURL,
			"permissions": map[string]interface{}{
				"edit":     utils.Ternary(config.Integrations.OnlyOffice.ViewOnly, "view", canEditMode),
				"download": true,
				"print":    true,
			},
		},
		"editorConfig": map[string]interface{}{
			"callbackUrl": callbackURL,
			"user": map[string]interface{}{
				"id":   strconv.FormatUint(uint64(d.user.ID), 10),
				"name": d.user.Username,
			},
			"customization": map[string]interface{}{
				"autosave":  true,
				"forcesave": true,
				"uiTheme":   themeMode,
			},
			"lang": d.user.Locale,
			"mode": utils.Ternary(config.Integrations.OnlyOffice.ViewOnly, "view", canEditMode),
		},
	}

	// Sign configuration with JWT if secret is configured
	if config.Integrations.OnlyOffice.Secret != "" {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(clientConfig))
		signature, err := token.SignedString([]byte(config.Integrations.OnlyOffice.Secret))
		if err != nil {
			logger.Errorf("OnlyOffice: failed to sign JWT: %v", err)
			return http.StatusInternalServerError, fmt.Errorf("failed to sign configuration")
		}
		clientConfig["token"] = signature
	}

	return renderJSON(w, r, clientConfig)
}

func onlyOfficeValidHost(host string) bool {
	if host == "" || strings.Contains(host, ",") || strings.HasSuffix(host, ":") || !httpguts.ValidHostHeader(host) {
		return false
	}
	parsed, err := url.Parse("http://" + host)
	if err != nil || parsed.User != nil || parsed.Host != host || parsed.Hostname() == "" ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return false
		}
	}
	return true
}

func onlyOfficeValidatedBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.RawPath != "" || strings.ContainsAny(parsed.Path, "\\\r\n\t") ||
		!isAllowedOnlyOfficeScheme(strings.ToLower(parsed.Scheme)) || !onlyOfficeValidHost(parsed.Host) {
		return nil, errors.New("invalid OnlyOffice base URL")
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, errors.New("invalid OnlyOffice base URL path")
		}
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	return parsed, nil
}

func onlyOfficeBaseURL(r *http.Request) string {
	configured := config.Server.InternalUrl
	if configured == "" {
		configured = config.Server.ExternalUrl
	}
	var base *url.URL
	var err error
	if configured != "" {
		base, err = onlyOfficeValidatedBaseURL(configured)
	} else {
		if r == nil {
			return ""
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if config.Http.TrustedHeaders["x-forwarded-proto"] {
			if forwardedProto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwardedProto != "" {
				scheme = strings.ToLower(forwardedProto)
			}
		}
		host := strings.TrimSpace(r.Host)
		if config.Http.TrustedHeaders["x-forwarded-host"] {
			if forwardedHost := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
				host = forwardedHost
			}
		}
		base, err = onlyOfficeValidatedBaseURL(scheme + "://" + host)
	}
	if err != nil {
		return ""
	}
	basePath := strings.Trim(config.Server.BaseURL, "/")
	if basePath != "" {
		base.Path = strings.TrimSuffix(base.Path, "/") + "/" + basePath
	}
	return strings.TrimSuffix(base.String(), "/")
}

func buildOnlyOfficeCapabilityURL(baseURL, endpoint, capability string) string {
	if baseURL == "" || capability == "" {
		return ""
	}
	params := url.Values{"capability": {capability}}
	return strings.TrimSuffix(baseURL, "/") + endpoint + "?" + params.Encode()
}

// buildOnlyOfficeDownloadURL constructs the capability-scoped download URL.
func buildOnlyOfficeDownloadURL(r *http.Request, capability string) string {
	return buildOnlyOfficeCapabilityURL(onlyOfficeBaseURL(r), "/api/office/download", capability)
}

// buildOnlyOfficeCallbackURL constructs the capability-scoped callback URL.
func buildOnlyOfficeCallbackURL(r *http.Request, capability string) string {
	return buildOnlyOfficeCapabilityURL(onlyOfficeBaseURL(r), "/api/office/callback", capability)
}

func onlyOfficePublicEditAllowed(d *requestContext) bool {
	return d != nil && d.share != nil && d.shareUser != nil &&
		d.share.CapabilityVersion == share.CurrentCapabilityVersion &&
		d.shareUser.Permissions.Share && d.shareUser.Permissions.Modify &&
		d.share.CreatorCapabilities.Share && d.share.CreatorCapabilities.Modify && d.share.AllowModify
}

func onlyOfficeCapabilityRequester(claims *onlyOfficeCapabilityClaims) (*users.User, error) {
	if claims.RequesterID == 0 {
		if claims.RequesterUsername != "anonymous" {
			return nil, errors.New("capability requester is invalid")
		}
		requester := &users.User{Username: "anonymous"}
		settings.ApplyUserDefaults(requester)
		return requester, nil
	}
	requester, err := store.Users.Get(claims.RequesterID)
	if err != nil || requester.Username == "" || requester.Username != claims.RequesterUsername {
		return nil, errors.New("capability requester is not available")
	}
	return requester, nil
}

func onlyOfficeUserHasAPITokenHash(user *users.User, tokenHash string) bool {
	if user == nil || tokenHash == "" {
		return false
	}
	for _, tokens := range []map[string]users.AuthToken{user.Tokens, user.ApiKeys} {
		for _, token := range tokens {
			if token.MatchesTokenHash(tokenHash) {
				return true
			}
		}
	}
	return false
}

func onlyOfficeParentAPITokenActive(state onlyOfficeCapabilityState, requester *users.User) bool {
	if state.ParentAPITokenHash == "" {
		return true
	}
	return store.Access != nil && requester != nil &&
		store.Access.IsApiTokenHashActive(state.ParentAPITokenHash, requester.ID) &&
		onlyOfficeUserHasAPITokenHash(requester, state.ParentAPITokenHash)
}

func resolveOnlyOfficeCapability(claims *onlyOfficeCapabilityClaims, requireEdit bool) (*requestContext, onlyOfficeCapabilityState, error) {
	state, err := onlyOfficeCapabilityStateForClaims(claims)
	if err != nil {
		return nil, state, err
	}
	owner, err := store.Users.Get(claims.UserID)
	if err != nil || owner.Username == "" {
		return nil, state, errors.New("capability user is not available")
	}
	requester, err := onlyOfficeCapabilityRequester(claims)
	if err != nil || !onlyOfficeParentAPITokenActive(state, requester) {
		return nil, state, errors.New("capability requester credential is no longer available")
	}
	if requireEdit && config.Integrations.OnlyOffice.ViewOnly {
		return nil, state, errors.New("OnlyOffice is now view-only")
	}
	d := &requestContext{user: requester}
	var fileInfo *iteminfo.ExtendedFileInfo
	if claims.ShareHash != "" {
		link, err := store.Share.GetByHash(claims.ShareHash)
		if err != nil || link != state.ShareLink || link.UserID != owner.ID || !link.EnableOnlyOffice {
			return nil, state, errors.New("capability share is not available")
		}
		if !publicShareAudienceAllowed(link, requester) ||
			(link.PerUserDownloadLimit && requester.Username == "anonymous") {
			return nil, state, errors.New("capability requester is no longer allowed")
		}
		sourceInfo, ok := config.Server.SourceMap[link.Source]
		if !ok || sourceInfo.Config.Private || sourceInfo.Name != claims.Source {
			return nil, state, errors.New("capability source is not available")
		}
		access := calculatePublicShareAccess(link, owner)
		if !claims.Browse || !claims.Download || !access.allows(publicShareReadOriginalViewer) {
			return nil, state, errors.New("capability read permission is no longer available")
		}
		if requireEdit && (!claims.CanEdit || !onlyOfficePublicEditAllowed(&requestContext{share: link, shareUser: owner})) {
			return nil, state, errors.New("capability edit permission is no longer available")
		}
		ownerScope, err := owner.GetScopeForSourceName(sourceInfo.Name)
		if err != nil || ownerScope == "" {
			return nil, state, errors.New("capability owner scope is not available")
		}
		cleanScope, err := cleanPublicShareRelativePath(ownerScope)
		if err != nil {
			return nil, state, errors.New("capability owner scope is invalid")
		}
		d.share = link
		d.shareUser = owner
		d.shareAccess = access
		d.shareScope = normalizePublicShareIndexPath(cleanScope)
		target, err := resolvePublicShareLogicalTarget(d, sourceInfo.Path, claims.LogicalPath)
		if err != nil || target.IsDir || target.CanonicalPath != claims.CanonicalPath || target.ScopedPath != claims.Path {
			return nil, state, errors.New("capability target is no longer available")
		}
		fileInfo, err = files.FileInfoFaster(utils.FileOptions{
			Path:           target.ScopedPath,
			Source:         sourceInfo.Name,
			Expand:         false,
			FollowSymlinks: true,
		}, store.Access, owner, store.Share)
		if err != nil {
			return nil, state, errors.New("capability target is no longer available")
		}
		fileInfo.RealPath = target.RealPath
		fileInfo.Hash = link.Hash
		d.IndexPath = target.ScopedPath
		d.shareTargets = []publicShareTarget{target}
	} else {
		if requester.ID != owner.ID || requester.Username != owner.Username {
			return nil, state, errors.New("capability requester does not match its owner")
		}
		if !claims.Browse || !claims.Download || !owner.Permissions.Browse || !owner.Permissions.Download {
			return nil, state, errors.New("capability read permission is no longer available")
		}
		if requireEdit && (!claims.CanEdit || !owner.Permissions.Modify) {
			return nil, state, errors.New("capability edit permission is no longer available")
		}
		sourceInfo, ok := config.Server.NameToSource[claims.Source]
		if !ok || store.Access == nil {
			return nil, state, errors.New("capability source is not available")
		}
		userScope, err := owner.GetScopeForSourceName(sourceInfo.Name)
		if err != nil || userScope == "" {
			return nil, state, errors.New("capability user scope is not available")
		}
		logicalPath := utils.JoinPathAsUnix(userScope, claims.Path)
		if !store.Access.PermittedFresh(sourceInfo.Path, logicalPath, owner.Username) {
			return nil, state, errors.New("capability access rule is no longer available")
		}
		fileInfo, err = files.FileInfoFaster(utils.FileOptions{
			Path:           claims.Path,
			Source:         claims.Source,
			Expand:         false,
			FollowSymlinks: true,
		}, store.Access, owner, store.Share)
		if err != nil {
			return nil, state, errors.New("capability target is no longer available")
		}
		d.IndexPath = claims.Path
	}
	if fileInfo == nil || fileInfo.RealPath == "" || fileInfo.Type == "directory" {
		return nil, state, errors.New("capability target is not a file")
	}
	current, err := onlyOfficeFileState(fileInfo.RealPath)
	if err != nil || !publicShareSameRealPath(current.RealPath, state.RealPath) ||
		!publicShareSameFileIdentity(state.FileInfo, current.FileInfo) || current.ContentSHA256 != state.ContentSHA256 {
		return nil, state, errors.New("capability file identity changed")
	}
	documentKey, ok := utils.OnlyOfficeCache.Get(fileInfo.RealPath)
	if !ok || documentKey != claims.DocumentKey {
		return nil, state, errors.New("capability document key is no longer valid")
	}
	d.fileInfo = *fileInfo
	return d, state, nil
}

func onlyOfficeCapabilityDownloadHandler(w http.ResponseWriter, r *http.Request, _ *requestContext) (int, error) {
	claims, err := parseOnlyOfficeCapability(r, onlyOfficeDownloadAudience, http.MethodGet)
	if err != nil {
		return http.StatusForbidden, errors.New("invalid OnlyOffice download capability")
	}
	d, state, err := resolveOnlyOfficeCapability(claims, false)
	if err != nil {
		return http.StatusForbidden, errors.New("OnlyOffice download capability is no longer authorized")
	}
	file, err := os.Open(d.fileInfo.RealPath)
	if err != nil {
		return http.StatusNotFound, errors.New("OnlyOffice document is not available")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !publicShareSameFileIdentity(state.FileInfo, info) {
		return http.StatusForbidden, errors.New("OnlyOffice document changed")
	}
	hasher := sha256.New()
	if _, err = io.Copy(hasher, file); err != nil {
		return http.StatusForbidden, errors.New("OnlyOffice document could not be verified")
	}
	after, err := file.Stat()
	if err != nil || !publicShareSameFileIdentity(info, after) ||
		[sha256.Size]byte(hasher.Sum(nil)) != state.ContentSHA256 {
		return http.StatusForbidden, errors.New("OnlyOffice document changed")
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return http.StatusInternalServerError, errors.New("OnlyOffice document could not be read")
	}
	onlyOfficeCapabilityUseMu.Lock()
	if _, err := onlyOfficeCapabilityStateForClaims(claims); err != nil {
		onlyOfficeCapabilityUseMu.Unlock()
		return http.StatusForbidden, errors.New("OnlyOffice download capability was already used")
	}
	if d.share != nil && !consumePublicShareOriginalRead(d) {
		onlyOfficeCapabilityUseMu.Unlock()
		return http.StatusForbidden, errors.New("OnlyOffice public download limit reached")
	}
	onlyOfficeCapabilityCache.Delete(claims.ID)
	onlyOfficeCapabilityUseMu.Unlock()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, d.fileInfo.Name, after.ModTime(), file)
	return http.StatusOK, nil
}

func beginOnlyOfficeCallbackUse(claims *onlyOfficeCapabilityClaims) error {
	onlyOfficeCapabilityUseMu.Lock()
	defer onlyOfficeCapabilityUseMu.Unlock()
	if _, inFlight := onlyOfficeCallbackInFlight[claims.DocumentKey]; inFlight {
		return errors.New("OnlyOffice callback capability is already in use")
	}
	if _, err := onlyOfficeCapabilityStateForClaims(claims); err != nil {
		return err
	}
	onlyOfficeCallbackInFlight[claims.DocumentKey] = struct{}{}
	return nil
}

func finishOnlyOfficeCallbackUse(claims *onlyOfficeCapabilityClaims, consume bool) {
	onlyOfficeCapabilityUseMu.Lock()
	delete(onlyOfficeCallbackInFlight, claims.DocumentKey)
	if consume {
		onlyOfficeCapabilityCache.Delete(claims.ID)
	}
	onlyOfficeCapabilityUseMu.Unlock()
}

// resolveOnlyOfficeDownloadURL validates a callback document URL against
// integrations.office.url and optionally rewrites the origin to integrations.office.internalUrl.
// Returns an empty string when the URL is missing, malformed, or not hosted on the configured
// OnlyOffice server (SSRF protection).
func resolveOnlyOfficeDownloadURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	publicBase := config.Integrations.OnlyOffice.Url
	if publicBase == "" {
		logger.Warningf("OnlyOffice callback: integrations.office.url is not configured")
		return ""
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Opaque != "" || parsedURL.User != nil || parsedURL.Fragment != "" ||
		!isAllowedOnlyOfficeScheme(parsedURL.Scheme) || !onlyOfficeValidHost(parsedURL.Host) {
		logger.Warning("OnlyOffice callback: document URL is invalid")
		return ""
	}

	publicURL, err := onlyOfficeValidatedBaseURL(publicBase)
	if err != nil {
		logger.Warning("OnlyOffice callback: integrations.office.url is invalid")
		return ""
	}

	if !onlyOfficeURLHostsMatch(parsedURL, publicURL) {
		logger.Warning("OnlyOffice callback: rejecting document URL with an untrusted origin")
		return ""
	}

	internalBase := config.Integrations.OnlyOffice.InternalUrl
	if internalBase == "" {
		return rawURL
	}

	internalURL, err := onlyOfficeValidatedBaseURL(internalBase)
	if err != nil {
		logger.Warning("OnlyOffice callback: integrations.office.internalUrl is invalid")
		return ""
	}

	rewritten := *parsedURL
	rewritten.Scheme = internalURL.Scheme
	rewritten.Host = internalURL.Host
	result := rewritten.String()
	if result != rawURL {
		logger.Debug("OnlyOffice callback: using configured internal document server URL")
	}
	return result
}

func isAllowedOnlyOfficeScheme(scheme string) bool {
	return strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "https")
}

func onlyOfficeEffectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

// onlyOfficeURLHostsMatch reports whether callback and configured URLs refer to the same
// OnlyOffice host, comparing hostname and effective port (so office.local matches office.local:80).
func onlyOfficeURLHostsMatch(callback, configured *url.URL) bool {
	if callback == nil || configured == nil || callback.User != nil || configured.User != nil ||
		!isAllowedOnlyOfficeScheme(callback.Scheme) || !isAllowedOnlyOfficeScheme(configured.Scheme) ||
		!onlyOfficeValidHost(callback.Host) || !onlyOfficeValidHost(configured.Host) {
		return false
	}
	if callback.Hostname() == "" || configured.Hostname() == "" {
		return false
	}
	if !strings.EqualFold(callback.Hostname(), configured.Hostname()) {
		return false
	}
	return onlyOfficeEffectivePort(callback) == onlyOfficeEffectivePort(configured)
}

func onlyOfficeRedirectAllowed(target *url.URL) bool {
	for _, configured := range []string{config.Integrations.OnlyOffice.Url, config.Integrations.OnlyOffice.InternalUrl} {
		if configured == "" {
			continue
		}
		base, err := url.Parse(configured)
		if err == nil && onlyOfficeURLHostsMatch(target, base) {
			return true
		}
	}
	return false
}

func onlyOfficeCheckRedirect(request *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("too many OnlyOffice redirects")
	}
	if !onlyOfficeRedirectAllowed(request.URL) {
		return errors.New("OnlyOffice redirect target is not trusted")
	}
	return nil
}

func onlyOfficeOriginForLog(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || !isAllowedOnlyOfficeScheme(parsed.Scheme) || !onlyOfficeValidHost(parsed.Host) {
		return "[redacted]"
	}
	return strings.ToLower(parsed.Scheme) + "://" + parsed.Host
}

func logOnlyOfficeDownloadError(err error) {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		logger.Errorf("OnlyOffice callback: failed to download updated document from %s (%T)",
			onlyOfficeOriginForLog(urlErr.URL), urlErr.Err)
		return
	}
	logger.Errorf("OnlyOffice callback: failed to download updated document (%T)", err)
}

// processOnlyOfficeCallback handles the common callback processing logic for both GET and POST requests
func processOnlyOfficeCallback(w http.ResponseWriter, r *http.Request, d *requestContext, data *OnlyOfficeCallback, authorizeWrite func() error) (int, error) {
	// Extract clean parameters from query string
	source := r.URL.Query().Get("source")
	path := r.URL.Query().Get("path")
	user := d.user

	if d.share != nil {
		source = d.share.GetSourceName()
		path = d.IndexPath
		user = d.shareUser
	}

	// Validate required parameters
	if (path == "" || source == "") && d.fileInfo.Hash == "" {
		logger.Errorf("OnlyOffice callback missing required parameters: source=%s, path=%s", source, path)
		return returnOnlyOfficeError(w, r, 400, "missing required parameters: path + source/hash are required")
	}

	// Rule 1: Validate user-provided path to prevent path traversal
	cleanPath, err := utils.SanitizeUserPath(path)
	if err != nil {
		return returnOnlyOfficeError(w, r, 400, err.Error())
	}
	path = cleanPath

	// Handle document being edited (status 1) - just log for now
	if data.Status == onlyOfficeStatusDocumentBeingEdited {
		logger.Debugf("OnlyOffice callback: document being edited, key=%s, users=%v", data.Key, data.Users)

		// Send log event for document being edited
		if logContext := getOnlyOfficeLogContext(data.Key); logContext != nil {
			sendOnlyOfficeLogEvent(logContext, "DEBUG", "callback", fmt.Sprintf("Document being edited, users: %v", data.Users))
		}

		// Handle actions if present
		for _, action := range data.Actions {
			actionMsg := ""
			switch action.Type {
			case 0: // User disconnects
				actionMsg = fmt.Sprintf("User ID %s disconnected from document", action.UserID)
				logger.Debugf("OnlyOffice callback: user ID %s disconnected from document", action.UserID)
			case 1: // New user connects
				actionMsg = fmt.Sprintf("User ID %s connected to document", action.UserID)
				logger.Debugf("OnlyOffice callback: user ID %s connected to document", action.UserID)
			case 2: // User clicked forcesave button
				actionMsg = fmt.Sprintf("User ID %s clicked forcesave button", action.UserID)
				logger.Debugf("OnlyOffice callback: user ID %s clicked forcesave button", action.UserID)
			default:
				actionMsg = fmt.Sprintf("Unknown action type %d for user ID %s", action.Type, action.UserID)
				logger.Debugf("OnlyOffice callback: unknown action type %d for user ID %s", action.Type, action.UserID)
			}

			// Send log event for action
			if logContext := getOnlyOfficeLogContext(data.Key); logContext != nil {
				sendOnlyOfficeLogEvent(logContext, "DEBUG", "callback", actionMsg)
			}
		}
	}

	// Handle document save operations (status 2, 3, 6, 7)
	if data.Status == onlyOfficeStatusDocumentClosedWithChanges ||
		data.Status == onlyOfficeStatusDocumentSavingError ||
		data.Status == onlyOfficeStatusForceSaveWhileDocumentStillOpen ||
		data.Status == onlyOfficeStatusForceSaveError {

		// Log the save operation details
		statusDesc := ""
		switch data.Status {
		case onlyOfficeStatusDocumentClosedWithChanges:
			statusDesc = "document closed with changes"
		case onlyOfficeStatusDocumentSavingError:
			statusDesc = "document saving error"
		case onlyOfficeStatusForceSaveWhileDocumentStillOpen:
			statusDesc = "force save while document still open"
		case onlyOfficeStatusForceSaveError:
			statusDesc = "force save error"
		}

		logger.Debugf("OnlyOffice callback: processing save operation - %s, key=%s, forcesavetype=%d",
			statusDesc, data.Key, data.ForceSaveType)

		// Send log event for save operation
		if logContext := getOnlyOfficeLogContext(data.Key); logContext != nil {
			sendOnlyOfficeLogEvent(logContext, "INFO", "callback", fmt.Sprintf("Processing save operation: %s", statusDesc))
		}

		// Handle history and changes URL if present
		if data.History != nil {
			logger.Debugf("OnlyOffice callback: received history data with serverVersion=%s", data.History.ServerVersion)
			if logContext := getOnlyOfficeLogContext(data.Key); logContext != nil {
				sendOnlyOfficeLogEvent(logContext, "DEBUG", "callback", fmt.Sprintf("Received history data with serverVersion=%s", data.History.ServerVersion))
			}
		}
		if data.ChangesURL != "" {
			logger.Debug("OnlyOffice callback: received changes URL")
			if logContext := getOnlyOfficeLogContext(data.Key); logContext != nil {
				sendOnlyOfficeLogEvent(logContext, "DEBUG", "callback", "Received changes URL for document history")
			}
		}

		// Error statuses acknowledge the callback but never fetch or write document bytes.
		if data.Status == onlyOfficeStatusDocumentSavingError || data.Status == onlyOfficeStatusForceSaveError {
			logger.Warningf("OnlyOffice callback: document saving error occurred, not attempting to save")
			return returnOnlyOfficeSuccess(w, r)
		}

		// Check share permissions first if this is a share request
		if d.share != nil {
			if !d.share.AllowModify {
				logger.Errorf("OnlyOffice callback: edit permission not allowed for this share")
				return returnOnlyOfficeError(w, r, 403, "edit permission not allowed for this share")
			}
		} else {
			// Verify user has modify permissions
			if !user.Permissions.Modify {
				logger.Errorf("OnlyOffice callback: user %s lacks modify permissions for path=%s",
					d.user.Username, path)
				return returnOnlyOfficeError(w, r, 403, "user lacks modify permissions")
			}
		}

		// Download the updated document from OnlyOffice server
		downloadURL := resolveOnlyOfficeDownloadURL(data.URL)
		if downloadURL == "" {
			logger.Errorf("OnlyOffice callback: missing or untrusted document URL in callback payload")
			return returnOnlyOfficeError(w, r, 500, "missing or untrusted document URL in callback payload")
		}
		client := *onlyOfficeDownloadClient
		client.CheckRedirect = onlyOfficeCheckRedirect
		doc, err := client.Get(downloadURL)
		if err != nil {
			logOnlyOfficeDownloadError(err)
			return returnOnlyOfficeError(w, r, 500, "failed to download updated document")
		}
		defer doc.Body.Close()

		// Check if the download was successful
		if doc.StatusCode != 200 {
			logger.Errorf("OnlyOffice callback: failed to download document, status code: %d", doc.StatusCode)
			return returnOnlyOfficeError(w, r, 500, "failed to download document from OnlyOffice server")
		}

		logger.Debugf("OnlyOffice callback: saving document to path=%s",
			path)

		// Send detailed log event for file saving with path information
		if logContext := getOnlyOfficeLogContext(data.Key); logContext != nil {
			sendOnlyOfficeLogEvent(logContext, "INFO", "callback", fmt.Sprintf("Saving document to path: %s", path))
		}

		// CRITICAL: Validate that the original file still exists before saving
		// This prevents creating duplicate files if the original was renamed/moved
		_, err = files.FileInfoFaster(utils.FileOptions{
			Source: source,
			Path:   path,
		}, store.Access, user, store.Share)
		if err != nil {
			logger.Errorf("OnlyOffice callback: original file no longer exists at path=%s: %v",
				path, err)

			// Send error log event with path information
			if logContext := getOnlyOfficeLogContext(data.Key); logContext != nil {
				sendOnlyOfficeLogEvent(logContext, "ERROR", "callback",
					fmt.Sprintf("Original file no longer exists at path: %s - %v -- was it renamed or moved?", path, err))
			}

			return returnOnlyOfficeError(w, r, 404, "original file no longer exists - it may have been renamed or moved")
		}

		// Get user scope to resolve full index path for write operation
		userScope, err := user.GetScopeForSourceName(source)
		if err != nil {
			return returnOnlyOfficeError(w, r, 403, "user scope not found")
		}
		fullIndexPath := utils.JoinPathAsUnix(userScope, path)

		reader := io.Reader(doc.Body)
		if authorizeWrite != nil {
			reader = &onlyOfficeAuthorizedReader{reader: reader, authorize: authorizeWrite}
		}
		writeErr := files.WriteFile(source, fullIndexPath, reader)
		if writeErr != nil {
			if errors.Is(writeErr, errOnlyOfficeWriteAuthorizationChanged) {
				return returnOnlyOfficeError(w, r, http.StatusForbidden, "OnlyOffice write authorization changed")
			}
			logger.Errorf("OnlyOffice callback: failed to write updated document to path=%s: %v",
				path, writeErr)

			// Send error log event with path information
			if logContext := getOnlyOfficeLogContext(data.Key); logContext != nil {
				sendOnlyOfficeLogEvent(logContext, "ERROR", "callback", fmt.Sprintf("Failed to save document to path: %s - %v", path, writeErr))
			}

			return returnOnlyOfficeError(w, r, 500, "failed to save document")
		}

		logger.Infof("OnlyOffice callback: successfully saved document to path=%s",
			path)

		// Send success log event with detailed path information
		if logContext := getOnlyOfficeLogContext(data.Key); logContext != nil {
			sendOnlyOfficeLogEvent(logContext, "INFO", "callback", fmt.Sprintf("Document saved successfully to path: %s", path))
		}
	}
	if data.Status == onlyOfficeStatusDocumentClosedWithChanges || data.Status == onlyOfficeStatusDocumentClosedWithNoChanges {
		deleteOfficeId(source, path)
		if logContext := getOnlyOfficeLogContext(data.Key); logContext != nil {
			statusMsg := "Document closed with changes"
			if data.Status == onlyOfficeStatusDocumentClosedWithNoChanges {
				statusMsg = "Document closed with no changes"
			}
			sendOnlyOfficeLogEvent(logContext, "INFO", "callback", statusMsg)
			removeOnlyOfficeLogContext(data.Key)
		}
	}

	// Return success response to OnlyOffice server
	return returnOnlyOfficeSuccess(w, r)
}

type onlyOfficeAuthorizedReader struct {
	reader     io.Reader
	authorize  func() error
	authorized bool
}

func (reader *onlyOfficeAuthorizedReader) Read(buffer []byte) (int, error) {
	n, err := reader.reader.Read(buffer)
	if err == io.EOF && !reader.authorized {
		reader.authorized = true
		if authErr := reader.authorize(); authErr != nil {
			return n, errOnlyOfficeWriteAuthorizationChanged
		}
	}
	return n, err
}

// onlyofficeCallbackHandler handles OnlyOffice document server callbacks
//
// @Summary Handle OnlyOffice document server callback
// @Description Receives callbacks from OnlyOffice document server for document status changes and saves
// @Tags Office
// @Accept json
// @Produce json
// @Param source query string false "Source name"
// @Param path query string false "File path"
// @Param hash query string false "Share hash (for public shares)"
// @Success 200 {object} map[string]interface{} "Callback processed successfully"
// @Failure 400 {object} map[string]string "Invalid callback data"
// @Failure 500 {object} map[string]string "Server error"
// @Router /api/office/callback [post]
// @Security ApiKeyAuth
func onlyofficeCallbackHandler(w http.ResponseWriter, r *http.Request, _ *requestContext) (int, error) {
	// Capability and payload signatures are verified before any store, file, cache, or network access.
	claims, err := parseOnlyOfficeCapability(r, onlyOfficeCallbackAudience, http.MethodPost)
	if err != nil {
		return http.StatusForbidden, errors.New("invalid OnlyOffice callback capability")
	}
	callbackData, err := parseOnlyOfficeCallbackFromJSON(r)
	if errors.Is(err, errOnlyOfficeCallbackTooLarge) {
		return http.StatusRequestEntityTooLarge, errOnlyOfficeCallbackTooLarge
	}
	if err != nil || callbackData == nil {
		return http.StatusForbidden, errors.New("invalid OnlyOffice callback payload")
	}
	if err := verifyOnlyOfficeCallbackBody(r, callbackData); err != nil {
		return http.StatusForbidden, errors.New("invalid OnlyOffice callback signature")
	}
	if callbackData.Key != claims.DocumentKey {
		return http.StatusForbidden, errors.New("OnlyOffice callback document key mismatch")
	}
	if err := beginOnlyOfficeCallbackUse(claims); err != nil {
		return http.StatusForbidden, errors.New("OnlyOffice callback capability is already in use or unavailable")
	}
	consumeCapability := false
	defer func() { finishOnlyOfficeCallbackUse(claims, consumeCapability) }()
	requireEdit := callbackData.Status == onlyOfficeStatusDocumentClosedWithChanges ||
		callbackData.Status == onlyOfficeStatusForceSaveWhileDocumentStillOpen
	d, state, err := resolveOnlyOfficeCapability(claims, requireEdit)
	if err != nil {
		return http.StatusForbidden, errors.New("OnlyOffice callback capability is no longer authorized")
	}
	query := url.Values{"source": {claims.Source}, "path": {claims.Path}}
	r.URL.RawQuery = query.Encode()
	authorizeWrite := func() error {
		if _, _, authErr := resolveOnlyOfficeCapability(claims, true); authErr != nil {
			return errOnlyOfficeWriteAuthorizationChanged
		}
		return nil
	}
	status, processErr := processOnlyOfficeCallback(w, r, d, callbackData, authorizeWrite)
	if processErr == nil && status < http.StatusBadRequest {
		switch callbackData.Status {
		case onlyOfficeStatusDocumentClosedWithChanges, onlyOfficeStatusDocumentClosedWithNoChanges:
			consumeCapability = true
		case onlyOfficeStatusForceSaveWhileDocumentStillOpen:
			updated, stateErr := onlyOfficeFileState(d.fileInfo.RealPath)
			if stateErr != nil {
				onlyOfficeCapabilityCache.Delete(claims.ID)
			} else {
				state.RealPath = updated.RealPath
				state.FileInfo = updated.FileInfo
				state.ContentSHA256 = updated.ContentSHA256
				remaining := time.Until(claims.ExpiresAt.Time)
				if remaining > 0 {
					onlyOfficeCapabilityCache.SetWithExp(claims.ID, state, remaining)
				}
			}
		}
	}
	return status, processErr
}

// parseOnlyOfficeCallbackFromJWT extracts callback data from JWT in Authorization header
func parseOnlyOfficeCallbackFromJWT(r *http.Request) (*OnlyOfficeCallback, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, errors.New("missing Authorization header")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errors.New("invalid Authorization header format")
	}

	jwtToken := strings.TrimPrefix(authHeader, "Bearer ")

	return parseOnlyOfficeJWT(jwtToken)
}

// parseOnlyOfficeCallbackFromJSON extracts callback data from JSON request body
func parseOnlyOfficeCallbackFromJSON(r *http.Request) (*OnlyOfficeCallback, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, onlyOfficeCallbackMaxBody+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %v", err)
	}
	if len(body) > onlyOfficeCallbackMaxBody {
		return nil, errOnlyOfficeCallbackTooLarge
	}
	var data OnlyOfficeCallback
	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	return &data, nil
}

func getOnlyOfficeId(realpath string) (string, error) {
	// error is intentionally ignored in order treat errors
	// the same as a cache-miss
	cachedDocumentKey, ok := utils.OnlyOfficeCache.Get(realpath)
	if ok {
		return cachedDocumentKey, nil
	}
	return "", fmt.Errorf("document key not found")
}

func deleteOfficeId(source, path string) {
	idx := indexing.GetIndex(source)
	if idx == nil {
		logger.Errorf("deleteOfficeId: failed to find source index for user home dir creation: %s", source)
		return
	}
	realpath, _, _ := idx.GetRealPath(path)
	utils.OnlyOfficeCache.Delete(realpath)
}

// parseOnlyOfficeJWT verifies and parses the JWT token from an OnlyOffice callback.
func parseOnlyOfficeJWT(tokenString string) (*OnlyOfficeCallback, error) {
	if config.Integrations.OnlyOffice.Secret == "" {
		return nil, errors.New("OnlyOffice callback signing secret is not configured")
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected OnlyOffice signing method")
		}
		return []byte(config.Integrations.OnlyOffice.Secret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil || !token.Valid {
		return nil, errors.New("invalid OnlyOffice callback signature")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid OnlyOffice callback claims")
	}
	payload := any(claims)
	if wrapped, exists := claims["payload"]; exists {
		payload = wrapped
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.New("invalid OnlyOffice callback payload")
	}
	callback := &OnlyOfficeCallback{}
	if err := json.Unmarshal(payloadBytes, callback); err != nil {
		return nil, errors.New("invalid OnlyOffice callback payload")
	}
	if callback.Key == "" {
		return nil, errors.New("missing document key in OnlyOffice callback")
	}
	return callback, nil
}

func verifyOnlyOfficeCallbackBody(r *http.Request, body *OnlyOfficeCallback) error {
	signed, err := parseOnlyOfficeCallbackFromJWT(r)
	if err != nil {
		return err
	}
	if body == nil || signed.Key != body.Key || signed.Status != body.Status ||
		signed.URL != body.URL || signed.ChangesURL != body.ChangesURL ||
		signed.ForceSaveType != body.ForceSaveType || signed.FileType != body.FileType {
		return errors.New("OnlyOffice callback body does not match its signature")
	}
	return nil
}

// returnOnlyOfficeSuccess returns a success response to OnlyOffice server
func returnOnlyOfficeSuccess(w http.ResponseWriter, r *http.Request) (int, error) {
	resp := map[string]int{
		"error": 0,
	}
	return renderJSON(w, r, resp)
}

// returnOnlyOfficeError returns an error response to OnlyOffice server with proper status code
func returnOnlyOfficeError(w http.ResponseWriter, r *http.Request, statusCode int, message string) (int, error) {
	// OnlyOffice expects specific error codes in the response body
	errorCode := 0
	switch statusCode {
	case 400:
		errorCode = 1 // Bad request
	case 403:
		errorCode = 1 // Forbidden (treated as bad request by OnlyOffice)
	case 404:
		errorCode = 1 // Not found (treated as bad request by OnlyOffice)
	case 500:
		errorCode = 1 // Internal server error (treated as bad request by OnlyOffice)
	default:
		errorCode = 1 // Default to bad request
	}

	resp := map[string]interface{}{
		"error": errorCode,
	}

	// Log the error for debugging
	logger.Errorf("OnlyOffice callback error (HTTP %d): %s", statusCode, message)

	return renderJSON(w, r, resp, statusCode)
}
