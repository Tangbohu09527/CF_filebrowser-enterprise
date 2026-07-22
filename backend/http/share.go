package http

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/go-logger/logger"
)

func validateSharePolicy(common share.CommonShare, capabilities share.CapabilitySnapshot) error {
	if !capabilities.Share {
		return fmt.Errorf("share permission is required")
	}
	if common.ShareType == "upload" && !common.AllowCreate {
		common.AllowCreate = true
	}
	if common.ShareType != "upload" {
		if !capabilities.Browse {
			return fmt.Errorf("browse permission is required for readable shares")
		}
		if (!common.DisableThumbnails || !common.DisableFileViewer || common.EnableOnlyOffice) && !capabilities.Preview {
			return fmt.Errorf("preview permission is required by the share policy")
		}
		if (!common.DisableDownload || common.EnableOnlyOffice) && !capabilities.Download {
			return fmt.Errorf("download permission is required by the share policy")
		}
	}
	if common.AllowCreate && !capabilities.Create {
		return fmt.Errorf("create permission is required by the share policy")
	}
	if (common.AllowModify || common.AllowReplacements) && !capabilities.Modify {
		return fmt.Errorf("modify permission is required by the share policy")
	}
	if common.AllowDelete && !capabilities.Delete {
		return fmt.Errorf("delete permission is required by the share policy")
	}
	return nil
}

func shareRequestCapabilities(d *requestContext) share.CapabilitySnapshot {
	if d == nil || d.user == nil {
		return share.CapabilitySnapshot{}
	}
	if d.user.Permissions.Admin && !d.apiToken {
		return share.CapabilitySnapshot{
			Share: true, Browse: true, Preview: true, Download: true,
			Create: true, Modify: true, Delete: true,
		}
	}
	return share.CapabilitiesFromPermissions(d.user.Permissions)
}

func validateShareRoot(link *share.Link, owner *users.User) error {
	if link == nil || owner == nil || link.Path == "" {
		return errors.ErrAccessDenied
	}
	sourceInfo, ok := config.Server.SourceMap[link.Source]
	if !ok || sourceInfo.Config.Private {
		return errors.ErrAccessDenied
	}
	ownerScope, err := owner.GetScopeForSourceName(sourceInfo.Name)
	if err != nil || ownerScope == "" {
		return errors.ErrAccessDenied
	}
	cleanScope, err := cleanPublicShareRelativePath(ownerScope)
	if err != nil {
		return errors.ErrAccessDenied
	}
	data := &requestContext{
		share:      link,
		shareUser:  owner,
		shareScope: normalizePublicShareIndexPath(cleanScope),
	}
	_, err = resolvePublicShareLogicalTarget(data, sourceInfo.Path, link.Path)
	return err
}

// ShareResponse represents a share with computed username field and download URL
type ShareResponse struct {
	*share.Link
	Source     string `json:"source"` // Override embedded field to show source name
	Username   string `json:"username,omitempty"`
	PathExists bool   `json:"pathExists"`
}

// convertToFrontendShareResponse converts shares to response format with usernames
func convertToFrontendShareResponse(r *http.Request, shares []*share.Link, user *users.User) ([]*ShareResponse, error) {
	responses := make([]*ShareResponse, 0, len(shares))
	for _, stored := range shares {
		if stored == nil {
			continue
		}
		s := stored.Clone()
		// Look for the username of the user who created the share
		creator, err := store.Users.Get(s.UserID)
		username := ""
		if err == nil {
			username = creator.Username
		}

		// Get source info to convert path to name for frontend
		sourceInfo, ok := config.Server.SourceMap[s.Source]
		if !ok {
			// Source not found - likely corrupted data. Try to find by name as fallback
			sourceInfo, ok = config.Server.NameToSource[s.Source]
			if !ok {
				continue
			}
			logger.Warning("Share has source stored by name", "source", s.Source)
			s.Source = sourceInfo.Path
		}

		// Check if the path exists on the filesystem
		pathExists := utils.CheckPathExists(filepath.Join(sourceInfo.Path, s.Path))

		s.CommonShare.HasPassword = s.HasPassword()
		s.DownloadURL = getShareURL(r, s.Hash, true, s.Token)
		s.ShareURL = getShareURL(r, s.Hash, false, s.Token)
		if s.UserCanEdit(user) {
			s.CommonShare.SourceURL = s.SourceURL(user)
		}
		// Create response with source name (overrides the embedded Link's source field)
		responses = append(responses, &ShareResponse{
			Link:       s,
			Source:     sourceInfo.Name, // Override to show source name instead of backend path
			Username:   username,
			PathExists: pathExists,
		})
	}
	return responses, nil
}

func filterSharesForCaller(shares []*share.Link, d *requestContext) []*share.Link {
	if d == nil || !d.apiToken {
		return shares
	}
	limit := shareRequestCapabilities(d)
	filtered := make([]*share.Link, 0, len(shares))
	for _, link := range shares {
		if link != nil && link.CapabilityVersion == share.CurrentCapabilityVersion && link.CreatorCapabilities.IsSubsetOf(limit) {
			filtered = append(filtered, link)
		}
	}
	return filtered
}

// shareListHandler returns a list of all share links.
// @Summary List share links
// @Description Returns a list of share links for the current user, or all links if the user is an admin.
// @Tags Shares
// @Accept json
// @Produce json
// @Success 200 {array} share.Link "List of share links"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/share/list [get]
func shareListHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	var err error
	var shares []*share.Link
	if d.user.Permissions.Admin {
		shares, err = store.Share.All()
	} else {
		shares, err = store.Share.FindByUserID(d.user.ID)
	}
	if err != nil && err != errors.ErrNotExist {
		return http.StatusInternalServerError, err
	}
	shares = utils.NonNilSlice(shares)
	shares = filterSharesForCaller(shares, d)
	sharesWithUsernames, err := convertToFrontendShareResponse(r, shares, d.user)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return renderJSON(w, r, sharesWithUsernames)
}

// shareGetsHandler retrieves share links for a specific resource path.
// @Summary Get share links by path
// @Description Retrieves all share links associated with a specific resource path for the current user.
// @Tags Shares
// @Accept json
// @Produce json
// @Param path query string true "Resource path for which to retrieve share links"
// @Param source query string true "Source name for share links"
// @Success 200 {array} share.Link "List of share links for the specified path"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/share [get]
func shareGetHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	path := r.URL.Query().Get("path")
	sourceName := r.URL.Query().Get("source")
	sourceInfo, ok := config.Server.NameToSource[sourceName] // backend source is path
	if !ok {
		return http.StatusBadRequest, fmt.Errorf("invalid source name: %s", sourceName)
	}
	userscope, err := d.user.GetScopeForSourceName(sourceName)
	if err != nil {
		return http.StatusForbidden, err
	}
	scopePath := utils.JoinPathAsUnix(userscope, path)
	scopePath = utils.AddTrailingSlashIfNotExists(scopePath)
	s, err := store.Share.Gets(scopePath, sourceInfo.Path, d.user.ID)
	if err == errors.ErrNotExist || len(s) == 0 {
		return renderJSON(w, r, []*ShareResponse{})
	}
	// DownloadURL will be set in convertToFrontendShareResponse

	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("error getting share info from server")
	}
	s = filterSharesForCaller(s, d)
	sharesWithUsernames, err := convertToFrontendShareResponse(r, s, d.user)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return renderJSON(w, r, sharesWithUsernames)
}

// shareDeleteHandler deletes a specific share link by its hash.
// @Summary Delete a share link
// @Description Deletes a share link specified by its hash.
// @Tags Shares
// @Accept json
// @Produce json
// @Param hash query string true "Hash of the share link to delete"
// @Success 200 "Share link deleted successfully"
// @Failure 400 {object} map[string]string "Bad request - missing or invalid hash"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/share [delete]
func shareDeleteHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	hash := r.URL.Query().Get("hash")

	if hash == "" {
		return http.StatusBadRequest, nil
	}

	// only allow users to delete their own shares
	thisShare, err := store.Share.GetByHash(hash)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("share not found")
	}
	if thisShare.UserID != d.user.ID && !d.user.Permissions.Admin {
		return http.StatusForbidden, fmt.Errorf("you are not allowed to delete this share")
	}

	err = store.Share.Delete(hash)
	if err != nil {
		return errToStatus(err), err
	}

	return errToStatus(err), err
}

// sharePatchHandler updates a share link's path.
// @Summary Update share link path
// @Description Updates the path for a specific share link identified by hash
// @Tags Shares
// @Accept json
// @Produce json
// @Param body body object{hash=string,path=string} true "Hash and new path"
// @Success 200 {object} ShareResponse "Updated share link"
// @Failure 400 {object} map[string]string "Bad request - missing or invalid parameters"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/share [patch]
func sharePatchHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	var body struct {
		Hash string `json:"hash"`
		Path string `json:"path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return http.StatusBadRequest, fmt.Errorf("failed to decode body: %w", err)
	}
	defer r.Body.Close()

	if body.Hash == "" || body.Path == "" {
		return http.StatusBadRequest, fmt.Errorf("hash and path are required")
	}

	requestedPath, err := cleanPublicShareRelativePath(body.Path)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("invalid path: %w", err)
	}

	// only allow users to update their own shares
	thisShare, err := store.Share.GetByHash(body.Hash)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("share not found")
	}
	if thisShare.UserID != d.user.ID && !d.user.Permissions.Admin {
		return http.StatusForbidden, fmt.Errorf("you are not allowed to update this share")
	}
	if thisShare.CapabilityVersion != share.CurrentCapabilityVersion {
		return http.StatusForbidden, fmt.Errorf("legacy share capability state must be rebound before changing its path")
	}
	actorCapabilities := shareRequestCapabilities(d)
	if err := validateSharePolicy(thisShare.CommonShare, thisShare.CreatorCapabilities.Intersect(actorCapabilities)); err != nil {
		return http.StatusForbidden, fmt.Errorf("calling token cannot carry the existing share policy: %w", err)
	}
	owner, err := store.Users.Get(thisShare.UserID)
	if err != nil {
		return http.StatusNotFound, fmt.Errorf("share owner not found")
	}
	sourceInfo, ok := config.Server.SourceMap[thisShare.Source]
	if !ok || sourceInfo.Config.Private {
		return http.StatusForbidden, fmt.Errorf("share source is not available")
	}
	ownerScope, err := owner.GetScopeForSourceName(sourceInfo.Name)
	if err != nil || ownerScope == "" {
		return http.StatusForbidden, fmt.Errorf("share owner scope is not available")
	}
	cleanScope, err := cleanPublicShareRelativePath(ownerScope)
	if err != nil {
		return http.StatusForbidden, fmt.Errorf("share owner scope is invalid")
	}
	normalizedScope := normalizePublicShareIndexPath(cleanScope)
	requestedAbsolute := normalizePublicShareIndexPath(requestedPath)
	newPath := normalizePublicShareIndexPath(pathpkg.Join(normalizedScope, requestedPath))
	if normalizedScope != "/" && publicSharePathWithin(normalizedScope, requestedAbsolute) {
		newPath = requestedAbsolute
	}
	updatedCandidate := thisShare.Clone()
	updatedCandidate.Path = utils.AddTrailingSlashIfNotExists(newPath)
	if err := validateShareRoot(updatedCandidate, owner); err != nil {
		return http.StatusForbidden, fmt.Errorf("new share path is not authorized")
	}
	// Update the share path
	err = store.Share.UpdateSharePath(body.Hash, updatedCandidate.Path)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// Get the updated share
	updatedShare, err := store.Share.GetByHash(body.Hash)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// Convert to response format
	sharesWithUsernames, err := convertToFrontendShareResponse(r, []*share.Link{updatedShare}, d.user)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	return renderJSON(w, r, sharesWithUsernames[0])
}

// sharePostHandler creates a new share link.
// @Summary Create a share link
// @Description Creates a new share link with an optional expiration time and password protection.
// @Tags Shares
// @Accept json
// @Produce json
// @Param body body share.CreateBody true "Share creation parameters"
// @Success 200 {object} share.Link "Created share link"
// @Failure 400 {object} map[string]string "Bad request - failed to decode body"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/share [post]
func sharePostHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	var s *share.Link
	var err error
	var body share.CreateBody
	if r.Body != nil {
		if err = json.NewDecoder(r.Body).Decode(&body); err != nil {
			return http.StatusBadRequest, fmt.Errorf("failed to decode body: %w", err)
		}
		defer r.Body.Close()
	}
	body.Capabilities = nil

	// check if body.Hash is a valid hash
	if body.Hash != "" {
		s, err = store.Share.GetByHash(body.Hash)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid hash provided")
		}
		if !s.UserCanEdit(d.user) {
			return http.StatusForbidden, fmt.Errorf("you are not allowed to update this share")
		}
	}

	var expire int64 = 0

	if body.Expires != "" {
		var num int
		num, err = strconv.Atoi(body.Expires)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		var add time.Duration
		switch body.Unit {
		case "seconds":
			add = time.Second * time.Duration(num)
		case "minutes":
			add = time.Minute * time.Duration(num)
		case "days":
			add = time.Hour * 24 * time.Duration(num)
		default:
			add = time.Hour * time.Duration(num)
		}

		expire = time.Now().Add(add).Unix()
	}

	hash, status, err := getSharePasswordHash(body)
	if err != nil {
		return status, err
	}
	stringHash := ""
	var token string
	if len(hash) > 0 {
		// Generate a cryptographically secure token similar to JWT
		// Create a random payload
		payloadBuffer := make([]byte, 24)
		if _, err = rand.Read(payloadBuffer); err != nil {
			return http.StatusInternalServerError, err
		}
		payload := base64.URLEncoding.EncodeToString(payloadBuffer)

		// Sign the payload with HMAC-SHA256 using the same secret key as JWT tokens
		mac := hmac.New(sha256.New, []byte(config.Auth.Key))
		mac.Write([]byte(payload))
		signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

		// Combine payload and signature: payload.signature (similar to JWT format)
		token = payload + "." + signature
		stringHash = string(hash)
	}
	if s != nil {
		existing := s
		owner, ownerErr := store.Users.Get(s.UserID)
		if ownerErr != nil {
			return http.StatusNotFound, fmt.Errorf("share owner not found")
		}
		actorCapabilities := shareRequestCapabilities(d)
		ownerCapabilities := share.CapabilitiesFromPermissions(owner.Permissions)
		if s.CapabilityVersion > share.CurrentCapabilityVersion {
			return http.StatusForbidden, fmt.Errorf("share capability version is not supported")
		}
		policyCapabilities := actorCapabilities
		if s.CapabilityVersion == 0 {
			s = s.Clone()
			s.CapabilityVersion = share.CurrentCapabilityVersion
			s.CreatorCapabilities = ownerCapabilities.Intersect(actorCapabilities)
			policyCapabilities = s.CreatorCapabilities
		}
		if body.ShareType == "upload" && !body.AllowCreate {
			body.AllowCreate = true
		}
		if err := validateSharePolicy(body.CommonShare, policyCapabilities); err != nil {
			return http.StatusForbidden, err
		}
		// Check if downloads limit or per-user limit changed - reset counts if so
		shouldResetCounts := s.DownloadsLimit != body.DownloadsLimit || s.PerUserDownloadLimit != body.PerUserDownloadLimit

		candidate := s.Clone()
		candidate.Expire = expire
		candidate.PasswordHash = stringHash
		candidate.Token = token
		// Preserve immutable fields for updates. Path and Source should not change on edits.
		// If the request attempts to provide empty values (or any values) for these,
		// keep the existing ones from the stored share.
		body.Path = candidate.Path
		body.Source = candidate.Source
		candidate.CommonShare = body.CommonShare
		if candidate.ShareType == "upload" && !body.AllowCreate {
			candidate.AllowCreate = true
		}
		if err := validateShareRoot(candidate, owner); err != nil {
			return http.StatusForbidden, fmt.Errorf("share root is no longer authorized")
		}

		// Reset download counts if limit settings changed
		if shouldResetCounts {
			candidate.ResetDownloadCounts()
		}

		if err = store.Share.UpdateIfUnchanged(existing, candidate); err != nil {
			if err == share.ErrConcurrentUpdate || err == errors.ErrNotExist {
				return http.StatusConflict, fmt.Errorf("share changed while it was being updated")
			}
			return http.StatusInternalServerError, err
		}
		s = candidate
		// Convert to ShareResponse format with username
		var user *users.User
		user, err = store.Users.Get(s.UserID)
		username := ""
		if err == nil {
			username = user.Username
		}
		response := &ShareResponse{
			Link:     s,
			Username: username,
		}
		return renderJSON(w, r, response)
	}

	source, ok := config.Server.NameToSource[body.Source]
	if !ok {
		return http.StatusForbidden, fmt.Errorf("source with name not found: %s", body.Source)
	}

	if source.Config.Private {
		return http.StatusForbidden, fmt.Errorf("the target source is private, sharing is not permitted")
	}

	// create a new share link
	secure_hash, err := generateShortUUID()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	// validate source path exists
	if indexing.GetIndex(source.Name) == nil {
		return http.StatusForbidden, fmt.Errorf("source with name not found: %s", body.Source)
	}
	userscope, err := d.user.GetScopeForSourceName(source.Name)
	if err != nil {
		return http.StatusForbidden, err
	}
	providedPath := body.Path

	// Rule 1: Validate user-provided path to prevent path traversal
	cleanPath, err := utils.SanitizeUserPath(providedPath)
	if err != nil {
		return http.StatusBadRequest, err
	}

	body.Path = utils.JoinPathAsUnix(userscope, cleanPath)
	body.Path = utils.AddTrailingSlashIfNotExists(body.Path)
	if body.ShareType == "upload" && !body.AllowCreate {
		body.AllowCreate = true
	}
	creatorCapabilities := shareRequestCapabilities(d)
	if err := validateSharePolicy(body.CommonShare, creatorCapabilities); err != nil {
		return http.StatusForbidden, err
	}
	body.Source = source.Path // backend source is path
	s = &share.Link{
		Expire:              expire,
		UserID:              d.user.ID,
		Hash:                secure_hash,
		PasswordHash:        stringHash,
		Token:               token,
		CommonShare:         body.CommonShare,
		Version:             1, // Set version for new shares
		CapabilityVersion:   share.CurrentCapabilityVersion,
		CreatorCapabilities: creatorCapabilities,
	}
	if err = validateShareRoot(s, d.user); err != nil {
		return http.StatusForbidden, fmt.Errorf("share root is not authorized")
	}
	if err = store.Share.Save(s); err != nil {
		return http.StatusInternalServerError, err
	}
	sharesWithUsernames, err := convertToFrontendShareResponse(r, []*share.Link{s}, d.user)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return renderJSON(w, r, sharesWithUsernames[0])
}

// DirectDownloadResponse represents the response for direct download endpoint
type DirectDownloadResponse struct {
	Status      string `json:"status"`
	Hash        string `json:"hash"`
	DownloadURL string `json:"url"`
	ShareURL    string `json:"shareUrl"`
}

// shareDirectDownloadHandler creates a direct download link for files only.
// @Summary Create direct download link
// @Description Creates a direct download link for a specific file with configurable duration, download count, and speed limits. If a share already exists with matching parameters, the existing share will be reused.
// @Tags Shares
// @Accept json
// @Produce json
// @Param path query string true "File path to create download link for"
// @Param source query string true "Source name for the file"
// @Param duration query string false "Duration in minutes for link validity (default: 60)"
// @Param count query string false "Maximum number of downloads allowed (default: unlimited)"
// @Param speed query string false "Download speed limit in kbps (default: unlimited)"
// @Success 201 {object} DirectDownloadResponse "Direct download link created"
// @Failure 400 {object} map[string]string "Bad request - invalid parameters or path is not a file"
// @Failure 403 {object} map[string]string "Forbidden - access denied"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/share/direct [get]
func shareDirectDownloadHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	// Extract query parameters
	path := r.URL.Query().Get("path")
	source := r.URL.Query().Get("source")
	duration := r.URL.Query().Get("duration")
	downloadCountStr := r.URL.Query().Get("count")
	downloadSpeedStr := r.URL.Query().Get("speed")

	// Validate required parameters
	if path == "" || source == "" {
		return http.StatusBadRequest, fmt.Errorf("path and source are required")
	}
	creatorCapabilities := shareRequestCapabilities(d)
	if !creatorCapabilities.Share || !creatorCapabilities.Browse || !creatorCapabilities.Download {
		return http.StatusForbidden, fmt.Errorf("share, browse, and download permissions are required")
	}

	// Validate source exists
	sourceInfo, ok := config.Server.NameToSource[source]
	if !ok {
		return http.StatusBadRequest, fmt.Errorf("invalid source name: %s", source)
	}

	// Get user scope for this source
	userscope, err := d.user.GetScopeForSourceName(source)
	if err != nil {
		return http.StatusForbidden, err
	}

	cleanPath, err := cleanPublicShareRelativePath(path)
	if err != nil || cleanPath == "" {
		return http.StatusBadRequest, fmt.Errorf("invalid path")
	}
	scopePath := normalizePublicShareIndexPath(utils.JoinPathAsUnix(userscope, cleanPath))

	// Resolve Scope, Access Rules and filesystem containment before consulting index metadata.
	idx := indexing.GetIndex(source)
	if idx == nil {
		return http.StatusForbidden, fmt.Errorf("source with name not found: %s", source)
	}

	// Set default duration to 60 minutes if not provided
	if duration == "" {
		duration = "60"
	}

	// Parse download count
	var downloadCount int
	if downloadCountStr != "" {
		downloadCount, err = strconv.Atoi(downloadCountStr)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid downloadCount: %v", err)
		}
	}

	// Parse download speed (in bytes per second)
	var downloadSpeed int
	if downloadSpeedStr != "" {
		downloadSpeed, err = strconv.Atoi(downloadSpeedStr)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid downloadSpeed: %v", err)
		}
	}

	// Calculate expiration time
	durationNum, err := strconv.Atoi(duration)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("invalid duration: %v", err)
	}
	expire := time.Now().Add(time.Minute * time.Duration(durationNum)).Unix()

	// Generate secure hash for the share
	secureHash, err := generateShortUUID()
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// Quick shares are always bound to the current caller's capability snapshot.
	shareLink := &share.Link{
		Expire:  expire,
		UserID:  d.user.ID,
		Hash:    secureHash,
		Version: 1, // Set version for new shares
		CommonShare: share.CommonShare{
			Path:           scopePath,
			Source:         idx.Path,
			DownloadsLimit: downloadCount,
			MaxBandwidth:   downloadSpeed,
			QuickDownload:  true, // Enable quick download for direct downloads
		},
		CapabilityVersion:   share.CurrentCapabilityVersion,
		CreatorCapabilities: creatorCapabilities,
	}
	if err := validateShareRoot(shareLink, d.user); err != nil {
		return http.StatusForbidden, fmt.Errorf("share root is not authorized")
	}
	metadata, exists := idx.GetReducedMetadata(scopePath, false)
	if !exists {
		return http.StatusBadRequest, fmt.Errorf("path is either not a file or not found: %s", path)
	}
	if metadata.Type == "directory" {
		return http.StatusBadRequest, fmt.Errorf("path must be a file, not a directory: %s", path)
	}
	if sourceInfo.Config.Private {
		return http.StatusForbidden, fmt.Errorf("the target source is private")
	}

	// Save the share
	if err := store.Share.Save(shareLink); err != nil {
		return http.StatusInternalServerError, err
	}

	// Return response
	response := DirectDownloadResponse{
		Status:      "200",
		Hash:        secureHash,
		DownloadURL: getShareURL(r, secureHash, true, shareLink.Token),
		ShareURL:    getShareURL(r, secureHash, false, shareLink.Token),
	}

	return renderJSON(w, r, response)
}

func getShareURL(r *http.Request, hash string, isDirectDownload bool, token string) string {
	var shareURL string
	tokenParam := ""
	if token != "" && isDirectDownload {
		tokenParam = fmt.Sprintf("&token=%s", url.QueryEscape(token))
	}

	if config.Server.ExternalUrl != "" {
		if isDirectDownload {
			shareURL = fmt.Sprintf("%s%spublic/api/resources/download?hash=%s%s", config.Server.ExternalUrl, config.Server.BaseURL, hash, tokenParam)
		} else {
			shareURL = fmt.Sprintf("%s%spublic/share/%s", config.Server.ExternalUrl, config.Server.BaseURL, hash)
		}

	} else {
		// Prefer X-Forwarded-Host for proxy support
		var host string
		var scheme string
		if forwardedHost := r.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
			host = forwardedHost
			// Use X-Forwarded-Proto if available, otherwise default to https for proxied requests
			if forwardedProto := r.Header.Get("X-Forwarded-Proto"); forwardedProto != "" {
				scheme = forwardedProto
			} else {
				scheme = "https"
			}
		} else {
			// Fallback to simple approach
			host = r.Host
			scheme = getScheme(r)
		}
		if isDirectDownload {
			shareURL = fmt.Sprintf("%s://%s%spublic/api/resources/download?hash=%s%s", scheme, host, config.Server.BaseURL, hash, tokenParam)
		} else {
			shareURL = fmt.Sprintf("%s://%s%spublic/share/%s", scheme, host, config.Server.BaseURL, hash)
		}
	}
	return shareURL
}

// shareInfoHandler retrieves share information by hash.
// @Summary Get share information by hash
// @Description Returns information about a share link based on its hash. This endpoint is publicly accessible and can be used with or without authentication.
// @Tags Shares
// @Accept json
// @Produce json
// @Param hash query string true "Hash of the share link"
// @Success 200 {object} share.CommonShare "Share information"
// @Failure 404 {object} map[string]string "Share hash not found"
// @Router /public/api/share/info [get]
func shareInfoHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	hash := r.URL.Query().Get("hash")
	// Get the file link by hash (need full Link to get Token)
	shareLink, err := store.Share.GetByHash(hash)
	if err != nil {
		return http.StatusNotFound, fmt.Errorf("share hash not found")
	}
	if !publicShareAudienceAllowed(shareLink, d.user) {
		return http.StatusForbidden, fmt.Errorf("share is not available to this user")
	}
	owner, err := store.Users.Get(shareLink.UserID)
	if err != nil {
		return http.StatusNotFound, fmt.Errorf("user for share no longer exists")
	}
	access := calculatePublicShareAccess(shareLink, owner)
	if err := validateShareRoot(shareLink, owner); err != nil {
		return http.StatusForbidden, fmt.Errorf("public share access denied")
	}
	if shareLink.ShareType == "upload" {
		if !access.create && !access.modify && !access.delete {
			return http.StatusForbidden, fmt.Errorf("public share access denied")
		}
	} else if !access.allows(publicShareReadBrowse) {
		return http.StatusForbidden, fmt.Errorf("public share access denied")
	}
	commonShare := shareLink.CommonShare
	commonShare.Capabilities = access.frontendCapabilities()
	commonShare.ShareURL = getShareURL(r, hash, false, "")
	commonShare.BannerUrl = shareLink.BannerURL()
	commonShare.FaviconUrl = shareLink.FaviconURL()
	commonShare.Source = ""
	commonShare.Path = ""
	commonShare.DownloadURL = ""
	commonShare.SidebarLinks = []users.SidebarLink{}
	for _, link := range shareLink.SidebarLinks {
		if link.Category == "download" && shareLink.ShareType == "upload" {
			continue
		} else {
			commonShare.SidebarLinks = append(commonShare.SidebarLinks, link)
		}
	}
	commonShare.SourceURL = shareLink.SourceURL(d.user)
	commonShare.CanEditShare = shareLink.UserCanEdit(d.user)
	if commonShare.SourceURL != "" {
		link := users.SidebarLink{
			Name:     "sourceLocation",
			Category: "custom",
			Target:   commonShare.SourceURL,
		}
		commonShare.SidebarLinks = append(commonShare.SidebarLinks, link)
	}

	return renderJSON(w, r, commonShare)
}

func getSharePasswordHash(body share.CreateBody) (data []byte, statuscode int, err error) {
	if body.Password == "" {
		return nil, 0, nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to hash password")
	}

	return hash, 0, nil
}

func generateShortUUID() (string, error) {
	// Generate 16 random bytes (128 bits of entropy)
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Encode the bytes to a URL-safe base64 string
	uuid := base64.RawURLEncoding.EncodeToString(bytes)

	// Trim the length to 22 characters for a shorter ID
	return uuid[:22], nil
}

func redirectToShare(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	// Remove the base URL and "/share/" prefix to get the full path after share
	sharePath := strings.TrimPrefix(r.URL.Path, config.Server.BaseURL+"share/")
	newURL := config.Server.BaseURL + "public/share/" + sharePath
	if r.URL.RawQuery != "" {
		newURL += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, newURL, http.StatusMovedPermanently)
	return http.StatusMovedPermanently, nil
}
