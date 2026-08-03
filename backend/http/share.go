package http

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	pathpkg "path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
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

func resolveShareRoot(link *share.Link, owner *users.User) (publicShareTarget, error) {
	var target publicShareTarget
	if link == nil || owner == nil || link.Path == "" {
		return target, errors.ErrAccessDenied
	}
	sourceInfo, ok := config.Server.SourceMap[link.Source]
	if !ok || sourceInfo.Config.Private {
		return target, errors.ErrAccessDenied
	}
	ownerScope, err := owner.GetScopeForSourceName(sourceInfo.Name)
	if err != nil || ownerScope == "" {
		return target, errors.ErrAccessDenied
	}
	cleanScope, err := cleanPublicShareRelativePath(ownerScope)
	if err != nil {
		return target, errors.ErrAccessDenied
	}
	data := &requestContext{
		share:      link,
		shareUser:  owner,
		shareScope: normalizePublicShareIndexPath(cleanScope),
	}
	return resolvePublicShareLogicalTarget(data, sourceInfo.Path, link.Path)
}

func validateShareRoot(link *share.Link, owner *users.User) error {
	_, err := resolveShareRoot(link, owner)
	return err
}

type ManagementShareCapabilities struct {
	Browse    bool `json:"browse"`
	Preview   bool `json:"preview"`
	Download  bool `json:"download"`
	Thumbnail bool `json:"thumbnail"`
	Viewer    bool `json:"viewer"`
	Create    bool `json:"create"`
	Modify    bool `json:"modify"`
	Delete    bool `json:"delete"`
	Replace   bool `json:"replace"`
}

func configuredManagementShareCapabilities(link *share.Link) ManagementShareCapabilities {
	if link == nil {
		return ManagementShareCapabilities{}
	}
	readable := link.ShareType != "upload"
	thumbnail := readable && !link.DisableThumbnails
	viewer := readable && !link.DisableFileViewer
	return ManagementShareCapabilities{
		Browse:    readable,
		Preview:   thumbnail || viewer,
		Download:  readable && !link.DisableDownload,
		Thumbnail: thumbnail,
		Viewer:    viewer,
		Create:    link.AllowCreate,
		Modify:    link.AllowModify,
		Delete:    link.AllowDelete,
		Replace:   link.AllowReplacements,
	}
}

func calculateManagementShareCapabilities(link *share.Link, owner *users.User, root publicShareTarget, rootErr error) ManagementShareCapabilities {
	if link == nil || owner == nil || rootErr != nil ||
		(link.Expire != 0 && link.Expire <= time.Now().Unix()) {
		return ManagementShareCapabilities{}
	}
	access := calculatePublicShareAccess(link, owner)
	browse := access.allows(publicShareReadBrowse)
	thumbnail := access.allows(publicShareReadBrowse | publicShareReadThumbnail)
	viewer := access.allows(publicShareReadBrowse | publicShareReadViewer)
	capabilities := ManagementShareCapabilities{
		Browse:    browse,
		Preview:   thumbnail || viewer,
		Download:  access.allows(publicShareReadBrowse | publicShareReadDownload),
		Thumbnail: thumbnail,
		Viewer:    viewer,
	}
	if root.IsDir {
		capabilities.Create = access.create
		capabilities.Modify = access.modify
		capabilities.Delete = access.delete
		capabilities.Replace = access.replace
	}
	return capabilities
}

func managementShareStatus(link *share.Link, rootErr error) string {
	if link != nil && link.Expire != 0 && link.Expire <= time.Now().Unix() {
		return "expired"
	}
	if rootErr != nil {
		return "unavailable"
	}
	return "active"
}

// ShareResponse is the explicit, secret-free DTO used by every Share management response.
type ShareResponse struct {
	DownloadsLimit           int                         `json:"downloadsLimit,omitempty"`
	ShareTheme               string                      `json:"shareTheme,omitempty"`
	DisableAnonymous         bool                        `json:"disableAnonymous"`
	MaxBandwidth             int                         `json:"maxBandwidth,omitempty"`
	DisableThumbnails        bool                        `json:"disableThumbnails"`
	KeepAfterExpiration      bool                        `json:"keepAfterExpiration"`
	AllowedUsernames         []string                    `json:"allowedUsernames,omitempty"`
	ThemeColor               string                      `json:"themeColor,omitempty"`
	Banner                   string                      `json:"banner,omitempty"`
	Title                    string                      `json:"title,omitempty"`
	Description              string                      `json:"description,omitempty"`
	Favicon                  string                      `json:"favicon,omitempty"`
	QuickDownload            bool                        `json:"quickDownload"`
	HideNavButtons           bool                        `json:"hideNavButtons"`
	DisableSidebar           bool                        `json:"disableSidebar"`
	Source                   string                      `json:"source"`
	Path                     string                      `json:"path"`
	DownloadURL              string                      `json:"downloadURL,omitempty"`
	ShareURL                 string                      `json:"shareURL"`
	FaviconURL               string                      `json:"faviconUrl,omitempty"`
	BannerURL                string                      `json:"bannerUrl,omitempty"`
	DisableShareCard         bool                        `json:"disableShareCard"`
	EnforceDarkLightMode     string                      `json:"enforceDarkLightMode,omitempty"`
	ViewMode                 string                      `json:"viewMode,omitempty"`
	EnableOnlyOffice         bool                        `json:"enableOnlyOffice"`
	ShareType                string                      `json:"shareType"`
	PerUserDownloadLimit     bool                        `json:"perUserDownloadLimit"`
	ExtractEmbeddedSubtitles bool                        `json:"extractEmbeddedSubtitles"`
	AllowDelete              bool                        `json:"allowDelete"`
	AllowCreate              bool                        `json:"allowCreate"`
	AllowModify              bool                        `json:"allowModify"`
	DisableFileViewer        bool                        `json:"disableFileViewer"`
	DisableDownload          bool                        `json:"disableDownload"`
	AllowReplacements        bool                        `json:"allowReplacements"`
	SidebarLinks             []users.SidebarLink         `json:"sidebarLinks"`
	HasPassword              bool                        `json:"hasPassword"`
	ShowHidden               bool                        `json:"showHidden"`
	HideFileExt              string                      `json:"hideFileExt,omitempty"`
	DisableLoginOption       bool                        `json:"disableLoginOption"`
	SourceURL                string                      `json:"sourceURL,omitempty"`
	CanEditShare             bool                        `json:"canEditShare"`
	Downloads                int                         `json:"downloads"`
	Hash                     string                      `json:"hash"`
	Expire                   int64                       `json:"expire"`
	Username                 string                      `json:"username,omitempty"`
	PathExists               bool                        `json:"pathExists"`
	Status                   string                      `json:"status"`
	ConfiguredCapabilities   ManagementShareCapabilities `json:"configuredCapabilities"`
	EffectiveCapabilities    ManagementShareCapabilities `json:"effectiveCapabilities"`
}

// convertToFrontendShareResponse converts shares to response format with usernames
func convertToFrontendShareResponse(r *http.Request, shares []*share.Link, user *users.User) ([]*ShareResponse, error) {
	responses := make([]*ShareResponse, 0, len(shares))
	for _, stored := range shares {
		if stored == nil {
			continue
		}
		s := stored.Clone()
		creator, creatorErr := store.Users.Get(s.UserID)
		username := ""
		if creatorErr == nil {
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

		pathExists := utils.CheckPathExists(filepath.Join(sourceInfo.Path, s.Path))
		var root publicShareTarget
		rootErr := errors.ErrAccessDenied
		if creatorErr == nil {
			root, rootErr = resolveShareRoot(s, creator)
		}
		canEditShare := user != nil && s.UserCanEdit(user)
		sourceURL := ""
		if canEditShare {
			sourceURL = s.SourceURL(user)
		}
		responses = append(responses, &ShareResponse{
			DownloadsLimit:           s.DownloadsLimit,
			ShareTheme:               s.ShareTheme,
			DisableAnonymous:         s.DisableAnonymous,
			MaxBandwidth:             s.MaxBandwidth,
			DisableThumbnails:        s.DisableThumbnails,
			KeepAfterExpiration:      s.KeepAfterExpiration,
			AllowedUsernames:         append([]string(nil), s.AllowedUsernames...),
			ThemeColor:               s.ThemeColor,
			Banner:                   s.Banner,
			Title:                    s.Title,
			Description:              s.Description,
			Favicon:                  s.Favicon,
			QuickDownload:            s.QuickDownload,
			HideNavButtons:           s.HideNavButtons,
			DisableSidebar:           s.DisableSidebar,
			Source:                   sourceInfo.Name,
			Path:                     s.Path,
			DownloadURL:              getShareURL(r, s.Hash, true),
			ShareURL:                 getShareURL(r, s.Hash, false),
			FaviconURL:               s.FaviconURL(),
			BannerURL:                s.BannerURL(),
			DisableShareCard:         s.DisableShareCard,
			EnforceDarkLightMode:     s.EnforceDarkLightMode,
			ViewMode:                 s.ViewMode,
			EnableOnlyOffice:         s.EnableOnlyOffice,
			ShareType:                s.ShareType,
			PerUserDownloadLimit:     s.PerUserDownloadLimit,
			ExtractEmbeddedSubtitles: s.ExtractEmbeddedSubtitles,
			AllowDelete:              s.AllowDelete,
			AllowCreate:              s.AllowCreate,
			AllowModify:              s.AllowModify,
			DisableFileViewer:        s.DisableFileViewer,
			DisableDownload:          s.DisableDownload,
			AllowReplacements:        s.AllowReplacements,
			SidebarLinks:             append([]users.SidebarLink(nil), s.SidebarLinks...),
			HasPassword:              s.HasPassword(),
			ShowHidden:               s.ShowHidden,
			HideFileExt:              s.HideFileExt,
			DisableLoginOption:       s.DisableLoginOption,
			SourceURL:                sourceURL,
			CanEditShare:             canEditShare,
			Downloads:                s.Downloads,
			Hash:                     s.Hash,
			Expire:                   s.Expire,
			Username:                 username,
			PathExists:               pathExists,
			Status:                   managementShareStatus(s, rootErr),
			ConfiguredCapabilities:   configuredManagementShareCapabilities(s),
			EffectiveCapabilities:    calculateManagementShareCapabilities(s, creator, root, rootErr),
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
// @Success 200 {array} ShareResponse "List of share links"
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
// @Success 200 {array} ShareResponse "List of share links for the specified path"
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
	if err := configureShareMutationAudit(r, auditdb.ActionShareDelete, thisShare, nil); err != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
	}
	if err := reserveShareMutationAudit(r); err != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
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
	updatedCandidate.Token = ""
	if err := validateShareRoot(updatedCandidate, owner); err != nil {
		return http.StatusForbidden, fmt.Errorf("new share path is not authorized")
	}
	if err := configureShareMutationAudit(r, auditdb.ActionShareUpdate, updatedCandidate,
		[]auditdb.ChangedField{auditdb.ChangedFieldPath}); err != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
	}
	if err := reserveShareMutationAudit(r); err != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
	}
	if err = store.Share.UpdateIfUnchanged(thisShare, updatedCandidate); err != nil {
		if err == share.ErrConcurrentUpdate || err == errors.ErrNotExist {
			return http.StatusConflict, fmt.Errorf("share changed while it was being updated")
		}
		return http.StatusInternalServerError, err
	}

	// Convert to response format
	sharesWithUsernames, err := convertToFrontendShareResponse(r, []*share.Link{updatedCandidate}, d.user)
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
// @Success 200 {object} ShareResponse "Created or updated share link"
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
	if body.Hash != "" {
		if recorder := AuditRecorderFromRequest(r); recorder != nil {
			if err := recorder.SetAction(auditdb.ActionShareUpdate); err != nil {
				return http.StatusServiceUnavailable, ErrAuditUnavailable
			}
		}
	}

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

	hash, status, err := getSharePasswordHash(body.Password)
	if err != nil {
		return status, err
	}
	stringHash := ""
	if len(hash) > 0 {
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
		if body.Password != nil {
			candidate.PasswordHash = stringHash
		}
		candidate.Token = ""
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

		if err = configureShareMutationAudit(r, auditdb.ActionShareUpdate, candidate,
			auditShareChangedFields(existing, candidate)); err != nil {
			return http.StatusServiceUnavailable, ErrAuditUnavailable
		}
		if err = reserveShareMutationAudit(r); err != nil {
			return http.StatusServiceUnavailable, ErrAuditUnavailable
		}
		if err = store.Share.UpdateIfUnchanged(existing, candidate); err != nil {
			if err == share.ErrConcurrentUpdate || err == errors.ErrNotExist {
				return http.StatusConflict, fmt.Errorf("share changed while it was being updated")
			}
			return http.StatusInternalServerError, err
		}
		sharesWithUsernames, convertErr := convertToFrontendShareResponse(r, []*share.Link{candidate}, d.user)
		if convertErr != nil {
			return http.StatusInternalServerError, convertErr
		}
		return renderJSON(w, r, sharesWithUsernames[0])
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
		CommonShare:         body.CommonShare,
		Version:             1, // Set version for new shares
		CapabilityVersion:   share.CurrentCapabilityVersion,
		CreatorCapabilities: creatorCapabilities,
	}
	if err = validateShareRoot(s, d.user); err != nil {
		return http.StatusForbidden, fmt.Errorf("share root is not authorized")
	}
	if err = configureShareMutationAudit(r, auditdb.ActionShareCreate, s, []auditdb.ChangedField{
		auditdb.ChangedFieldSource,
		auditdb.ChangedFieldPath,
		auditdb.ChangedFieldExpiration,
		auditdb.ChangedFieldCapabilities,
	}); err != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
	}
	if err = reserveShareMutationAudit(r); err != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
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

	if err := configureShareMutationAudit(r, auditdb.ActionShareCreate, shareLink, []auditdb.ChangedField{
		auditdb.ChangedFieldSource,
		auditdb.ChangedFieldPath,
		auditdb.ChangedFieldExpiration,
		auditdb.ChangedFieldDownloadLimit,
		auditdb.ChangedFieldBandwidthLimit,
		auditdb.ChangedFieldCapabilities,
	}); err != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
	}
	if err := reserveShareMutationAudit(r); err != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
	}
	// Save the share
	if err := store.Share.Save(shareLink); err != nil {
		return http.StatusInternalServerError, err
	}

	// Return response
	response := DirectDownloadResponse{
		Status:      "200",
		Hash:        secureHash,
		DownloadURL: getShareURL(r, secureHash, true),
		ShareURL:    getShareURL(r, secureHash, false),
	}

	return renderJSON(w, r, response)
}

func configureShareMutationAudit(r *http.Request, action auditdb.Action, link *share.Link, changedFields []auditdb.ChangedField) error {
	recorder := AuditRecorderFromRequest(r)
	if recorder == nil {
		return nil
	}
	if link == nil || link.UserID == 0 {
		return ErrAuditInvalidState
	}
	if err := recorder.SetAction(action); err != nil {
		return err
	}
	shareRef := auditdb.DeriveShareRef(link.Hash)
	if shareRef == "" {
		return ErrAuditInvalidState
	}
	if err := recorder.SetShareRef(shareRef); err != nil {
		return err
	}
	if err := recorder.SetResource(auditShareSourceName(link), link.Path, link.Path); err != nil {
		return err
	}
	ownerPath := "/" + strconv.FormatUint(uint64(link.UserID), 10)
	if err := recorder.SetTarget("users", ownerPath, ownerPath); err != nil {
		return err
	}
	if len(changedFields) == 0 {
		return nil
	}
	return recorder.MergeMetadata(&auditdb.MetadataV1{
		SchemaVersion: auditdb.CurrentMetadataSchemaVersion,
		ChangedFields: changedFields,
	})
}

func reserveShareMutationAudit(r *http.Request) error {
	recorder := AuditRecorderFromRequest(r)
	if recorder == nil {
		return nil
	}
	if err := recorder.ReservePending(); err != nil {
		_ = recorder.SetErrorCode(auditErrorCodeAuditUnavailable)
		return ErrAuditUnavailable
	}
	return nil
}

func auditShareSourceName(link *share.Link) string {
	if link == nil || config == nil {
		return ""
	}
	if sourceInfo, ok := config.Server.SourceMap[link.Source]; ok && sourceInfo != nil {
		return sourceInfo.Name
	}
	if sourceInfo, ok := config.Server.NameToSource[link.Source]; ok && sourceInfo != nil {
		return sourceInfo.Name
	}
	return ""
}

func auditShareChangedFields(before, after *share.Link) []auditdb.ChangedField {
	if before == nil || after == nil {
		return nil
	}
	changed := make([]auditdb.ChangedField, 0, 8)
	if before.Expire != after.Expire {
		changed = append(changed, auditdb.ChangedFieldExpiration)
	}
	if before.DownloadsLimit != after.DownloadsLimit || before.PerUserDownloadLimit != after.PerUserDownloadLimit {
		changed = append(changed, auditdb.ChangedFieldDownloadLimit)
	}
	if before.MaxBandwidth != after.MaxBandwidth {
		changed = append(changed, auditdb.ChangedFieldBandwidthLimit)
	}
	if !reflect.DeepEqual(before.AllowedUsernames, after.AllowedUsernames) {
		changed = append(changed, auditdb.ChangedFieldAllowedUsers)
	}
	if before.PasswordHash != after.PasswordHash {
		changed = append(changed, auditdb.ChangedFieldAuthentication)
	}
	if before.Title != after.Title {
		changed = append(changed, auditdb.ChangedFieldName)
	}
	if before.Description != after.Description {
		changed = append(changed, auditdb.ChangedFieldDescription)
	}
	if before.CreatorCapabilities != after.CreatorCapabilities || before.CapabilityVersion != after.CapabilityVersion ||
		before.AllowCreate != after.AllowCreate || before.AllowModify != after.AllowModify ||
		before.AllowDelete != after.AllowDelete || before.AllowReplacements != after.AllowReplacements ||
		before.DisableDownload != after.DisableDownload || before.DisableFileViewer != after.DisableFileViewer {
		changed = append(changed, auditdb.ChangedFieldCapabilities)
	}
	return changed
}

func getShareURL(r *http.Request, hash string, isDirectDownload bool) string {
	var shareURL string

	if config.Server.ExternalUrl != "" {
		if isDirectDownload {
			shareURL = fmt.Sprintf("%s%spublic/api/resources/download?hash=%s", config.Server.ExternalUrl, config.Server.BaseURL, hash)
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
			shareURL = fmt.Sprintf("%s://%s%spublic/api/resources/download?hash=%s", scheme, host, config.Server.BaseURL, hash)
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
	// Get the file link by hash.
	shareLink, err := store.Share.GetByHash(hash)
	if err != nil {
		return http.StatusNotFound, fmt.Errorf("share hash not found")
	}
	if auditErr := setPublicShareAuditContext(r, d, shareLink, nil); auditErr != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
	}
	if !publicShareAudienceAllowed(shareLink, d.user) {
		return http.StatusForbidden, fmt.Errorf("share is not available to this user")
	}
	owner, err := store.Users.Get(shareLink.UserID)
	if err != nil {
		return http.StatusNotFound, fmt.Errorf("user for share no longer exists")
	}
	access := calculatePublicShareAccess(shareLink, owner)
	d.share = shareLink
	d.shareUser = owner
	d.shareAccess = access
	root, err := resolveShareRoot(shareLink, owner)
	if err != nil {
		return http.StatusForbidden, fmt.Errorf("public share access denied")
	}
	if auditErr := setPublicShareAuditContext(r, d, shareLink, &root); auditErr != nil {
		return http.StatusServiceUnavailable, ErrAuditUnavailable
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
	commonShare.ShareURL = getShareURL(r, hash, false)
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

func getSharePasswordHash(password *string) (data []byte, statuscode int, err error) {
	if password == nil || *password == "" {
		return nil, 0, nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
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
