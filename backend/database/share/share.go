package share

import (
	"sync"

	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

type CommonShare struct {
	DownloadsLimit           int                 `json:"downloadsLimit,omitempty"`
	ShareTheme               string              `json:"shareTheme,omitempty"`
	DisableAnonymous         bool                `json:"disableAnonymous,omitempty"`
	MaxBandwidth             int                 `json:"maxBandwidth,omitempty"`
	DisableThumbnails        bool                `json:"disableThumbnails,omitempty"`
	KeepAfterExpiration      bool                `json:"keepAfterExpiration,omitempty"`
	AllowedUsernames         []string            `json:"allowedUsernames,omitempty"`
	ThemeColor               string              `json:"themeColor,omitempty"`
	Banner                   string              `json:"banner,omitempty"`
	Title                    string              `json:"title,omitempty"`
	Description              string              `json:"description,omitempty"`
	Favicon                  string              `json:"favicon,omitempty"`
	QuickDownload            bool                `json:"quickDownload,omitempty"`
	HideNavButtons           bool                `json:"hideNavButtons,omitempty"`
	DisableSidebar           bool                `json:"disableSidebar"`
	Source                   string              `json:"source,omitempty"` // backend source is path to maintain between name changes
	Path                     string              `json:"path,omitempty"`
	DownloadURL              string              `json:"downloadURL,omitempty"`
	ShareURL                 string              `json:"shareURL,omitempty"`
	FaviconUrl               string              `json:"faviconUrl,omitempty"`
	BannerUrl                string              `json:"bannerUrl,omitempty"`
	DisableShareCard         bool                `json:"disableShareCard,omitempty"`
	EnforceDarkLightMode     string              `json:"enforceDarkLightMode,omitempty"` // "dark" or "light"
	ViewMode                 string              `json:"viewMode,omitempty"`             // default view mode for anonymous users: "list", "compact", "normal", "gallery"
	EnableOnlyOffice         bool                `json:"enableOnlyOffice,omitempty"`
	ShareType                string              `json:"shareType"` // type of share: normal, upload, max
	PerUserDownloadLimit     bool                `json:"perUserDownloadLimit,omitempty"`
	ExtractEmbeddedSubtitles bool                `json:"extractEmbeddedSubtitles,omitempty"` // can be io intensive for large files and take 10-30 seconds.
	AllowDelete              bool                `json:"allowDelete,omitempty"`
	AllowCreate              bool                `json:"allowCreate,omitempty"`       // allow creating files
	AllowModify              bool                `json:"allowModify,omitempty"`       // allow modifying files
	DisableFileViewer        bool                `json:"disableFileViewer,omitempty"` // don't allow viewing files
	DisableDownload          bool                `json:"disableDownload,omitempty"`   // don't allow downloading files
	AllowReplacements        bool                `json:"allowReplacements,omitempty"` // allow replacements of files
	SidebarLinks             []users.SidebarLink `json:"sidebarLinks"`                // customizable sidebar links
	HasPassword              bool                `json:"hasPassword,omitempty"`
	ShowHidden               bool                `json:"showHidden,omitempty"`  // show hidden files in share (true = show, false = hide)
	HideFileExt              string              `json:"hideFileExt,omitempty"` // show hidden files based on extensions in shares
	DisableLoginOption       bool                `json:"disableLoginOption"`    // disable login option in share (true = hide, false = show)
	SourceURL                string              `json:"sourceURL,omitempty"`
	CanEditShare             bool                `json:"canEditShare,omitempty"`
}
type CreateBody struct {
	CommonShare
	Hash     string `json:"hash,omitempty"`
	Password string `json:"password"`
	Expires  string `json:"expires"`
	Unit     string `json:"unit"`
}

// Link is the information needed to build a shareable link.
type Link struct {
	CommonShare
	Downloads    int    `json:"downloads"`
	Hash         string `json:"hash" storm:"id,index"`
	UserID       uint   `json:"userID"`
	Expire       int64  `json:"expire"`
	PasswordHash string `json:"password_hash,omitempty"`
	// Token is a random value that will only be set when PasswordHash is set. It is
	// URL-Safe and is used to download links in password-protected shares via a
	// query arg.
	Token string `json:"token,omitempty"`

	Mu            sync.Mutex     `json:"-"`
	UserDownloads map[string]int `json:"userDownloads,omitempty"` // Track downloads per username
	Version       int            `json:"version,omitempty"`

	// Metadata snapshots share one stable owner for runtime download counts.
	// The owner keeps the existing persisted fields and mutex; neither is copied.
	downloadState *downloadState
}

type downloadState struct {
	owner *Link
}

func (link *Link) downloadsOwner() *Link {
	link.Mu.Lock()
	defer link.Mu.Unlock()
	if link.downloadState == nil {
		link.downloadState = &downloadState{owner: link}
	}
	return link.downloadState.owner
}

// Clone returns detached metadata and count snapshots while retaining the
// stable runtime download state used by active requests for this share.
func (link *Link) Clone() *Link {
	if link == nil {
		return nil
	}
	owner := link.downloadsOwner()
	owner.Mu.Lock()
	defer owner.Mu.Unlock()
	common := link.CommonShare
	if common.AllowedUsernames != nil {
		common.AllowedUsernames = append([]string{}, common.AllowedUsernames...)
	}
	if common.SidebarLinks != nil {
		common.SidebarLinks = append([]users.SidebarLink{}, common.SidebarLinks...)
	}
	var userDownloads map[string]int
	if owner.UserDownloads != nil {
		userDownloads = make(map[string]int, len(owner.UserDownloads))
		for username, downloads := range owner.UserDownloads {
			userDownloads[username] = downloads
		}
	}
	return &Link{
		CommonShare: common, Downloads: owner.Downloads, Hash: link.Hash,
		UserID: link.UserID, Expire: link.Expire, PasswordHash: link.PasswordHash,
		Token: link.Token, UserDownloads: userDownloads, Version: link.Version,
		downloadState: link.downloadState,
	}
}

// persistenceSnapshot has no runtime aliases, so backend serialization cannot
// race with a download that starts after this snapshot was taken.
func (link *Link) persistenceSnapshot() *Link {
	snapshot := link.Clone()
	snapshot.downloadState = nil
	return snapshot
}
