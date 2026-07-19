package filebridge

import "fmt"

const SchemaVersion = "filebrowser-agentctl/v1"

type Input struct {
	SchemaVersion  string `json:"schema_version,omitempty"`
	RequestID      string `json:"request_id,omitempty"`
	OperationID    string `json:"operation_id,omitempty"`
	Source         string `json:"source,omitempty"`
	Path           string `json:"path,omitempty"`
	Query          string `json:"query,omitempty"`
	Limit          int    `json:"limit,omitempty"`
	Algorithm      string `json:"algorithm,omitempty"`
	OutputFile     string `json:"output_file,omitempty"`
	LocalFile      string `json:"local_file,omitempty"`
	ExpectedBytes  *int64 `json:"expected_bytes,omitempty"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
}

type Response struct {
	SchemaVersion string         `json:"schema_version"`
	OK            bool           `json:"ok"`
	Command       string         `json:"command"`
	RequestID     string         `json:"request_id"`
	OperationID   string         `json:"operation_id"`
	DryRun        bool           `json:"dry_run"`
	Result        any            `json:"result,omitempty"`
	Error         *ErrorResponse `json:"error,omitempty"`
}

type ErrorResponse struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Retryable  bool   `json:"retryable"`
}

type BridgeError struct {
	Code       string
	Message    string
	HTTPStatus int
	Retryable  bool
}

func (e *BridgeError) Error() string {
	return e.Message
}

func bridgeError(code, message string) *BridgeError {
	return &BridgeError{Code: code, Message: message}
}

func errorResponse(err error) *ErrorResponse {
	var bridgeErr *BridgeError
	if !asBridgeError(err, &bridgeErr) {
		return &ErrorResponse{Code: "internal_error", Message: "internal client error"}
	}
	return &ErrorResponse{
		Code:       bridgeErr.Code,
		Message:    bridgeErr.Message,
		HTTPStatus: bridgeErr.HTTPStatus,
		Retryable:  bridgeErr.Retryable,
	}
}

func asBridgeError(err error, target **BridgeError) bool {
	for err != nil {
		if value, ok := err.(*BridgeError); ok {
			*target = value
			return true
		}
		type unwrapper interface{ Unwrap() error }
		value, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = value.Unwrap()
	}
	return false
}

type Permissions struct {
	API      bool `json:"api"`
	Admin    bool `json:"admin"`
	Modify   bool `json:"modify"`
	Share    bool `json:"share"`
	Realtime bool `json:"realtime"`
	Delete   bool `json:"delete"`
	Create   bool `json:"create"`
	Browse   bool `json:"browse"`
	Preview  bool `json:"preview"`
	Download bool `json:"download"`
}

func (p Permissions) intersect(other Permissions) Permissions {
	return Permissions{
		API:      p.API && other.API,
		Admin:    p.Admin && other.Admin,
		Modify:   p.Modify && other.Modify,
		Share:    p.Share && other.Share,
		Realtime: p.Realtime && other.Realtime,
		Delete:   p.Delete && other.Delete,
		Create:   p.Create && other.Create,
		Browse:   p.Browse && other.Browse,
		Preview:  p.Preview && other.Preview,
		Download: p.Download && other.Download,
	}
}

type Scope struct {
	Name  string `json:"name"`
	Scope string `json:"scope"`
}

type wireUser struct {
	ID          uint        `json:"id"`
	Username    string      `json:"username"`
	Permissions Permissions `json:"permissions"`
	Scopes      []Scope     `json:"scopes"`
}

type Item struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	Source     string `json:"source"`
	Size       int64  `json:"size"`
	Modified   string `json:"modified,omitempty"`
	Type       string `json:"type"`
	IsDir      bool   `json:"is_dir"`
	Hidden     bool   `json:"hidden"`
	HasPreview bool   `json:"has_preview"`
}

type wireItem struct {
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	Modified   string `json:"modified"`
	Type       string `json:"type"`
	Hidden     bool   `json:"hidden"`
	HasPreview bool   `json:"hasPreview"`
}

type wireResource struct {
	wireItem
	Path      string            `json:"path"`
	Source    string            `json:"source"`
	Files     []wireItem        `json:"files"`
	Folders   []wireItem        `json:"folders"`
	Checksums map[string]string `json:"checksums"`
}

type wireSearchResult struct {
	Path       string `json:"path"`
	Type       string `json:"type"`
	Size       int64  `json:"size"`
	Modified   string `json:"modified"`
	HasPreview bool   `json:"hasPreview"`
	Source     string `json:"source"`
}

type CapabilitiesResult struct {
	Username          string      `json:"username"`
	UserID            uint        `json:"user_id"`
	Permissions       Permissions `json:"permissions"`
	Sources           []Scope     `json:"sources"`
	CapabilitiesExact bool        `json:"capabilities_exact"`
	PermissionSource  string      `json:"permission_source"`
}

type SourcesResult struct {
	Sources []SourceResult `json:"sources"`
}

type SourceResult struct {
	Name      string      `json:"name"`
	Scope     string      `json:"scope"`
	Available bool        `json:"available"`
	Info      *SourceInfo `json:"info,omitempty"`
}

type SourceInfo struct {
	Name            string `json:"name"`
	ReadOnly        bool   `json:"read_only"`
	Private         bool   `json:"private"`
	Status          string `json:"status"`
	NumDirectories  uint64 `json:"num_directories"`
	NumFiles        uint64 `json:"num_files"`
	UsedBytes       uint64 `json:"used_bytes"`
	TotalBytes      uint64 `json:"total_bytes"`
	LastIndexedUnix int64  `json:"last_indexed_unix"`
}

type ListResult struct {
	Source  string `json:"source"`
	Path    string `json:"path"`
	Files   []Item `json:"files"`
	Folders []Item `json:"folders"`
}

type SearchResult struct {
	Source    string `json:"source"`
	Scope     string `json:"scope"`
	Query     string `json:"query"`
	Limit     int    `json:"limit"`
	Truncated bool   `json:"truncated"`
	Items     []Item `json:"items"`
}

type StatResult struct {
	Item      Item              `json:"item"`
	Checksums map[string]string `json:"checksums,omitempty"`
}

type ReadResult struct {
	Source      string `json:"source"`
	Path        string `json:"path"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
	ContentType string `json:"content_type,omitempty"`
	Encoding    string `json:"encoding"`
	Content     string `json:"content"`
	Untrusted   bool   `json:"untrusted"`
}

type DownloadResult struct {
	Source     string `json:"source"`
	Path       string `json:"path"`
	OutputFile string `json:"output_file"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
}

type WriteResult struct {
	Action      string `json:"action"`
	Source      string `json:"source"`
	Path        string `json:"path"`
	Applied     bool   `json:"applied"`
	AlreadyDone bool   `json:"already_done"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256,omitempty"`
	Verified    bool   `json:"verified"`
}

func requireString(value, name string) error {
	if value == "" {
		return bridgeError("invalid_input", fmt.Sprintf("%s is required", name))
	}
	return nil
}
