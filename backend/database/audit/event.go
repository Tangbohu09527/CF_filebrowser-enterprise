package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const (
	CurrentSchemaVersion         uint16 = 1
	CurrentMetadataSchemaVersion uint16 = 1
)

type AuthMethod string

const (
	AuthMethodSession    AuthMethod = "session"
	AuthMethodToken      AuthMethod = "token"
	AuthMethodShare      AuthMethod = "share"
	AuthMethodWebDAV     AuthMethod = "webdav"
	AuthMethodOnlyOffice AuthMethod = "onlyoffice"
	AuthMethodAnonymous  AuthMethod = "anonymous"
	AuthMethodInternal   AuthMethod = "internal"
)

type Origin string

const (
	OriginHTTP       Origin = "http"
	OriginWebDAV     Origin = "webdav"
	OriginOnlyOffice Origin = "onlyoffice"
	OriginInternal   Origin = "internal"
)

type Result string

const (
	ResultSuccess   Result = "success"
	ResultDenied    Result = "denied"
	ResultFailed    Result = "failed"
	ResultCancelled Result = "cancelled"
	ResultUnknown   Result = "unknown"
)

type Action string

const (
	ActionAuthLogin             Action = "auth.login"
	ActionAuthLoginFailed       Action = "auth.login_failed"
	ActionFileBrowse            Action = "file.browse"
	ActionFilePreview           Action = "file.preview"
	ActionFileDownload          Action = "file.download"
	ActionFileUpload            Action = "file.upload"
	ActionFileModify            Action = "file.modify"
	ActionFileRename            Action = "file.rename"
	ActionFileMove              Action = "file.move"
	ActionFileDelete            Action = "file.delete"
	ActionArchiveCreate         Action = "archive.create"
	ActionArchiveExtract        Action = "archive.extract"
	ActionShareCreate           Action = "share.create"
	ActionShareUpdate           Action = "share.update"
	ActionShareDelete           Action = "share.delete"
	ActionShareAccess           Action = "share.access"
	ActionTokenCreate           Action = "token.create"
	ActionTokenRevoke           Action = "token.revoke"
	ActionTokenDenied           Action = "token.denied"
	ActionUserCreate            Action = "user.create"
	ActionUserUpdate            Action = "user.update"
	ActionUserDelete            Action = "user.delete"
	ActionPermissionUpdate      Action = "permission.update"
	ActionWebDAVRead            Action = "webdav.read"
	ActionWebDAVWrite           Action = "webdav.write"
	ActionOnlyOfficeSave        Action = "onlyoffice.save"
	ActionAuditQuery            Action = "audit.query"
	ActionAuditRetentionCleanup Action = "audit.retention_cleanup"
)

type Method string

const (
	MethodGET       Method = "GET"
	MethodHEAD      Method = "HEAD"
	MethodPOST      Method = "POST"
	MethodPUT       Method = "PUT"
	MethodPATCH     Method = "PATCH"
	MethodDELETE    Method = "DELETE"
	MethodOPTIONS   Method = "OPTIONS"
	MethodPROPFIND  Method = "PROPFIND"
	MethodPROPPATCH Method = "PROPPATCH"
	MethodMKCOL     Method = "MKCOL"
	MethodCOPY      Method = "COPY"
	MethodMOVE      Method = "MOVE"
	MethodLOCK      Method = "LOCK"
	MethodUNLOCK    Method = "UNLOCK"
)

type ChangedField string

const (
	ChangedFieldUsername            ChangedField = "username"
	ChangedFieldPassword            ChangedField = "password"
	ChangedFieldPermissions         ChangedField = "permissions"
	ChangedFieldScopes              ChangedField = "scopes"
	ChangedFieldTokens              ChangedField = "tokens"
	ChangedFieldLoginMethod         ChangedField = "login_method"
	ChangedFieldDisabled            ChangedField = "disabled"
	ChangedFieldLocale              ChangedField = "locale"
	ChangedFieldViewMode            ChangedField = "view_mode"
	ChangedFieldSource              ChangedField = "source"
	ChangedFieldPath                ChangedField = "path"
	ChangedFieldTarget              ChangedField = "target"
	ChangedFieldExpiration          ChangedField = "expiration"
	ChangedFieldAccess              ChangedField = "access"
	ChangedFieldCapabilities        ChangedField = "capabilities"
	ChangedFieldCreatorCapabilities ChangedField = "creator_capabilities"
	ChangedFieldSettings            ChangedField = "settings"
	ChangedFieldContent             ChangedField = "content"
	ChangedFieldName                ChangedField = "name"
	ChangedFieldDescription         ChangedField = "description"
	ChangedFieldAllowedUsers        ChangedField = "allowed_users"
	ChangedFieldDownloadLimit       ChangedField = "download_limit"
	ChangedFieldBandwidthLimit      ChangedField = "bandwidth_limit"
	ChangedFieldTheme               ChangedField = "theme"
	ChangedFieldPreview             ChangedField = "preview"
	ChangedFieldSidebar             ChangedField = "sidebar"
	ChangedFieldAuthentication      ChangedField = "authentication"
	ChangedFieldCreate              ChangedField = "create"
	ChangedFieldModify              ChangedField = "modify"
	ChangedFieldDelete              ChangedField = "delete"
	ChangedFieldDownload            ChangedField = "download"
	ChangedFieldShare               ChangedField = "share"
)

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

type MetadataV1 struct {
	SchemaVersion    uint16         `json:"schemaVersion"`
	DurationMs       *int64         `json:"durationMs,omitempty"`
	Bytes            *int64         `json:"bytes,omitempty"`
	RangeStart       *int64         `json:"rangeStart,omitempty"`
	RangeEnd         *int64         `json:"rangeEnd,omitempty"`
	Overwrite        *bool          `json:"overwrite,omitempty"`
	Method           Method         `json:"method,omitempty"`
	ChangedFields    []ChangedField `json:"changedFields,omitempty"`
	ItemCount        *int64         `json:"itemCount,omitempty"`
	SuccessCount     *int64         `json:"successCount,omitempty"`
	FailedCount      *int64         `json:"failedCount,omitempty"`
	DeniedCount      *int64         `json:"deniedCount,omitempty"`
	ClientCancelled  *bool          `json:"clientCancelled,omitempty"`
	OnlyOfficeStatus *int           `json:"onlyOfficeStatus,omitempty"`
}

func (metadata *MetadataV1) UnmarshalJSON(data []byte) error {
	type metadataAlias MetadataV1
	var decoded metadataAlias
	if err := decodeStrictJSON(data, &decoded); err != nil {
		return errors.New("invalid audit metadata JSON")
	}
	*metadata = MetadataV1(decoded)
	return nil
}

type Event struct {
	SchemaVersion uint16    `json:"schemaVersion"`
	ID            string    `json:"id,omitempty"`
	TimestampUTC  time.Time `json:"timestampUtc,omitempty"`
	RequestID     string    `json:"requestId"`

	UserID     *uint      `json:"userId,omitempty"`
	Username   string     `json:"username,omitempty"`
	AuthMethod AuthMethod `json:"authMethod"`

	TokenRef string `json:"tokenRef,omitempty"`
	ShareRef string `json:"shareRef,omitempty"`
	ClientIP string `json:"clientIp,omitempty"`

	Action Action `json:"action"`
	Origin Origin `json:"origin"`

	// Source fields are logical identifiers; path fields are virtual paths, never host filesystem paths.
	Source        string `json:"source,omitempty"`
	Path          string `json:"path,omitempty"`
	CanonicalPath string `json:"canonicalPath,omitempty"`

	TargetSource        string `json:"targetSource,omitempty"`
	TargetPath          string `json:"targetPath,omitempty"`
	TargetCanonicalPath string `json:"targetCanonicalPath,omitempty"`

	EffectivePermissions *Permissions `json:"effectivePermissions,omitempty"`

	Result     Result `json:"result,omitempty"`
	HTTPStatus *int   `json:"httpStatus,omitempty"`
	ErrorCode  string `json:"errorCode,omitempty"`

	Metadata *MetadataV1 `json:"metadata,omitempty"`
}

func (event *Event) UnmarshalJSON(data []byte) error {
	type eventAlias Event
	var decoded eventAlias
	if err := decodeStrictJSON(data, &decoded); err != nil {
		return errors.New("invalid audit event JSON")
	}
	*event = Event(decoded)
	return nil
}

type Finalization struct {
	TimestampUTC time.Time
	Result       Result
	HTTPStatus   *int
	ErrorCode    string
	Metadata     *MetadataV1
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}
