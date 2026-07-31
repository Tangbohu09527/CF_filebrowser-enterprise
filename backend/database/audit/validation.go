package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxRequestIDBytes = 128
	MaxUsernameBytes  = 255
	MaxSourceBytes    = 255
	MaxPathBytes      = 4096
	MaxErrorCodeBytes = 64
	MaxChangedFields  = 32
	MaxMetadataBytes  = 768
	MaxEventBytes     = 16 * 1024
)

var (
	ErrInvalidEvent     = errors.New("invalid audit event")
	ErrMetadataTooLarge = fmt.Errorf("%w: metadata exceeds maximum serialized size", ErrInvalidEvent)
	ErrEventTooLarge    = fmt.Errorf("%w: event exceeds maximum serialized size", ErrInvalidEvent)

	requestIDPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	referencePattern        = regexp.MustCompile(`^[0-9a-f]{32}$`)
	errorCodePattern        = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	sourcePattern           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]*$`)
	eventIDPattern          = regexp.MustCompile(`^[0-9a-f]{32}$`)
	latestSortableTimestamp = time.Date(2262, 4, 11, 23, 47, 16, 854775807, time.UTC)
)

func (event Event) Validate() error {
	return event.validate(false)
}

func (event Event) ValidatePending() error {
	return event.validate(true)
}

func ValidateRequestID(requestID string) error {
	if !validBoundedString(requestID, MaxRequestIDBytes) || !requestIDPattern.MatchString(requestID) {
		return invalidField("requestId")
	}
	return nil
}

func ValidateEventID(id string) error {
	if !eventIDPattern.MatchString(id) {
		return invalidField("id")
	}
	return nil
}

func (event Event) validate(pending bool) error {
	if err := event.validateCommon(); err != nil {
		return err
	}
	if pending {
		if event.ID != "" || !event.TimestampUTC.IsZero() || event.Result != "" ||
			event.HTTPStatus != nil || event.ErrorCode != "" {
			return invalidField("pending terminal fields")
		}
	} else {
		if event.TimestampUTC.IsZero() || event.TimestampUTC.Before(time.Unix(0, 0)) ||
			event.TimestampUTC.After(latestSortableTimestamp) ||
			event.TimestampUTC.Location() != time.UTC {
			return invalidField("timestampUtc")
		}
		if !validResult(event.Result) {
			return invalidField("result")
		}
	}
	serialized, err := json.Marshal(event)
	if err != nil {
		return invalidField("serialization")
	}
	if len(serialized) > MaxEventBytes {
		return ErrEventTooLarge
	}
	return nil
}

func (event Event) validateCommon() error {
	if event.SchemaVersion != CurrentSchemaVersion {
		return invalidField("schemaVersion")
	}
	if event.ID != "" && !eventIDPattern.MatchString(event.ID) {
		return invalidField("id")
	}
	if err := ValidateRequestID(event.RequestID); err != nil {
		return err
	}
	if event.UserID != nil && *event.UserID == 0 {
		return invalidField("userId")
	}
	if !validOptionalText(event.Username, MaxUsernameBytes) {
		return invalidField("username")
	}
	if !validAuthMethod(event.AuthMethod) {
		return invalidField("authMethod")
	}
	if !validReference(event.TokenRef) {
		return invalidField("tokenRef")
	}
	if !validReference(event.ShareRef) {
		return invalidField("shareRef")
	}
	if event.ClientIP != "" && net.ParseIP(event.ClientIP) == nil {
		return invalidField("clientIp")
	}
	if !validAction(event.Action) {
		return invalidField("action")
	}
	if !validOrigin(event.Origin) {
		return invalidField("origin")
	}
	if !validSource(event.Source) || !validSource(event.TargetSource) {
		return invalidField("source")
	}
	for _, path := range []string{event.Path, event.CanonicalPath, event.TargetPath, event.TargetCanonicalPath} {
		if !validAuditPath(path) {
			return invalidField("path")
		}
	}
	if event.HTTPStatus != nil && (*event.HTTPStatus < 100 || *event.HTTPStatus > 599) {
		return invalidField("httpStatus")
	}
	if event.ErrorCode != "" && (!validBoundedString(event.ErrorCode, MaxErrorCodeBytes) ||
		!errorCodePattern.MatchString(event.ErrorCode)) {
		return invalidField("errorCode")
	}
	if event.Metadata != nil {
		if err := event.Metadata.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (metadata MetadataV1) Validate() error {
	if metadata.SchemaVersion != CurrentMetadataSchemaVersion {
		return invalidField("metadata.schemaVersion")
	}
	serialized, err := json.Marshal(metadata)
	if err != nil {
		return invalidField("metadata serialization")
	}
	if len(serialized) > MaxMetadataBytes {
		return ErrMetadataTooLarge
	}
	for _, value := range []*int64{
		metadata.DurationMs,
		metadata.Bytes,
		metadata.RangeStart,
		metadata.RangeEnd,
		metadata.ItemCount,
		metadata.SuccessCount,
		metadata.FailedCount,
		metadata.DeniedCount,
	} {
		if value != nil && *value < 0 {
			return invalidField("metadata numeric value")
		}
	}
	if metadata.RangeStart != nil && metadata.RangeEnd != nil && *metadata.RangeEnd < *metadata.RangeStart {
		return invalidField("metadata range")
	}
	if metadata.Method != "" && !validMethod(metadata.Method) {
		return invalidField("metadata method")
	}
	if len(metadata.ChangedFields) > MaxChangedFields {
		return invalidField("metadata changedFields")
	}
	for _, field := range metadata.ChangedFields {
		if !validChangedField(field) {
			return invalidField("metadata changedFields")
		}
	}
	if metadata.ItemCount != nil {
		remaining := *metadata.ItemCount
		for _, count := range []*int64{metadata.SuccessCount, metadata.FailedCount, metadata.DeniedCount} {
			if count != nil {
				if *count > remaining {
					return invalidField("metadata counts")
				}
				remaining -= *count
			}
		}
	}
	if metadata.OnlyOfficeStatus != nil && !validOnlyOfficeStatus(*metadata.OnlyOfficeStatus) {
		return invalidField("metadata onlyOfficeStatus")
	}
	return nil
}

func validBoundedString(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && !containsControl(value)
}

func validOptionalText(value string, maximum int) bool {
	return value == "" || (len(value) <= maximum && utf8.ValidString(value) && !containsControl(value))
}

func validReference(value string) bool {
	return value == "" || referencePattern.MatchString(value)
}

func validSource(value string) bool {
	return value == "" || (len(value) <= MaxSourceBytes && strings.TrimSpace(value) == value &&
		sourcePattern.MatchString(value))
}

func validAuditPath(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > MaxPathBytes || !utf8.ValidString(value) || containsControl(value) ||
		!strings.HasPrefix(value, "/") || strings.Contains(value, `\`) {
		return false
	}
	lower := strings.ToLower(value)
	return !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") &&
		!strings.HasPrefix(lower, "file://")
}

func containsControl(value string) bool {
	return strings.IndexFunc(value, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) >= 0
}

func invalidField(field string) error {
	return fmt.Errorf("%w: invalid %s", ErrInvalidEvent, field)
}

func validAuthMethod(value AuthMethod) bool {
	switch value {
	case AuthMethodSession, AuthMethodToken, AuthMethodShare, AuthMethodWebDAV,
		AuthMethodOnlyOffice, AuthMethodAnonymous, AuthMethodInternal:
		return true
	default:
		return false
	}
}

func validOrigin(value Origin) bool {
	switch value {
	case OriginHTTP, OriginWebDAV, OriginOnlyOffice, OriginInternal:
		return true
	default:
		return false
	}
}

func validResult(value Result) bool {
	switch value {
	case ResultSuccess, ResultDenied, ResultFailed, ResultCancelled, ResultUnknown:
		return true
	default:
		return false
	}
}

func validAction(value Action) bool {
	switch value {
	case ActionAuthLogin, ActionAuthLoginFailed,
		ActionFileBrowse, ActionFilePreview, ActionFileDownload, ActionFileUpload,
		ActionFileModify, ActionFileRename, ActionFileMove, ActionFileDelete,
		ActionArchiveCreate, ActionArchiveExtract,
		ActionShareCreate, ActionShareUpdate, ActionShareDelete, ActionShareAccess,
		ActionTokenCreate, ActionTokenRevoke, ActionTokenDenied,
		ActionUserCreate, ActionUserUpdate, ActionUserDelete,
		ActionPermissionUpdate, ActionWebDAVRead, ActionWebDAVWrite,
		ActionOnlyOfficeSave, ActionAuditQuery, ActionAuditRetentionCleanup:
		return true
	default:
		return false
	}
}

func validMethod(value Method) bool {
	switch value {
	case MethodGET, MethodHEAD, MethodPOST, MethodPUT, MethodPATCH, MethodDELETE,
		MethodOPTIONS, MethodPROPFIND, MethodPROPPATCH, MethodMKCOL, MethodCOPY,
		MethodMOVE, MethodLOCK, MethodUNLOCK:
		return true
	default:
		return false
	}
}

func validChangedField(value ChangedField) bool {
	switch value {
	case ChangedFieldUsername, ChangedFieldPassword, ChangedFieldPermissions,
		ChangedFieldScopes, ChangedFieldTokens, ChangedFieldLoginMethod, ChangedFieldDisabled,
		ChangedFieldLocale, ChangedFieldViewMode, ChangedFieldSource, ChangedFieldPath,
		ChangedFieldTarget, ChangedFieldExpiration, ChangedFieldAccess, ChangedFieldCapabilities,
		ChangedFieldCreatorCapabilities, ChangedFieldSettings, ChangedFieldContent,
		ChangedFieldName, ChangedFieldDescription, ChangedFieldAllowedUsers,
		ChangedFieldDownloadLimit, ChangedFieldBandwidthLimit, ChangedFieldTheme,
		ChangedFieldPreview, ChangedFieldSidebar, ChangedFieldAuthentication,
		ChangedFieldCreate, ChangedFieldModify, ChangedFieldDelete, ChangedFieldDownload,
		ChangedFieldShare:
		return true
	default:
		return false
	}
}

func validOnlyOfficeStatus(value int) bool {
	switch value {
	case 1, 2, 3, 4, 6, 7:
		return true
	default:
		return false
	}
}
