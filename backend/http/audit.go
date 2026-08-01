package http

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"strings"
	"sync"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

const auditRequestIDHeader = "X-Request-ID"

var (
	ErrAuditUnavailable         = errors.New("audit unavailable")
	ErrAuditFieldsFrozen        = errors.New("audit reservation fields are frozen")
	ErrAuditInvalidState        = errors.New("invalid audit recorder state")
	ErrAuditInvalidFinalization = errors.New("invalid audit finalization")
	ErrAuditFinalized           = errors.New("audit recorder already finalized")
)

type AuditFailureCategory string

const (
	AuditFailureNone        AuditFailureCategory = ""
	AuditFailureAppend      AuditFailureCategory = "append"
	AuditFailureReservation AuditFailureCategory = "reservation"
	AuditFailureFinalize    AuditFailureCategory = "finalize"
	AuditFailureRecovery    AuditFailureCategory = "recovery"
)

const (
	auditErrorCodeClientCancelled        = "client_cancelled"
	auditErrorCodeResponseWriteFailed    = "response_write_failed"
	auditErrorCodeInternalError          = "internal_error"
	auditErrorCodeAuthenticationRequired = "authentication_required"
	auditErrorCodeAPIPermissionRequired  = "api_permission_required"
	auditErrorCodeTokenChainingDenied    = "token_chaining_denied"
	auditErrorCodeInvalidTokenRequest    = "invalid_token_request"
	auditErrorCodeTokenNotFound          = "token_not_found"
	auditErrorCodeTokenCreateFailed      = "token_create_failed"
	auditErrorCodeTokenRevokeFailed      = "token_revoke_failed"
	auditErrorCodeAuditUnavailable       = "audit_unavailable"
)

// AuditService adds a thread-safe degraded state to the persistent Audit Store.
// It deliberately returns stable errors and never retains underlying error text.
type AuditService struct {
	store auditdb.Store

	mu                  sync.RWMutex
	degraded            bool
	lastFailureCategory AuditFailureCategory
}

func NewAuditService(store auditdb.Store) *AuditService {
	return &AuditService{store: store}
}

func (service *AuditService) IsDegraded() bool {
	if service == nil {
		return true
	}
	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.degraded
}

func (service *AuditService) LastFailureCategory() AuditFailureCategory {
	if service == nil {
		return AuditFailureAppend
	}
	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.lastFailureCategory
}

func (service *AuditService) markFailure(category AuditFailureCategory) error {
	if service != nil {
		service.mu.Lock()
		service.degraded = true
		service.lastFailureCategory = category
		service.mu.Unlock()
	}
	return ErrAuditUnavailable
}

func (service *AuditService) markSuccess() {
	if service == nil {
		return
	}
	service.mu.Lock()
	service.degraded = false
	service.lastFailureCategory = AuditFailureNone
	service.mu.Unlock()
}

func (service *AuditService) AppendTerminal(event auditdb.Event) (*auditdb.Event, error) {
	if service == nil || service.store == nil {
		return nil, service.markFailure(AuditFailureAppend)
	}
	eventResult, err := service.store.AppendTerminal(event)
	if err != nil {
		return nil, service.markFailure(AuditFailureAppend)
	}
	service.markSuccess()
	return eventResult, nil
}

func (service *AuditService) CreatePending(event auditdb.Event) error {
	if service == nil || service.store == nil {
		return service.markFailure(AuditFailureReservation)
	}
	if err := service.store.CreatePending(event); err != nil {
		return service.markFailure(AuditFailureReservation)
	}
	service.markSuccess()
	return nil
}

func (service *AuditService) Finalize(requestID string, finalization auditdb.Finalization) (*auditdb.Event, error) {
	if service == nil || service.store == nil {
		return nil, service.markFailure(AuditFailureFinalize)
	}
	event, err := service.store.Finalize(requestID, finalization)
	if err != nil {
		return nil, service.markFailure(AuditFailureFinalize)
	}
	service.markSuccess()
	return event, nil
}

func (service *AuditService) Recover() (int, error) {
	if service == nil || service.store == nil {
		return 0, service.markFailure(AuditFailureRecovery)
	}
	recovered, err := service.store.RecoverPending()
	if err != nil {
		return 0, service.markFailure(AuditFailureRecovery)
	}
	service.markSuccess()
	return recovered, nil
}

type AuditFinalization struct {
	HTTPStatus      int
	Bytes           int64
	WriteFailed     bool
	ClientCancelled bool
	ErrorCode       string
}

type AuditRecorder struct {
	service   *AuditService
	startedAt time.Time

	mu                sync.Mutex
	event             auditdb.Event
	errorCode         string
	reserved          bool
	reservationFailed bool
	finalized         bool

	finalizeOnce sync.Once
	finalizeErr  error
}

func newAuditRecorder(service *AuditService, requestID, clientIP string, startedAt time.Time) *AuditRecorder {
	return &AuditRecorder{
		service:   service,
		startedAt: startedAt,
		event: auditdb.Event{
			SchemaVersion: auditdb.CurrentSchemaVersion,
			RequestID:     requestID,
			ClientIP:      clientIP,
			Origin:        auditdb.OriginHTTP,
		},
	}
}

func (recorder *AuditRecorder) RequestID() string {
	if recorder == nil {
		return ""
	}
	return recorder.event.RequestID
}

func (recorder *AuditRecorder) mutateReservationField(mutate func(*auditdb.Event)) error {
	if recorder == nil {
		return ErrAuditInvalidState
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.reserved {
		return ErrAuditFieldsFrozen
	}
	if recorder.finalized {
		return ErrAuditFinalized
	}
	mutate(&recorder.event)
	return nil
}

func (recorder *AuditRecorder) SetActor(userID *uint, username string) error {
	return recorder.mutateReservationField(func(event *auditdb.Event) {
		if userID == nil {
			event.UserID = nil
		} else {
			value := *userID
			event.UserID = &value
		}
		event.Username = username
	})
}

func (recorder *AuditRecorder) SetAuthMethod(method auditdb.AuthMethod) error {
	return recorder.mutateReservationField(func(event *auditdb.Event) {
		event.AuthMethod = method
	})
}

func (recorder *AuditRecorder) SetTokenRef(reference string) error {
	return recorder.mutateReservationField(func(event *auditdb.Event) {
		event.TokenRef = reference
	})
}

func (recorder *AuditRecorder) SetShareRef(reference string) error {
	return recorder.mutateReservationField(func(event *auditdb.Event) {
		event.ShareRef = reference
	})
}

func (recorder *AuditRecorder) SetClientIP(clientIP string) error {
	if clientIP != "" {
		parsed := net.ParseIP(clientIP)
		if parsed == nil {
			return ErrAuditInvalidState
		}
		clientIP = parsed.String()
	}
	return recorder.mutateReservationField(func(event *auditdb.Event) {
		event.ClientIP = clientIP
	})
}

func (recorder *AuditRecorder) SetAction(action auditdb.Action) error {
	return recorder.mutateReservationField(func(event *auditdb.Event) {
		event.Action = action
	})
}

func (recorder *AuditRecorder) SetOrigin(origin auditdb.Origin) error {
	return recorder.mutateReservationField(func(event *auditdb.Event) {
		event.Origin = origin
	})
}

func (recorder *AuditRecorder) SetResource(source, path, canonicalPath string) error {
	return recorder.mutateReservationField(func(event *auditdb.Event) {
		event.Source = source
		event.Path = path
		event.CanonicalPath = canonicalPath
	})
}

func (recorder *AuditRecorder) SetTarget(source, path, canonicalPath string) error {
	return recorder.mutateReservationField(func(event *auditdb.Event) {
		event.TargetSource = source
		event.TargetPath = path
		event.TargetCanonicalPath = canonicalPath
	})
}

func (recorder *AuditRecorder) SetEffectivePermissions(permissions *auditdb.Permissions) error {
	return recorder.mutateReservationField(func(event *auditdb.Event) {
		if permissions == nil {
			event.EffectivePermissions = nil
			return
		}
		value := *permissions
		event.EffectivePermissions = &value
	})
}

func (recorder *AuditRecorder) SetErrorCode(errorCode string) error {
	if recorder == nil || !validAuditFinalizationErrorCode(errorCode) {
		return ErrAuditInvalidFinalization
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.finalized {
		return ErrAuditFinalized
	}
	recorder.errorCode = errorCode
	return nil
}

func (recorder *AuditRecorder) setErrorCodeIfEmpty(errorCode string) error {
	if recorder == nil || !validAuditFinalizationErrorCode(errorCode) {
		return ErrAuditInvalidFinalization
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.finalized {
		return ErrAuditFinalized
	}
	if recorder.errorCode == "" {
		recorder.errorCode = errorCode
	}
	return nil
}

func (recorder *AuditRecorder) MergeMetadata(metadata *auditdb.MetadataV1) error {
	if recorder == nil {
		return ErrAuditInvalidState
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.finalized {
		return ErrAuditFinalized
	}
	merged := auditdb.MergeMetadataV1(recorder.event.Metadata, metadata)
	if merged != nil {
		if err := merged.Validate(); err != nil {
			return ErrAuditInvalidState
		}
	}
	recorder.event.Metadata = merged
	return nil
}

func (recorder *AuditRecorder) ReservePending() error {
	if recorder == nil {
		return ErrAuditInvalidState
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.reserved {
		return nil
	}
	if recorder.reservationFailed {
		return ErrAuditUnavailable
	}
	if recorder.finalized {
		return ErrAuditFinalized
	}
	if !reservationResourceFieldsPresent(recorder.event) {
		return ErrAuditInvalidState
	}
	pending := cloneRecorderEvent(recorder.event)
	if err := pending.ValidatePending(); err != nil {
		return ErrAuditInvalidState
	}
	if err := recorder.service.CreatePending(pending); err != nil {
		recorder.reservationFailed = true
		return err
	}
	recorder.reserved = true
	return nil
}

func reservationResourceFieldsPresent(event auditdb.Event) bool {
	requiresResource := false
	switch event.Action {
	case auditdb.ActionFileBrowse, auditdb.ActionFilePreview, auditdb.ActionFileDownload,
		auditdb.ActionFileUpload, auditdb.ActionFileModify, auditdb.ActionFileRename,
		auditdb.ActionFileMove, auditdb.ActionFileDelete, auditdb.ActionArchiveCreate,
		auditdb.ActionArchiveExtract, auditdb.ActionWebDAVRead, auditdb.ActionWebDAVWrite,
		auditdb.ActionOnlyOfficeSave:
		requiresResource = true
	}
	if requiresResource && (event.Source == "" || event.CanonicalPath == "") {
		return false
	}
	if (event.Action == auditdb.ActionFileRename || event.Action == auditdb.ActionFileMove) &&
		(event.TargetSource == "" || event.TargetCanonicalPath == "") {
		return false
	}
	return true
}

func (recorder *AuditRecorder) Finalize(finalization AuditFinalization) error {
	if recorder == nil {
		return ErrAuditInvalidState
	}
	recorder.finalizeOnce.Do(func() {
		recorder.finalizeErr = recorder.finalize(finalization)
	})
	return recorder.finalizeErr
}

func (recorder *AuditRecorder) finalize(finalization AuditFinalization) error {
	now := time.Now().UTC()
	recorder.mu.Lock()
	recorder.finalized = true
	if recorder.event.Action == "" {
		recorder.mu.Unlock()
		return nil
	}
	errorCode := finalization.ErrorCode
	if errorCode == "" {
		errorCode = recorder.errorCode
	}
	if finalization.Bytes < 0 || !validAuditFinalizationErrorCode(errorCode) {
		recorder.mu.Unlock()
		return ErrAuditInvalidFinalization
	}
	if finalization.HTTPStatus != 0 && (finalization.HTTPStatus < 100 || finalization.HTTPStatus > 599) {
		recorder.mu.Unlock()
		return ErrAuditInvalidFinalization
	}

	durationMilliseconds := now.Sub(recorder.startedAt).Milliseconds()
	if durationMilliseconds < 0 {
		durationMilliseconds = 0
	}
	bytesWritten := finalization.Bytes
	clientCancelled := finalization.ClientCancelled
	terminalMetadata := &auditdb.MetadataV1{
		SchemaVersion:   auditdb.CurrentMetadataSchemaVersion,
		DurationMs:      &durationMilliseconds,
		Bytes:           &bytesWritten,
		ClientCancelled: &clientCancelled,
	}
	event := cloneRecorderEvent(recorder.event)
	event.TimestampUTC = now
	event.Result = classifyAuditResult(finalization.HTTPStatus, finalization.ClientCancelled, finalization.WriteFailed)
	if finalization.HTTPStatus != 0 {
		status := finalization.HTTPStatus
		event.HTTPStatus = &status
	}
	event.ErrorCode = errorCode
	if event.ErrorCode == "" {
		switch {
		case finalization.ClientCancelled:
			event.ErrorCode = auditErrorCodeClientCancelled
		case finalization.WriteFailed:
			event.ErrorCode = auditErrorCodeResponseWriteFailed
		}
	}
	event.Metadata = auditdb.MergeMetadataV1(event.Metadata, terminalMetadata)
	reserved := recorder.reserved
	reservationFailed := recorder.reservationFailed
	recorder.mu.Unlock()

	if reservationFailed {
		return ErrAuditUnavailable
	}
	if err := event.Validate(); err != nil {
		return ErrAuditInvalidFinalization
	}
	if reserved {
		_, err := recorder.service.Finalize(event.RequestID, auditdb.Finalization{
			TimestampUTC: event.TimestampUTC,
			Result:       event.Result,
			HTTPStatus:   event.HTTPStatus,
			ErrorCode:    event.ErrorCode,
			Metadata:     event.Metadata,
		})
		return err
	}
	_, err := recorder.service.AppendTerminal(event)
	return err
}

func validAuditFinalizationErrorCode(errorCode string) bool {
	switch errorCode {
	case "", auditErrorCodeClientCancelled, auditErrorCodeResponseWriteFailed, auditErrorCodeInternalError,
		auditErrorCodeAuthenticationRequired, auditErrorCodeAPIPermissionRequired,
		auditErrorCodeTokenChainingDenied, auditErrorCodeInvalidTokenRequest,
		auditErrorCodeTokenNotFound, auditErrorCodeTokenCreateFailed,
		auditErrorCodeTokenRevokeFailed, auditErrorCodeAuditUnavailable:
		return true
	default:
		return false
	}
}

func withAuditDefaultAction(action auditdb.Action, fn handleFunc) stdhttp.HandlerFunc {
	return wrapHandler(func(writer stdhttp.ResponseWriter, request *stdhttp.Request, data *requestContext) (int, error) {
		recorder := AuditRecorderFromRequest(request)
		if recorder == nil {
			return stdhttp.StatusServiceUnavailable, ErrAuditUnavailable
		}
		if err := recorder.SetAction(action); err != nil {
			return stdhttp.StatusServiceUnavailable, ErrAuditUnavailable
		}
		if err := recorder.SetAuthMethod(auditdb.AuthMethodAnonymous); err != nil {
			return stdhttp.StatusServiceUnavailable, ErrAuditUnavailable
		}
		status, err := fn(writer, request, data)
		if status == stdhttp.StatusUnauthorized || status == stdhttp.StatusForbidden {
			if codeErr := recorder.setErrorCodeIfEmpty(auditErrorCodeAuthenticationRequired); codeErr != nil {
				return stdhttp.StatusServiceUnavailable, ErrAuditUnavailable
			}
		}
		return status, err
	})
}

func withAuditAuthenticatedUser(fn handleFunc) handleFunc {
	return func(writer stdhttp.ResponseWriter, request *stdhttp.Request, data *requestContext) (int, error) {
		recorder := AuditRecorderFromRequest(request)
		if recorder == nil || data.user == nil || data.user.ID == 0 || data.user.Username == "" {
			return stdhttp.StatusServiceUnavailable, ErrAuditUnavailable
		}
		if err := recorder.SetActor(&data.user.ID, data.user.Username); err != nil {
			return stdhttp.StatusServiceUnavailable, ErrAuditUnavailable
		}
		authMethod := auditdb.AuthMethodSession
		tokenRef := ""
		if data.apiToken {
			authMethod = auditdb.AuthMethodToken
			tokenRef = auditdb.DeriveTokenRef(utils.HashSHA256(data.token))
			if tokenRef == "" {
				return stdhttp.StatusServiceUnavailable, ErrAuditUnavailable
			}
		}
		if err := recorder.SetAuthMethod(authMethod); err != nil {
			return stdhttp.StatusServiceUnavailable, ErrAuditUnavailable
		}
		if err := recorder.SetTokenRef(tokenRef); err != nil {
			return stdhttp.StatusServiceUnavailable, ErrAuditUnavailable
		}
		permissions := auditPermissions(data.user.Permissions)
		if err := recorder.SetEffectivePermissions(&permissions); err != nil {
			return stdhttp.StatusServiceUnavailable, ErrAuditUnavailable
		}
		return fn(writer, request, data)
	}
}

func auditPermissions(permissions users.Permissions) auditdb.Permissions {
	return auditdb.Permissions{
		API:      permissions.Api,
		Admin:    permissions.Admin,
		Modify:   permissions.Modify,
		Share:    permissions.Share,
		Realtime: permissions.Realtime,
		Delete:   permissions.Delete,
		Create:   permissions.Create,
		Browse:   permissions.Browse,
		Preview:  permissions.Preview,
		Download: permissions.Download,
	}
}

func classifyAuditResult(status int, clientCancelled, writeFailed bool) auditdb.Result {
	if clientCancelled {
		return auditdb.ResultCancelled
	}
	if writeFailed {
		return auditdb.ResultFailed
	}
	if status == stdhttp.StatusUnauthorized || status == stdhttp.StatusForbidden {
		return auditdb.ResultDenied
	}
	if status >= 200 && status <= 399 {
		return auditdb.ResultSuccess
	}
	if status >= 400 && status <= 599 {
		return auditdb.ResultFailed
	}
	return auditdb.ResultUnknown
}

func cloneRecorderEvent(event auditdb.Event) auditdb.Event {
	if event.UserID != nil {
		value := *event.UserID
		event.UserID = &value
	}
	if event.HTTPStatus != nil {
		value := *event.HTTPStatus
		event.HTTPStatus = &value
	}
	if event.EffectivePermissions != nil {
		value := *event.EffectivePermissions
		event.EffectivePermissions = &value
	}
	event.Metadata = auditdb.MergeMetadataV1(nil, event.Metadata)
	return event
}

type auditRecorderContextKey struct{}

func AuditRecorderFromContext(ctx context.Context) *AuditRecorder {
	if ctx == nil {
		return nil
	}
	recorder, _ := ctx.Value(auditRecorderContextKey{}).(*AuditRecorder)
	return recorder
}

func AuditRecorderFromRequest(request *stdhttp.Request) *AuditRecorder {
	if request == nil {
		return nil
	}
	return AuditRecorderFromContext(request.Context())
}

func AuditMiddleware(next stdhttp.Handler, service *AuditService) stdhttp.Handler {
	return auditMiddlewareWithRandom(next, service, rand.Reader)
}

func auditMiddlewareWithRandom(next stdhttp.Handler, service *AuditService, random io.Reader) stdhttp.Handler {
	return stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		requestID, err := newAuditRequestID(random)
		if err != nil {
			stdhttp.Error(writer, "Internal Server Error", stdhttp.StatusInternalServerError)
			return
		}
		writer.Header().Set(auditRequestIDHeader, requestID)
		wrappedWriter, responseState := wrapResponseWriter(writer)
		recorder := newAuditRecorder(service, requestID, normalizedAuditClientIP(request), time.Now())
		request = request.WithContext(context.WithValue(request.Context(), auditRecorderContextKey{}, recorder))
		defer func() {
			clientCancelled := errors.Is(request.Context().Err(), context.Canceled)
			_ = recorder.Finalize(AuditFinalization{
				HTTPStatus:      responseState.StatusCode,
				Bytes:           responseState.PayloadSize,
				WriteFailed:     responseState.WriteFailed(),
				ClientCancelled: clientCancelled,
			})
		}()
		next.ServeHTTP(wrappedWriter, request)
	})
}

func newAuditRequestID(random io.Reader) (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(random, value[:]); err != nil {
		return "", ErrAuditUnavailable
	}
	return hex.EncodeToString(value[:]), nil
}

func normalizedAuditClientIP(request *stdhttp.Request) string {
	if request == nil {
		return ""
	}
	candidate := ""
	if config != nil {
		candidate = strings.TrimSpace(getRemoteIP(request))
	}
	if parsed := net.ParseIP(candidate); parsed != nil {
		return parsed.String()
	}
	remoteAddress := strings.TrimSpace(request.RemoteAddr)
	if host, _, err := net.SplitHostPort(remoteAddress); err == nil {
		remoteAddress = host
	}
	if parsed := net.ParseIP(remoteAddress); parsed != nil {
		return parsed.String()
	}
	return ""
}
