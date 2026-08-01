package audit

import (
	"context"
	"errors"
	"fmt"
	pathpkg "path"
	"time"
)

const (
	ProcessInterruptedErrorCode = "process_interrupted"
	DefaultQueryLimit           = 50
	MaxQueryLimit               = 200
)

var (
	ErrEventNotFound   = errors.New("audit event not found")
	ErrPendingNotFound = errors.New("audit pending event not found")
	ErrRequestIDExists = errors.New("audit request ID already exists")
	ErrInvalidLimit    = errors.New("invalid audit list limit")
	ErrInvalidQuery    = errors.New("invalid audit query")
)

type QueryOptions struct {
	Actor     string
	TokenRef  string
	ShareRef  string
	Action    Action
	Source    string
	Path      string
	RequestID string
	Result    Result
	From      *time.Time
	To        *time.Time
	Limit     int
	AfterID   string
}

type QueryResult struct {
	Events  []Event
	HasMore bool
	NextID  string
}

type Store interface {
	CreatePending(event Event) error
	Finalize(requestID string, finalization Finalization) (*Event, error)
	AppendTerminal(event Event) (*Event, error)
	GetByID(id string) (*Event, error)
	GetByRequestID(requestID string) (*Event, error)
	ListTerminal(limit int) ([]Event, error)
	Query(ctx context.Context, options QueryOptions) (QueryResult, error)
	RecoverPending() (int, error)
}

func NormalizeQueryOptions(options QueryOptions) (QueryOptions, error) {
	if options.Limit < 1 || options.Limit > MaxQueryLimit {
		return QueryOptions{}, invalidQueryField("limit")
	}
	if options.Actor != "" && !validOptionalText(options.Actor, MaxUsernameBytes) {
		return QueryOptions{}, invalidQueryField("actor")
	}
	if !validReference(options.TokenRef) {
		return QueryOptions{}, invalidQueryField("tokenRef")
	}
	if !validReference(options.ShareRef) {
		return QueryOptions{}, invalidQueryField("shareRef")
	}
	if options.Action != "" && !validAction(options.Action) {
		return QueryOptions{}, invalidQueryField("action")
	}
	if !validSource(options.Source) {
		return QueryOptions{}, invalidQueryField("source")
	}
	if options.Path != "" {
		if !validAuditPath(options.Path) {
			return QueryOptions{}, invalidQueryField("path")
		}
		options.Path = pathpkg.Clean(options.Path)
	}
	if options.RequestID != "" {
		if err := ValidateRequestID(options.RequestID); err != nil {
			return QueryOptions{}, invalidQueryField("requestId")
		}
	}
	if options.Result != "" && !validResult(options.Result) {
		return QueryOptions{}, invalidQueryField("result")
	}
	if options.AfterID != "" {
		if err := ValidateEventID(options.AfterID); err != nil {
			return QueryOptions{}, invalidQueryField("cursor event")
		}
	}
	if options.From != nil {
		value := options.From.UTC()
		options.From = &value
	}
	if options.To != nil {
		value := options.To.UTC()
		options.To = &value
	}
	if options.From != nil && options.To != nil && options.From.After(*options.To) {
		return QueryOptions{}, invalidQueryField("time range")
	}
	return options, nil
}

func invalidQueryField(field string) error {
	return fmt.Errorf("%w: invalid %s", ErrInvalidQuery, field)
}

// MergeMetadataV1 keeps safe reservation metadata and applies terminal values that were provided.
func MergeMetadataV1(base, updates *MetadataV1) *MetadataV1 {
	if base == nil && updates == nil {
		return nil
	}
	merged := MetadataV1{SchemaVersion: CurrentMetadataSchemaVersion}
	if base != nil {
		merged = cloneMetadataV1(*base)
	}
	if updates == nil {
		return &merged
	}
	if updates.SchemaVersion != 0 {
		merged.SchemaVersion = updates.SchemaVersion
	}
	setInt64 := func(destination **int64, value *int64) {
		if value != nil {
			*destination = value
		}
	}
	setBool := func(destination **bool, value *bool) {
		if value != nil {
			*destination = value
		}
	}
	setInt64(&merged.DurationMs, updates.DurationMs)
	setInt64(&merged.Bytes, updates.Bytes)
	setInt64(&merged.RangeStart, updates.RangeStart)
	setInt64(&merged.RangeEnd, updates.RangeEnd)
	setBool(&merged.Overwrite, updates.Overwrite)
	if updates.Method != "" {
		merged.Method = updates.Method
	}
	if updates.ChangedFields != nil {
		merged.ChangedFields = append([]ChangedField(nil), updates.ChangedFields...)
	}
	setInt64(&merged.ItemCount, updates.ItemCount)
	setInt64(&merged.SuccessCount, updates.SuccessCount)
	setInt64(&merged.FailedCount, updates.FailedCount)
	setInt64(&merged.DeniedCount, updates.DeniedCount)
	setBool(&merged.ClientCancelled, updates.ClientCancelled)
	if updates.OnlyOfficeStatus != nil {
		merged.OnlyOfficeStatus = updates.OnlyOfficeStatus
	}
	return &merged
}

func cloneMetadataV1(metadata MetadataV1) MetadataV1 {
	metadata.ChangedFields = append([]ChangedField(nil), metadata.ChangedFields...)
	return metadata
}
