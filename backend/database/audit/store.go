package audit

import "errors"

const ProcessInterruptedErrorCode = "process_interrupted"

var (
	ErrEventNotFound   = errors.New("audit event not found")
	ErrPendingNotFound = errors.New("audit pending event not found")
	ErrRequestIDExists = errors.New("audit request ID already exists")
	ErrInvalidLimit    = errors.New("invalid audit list limit")
)

type Store interface {
	CreatePending(event Event) error
	Finalize(requestID string, finalization Finalization) (*Event, error)
	AppendTerminal(event Event) (*Event, error)
	GetByID(id string) (*Event, error)
	GetByRequestID(requestID string) (*Event, error)
	ListTerminal(limit int) ([]Event, error)
	RecoverPending() (int, error)
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
