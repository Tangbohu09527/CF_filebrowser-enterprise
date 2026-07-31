package audit

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func intPointer(value int) *int {
	return &value
}

func int64Pointer(value int64) *int64 {
	return &value
}

func boolPointer(value bool) *bool {
	return &value
}

func validTerminalEvent() Event {
	return Event{
		SchemaVersion: CurrentSchemaVersion,
		TimestampUTC:  time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC),
		RequestID:     "018f2b4a-7f2e-7f3b-9e5f-123456789abc",
		Username:      "audit-user",
		AuthMethod:    AuthMethodSession,
		ClientIP:      "192.0.2.10",
		Action:        ActionFileDownload,
		Origin:        OriginHTTP,
		Source:        "primary",
		Path:          "/reports/quarterly.pdf",
		CanonicalPath: "/reports/quarterly.pdf",
		EffectivePermissions: &Permissions{
			Browse:   true,
			Preview:  true,
			Download: true,
		},
		Result:     ResultSuccess,
		HTTPStatus: intPointer(200),
		Metadata: &MetadataV1{
			SchemaVersion: CurrentMetadataSchemaVersion,
			DurationMs:    int64Pointer(0),
			Bytes:         int64Pointer(0),
			Overwrite:     boolPointer(false),
			Method:        MethodGET,
		},
	}
}

func TestEventValidationAcceptsValidTerminalEvent(t *testing.T) {
	event := validTerminalEvent()
	if err := event.Validate(); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}
	if event.EffectivePermissions == nil || event.EffectivePermissions.Create {
		t.Fatal("explicit all-false permissions must remain distinguishable from omitted permissions")
	}
	if event.HTTPStatus == nil || *event.HTTPStatus != 200 {
		t.Fatal("HTTP status pointer must preserve an explicit value")
	}
}

func TestEventValidationRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Event)
	}{
		{name: "schema", mutate: func(event *Event) { event.SchemaVersion++ }},
		{name: "request ID format", mutate: func(event *Event) { event.RequestID = "contains whitespace" }},
		{name: "request ID length", mutate: func(event *Event) { event.RequestID = strings.Repeat("a", MaxRequestIDBytes+1) }},
		{name: "username length", mutate: func(event *Event) { event.Username = strings.Repeat("u", MaxUsernameBytes+1) }},
		{name: "auth method", mutate: func(event *Event) { event.AuthMethod = AuthMethod("bearer") }},
		{name: "origin", mutate: func(event *Event) { event.Origin = Origin("browser") }},
		{name: "action", mutate: func(event *Event) { event.Action = Action("file.execute") }},
		{name: "result", mutate: func(event *Event) { event.Result = Result("maybe") }},
		{name: "client IP", mutate: func(event *Event) { event.ClientIP = "192.0.2.10:443" }},
		{name: "token reference", mutate: func(event *Event) { event.TokenRef = "ABCDEF" }},
		{name: "share reference", mutate: func(event *Event) { event.ShareRef = strings.Repeat("a", 31) }},
		{name: "source host path", mutate: func(event *Event) { event.Source = `C:\data\private` }},
		{name: "source length", mutate: func(event *Event) { event.Source = strings.Repeat("s", MaxSourceBytes+1) }},
		{name: "path length", mutate: func(event *Event) { event.Path = "/" + strings.Repeat("p", MaxPathBytes) }},
		{name: "host filesystem path", mutate: func(event *Event) { event.Path = `C:\data\private.txt` }},
		{name: "relative path", mutate: func(event *Event) { event.Path = "reports/private.txt" }},
		{name: "raw URL path", mutate: func(event *Event) { event.Path = "https://example.test/file?token=secret" }},
		{name: "status", mutate: func(event *Event) { event.HTTPStatus = intPointer(700) }},
		{name: "error code", mutate: func(event *Event) { event.ErrorCode = "Raw Error Text!" }},
		{name: "non UTC timestamp", mutate: func(event *Event) {
			event.TimestampUTC = event.TimestampUTC.In(time.FixedZone("offset", 3600))
		}},
		{name: "timestamp outside sortable key range", mutate: func(event *Event) {
			event.TimestampUTC = time.Date(2300, 1, 1, 0, 0, 0, 0, time.UTC)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := validTerminalEvent()
			test.mutate(&event)
			if err := event.Validate(); !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("expected ErrInvalidEvent, got %v", err)
			}
		})
	}
}

func TestMetadataValidation(t *testing.T) {
	negative := int64(-1)
	invalidCount := validTerminalEvent()
	invalidCount.Metadata.ItemCount = &negative
	if err := invalidCount.Validate(); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("negative count: got %v", err)
	}

	const maxInt64 = int64(9223372036854775807)
	overflowCounts := validTerminalEvent()
	overflowCounts.Metadata.ItemCount = int64Pointer(maxInt64)
	overflowCounts.Metadata.SuccessCount = int64Pointer(maxInt64)
	overflowCounts.Metadata.FailedCount = int64Pointer(maxInt64)
	if err := overflowCounts.Validate(); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("overflowing aggregate counts: got %v", err)
	}

	invalidMethod := validTerminalEvent()
	invalidMethod.Metadata.Method = Method("GET /private?token=secret")
	if err := invalidMethod.Validate(); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("invalid method: got %v", err)
	}

	invalidChangedField := validTerminalEvent()
	invalidChangedField.Metadata.ChangedFields = []ChangedField{"authorization"}
	if err := invalidChangedField.Validate(); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("invalid changed field: got %v", err)
	}

	tooManyFields := validTerminalEvent()
	tooManyFields.Metadata.ChangedFields = make([]ChangedField, MaxChangedFields+1)
	for index := range tooManyFields.Metadata.ChangedFields {
		tooManyFields.Metadata.ChangedFields[index] = ChangedFieldCreatorCapabilities
	}
	if err := tooManyFields.Validate(); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("changed field limit: got %v", err)
	}

	tooLarge := validTerminalEvent()
	tooLarge.Metadata.ChangedFields = make([]ChangedField, MaxChangedFields)
	for index := range tooLarge.Metadata.ChangedFields {
		tooLarge.Metadata.ChangedFields[index] = ChangedFieldCreatorCapabilities
	}
	if err := tooLarge.Validate(); !errors.Is(err, ErrMetadataTooLarge) {
		t.Fatalf("metadata size limit: got %v", err)
	}
}

func TestMetadataRejectsArbitraryJSONAndMapFields(t *testing.T) {
	var metadata MetadataV1
	err := json.Unmarshal([]byte(`{"schemaVersion":1,"authorization":"Bearer obvious-secret"}`), &metadata)
	if err == nil {
		t.Fatal("typed metadata must reject arbitrary JSON properties")
	}

	metadataType := reflect.TypeOf(MetadataV1{})
	for index := 0; index < metadataType.NumField(); index++ {
		field := metadataType.Field(index)
		if field.Type.Kind() == reflect.Map || field.Type.Kind() == reflect.Interface {
			t.Fatalf("metadata field %s permits arbitrary values", field.Name)
		}
	}
}

func TestEventRejectsArbitraryJSON(t *testing.T) {
	data, err := json.Marshal(validTerminalEvent())
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	data = append(data[:len(data)-1], []byte(`,"cookie":"obvious-secret"}`)...)
	var event Event
	if err := json.Unmarshal(data, &event); err == nil {
		t.Fatal("event must reject arbitrary JSON properties")
	}
}

func TestEventSerializedSizeLimit(t *testing.T) {
	event := validTerminalEvent()
	longPath := "/" + strings.Repeat("x", MaxPathBytes-1)
	event.Path = longPath
	event.CanonicalPath = longPath
	event.TargetPath = longPath
	event.TargetCanonicalPath = longPath
	if err := event.Validate(); !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("event size limit: got %v", err)
	}
}

func TestPendingValidation(t *testing.T) {
	pending := validTerminalEvent()
	pending.TimestampUTC = time.Time{}
	pending.Result = ""
	pending.HTTPStatus = nil
	pending.ErrorCode = ""
	if err := pending.ValidatePending(); err != nil {
		t.Fatalf("valid pending event rejected: %v", err)
	}

	pending.Result = ResultSuccess
	if err := pending.ValidatePending(); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("terminal result accepted in pending event: %v", err)
	}
}

func TestOptionalZeroValueFieldsSurviveJSONRoundTrip(t *testing.T) {
	event := validTerminalEvent()
	event.HTTPStatus = nil
	event.EffectivePermissions = &Permissions{}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	var decoded Event
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if decoded.HTTPStatus != nil {
		t.Fatal("non-HTTP status did not remain omitted")
	}
	if decoded.EffectivePermissions == nil {
		t.Fatal("explicit all-false permissions became omitted")
	}
	if decoded.Metadata == nil || decoded.Metadata.Bytes == nil || *decoded.Metadata.Bytes != 0 ||
		decoded.Metadata.Overwrite == nil || *decoded.Metadata.Overwrite {
		t.Fatal("explicit metadata zero values did not survive JSON round trip")
	}
}
