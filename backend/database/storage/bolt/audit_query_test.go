package bolt

import (
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	bbolt "go.etcd.io/bbolt"
)

func TestAuditQueryFiltersAndOrder(t *testing.T) {
	db, queryStore := openAuditTestDB(t, filepath.Join(t.TempDir(), "audit-query.db"))
	defer closeAuditTestDB(t, db)

	base := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	tokenA := auditdb.DeriveTokenRef("query-token-a")
	tokenB := auditdb.DeriveTokenRef("query-token-b")
	shareA := auditdb.DeriveShareRef("query-share-a")
	shareB := auditdb.DeriveShareRef("query-share-b")

	events := []auditdb.Event{
		queryAuditEvent("query-request-0", base, "alice", auditdb.ActionFileBrowse, tokenA, shareA, "primary", "/a/b", auditdb.ResultSuccess),
		queryAuditEvent("query-request-1", base.Add(time.Minute), "alice", auditdb.ActionFileDownload, tokenA, shareB, "primary", "/a/b/c", auditdb.ResultFailed),
		queryAuditEvent("query-request-2", base.Add(2*time.Minute), "bob", auditdb.ActionFileDownload, tokenB, shareA, "primary", "/a/b2", auditdb.ResultDenied),
		queryAuditEvent("query-request-3", base.Add(3*time.Minute), "alice", auditdb.ActionShareAccess, tokenB, shareB, "archive", "/a/b/d", auditdb.ResultSuccess),
		queryAuditEvent("query-request-4", base.Add(4*time.Minute), "carol", auditdb.ActionFileBrowse, tokenA, shareA, "archive", "/z", auditdb.ResultCancelled),
	}
	for index := range events {
		stored, err := queryStore.AppendTerminal(events[index])
		if err != nil {
			t.Fatalf("append event %d: %v", index, err)
		}
		events[index] = *stored
	}

	tests := []struct {
		name    string
		options auditdb.QueryOptions
		want    []string
	}{
		{
			name:    "no filter descending",
			options: auditdb.QueryOptions{Limit: 10},
			want:    []string{"query-request-4", "query-request-3", "query-request-2", "query-request-1", "query-request-0"},
		},
		{
			name: "half open time range",
			options: auditdb.QueryOptions{
				From:  auditTimePointer(base.Add(time.Minute)),
				To:    auditTimePointer(base.Add(4 * time.Minute)),
				Limit: 10,
			},
			want: []string{"query-request-3", "query-request-2", "query-request-1"},
		},
		{
			name:    "actor username",
			options: auditdb.QueryOptions{Actor: "alice", Limit: 10},
			want:    []string{"query-request-3", "query-request-1", "query-request-0"},
		},
		{
			name:    "action",
			options: auditdb.QueryOptions{Action: auditdb.ActionFileDownload, Limit: 10},
			want:    []string{"query-request-2", "query-request-1"},
		},
		{
			name:    "token ref",
			options: auditdb.QueryOptions{TokenRef: tokenA, Limit: 10},
			want:    []string{"query-request-4", "query-request-1", "query-request-0"},
		},
		{
			name:    "share ref",
			options: auditdb.QueryOptions{ShareRef: shareB, Limit: 10},
			want:    []string{"query-request-3", "query-request-1"},
		},
		{
			name:    "source",
			options: auditdb.QueryOptions{Source: "archive", Limit: 10},
			want:    []string{"query-request-4", "query-request-3"},
		},
		{
			name:    "result",
			options: auditdb.QueryOptions{Result: auditdb.ResultSuccess, Limit: 10},
			want:    []string{"query-request-3", "query-request-0"},
		},
		{
			name:    "request ID direct lookup",
			options: auditdb.QueryOptions{RequestID: "query-request-2", Limit: 10},
			want:    []string{"query-request-2"},
		},
		{
			name:    "canonical path segment prefix",
			options: auditdb.QueryOptions{Path: "/a/b/", Limit: 10},
			want:    []string{"query-request-3", "query-request-1", "query-request-0"},
		},
		{
			name: "filters combine with AND",
			options: auditdb.QueryOptions{
				Actor: "alice", Source: "primary", Result: auditdb.ResultFailed, Path: "/a/b", Limit: 10,
			},
			want: []string{"query-request-1"},
		},
		{
			name:    "empty result",
			options: auditdb.QueryOptions{Actor: "missing", Limit: 10},
			want:    []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := queryStore.Query(context.Background(), test.options)
			if err != nil {
				t.Fatalf("query audit events: %v", err)
			}
			assertAuditQueryRequestIDs(t, result.Events, test.want)
			if result.HasMore || result.NextID != "" {
				t.Fatalf("unexpected continuation: hasMore=%v nextID=%q", result.HasMore, result.NextID)
			}
		})
	}
}

func TestAuditQueryLimitAndStableSameTimestampOrder(t *testing.T) {
	db, queryStore := openAuditTestDB(t, filepath.Join(t.TempDir(), "audit-query-order.db"))
	defer closeAuditTestDB(t, db)

	timestamp := time.Date(2026, 7, 31, 11, 0, 0, 99, time.UTC)
	stored := make([]auditdb.Event, 3)
	for index, requestID := range []string{"query-order-first", "query-order-second", "query-order-third"} {
		event, err := queryStore.AppendTerminal(queryAuditEvent(
			requestID,
			timestamp,
			"alice",
			auditdb.ActionFileBrowse,
			auditdb.DeriveTokenRef("query-order-token"),
			auditdb.DeriveShareRef("query-order-share"),
			"primary",
			"/same-time",
			auditdb.ResultSuccess,
		))
		if err != nil {
			t.Fatalf("append event %d: %v", index, err)
		}
		stored[index] = *event
	}

	result, err := queryStore.Query(context.Background(), auditdb.QueryOptions{Limit: 2})
	if err != nil {
		t.Fatalf("query limited events: %v", err)
	}
	assertAuditQueryRequestIDs(t, result.Events, []string{"query-order-third", "query-order-second"})
	if !result.HasMore || result.NextID != stored[1].ID {
		t.Fatalf("continuation: got hasMore=%v nextID=%q, want true/%q", result.HasMore, result.NextID, stored[1].ID)
	}

	next, err := queryStore.Query(context.Background(), auditdb.QueryOptions{Limit: 2, AfterID: result.NextID})
	if err != nil {
		t.Fatalf("query next events: %v", err)
	}
	assertAuditQueryRequestIDs(t, next.Events, []string{"query-order-first"})
	if next.HasMore || next.NextID != "" {
		t.Fatalf("unexpected final continuation: hasMore=%v nextID=%q", next.HasMore, next.NextID)
	}

	if _, err := queryStore.Query(context.Background(), auditdb.QueryOptions{Limit: auditdb.MaxQueryLimit}); err != nil {
		t.Fatalf("maximum limit was rejected: %v", err)
	}
	if _, err := queryStore.Query(context.Background(), auditdb.QueryOptions{Limit: auditdb.MaxQueryLimit + 1}); !errors.Is(err, auditdb.ErrInvalidQuery) {
		t.Fatalf("over-maximum limit: got %v, want ErrInvalidQuery", err)
	}
}

func TestAuditQueryPathOnlyScanIsBoundedAndResumable(t *testing.T) {
	db, queryStore := openAuditTestDB(t, filepath.Join(t.TempDir(), "audit-query-scan.db"))
	defer closeAuditTestDB(t, db)
	queryStore.queryScanLimit = 2

	base := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	paths := []string{"/wanted", "/other/one", "/other/two"}
	for index, eventPath := range paths {
		_, err := queryStore.AppendTerminal(queryAuditEvent(
			[]string{"query-scan-oldest", "query-scan-middle", "query-scan-newest"}[index],
			base.Add(time.Duration(index)*time.Minute),
			"alice",
			auditdb.ActionFileBrowse,
			auditdb.DeriveTokenRef("query-scan-token"),
			auditdb.DeriveShareRef("query-scan-share"),
			"primary",
			eventPath,
			auditdb.ResultSuccess,
		))
		if err != nil {
			t.Fatalf("append event %d: %v", index, err)
		}
	}

	first, err := queryStore.Query(context.Background(), auditdb.QueryOptions{Path: "/wanted", Limit: 10})
	if err != nil {
		t.Fatalf("query first bounded scan: %v", err)
	}
	if len(first.Events) != 0 || !first.HasMore || first.NextID == "" {
		t.Fatalf("first bounded scan: events=%d hasMore=%v nextID=%q", len(first.Events), first.HasMore, first.NextID)
	}

	second, err := queryStore.Query(context.Background(), auditdb.QueryOptions{
		Path: "/wanted", Limit: 10, AfterID: first.NextID,
	})
	if err != nil {
		t.Fatalf("query resumed bounded scan: %v", err)
	}
	assertAuditQueryRequestIDs(t, second.Events, []string{"query-scan-oldest"})
	if second.HasMore || second.NextID != "" {
		t.Fatalf("unexpected resumed continuation: hasMore=%v nextID=%q", second.HasMore, second.NextID)
	}
}

func TestAuditQueryActorIncludesLegacyUserIDOnlyIndex(t *testing.T) {
	db, queryStore := openAuditTestDB(t, filepath.Join(t.TempDir(), "audit-query-legacy-actor.db"))
	defer closeAuditTestDB(t, db)

	event, err := queryStore.AppendTerminal(queryAuditEvent(
		"query-legacy-actor",
		time.Date(2026, 7, 31, 13, 0, 0, 0, time.UTC),
		"alice",
		auditdb.ActionFileBrowse,
		auditdb.DeriveTokenRef("query-legacy-actor-token"),
		auditdb.DeriveShareRef("query-legacy-actor-share"),
		"primary",
		"/legacy-actor",
		auditdb.ResultSuccess,
	))
	if err != nil {
		t.Fatalf("append legacy actor event: %v", err)
	}
	removeAuditUsernameIndex(t, queryStore, *event)

	result, err := queryStore.Query(context.Background(), auditdb.QueryOptions{Actor: "alice", Limit: 10})
	if err != nil {
		t.Fatalf("query legacy actor event: %v", err)
	}
	assertAuditQueryRequestIDs(t, result.Events, []string{"query-legacy-actor"})
	if result.HasMore || result.NextID != "" {
		t.Fatalf("unexpected continuation: hasMore=%v nextID=%q", result.HasMore, result.NextID)
	}
}

func TestAuditQueryActorDoesNotConfuseNumericUsernameAndUserID(t *testing.T) {
	db, queryStore := openAuditTestDB(t, filepath.Join(t.TempDir(), "audit-query-numeric-actor.db"))
	defer closeAuditTestDB(t, db)

	_, err := queryStore.AppendTerminal(queryAuditEvent(
		"query-user-id-42",
		time.Date(2026, 7, 31, 14, 0, 0, 0, time.UTC),
		"alice",
		auditdb.ActionFileBrowse,
		auditdb.DeriveTokenRef("query-user-id-token"),
		auditdb.DeriveShareRef("query-user-id-share"),
		"primary",
		"/user-id",
		auditdb.ResultSuccess,
	))
	if err != nil {
		t.Fatalf("append numeric user ID event: %v", err)
	}

	numericUsername := queryAuditEvent(
		"query-username-42",
		time.Date(2026, 7, 31, 14, 1, 0, 0, time.UTC),
		"42",
		auditdb.ActionFileBrowse,
		auditdb.DeriveTokenRef("query-numeric-username-token"),
		auditdb.DeriveShareRef("query-numeric-username-share"),
		"primary",
		"/numeric-username",
		auditdb.ResultSuccess,
	)
	numericUsername.UserID = nil
	if _, err := queryStore.AppendTerminal(numericUsername); err != nil {
		t.Fatalf("append numeric username event: %v", err)
	}

	result, err := queryStore.Query(context.Background(), auditdb.QueryOptions{Actor: "42", Limit: 10})
	if err != nil {
		t.Fatalf("query numeric username: %v", err)
	}
	assertAuditQueryRequestIDs(t, result.Events, []string{"query-username-42"})
}

func TestAuditQueryActorMixedLegacyAndNewPaginationIsBounded(t *testing.T) {
	db, queryStore := openAuditTestDB(t, filepath.Join(t.TempDir(), "audit-query-mixed-actor.db"))
	defer closeAuditTestDB(t, db)
	queryStore.queryScanLimit = 2

	base := time.Date(2026, 7, 31, 15, 0, 0, 0, time.UTC)
	actors := []string{"alice", "bob", "alice", "bob", "alice", "bob", "alice"}
	for index, actor := range actors {
		requestID := "query-mixed-actor-" + strconv.Itoa(index)
		stored, err := queryStore.AppendTerminal(queryAuditEvent(
			requestID,
			base.Add(time.Duration(index)*time.Minute),
			actor,
			auditdb.ActionFileBrowse,
			auditdb.DeriveTokenRef("query-mixed-actor-token"),
			auditdb.DeriveShareRef("query-mixed-actor-share"),
			"primary",
			"/mixed-actor/"+strconv.Itoa(index),
			auditdb.ResultSuccess,
		))
		if err != nil {
			t.Fatalf("append mixed actor event %d: %v", index, err)
		}
		if actor == "alice" && (index == 0 || index == 4) {
			removeAuditUsernameIndex(t, queryStore, *stored)
		}
	}

	got := make([]string, 0, 4)
	seenIDs := make(map[string]struct{}, 4)
	seenCursors := make(map[string]struct{})
	afterID := ""
	continuations := 0
	completed := false
	for page := 0; page < 10; page++ {
		result, err := queryStore.Query(context.Background(), auditdb.QueryOptions{
			Actor: "alice", Limit: 2, AfterID: afterID,
		})
		if err != nil {
			t.Fatalf("query mixed actor page %d: %v", page, err)
		}
		if len(result.Events) > 1 {
			t.Fatalf("page %d scanned past the bounded primary window: %+v", page, result.Events)
		}
		for _, event := range result.Events {
			if _, exists := seenIDs[event.ID]; exists {
				t.Fatalf("duplicate event %q on page %d", event.RequestID, page)
			}
			seenIDs[event.ID] = struct{}{}
			got = append(got, event.RequestID)
		}
		if !result.HasMore {
			if result.NextID != "" {
				t.Fatalf("final page returned next ID %q", result.NextID)
			}
			completed = true
			break
		}
		if result.NextID == "" {
			t.Fatalf("page %d reported more results without a next ID", page)
		}
		if _, exists := seenCursors[result.NextID]; exists {
			t.Fatalf("page %d repeated next ID %q", page, result.NextID)
		}
		seenCursors[result.NextID] = struct{}{}
		afterID = result.NextID
		continuations++
	}
	if !completed {
		t.Fatal("mixed actor pagination did not terminate")
	}
	want := []string{"query-mixed-actor-6", "query-mixed-actor-4", "query-mixed-actor-2", "query-mixed-actor-0"}
	if len(got) != len(want) {
		t.Fatalf("mixed actor result count: got %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("mixed actor result %d: got %q, want %q", index, got[index], want[index])
		}
	}
	if continuations != 3 {
		t.Fatalf("bounded continuation count: got %d, want 3", continuations)
	}
}

func removeAuditUsernameIndex(t *testing.T, store *auditBoltStore, event auditdb.Event) {
	t.Helper()
	if event.UserID == nil || event.Username == "" {
		t.Fatal("legacy actor simulation requires both user ID and username")
	}
	eventKey, err := hex.DecodeString(event.ID)
	if err != nil {
		t.Fatalf("decode audit event ID: %v", err)
	}
	userValue := "user:" + strconv.FormatUint(uint64(*event.UserID), 10)
	usernameValue := "username:" + event.Username
	err = store.db.Bolt.Update(func(tx *bbolt.Tx) error {
		actors := tx.Bucket(auditIndexActorBucket)
		if actors == nil {
			return errors.New("missing audit actor index")
		}
		userKey := auditSecondaryIndexKey(userValue, eventKey)
		if actors.Get(userKey) == nil {
			return errors.New("missing legacy user ID actor index entry")
		}
		usernameKey := auditSecondaryIndexKey(usernameValue, eventKey)
		if actors.Get(usernameKey) == nil {
			return errors.New("missing username actor index entry")
		}
		if err := actors.Delete(usernameKey); err != nil {
			return err
		}
		if actors.Get(usernameKey) != nil {
			return errors.New("username actor index entry was not removed")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("simulate legacy actor index: %v", err)
	}
}

func queryAuditEvent(
	requestID string,
	timestamp time.Time,
	username string,
	action auditdb.Action,
	tokenRef string,
	shareRef string,
	source string,
	canonicalPath string,
	result auditdb.Result,
) auditdb.Event {
	event := terminalAuditEvent(requestID, timestamp)
	event.Username = username
	event.Action = action
	event.TokenRef = tokenRef
	event.ShareRef = shareRef
	event.Source = source
	event.Path = canonicalPath
	event.CanonicalPath = canonicalPath
	event.Result = result
	return event
}

func auditTimePointer(value time.Time) *time.Time {
	return &value
}

func assertAuditQueryRequestIDs(t *testing.T, events []auditdb.Event, want []string) {
	t.Helper()
	if len(events) != len(want) {
		t.Fatalf("event count: got %d, want %d (%+v)", len(events), len(want), events)
	}
	for index := range want {
		if events[index].RequestID != want[index] {
			t.Fatalf("event %d request ID: got %q, want %q", index, events[index].RequestID, want[index])
		}
	}
}
