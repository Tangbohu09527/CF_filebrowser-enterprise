package trash

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRetentionProtectsExistingFilesAndPersistsAcrossOpen(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	policy, err := store.RetentionPolicy()
	if err != nil || policy.Enabled || policy.Days != 30 || policy.EnabledAt != nil {
		t.Fatalf("new Source default: %+v, %v", policy, err)
	}
	if _, err := store.SetRetentionPolicy(true, MaxRetentionDays+1, time.Now()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted invalid duration: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "large.txt"), bytes.Repeat([]byte("0123456789"), 1<<19), 0600); err != nil {
		t.Fatal(err)
	}
	item, err := store.Trash(Item{OperationID: "retention-old-file", OriginalPath: "large.txt", Source: "data"})
	if err != nil {
		t.Fatal(err)
	}
	enabledAt := item.CreatedAt.AddDate(0, 0, 10)
	policy, err = store.SetRetentionPolicy(true, 30, enabledAt)
	if err != nil || policy.EnabledAt == nil || !policy.EnabledAt.Equal(enabledAt) {
		t.Fatalf("first enablement: %+v, %v", policy, err)
	}
	updateAt := enabledAt.AddDate(0, 0, 5)
	policy, err = store.SetRetentionPolicy(true, 40, updateAt)
	if err != nil || policy.EnabledAt == nil || !policy.EnabledAt.Equal(enabledAt) {
		t.Fatalf("duration edit changed initial grace period: %+v, %v", policy, err)
	}
	deadline := enabledAt.AddDate(0, 0, 40)
	if got := policy.Deadline(item); got == nil || !got.Equal(deadline) {
		t.Fatalf("old file deadline: %v, want %v", got, deadline)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.txt"), []byte("synthetic newer payload"), 0600); err != nil {
		t.Fatal(err)
	}
	newer, err := store.Trash(Item{OperationID: "retention-new-file", OriginalPath: "new.txt", Source: "data"})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a new file moved later, without sleeping or altering system time.
	newer.CreatedAt = enabledAt.AddDate(0, 0, 1)
	if err = store.save(newer); err != nil {
		t.Fatal(err)
	}
	if got := policy.Deadline(newer); got == nil || !got.Equal(newer.CreatedAt.AddDate(0, 0, 40)) {
		t.Fatalf("new file deadline: %v, want expiry from recycle time", got)
	}
	got, err := store.PurgeExpired(item.OperationID, deadline.Add(-time.Second))
	if err != nil || got.State != "trashed" {
		t.Fatalf("file was eligible too early: %+v, %v", got, err)
	}
	before, err := store.OccupiedBytes(item)
	if err != nil || before != item.Size || before == 0 {
		t.Fatalf("incorrect initial payload bytes: %d, %v", before, err)
	}
	if _, err = store.SetRetentionPolicy(false, 40, updateAt); err != nil {
		t.Fatal(err)
	}
	got, err = store.PurgeExpired(item.OperationID, deadline)
	if err != nil || got.State != "trashed" {
		t.Fatalf("file was eligible while disabled: %+v, %v", got, err)
	}
	if _, err = store.SetRetentionPolicy(true, 40, updateAt); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err = store.PurgeExpired(item.OperationID, deadline)
	if err != nil || got.State != "purged" || got.PurgeMethod != PurgeAutomatic || got.PurgedAt == nil {
		t.Fatalf("automatic purge after reopen: %+v, %v", got, err)
	}
	if after, err := store.OccupiedBytes(got); err != nil || after != 0 {
		t.Fatalf("expired payload still occupies space: %d, %v", after, err)
	}
	newer, err = store.PurgeExpired(newer.OperationID, deadline)
	if err != nil || newer.State != "trashed" {
		t.Fatalf("newer file was eligible too early: %+v, %v", newer, err)
	}
}

func TestPermanentRemovalRetainsAuditAndProtectsReplacement(t *testing.T) {
	dir, store := fixture(t)
	item := mustTrash(t, store)
	_, otherStore := fixture(t)
	otherItem := mustTrash(t, otherStore)
	originalPath := filepath.Join(dir, filepath.FromSlash(item.OriginalPath))
	if err := os.WriteFile(originalPath, []byte("same-name replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	attemptID := "restore-original-occupied"
	if _, err := store.Restore(item.OperationID, attemptID, item.OriginalPath, 7, "ordinary-user"); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected occupied restore target: %v", err)
	}
	got, err := store.Purge(item.OperationID, 12, "first-admin", PurgeManual)
	if err != nil || got.State != "purged" || got.PurgeActor != "first-admin" || got.PurgeActorID != 12 || got.PurgeMethod != PurgeManual || got.PurgedAt == nil {
		t.Fatalf("incorrect manual purge: %+v, %v", got, err)
	}
	previous := *got.PurgedAt
	got, err = store.Purge(item.OperationID, 17, "second-admin", PurgeManual)
	if err != nil || !got.PurgedAt.Equal(previous) || got.PurgeActor != "first-admin" {
		t.Fatalf("retry changed outcome or audit: %+v, %v", got, err)
	}
	if _, err = store.Restore(item.OperationID, "cannot-restore-purged", "files/new.txt", 7, "ordinary-user"); !errors.Is(err, ErrConflict) {
		t.Fatalf("purged file was restorable: %v", err)
	}
	history, err := store.GetRestoreAttempt(item.OperationID, attemptID)
	if err != nil || history.State != "failed" || history.ErrorCode != "target_exists" {
		t.Fatalf("prior restore audit was changed: %+v, %v", history, err)
	}
	if data, err := os.ReadFile(originalPath); err != nil || string(data) != "same-name replacement" {
		t.Fatalf("same-name file was changed: %q, %v", data, err)
	}
	if size, err := otherStore.OccupiedBytes(otherItem); err != nil || size != otherItem.Size {
		t.Fatalf("another Source was affected: %d, %v", size, err)
	}
}

func TestPurgeReconciliationDoesNotReplayRemoval(t *testing.T) {
	for _, state := range []string{"pending_purge", "purged"} {
		t.Run(state, func(t *testing.T) {
			_, store := fixture(t)
			item := mustTrash(t, store)
			store.beforeSave = func(item *Item) error {
				if item.State == state {
					return errors.New("injected journal failure")
				}
				return nil
			}
			if _, err := store.Purge(item.OperationID, 7, "administrator", PurgeManual); !errors.Is(err, ErrUncertain) {
				t.Fatalf("failure arrived as confirmed outcome: %v", err)
			}
			store.beforeSave = nil
			got, err := store.Get(item.OperationID)
			if state == "pending_purge" {
				if err != nil || got.State != "trashed" {
					t.Fatalf("missing intent changed payload state: %+v, %v", got, err)
				}
				if size, err := store.OccupiedBytes(got); err != nil || size != item.Size {
					t.Fatalf("missing intent altered payload: %d, %v", size, err)
				}
				return
			}
			if err != nil || got.State != "purged" || got.PurgeActor != "administrator" || got.PurgedAt == nil {
				t.Fatalf("completed removal was not reconciled: %+v, %v", got, err)
			}
		})
	}
}

func TestInterruptedPurgeWithIntactPayloadCanBeRestored(t *testing.T) {
	_, store := fixture(t)
	item := mustTrash(t, store)
	item.State, item.PurgeActor, item.PurgeMethod = "pending_purge", "administrator", PurgeManual
	if err := store.save(item); err != nil {
		t.Fatal(err)
	}
	reconciled, err := store.Get(item.OperationID)
	if err != nil || reconciled.State != "trashed" || reconciled.PurgeMethod != "" {
		t.Fatalf("GET replayed a removal: %+v, %v", reconciled, err)
	}
	got, err := store.Restore(item.OperationID, "restore-while-purge-pending", item.OriginalPath, 7, "ordinary-user")
	if err != nil || got.State != "restored" {
		t.Fatalf("restore after uncommitted removal: %+v, %v", got, err)
	}
}

func TestPermanentRemovalRefusesChangedPayloadOfSameSize(t *testing.T) {
	dir, store := fixture(t)
	item := mustTrash(t, store)
	payload := filepath.Join(dir, filepath.FromSlash(contentPath(item.OperationID)))
	changed := bytes.Repeat([]byte("x"), int(item.Size))
	if err := os.WriteFile(payload, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Purge(item.OperationID, 7, "administrator", PurgeManual); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected integrity conflict: %v", err)
	}
	if data, err := os.ReadFile(payload); err != nil || !bytes.Equal(data, changed) {
		t.Fatalf("changed payload was removed: %q, %v", data, err)
	}
}

func TestPermanentRemovalAndRestoreSerializePerSource(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "files"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "files", "sample.txt"), []byte("synthetic payload"), 0600); err != nil {
		t.Fatal(err)
	}
	initial, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	item, err := initial.Trash(sampleItem())
	closeErr := initial.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("initial trash: %v, close: %v", err, closeErr)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var done sync.WaitGroup
	for _, restore := range []bool{false, true} {
		done.Add(1)
		go func() {
			defer done.Done()
			<-start
			view, err := Open(dir)
			if err != nil {
				results <- err
				return
			}
			defer view.Close()
			if restore {
				_, err = view.Restore(item.OperationID, "restore-race-attempt", item.OriginalPath, 7, "ordinary-user")
			} else {
				_, err = view.Purge(item.OperationID, 12, "administrator", PurgeManual)
			}
			results <- err
		}()
	}
	close(start)
	// Reopen only after both competing requests have released their locks.
	done.Wait()
	first, second := <-results, <-results
	if first == nil {
		first, second = second, first
	}
	if second != nil || !errors.Is(first, ErrConflict) {
		t.Fatalf("expected one successful operation and one conflict: %v, %v", first, second)
	}
	final, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer final.Close()
	got, err := final.Get(item.OperationID)
	if err != nil || (got.State != "restored" && got.State != "purged") {
		t.Fatalf("invalid terminal state: %+v, %v", got, err)
	}
}
