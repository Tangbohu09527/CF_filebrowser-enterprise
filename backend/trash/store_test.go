package trash

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func fixture(t *testing.T) (string, *Store) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "files"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "files", "sample.txt"), []byte("synthetic original bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s != nil {
			_ = s.Close()
		}
	})
	return dir, s
}

func sampleItem() Item {
	return Item{OperationID: "trash-operation-0001", Source: "data", OriginalPath: "files/sample.txt", ActorID: 7, Actor: "ordinary-user"}
}

func mustTrash(t *testing.T, s *Store) *Item {
	t.Helper()
	item, err := s.Trash(sampleItem())
	if err != nil || item.State != "trashed" {
		t.Fatalf("trash: %+v, %v", item, err)
	}
	return item
}

func TestLifecyclePersistenceIdempotencyAndNoOverwrite(t *testing.T) {
	dir, s := fixture(t)
	item := mustTrash(t, s)
	if item.Size != 24 || len(item.SHA256) != 64 || item.ActorID != 7 || item.CreatedAt.IsZero() {
		t.Fatalf("missing metadata: %+v", item)
	}
	if _, err := os.Stat(filepath.Join(dir, "files", "sample.txt")); !os.IsNotExist(err) {
		t.Fatalf("original still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".filebrowser-trash", item.OperationID, "record.json")); err != nil {
		t.Fatal(err)
	}
	again, err := s.Trash(sampleItem())
	if err != nil || again.SHA256 != item.SHA256 {
		t.Fatalf("replay: %+v %v", again, err)
	}
	changed := sampleItem()
	changed.OriginalPath = "files/different.txt"
	if _, err = s.Trash(changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("ID mismatch: %v", err)
	}
	if err = os.WriteFile(filepath.Join(dir, "files", "restored.txt"), []byte("new occupant"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Restore(item.OperationID, "restore-operation-0001", "files/restored.txt", 7, "ordinary-user"); !errors.Is(err, ErrConflict) {
		t.Fatalf("must not overwrite: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "files", "restored.txt"))
	if string(data) != "new occupant" {
		t.Fatal("overwritten occupant")
	}
	restored, err := s.Restore(item.OperationID, "restore-operation-0002", "files/sample.txt", 7, "ordinary-user")
	if err != nil || restored.State != "restored" {
		t.Fatalf("restore: %+v %v", restored, err)
	}
	data, _ = os.ReadFile(filepath.Join(dir, "files", "sample.txt"))
	if string(data) != "synthetic original bytes" {
		t.Fatal("wrong restored bytes")
	}
	again, err = s.Restore(item.OperationID, "restore-operation-0002", "files/sample.txt", 7, "ordinary-user")
	if err != nil || again.State != "restored" {
		t.Fatalf("restore replay: %+v %v", again, err)
	}
	if _, err = s.Restore(item.OperationID, "restore-operation-0002", "files/other.txt", 7, "ordinary-user"); !errors.Is(err, ErrConflict) {
		t.Fatalf("restore ID mismatch: %v", err)
	}
	// A replay after restoration must not remove a newly created original.
	if _, err = s.Trash(sampleItem()); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, "files", "sample.txt")); err != nil {
		t.Fatal("trash replay moved restored bytes")
	}
	loaded, err := s.Get(item.OperationID)
	if err != nil || loaded.SourceKey != dir || loaded.State != "restored" {
		t.Fatalf("disk reload: %+v %v", loaded, err)
	}
}

func TestMoveThenJournalFailureReconcilesWithoutReplay(t *testing.T) {
	for _, restoring := range []bool{false, true} {
		t.Run(map[bool]string{false: "trash", true: "restore"}[restoring], func(t *testing.T) {
			dir, s := fixture(t)
			if restoring {
				mustTrash(t, s)
			}
			s.beforeSave = func(item *Item) error {
				if (!restoring && item.State == "trashed") || (restoring && item.State == "restored") {
					return errors.New("injected journal I/O failure")
				}
				return nil
			}
			var err error
			if restoring {
				_, err = s.Restore(sampleItem().OperationID, "restore-journal-0001", "files/restored.txt", 7, "ordinary-user")
			} else {
				_, err = s.Trash(sampleItem())
			}
			if !errors.Is(err, ErrUncertain) {
				t.Fatalf("must report unknown: %v", err)
			}
			s.beforeSave = nil
			s.move = func(*os.Root, string, string) error { t.Fatal("Get must not replay move"); return nil }
			loaded, err := s.Get(sampleItem().OperationID)
			want := "trashed"
			if restoring {
				want = "restored"
			}
			if err != nil || loaded.State != want {
				t.Fatalf("reconciled: %+v %v", loaded, err)
			}
			if restoring {
				data, _ := os.ReadFile(filepath.Join(dir, "files", "restored.txt"))
				if string(data) != "synthetic original bytes" {
					t.Fatal("lost restore bytes")
				}
			}
		})
	}
}

func TestRejectedCrossDeviceMovePreservesOriginalAndJournal(t *testing.T) {
	dir, s := fixture(t)
	s.move = func(*os.Root, string, string) error { return syscall.EXDEV }
	item, err := s.Trash(sampleItem())
	if !errors.Is(err, syscall.EXDEV) || item == nil || item.State != "failed" {
		t.Fatalf("cross-device: %+v %v", item, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "files", "sample.txt"))
	if err != nil || string(data) != "synthetic original bytes" {
		t.Fatalf("original lost: %q %v", data, err)
	}
	loaded, err := s.Get(sampleItem().OperationID)
	if err != nil || loaded.ErrorCode != "move_rejected" {
		t.Fatalf("status unavailable: %+v %v", loaded, err)
	}
}

func TestPendingIntentAndIntegrityConflict(t *testing.T) {
	_, s := fixture(t)
	item := mustTrash(t, s)
	item.State = "pending_trash"
	if err := s.save(item); err != nil {
		t.Fatal(err)
	}
	f, err := s.root.OpenFile(contentPath(item.OperationID), os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteString("corrupt synthetic bytes"); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.Get(item.OperationID)
	if err != nil || loaded.State != "manual_reconciliation" {
		t.Fatalf("must retain uncertain data: %+v %v", loaded, err)
	}
	if _, err = s.Restore(item.OperationID, "restore-corrupt-0001", "files/restored.txt", 7, "ordinary-user"); !errors.Is(err, ErrConflict) {
		t.Fatalf("corrupt restore: %v", err)
	}
}

func TestIntentNotMovedAndRestoreIntentNotMoved(t *testing.T) {
	_, s := fixture(t)
	item := mustTrash(t, s)
	item.State = "pending_restore"
	item.RestoreOperationID = "restore-never-moved"
	item.RestoredPath = "files/restored.txt"
	if err := s.save(item); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.Get(item.OperationID)
	if err != nil || loaded.State != "trashed" || loaded.ErrorCode != "not_moved" {
		t.Fatalf("restore intent: %+v %v", loaded, err)
	}
	if _, err = s.Restore(item.OperationID, "restore-new-attempt", "files/restored.txt", 7, "ordinary-user"); err != nil {
		t.Fatal(err)
	}
}

func TestLargeFileRemainsOnSourceDataPath(t *testing.T) {
	dir, s := fixture(t)
	f, err := os.OpenFile(filepath.Join(dir, "files", "sample.txt"), os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(32 << 20); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	item := mustTrash(t, s)
	if item.Size != 32<<20 {
		t.Fatalf("wrong large file size: %d", item.Size)
	}
	info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(contentPath(item.OperationID))))
	if err != nil || info.Size() != 32<<20 {
		t.Fatalf("missing data-path payload: %v", err)
	}
}

func TestEveryRestoreIDRetainsHistoricalResultAcrossNewAttempts(t *testing.T) {
	dir, s := fixture(t)
	item := mustTrash(t, s)
	if err := os.WriteFile(filepath.Join(dir, "files", "sample.txt"), []byte("new occupant"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := s.Restore(item.OperationID, "restore-history-attempt-A", "files/sample.txt", 7, "ordinary-user")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected target conflict: %v", err)
	}
	a, err := s.GetRestoreAttempt(item.OperationID, "restore-history-attempt-A")
	if err != nil || a.State != "failed" || a.ErrorCode != "target_exists" {
		t.Fatalf("missing rejected intent: %+v %v", a, err)
	}
	if _, err = s.Restore(item.OperationID, "restore-history-attempt-B", "files/restored.txt", 7, "ordinary-user"); err != nil {
		t.Fatal(err)
	}
	a, err = s.GetRestoreAttempt(item.OperationID, "restore-history-attempt-A")
	if err != nil || a.State != "failed" {
		t.Fatalf("historical failure lost: %+v %v", a, err)
	}
	replayed, err := s.Restore(item.OperationID, "restore-history-attempt-A", "files/sample.txt", 7, "ordinary-user")
	if err != nil || replayed.State != "restored" {
		t.Fatalf("historical replay should only query: %+v %v", replayed, err)
	}
	if _, err = s.Restore(item.OperationID, "restore-history-attempt-A", "files/different.txt", 7, "ordinary-user"); !errors.Is(err, ErrConflict) {
		t.Fatalf("old ID changed target: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "files", "sample.txt"))
	if err != nil || string(data) != "new occupant" {
		t.Fatal("historical replay changed occupant")
	}
	for _, attempt := range []string{"restore-history-attempt-A", "restore-history-attempt-B"} {
		if _, err = s.root.Stat(restoreRecordPath(item.OperationID, attempt)); err != nil {
			t.Fatal("restore journal not retained on data path")
		}
	}
}

func TestRestoreIntentBeforeItemJournalFailureIsNotReplayed(t *testing.T) {
	_, s := fixture(t)
	item := mustTrash(t, s)
	s.beforeSave = func(item *Item) error {
		if item.State == "pending_restore" {
			return errors.New("injected intent failure")
		}
		return nil
	}
	_, err := s.Restore(item.OperationID, "restore-intent-uncommitted", "files/restored.txt", 7, "ordinary-user")
	if !errors.Is(err, ErrUncertain) {
		t.Fatalf("must retain unknown response: %v", err)
	}
	s.beforeSave = nil
	a, err := s.GetRestoreAttempt(item.OperationID, "restore-intent-uncommitted")
	if err != nil || a.State != "failed" || a.ErrorCode != "not_moved" {
		t.Fatalf("uncommitted intent result: %+v %v", a, err)
	}
	if _, err = s.Restore(item.OperationID, "restore-new-intent-after-failure", "files/restored.txt", 7, "ordinary-user"); err != nil {
		t.Fatal(err)
	}
}

func replaceSourceDuringMove(t *testing.T, root *os.Root, old, destination string) error {
	t.Helper()
	f, err := root.OpenFile(old+".replacement", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.WriteString("concurrent synthetic replacement"); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = root.Rename(old+".replacement", old); err != nil {
		return err
	}
	return moveNoReplace(root, old, destination)
}

func TestSourceReplacementAfterHashRequiresManualReconciliation(t *testing.T) {
	for _, restoring := range []bool{false, true} {
		t.Run(map[bool]string{false: "trash", true: "restore"}[restoring], func(t *testing.T) {
			_, s := fixture(t)
			if restoring {
				mustTrash(t, s)
			}
			s.move = func(root *os.Root, old, destination string) error {
				return replaceSourceDuringMove(t, root, old, destination)
			}
			var err error
			if restoring {
				_, err = s.Restore(sampleItem().OperationID, "restore-source-changed-001", "files/restored.txt", 7, "ordinary-user")
			} else {
				_, err = s.Trash(sampleItem())
			}
			if !errors.Is(err, ErrUncertain) {
				t.Fatalf("replacement incorrectly acknowledged: %v", err)
			}
			item, err := s.Get(sampleItem().OperationID)
			if err != nil || item.State != "manual_reconciliation" || item.ErrorCode != "source_changed" {
				t.Fatalf("missing changed-source outcome: %+v %v", item, err)
			}
			kept := contentPath(item.OperationID)
			if restoring {
				kept = "files/restored.txt"
			}
			f, err := s.root.Open(kept)
			if err != nil {
				t.Fatal("moved data was lost")
			}
			data, err := io.ReadAll(f)
			_ = f.Close()
			if err != nil || string(data) != "concurrent synthetic replacement" {
				t.Fatalf("replacement bytes not retained: %q %v", data, err)
			}
			if restoring {
				attempt, readErr := s.GetRestoreAttempt(item.OperationID, "restore-source-changed-001")
				if readErr != nil || attempt.State != "manual_reconciliation" {
					t.Fatalf("restore attempt misreported: %+v %v", attempt, readErr)
				}
			}
		})
	}
}

func TestRejectsDirectoriesRootsTraversalAndReservedNames(t *testing.T) {
	_, s := fixture(t)
	for i, name := range []string{".", "../sample.txt", "/files/sample.txt", "files", ".filebrowser-trash/version", "files/../../bad", "files\\sample.txt"} {
		item := sampleItem()
		item.OperationID = "rejected-operation-" + strings.Repeat("x", i+1)
		item.OriginalPath = name
		if _, err := s.Trash(item); err == nil {
			t.Fatalf("accepted unsafe input %q", name)
		}
	}
}

func TestSymlinkSourceAndRestoreParentRejected(t *testing.T) {
	dir, s := fixture(t)
	if err := os.Symlink("sample.txt", filepath.Join(dir, "files", "alias.txt")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("Windows symlink privilege unavailable: %v", err)
		}
		t.Fatal(err)
	}
	item := sampleItem()
	item.OriginalPath = "files/alias.txt"
	if _, err := s.Trash(item); err == nil {
		t.Fatal("symlink source accepted")
	}
	mustTrash(t, s)
	if err := os.Symlink(filepath.Join(dir, "files"), filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Restore(sampleItem().OperationID, "restore-symlink-0001", "alias/restored.txt", 7, "ordinary-user"); err == nil {
		t.Fatal("symlink parent accepted")
	}
}

func TestListOnlyJournalAndRejectsPreexistingStorageSymlink(t *testing.T) {
	dir, s := fixture(t)
	ids, err := s.IDs()
	if err != nil || len(ids) != 0 {
		t.Fatalf("empty list: %v %v", ids, err)
	}
	mustTrash(t, s)
	ids, err = s.IDs()
	if err != nil || len(ids) != 1 || ids[0] != sampleItem().OperationID {
		t.Fatalf("journal list: %v %v", ids, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "files", ".filebrowser-trash")); !os.IsNotExist(err) {
		t.Fatal("storage created outside Source root")
	}
}
