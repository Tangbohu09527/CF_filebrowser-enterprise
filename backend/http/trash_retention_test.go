package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/trash"
)

func TestTrashPurgeHTTPKeepsAuditAndRestrictsAccess(t *testing.T) {
	source, ordinary, id := createTrashFixture(t)
	admin := saveAPITokenTestUser(t, "trash-purge-admin", source, users.Permissions{Admin: true, Api: true, Browse: true, Delete: true})
	const purgePath = "/api/trash/purge"
	request := trashPurgeRequest{Source: "source1", IDs: []string{id}}
	expect := func(user *users.User, handler handleFunc, method, url, itemID string, body any, code int) string {
		t.Helper()
		status, result := callTrash(t, user, handler, method, url, itemID, body)
		if status != code {
			t.Fatalf("%s %s: expected %d, got %d %s", method, url, code, status, result)
		}
		return result
	}
	expect(ordinary, trashPostHandler, http.MethodPost, "/api/trash", "", trashRequest{
		Source: "source1", Path: "/public/sample.txt", OperationID: id,
	}, http.StatusOK)
	expect(ordinary, trashPurgeHandler, http.MethodPost, purgePath, "", request, http.StatusForbidden)
	expect(admin, trashPurgeHandler, http.MethodPost, purgePath, "", trashPurgeRequest{
		Source: "source1", IDs: []string{id, id},
	}, http.StatusBadRequest)

	admin.Scopes[0].Scope = "/public"
	policy := map[string]any{"source": "source1", "days": 30}
	expect(admin, trashRetentionHandler, http.MethodPut, "/api/trash/retention", "", policy, http.StatusForbidden)
	admin.Scopes[0].Scope = "/"
	expect(admin, trashRetentionHandler, http.MethodPut, "/api/trash/retention", "", policy, http.StatusOK)
	preview := expect(admin, trashPurgePreviewHandler, http.MethodGet, "/api/trash/purge/preview?source=source1", "", nil, http.StatusOK)
	var selected trashPurgePreview
	if err := json.Unmarshal([]byte(preview), &selected); err != nil || selected.Total != 1 || len(selected.Items) != 1 ||
		selected.Items[0].ID != id || selected.Size == 0 || selected.Snapshot == "" {
		t.Fatalf("invalid source preview: %s (%v)", preview, err)
	}
	list := expect(admin, trashListHandler, http.MethodGet, "/api/trash?source=source1&sort=size", "", nil, http.StatusOK)
	var summary trashListResponse
	if err := json.Unmarshal([]byte(list), &summary); err != nil || summary.UsageBytes != selected.Size || summary.NextCleanupAt == nil ||
		summary.Total != 1 || len(summary.Items) != 1 || summary.Items[0].ExpiresAt == nil {
		t.Fatalf("invalid summary: %s (%v)", list, err)
	}
	if err := store.Access.DenyUser(source, "/public/sample.txt", admin.Username); err != nil {
		t.Fatal(err)
	}
	result := expect(admin, trashPurgeHandler, http.MethodPost, purgePath, "", request, http.StatusOK)
	if !strings.Contains(result, `"error":"forbidden"`) {
		t.Fatalf("purge bypassed fresh ACL: %s", result)
	}
	if _, err := store.Access.RemoveDenyUser(source, "/public/sample.txt", admin.Username); err != nil {
		t.Fatal(err)
	}
	// Even an administrator's API token needs the effective Admin permission.
	previousConfigAuth, previousSettingsAuth := config.Auth, settings.Config.Auth
	t.Cleanup(func() {
		config.Auth = previousConfigAuth
		settings.Config.Auth = previousSettingsAuth
	})
	settings.Config.Auth.Key = "synthetic-trash-retention-test-key"
	config.Auth.Key = settings.Config.Auth.Key
	config.Auth.Methods.NoAuth = false
	narrow, _ := issuePermissionContractToken(t, admin, "purge-without-admin", "delete,browse")
	router := http.NewServeMux()
	registerTrashRoutes(router)
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	post := httptest.NewRequest(http.MethodPost, "/trash/purge", strings.NewReader(string(body)))
	post.Header.Set("Authorization", "Bearer "+narrow)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, post)
	if response.Code != http.StatusForbidden {
		t.Fatalf("narrow token could purge: %d %s", response.Code, response.Body.String())
	}

	for range 2 {
		result = expect(admin, trashPurgeHandler, http.MethodPost, purgePath, "", request, http.StatusOK)
		if !strings.Contains(result, `"state":"purged"`) {
			t.Fatalf("expected a durable purge: %s", result)
		}
	}
	result = expect(ordinary, trashGetHandler, http.MethodGet, "/api/trash/"+id+"?source=source1", id, nil, http.StatusOK)
	if !strings.Contains(result, `"purged_at":`) || !strings.Contains(result, `"purge_actor":"trash-purge-admin"`) {
		t.Fatalf("missing purge audit: %s", result)
	}
	list = expect(admin, trashListHandler, http.MethodGet, "/api/trash?source=source1", "", nil, http.StatusOK)
	if !strings.Contains(list, `"usage_bytes":0`) {
		t.Fatalf("retained usage after purge: %s", list)
	}
}

func TestTrashDailyCleanupCatchesUpAfterRestart(t *testing.T) {
	source := t.TempDir()
	const id = "cleanup-window-test-0001"
	now := time.Now()
	cutoff, next := trashCleanupWindow(now)
	if cutoff.After(now) || !next.After(now) || next.Sub(cutoff) != 24*time.Hour || cutoff.Hour() != 3 {
		t.Fatalf("unexpected interval %v to %v for %v", cutoff, next, now)
	}
	if err := os.WriteFile(filepath.Join(source, "old.txt"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := trash.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	item, err := s.Trash(trash.Item{OperationID: id, OriginalPath: "old.txt", Actor: "test", Source: "source"})
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	policy, err := s.SetRetentionPolicy(true, 1, now)
	s.Close()
	if err != nil {
		t.Fatal(err)
	}
	expiry := policy.Deadline(item)
	before, next := trashCleanupWindow(expiry.Add(-time.Second))
	if err := cleanTrashSource(context.Background(), source, before); err != nil {
		t.Fatal(err)
	}
	s, err = trash.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	item, err = s.Get(id)
	s.Close()
	if err != nil || item.State != "trashed" {
		t.Fatalf("removed before cutoff: %+v %v", item, err)
	}
	cutoff, _ = trashCleanupWindow(next.Add(time.Hour))
	if err := cleanTrashSource(context.Background(), source, cutoff); err != nil {
		t.Fatal(err)
	}
	s, err = trash.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	item, err = s.Get(id)
	if err != nil || item.State != "purged" || item.PurgeMethod != trash.PurgeAutomatic || item.PurgedAt == nil {
		t.Fatalf("missing catch-up purge: %+v %v", item, err)
	}
}
