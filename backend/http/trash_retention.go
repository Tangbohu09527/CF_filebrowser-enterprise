package http

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/filebrowser/backend/trash"
	"github.com/gtsteffaniak/go-logger/logger"
)

const trashPurgeBatchLimit = 50

type trashPurgeRequest struct {
	Source string   `json:"source"`
	IDs    []string `json:"operation_ids"`
}

type trashPurgeResult struct {
	ID    string `json:"operation_id"`
	State string `json:"state"`
	Error string `json:"error,omitempty"`
}

type trashPreviewItem struct {
	ID   string `json:"operation_id"`
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type trashPurgePreview struct {
	Items    []trashPreviewItem `json:"items"`
	Total    int                `json:"total"`
	Size     int64              `json:"size"`
	Snapshot string             `json:"snapshot"`
}

func trashAdminScope(d *requestContext, source string) (*indexing.Index, string, error) {
	if d.user == nil || !d.user.Permissions.Admin || !d.user.Permissions.Browse {
		return nil, "", os.ErrPermission
	}
	idx, scope, err := trashScope(d.user, source, true)
	if err == nil && idx.Config.Disabled {
		return nil, "", os.ErrPermission
	}
	return idx, scope, err
}

func trashPurgePreviewHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	idx, scope, err := trashAdminScope(d, r.URL.Query().Get("source"))
	if err != nil {
		return trashStatus(err)
	}
	limit, offset, err := trashPage(r)
	if err != nil {
		return http.StatusBadRequest, err
	}
	s, err := trash.Open(idx.Path)
	if err != nil {
		return trashStatus(err)
	}
	defer s.Close()
	ids, err := s.IDs()
	if err != nil {
		return trashStatus(err)
	}
	sort.Strings(ids)
	result := trashPurgePreview{Items: []trashPreviewItem{}}
	fingerprint := sha256.New()
	for _, id := range ids {
		item, err := s.Peek(id)
		if err != nil {
			return trashStatus(err)
		}
		if trashAuthorizeItem(d.user, idx, scope, item) != nil || item.State != "trashed" {
			continue
		}
		if result.Total >= offset && len(result.Items) < limit {
			result.Items = append(result.Items, trashPreviewItem{id, item.Name, item.Size})
		}
		result.Total++
		result.Size += item.Size
		_, _ = fmt.Fprintln(fingerprint, id)
	}
	result.Snapshot = hex.EncodeToString(fingerprint.Sum(nil))
	return renderJSON(w, r, result)
}

func trashPurgeHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	var request trashPurgeRequest
	if err := decodeTrashBody(w, r, &request); err != nil || len(request.IDs) == 0 || len(request.IDs) > trashPurgeBatchLimit {
		return http.StatusBadRequest, trash.ErrInvalid
	}
	seen := make(map[string]bool, len(request.IDs))
	for _, id := range request.IDs {
		if !trash.ValidID(id) || seen[id] {
			return http.StatusBadRequest, trash.ErrInvalid
		}
		seen[id] = true
	}
	idx, scope, err := trashAdminScope(d, request.Source)
	if err != nil {
		return trashStatus(err)
	}
	result := struct {
		Items []trashPurgeResult `json:"items"`
	}{Items: make([]trashPurgeResult, 0, len(request.IDs))}
	for _, id := range request.IDs {
		if r.Context().Err() != nil {
			return trashStatus(trash.ErrUncertain)
		}
		state, err := purgeTrashItem(idx, scope, d, id)
		entry := trashPurgeResult{ID: id, State: state}
		switch {
		case err == nil:
		case errors.Is(err, os.ErrPermission):
			entry.State, entry.Error = "error", "forbidden"
		case errors.Is(err, os.ErrNotExist):
			entry.State, entry.Error = "error", "not_found"
		case errors.Is(err, trash.ErrConflict):
			entry.State, entry.Error = "error", "conflict"
		default:
			entry.State, entry.Error = "unknown", "outcome_unknown"
		}
		result.Items = append(result.Items, entry)
	}
	return renderJSON(w, r, result)
}

func purgeTrashItem(idx *indexing.Index, scope string, d *requestContext, id string) (string, error) {
	s, err := trash.Open(idx.Path)
	if err != nil {
		return "", err
	}
	defer s.Close()
	item, err := s.Peek(id)
	if err != nil {
		return "", err
	}
	if err = trashAuthorizeItem(d.user, idx, scope, item); err != nil {
		return "", err
	}
	item, err = s.Purge(id, d.user.ID, d.user.Username, trash.PurgeManual)
	if err != nil {
		return "", err
	}
	return item.State, nil
}

func trashRetentionHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	var request struct {
		Source  string `json:"source"`
		Days    int    `json:"days"`
		Enabled *bool  `json:"enabled"`
	}
	if err := decodeTrashBody(w, r, &request); err != nil {
		return http.StatusBadRequest, trash.ErrInvalid
	}
	idx, scope, err := trashAdminScope(d, request.Source)
	if err != nil {
		return trashStatus(err)
	}
	if scope != "" || !store.Access.PermittedFresh(idx.Path, "/", d.user.Username) {
		return http.StatusForbidden, os.ErrPermission
	}
	s, err := trash.Open(idx.Path)
	if err != nil {
		return trashStatus(err)
	}
	defer s.Close()
	enabled := request.Enabled == nil || *request.Enabled
	policy, err := s.SetRetentionPolicy(enabled, request.Days, time.Now())
	if err != nil {
		return trashStatus(err)
	}
	return renderJSON(w, r, policy)
}

// trashCleanupWindow returns both boundaries of the daily 03:00 China-time
// schedule. A restart processes the last elapsed window before waiting again.
func trashCleanupWindow(now time.Time) (previous, next time.Time) {
	chinaTime := time.FixedZone("UTC+8", 8*60*60)
	local := now.In(chinaTime)
	previous = time.Date(local.Year(), local.Month(), local.Day(), 3, 0, 0, 0, chinaTime)
	if local.Before(previous) {
		previous = previous.AddDate(0, 0, -1)
	}
	return previous, previous.AddDate(0, 0, 1)
}

func runTrashRetention(ctx context.Context, sources []*settings.Source) {
	for ctx.Err() == nil {
		cutoff, next := trashCleanupWindow(time.Now())
		for _, source := range sources {
			if source.Config.ReadOnly || source.Config.Disabled || utils.CheckUserStoragePath(source.Path) != nil {
				continue
			}
			if err := cleanTrashSource(ctx, source.Path, cutoff); err != nil {
				logger.Warningf("Recycle bin cleanup needs attention for source %s: %v", source.Name, err)
			}
		}
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func cleanTrashSource(ctx context.Context, sourcePath string, cutoff time.Time) error {
	s, err := trash.Open(sourcePath)
	if err != nil {
		return err
	}
	policy, err := s.RetentionPolicy()
	if err != nil || !policy.Enabled {
		s.Close()
		return err
	}
	ids, err := s.IDs()
	s.Close()
	if err != nil {
		return err
	}
	var firstFailure error
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		// Recheck policy and state under the same Source lock as restore.
		s, err := trash.Open(sourcePath)
		if err != nil {
			return err
		}
		_, err = s.PurgeExpired(id, cutoff)
		s.Close()
		if err != nil && firstFailure == nil {
			firstFailure = err
		}
	}
	return firstFailure
}
