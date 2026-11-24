package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/filebrowser/backend/trash"
)

func registerTrashRoutes(api *http.ServeMux) {
	api.HandleFunc("POST /trash", withUser(trashPostHandler))
	api.HandleFunc("GET /trash", withUser(trashListHandler))
	api.HandleFunc("GET /trash/{id}", withUser(trashGetHandler))
	api.HandleFunc("POST /trash/{id}/restore", withUser(trashRestoreHandler))
	api.HandleFunc("GET /trash/purge/preview", withUser(trashPurgePreviewHandler))
	api.HandleFunc("POST /trash/purge", withUser(trashPurgeHandler))
	api.HandleFunc("PUT /trash/retention", withUser(trashRetentionHandler))
}

type trashRequest struct {
	Source             string `json:"source"`
	Path               string `json:"path"`
	OperationID        string `json:"operation_id"`
	RestoreOperationID string `json:"restore_operation_id"`
}

type trashItemResponse struct {
	trash.Item
	RestoreAttempt *trash.RestoreAttempt `json:"restore_attempt,omitempty"`
}

type trashListResponse struct {
	Items              []trashListItem       `json:"items"`
	Total              int                   `json:"total"`
	Retention          trash.RetentionPolicy `json:"retention"`
	UsageBytes         int64                 `json:"usage_bytes"`
	DueBytes           int64                 `json:"due_bytes"`
	NextCleanupAt      *time.Time            `json:"next_cleanup_at,omitempty"`
	CanPurge           bool                  `json:"can_purge"`
	CanManageRetention bool                  `json:"can_manage_retention"`
}

type trashListItem struct {
	trash.Item
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func decodeTrashRequest(w http.ResponseWriter, r *http.Request) (trashRequest, error) {
	var request trashRequest
	err := decodeTrashBody(w, r, &request)
	return request, err
}

func decodeTrashBody(w http.ResponseWriter, r *http.Request, request any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(request); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return trash.ErrInvalid
	}
	return nil
}

func trashStatus(err error) (int, error) {
	switch {
	case errors.Is(err, trash.ErrConflict), os.IsExist(err):
		return http.StatusConflict, fmt.Errorf("trash conflict; query the operation before retrying")
	case errors.Is(err, trash.ErrInvalid):
		return http.StatusBadRequest, fmt.Errorf("invalid trash request or storage")
	case errors.Is(err, trash.ErrUncertain):
		return http.StatusServiceUnavailable, fmt.Errorf("operation outcome pending; query its operation_id")
	case os.IsNotExist(err):
		return http.StatusNotFound, fmt.Errorf("trash item or path not found")
	case os.IsPermission(err):
		return http.StatusForbidden, fmt.Errorf("trash access denied")
	default:
		return http.StatusInternalServerError, fmt.Errorf("trash storage operation failed; query its operation_id")
	}
}

// No admin bypass: permissions already contain the user/token intersection.
func trashScope(user *users.User, source string, mutate bool) (*indexing.Index, string, error) {
	if user == nil || !user.Permissions.Delete || source == "" || store == nil || store.Access == nil {
		return nil, "", os.ErrPermission
	}
	idx := indexing.GetIndex(source)
	if idx == nil || idx.Name != source || utils.IsReservedStoragePath(idx.Path) {
		return nil, "", os.ErrPermission
	}
	if utils.CheckUserStoragePath(idx.Path) != nil {
		return nil, "", os.ErrPermission
	}
	scope, err := user.GetScopeForSourcePath(idx.Path)
	if err != nil || scope == "" {
		return nil, "", os.ErrPermission
	}
	if mutate && idx.Config.ReadOnly {
		return nil, "", os.ErrPermission
	}
	clean, err := sanitizeAuthenticatedReadPath(scope)
	if err != nil || utils.IsReservedStoragePath(clean) {
		return nil, "", os.ErrPermission
	}
	return idx, strings.Trim(filepath.ToSlash(clean), "/"), nil
}

func trashWithin(scope, filename string) bool {
	return filename != "" && (scope == "" || strings.HasPrefix(filename, scope+"/"))
}

func trashRelativePath(idx *indexing.Index, scope, requested string, user *users.User) (string, error) {
	clean, err := sanitizeAuthenticatedReadPath(requested)
	clean = filepath.ToSlash(clean)
	if err != nil || clean == "/" || utils.IsReservedStoragePath(clean) {
		return "", trash.ErrInvalid
	}
	filename := strings.TrimPrefix(path.Join("/", scope, clean), "/")
	if !trashWithin(scope, filename) || !store.Access.PermittedFresh(idx.Path, "/"+filename, user.Username) {
		return "", os.ErrPermission
	}
	return filename, nil
}

func trashAuthorizeItem(user *users.User, idx *indexing.Index, scope string, item *trash.Item) error {
	if item.SourceKey != idx.Path || !trashWithin(scope, item.OriginalPath) || utils.IsReservedStoragePath(item.OriginalPath) ||
		!store.Access.PermittedFresh(idx.Path, "/"+item.OriginalPath, user.Username) {
		return os.ErrPermission
	}
	if !user.Permissions.Admin && (item.ActorID != user.ID || user.ID == 0 && item.Actor != user.Username) {
		return os.ErrPermission
	}
	return nil
}

func trashClientItem(item *trash.Item, scope string, idx *indexing.Index, user *users.User) trash.Item {
	result := *item
	result.OriginalPath = "/" + strings.TrimPrefix(strings.TrimPrefix(item.OriginalPath, scope), "/")
	if trashWithin(scope, item.RestoredPath) && store.Access.PermittedFresh(idx.Path, "/"+item.RestoredPath, user.Username) {
		result.RestoredPath = "/" + strings.TrimPrefix(strings.TrimPrefix(item.RestoredPath, scope), "/")
	} else {
		result.RestoredPath = ""
	}
	return result
}

func renderTrashItem(w http.ResponseWriter, r *http.Request, user *users.User, idx *indexing.Index, scope string, item *trash.Item, s *trash.Store, restoreID string) (int, error) {
	client := trashClientItem(item, scope, idx, user)
	if restoreID == "" {
		return renderJSON(w, r, client)
	}
	attempt, err := s.GetRestoreAttempt(item.OperationID, restoreID)
	if err != nil {
		return trashStatus(err)
	}
	if !trashWithin(scope, attempt.Path) || !store.Access.PermittedFresh(idx.Path, "/"+attempt.Path, user.Username) {
		return http.StatusForbidden, os.ErrPermission
	}
	copy := *attempt
	copy.Path = "/" + strings.TrimPrefix(strings.TrimPrefix(attempt.Path, scope), "/")
	return renderJSON(w, r, trashItemResponse{client, &copy})
}

// trashPostHandler explicitly recycles one regular file.
// @Summary Move one file into the filesystem recycle bin
// @Description Requires current Delete, SourceScope and AccessRules. Directories and symlinks are rejected. Reuse operation_id to query an unknown outcome without moving again.
// @Tags Trash
// @Accept json
// @Produce json
// @Param body body trashRequest true "source, scoped path and persistent operation_id"
// @Success 200 {object} trash.Item
// @Failure 400 {object} HttpResponse
// @Failure 403 {object} HttpResponse
// @Failure 409 {object} HttpResponse
// @Failure 503 {object} HttpResponse
// @Router /api/trash [post]
func trashPostHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	request, err := decodeTrashRequest(w, r)
	if err != nil || !trash.ValidID(request.OperationID) {
		return http.StatusBadRequest, trash.ErrInvalid
	}
	idx, scope, err := trashScope(d.user, request.Source, true)
	if err != nil {
		return trashStatus(err)
	}
	filename, err := trashRelativePath(idx, scope, request.Path, d.user)
	if err != nil {
		return trashStatus(err)
	}
	s, err := trash.Open(idx.Path)
	if err != nil {
		return trashStatus(err)
	}
	defer s.Close()
	item, err := s.Trash(trash.Item{OperationID: request.OperationID, Source: request.Source, OriginalPath: filename, ActorID: d.user.ID, Actor: d.user.Username})
	if err != nil {
		return trashStatus(err)
	}
	if item.State == "trashed" {
		idx.DeleteMetadata("/"+filename, false, false)
	}
	return renderTrashItem(w, r, d.user, idx, scope, item, s, "")
}

// trashGetHandler returns an authorized item's durable outcome.
// @Summary Query a recycle operation or a historical restore attempt
// @Tags Trash
// @Produce json
// @Param id path string true "Trash operation ID"
// @Param source query string true "Configured Source display name"
// @Param restore_operation_id query string false "Include the specified historical restore attempt"
// @Success 200 {object} trashItemResponse
// @Failure 403 {object} HttpResponse
// @Failure 404 {object} HttpResponse
// @Failure 503 {object} HttpResponse
// @Router /api/trash/{id} [get]
func trashGetHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if d.user == nil || !d.user.Permissions.Browse {
		return http.StatusForbidden, os.ErrPermission
	}
	idx, scope, err := trashScope(d.user, r.URL.Query().Get("source"), false)
	if err != nil {
		return trashStatus(err)
	}
	s, err := trash.Open(idx.Path)
	if err != nil {
		return trashStatus(err)
	}
	defer s.Close()
	item, err := s.Peek(r.PathValue("id"))
	if err != nil {
		return trashStatus(err)
	}
	if err = trashAuthorizeItem(d.user, idx, scope, item); err != nil {
		return trashStatus(err)
	}
	item, err = s.Get(item.OperationID)
	if err != nil {
		return trashStatus(err)
	}
	return renderTrashItem(w, r, d.user, idx, scope, item, s, r.URL.Query().Get("restore_operation_id"))
}

// trashRestoreHandler restores to an explicit, authorized, unused target.
// @Summary Restore a recycled file without overwriting an existing target
// @Description Requires current Delete and Create, original ownership, SourceScope and AccessRules. A rejected restore retains its journal and the recycled bytes; retry with a new restore_operation_id only after querying the outcome.
// @Tags Trash
// @Accept json
// @Produce json
// @Param id path string true "Trash operation ID"
// @Param body body trashRequest true "source, explicit scoped target path and persistent restore_operation_id"
// @Success 200 {object} trashItemResponse
// @Failure 400 {object} HttpResponse
// @Failure 403 {object} HttpResponse
// @Failure 409 {object} HttpResponse
// @Failure 503 {object} HttpResponse
// @Router /api/trash/{id}/restore [post]
func trashRestoreHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	request, err := decodeTrashRequest(w, r)
	if err != nil || !trash.ValidID(request.RestoreOperationID) {
		return http.StatusBadRequest, trash.ErrInvalid
	}
	idx, scope, err := trashScope(d.user, request.Source, true)
	if err != nil {
		return trashStatus(err)
	}
	if !d.user.Permissions.Create {
		return http.StatusForbidden, os.ErrPermission
	}
	destination, err := trashRelativePath(idx, scope, request.Path, d.user)
	if err != nil {
		return trashStatus(err)
	}
	// The target must have an existing, authorized directory. No mkdir or overwrite.
	parent := path.Dir(destination)
	if !store.Access.PermittedFresh(idx.Path, "/"+parent, d.user.Username) {
		return http.StatusForbidden, os.ErrPermission
	}
	s, err := trash.Open(idx.Path)
	if err != nil {
		return trashStatus(err)
	}
	defer s.Close()
	item, err := s.Peek(r.PathValue("id"))
	if err != nil {
		return trashStatus(err)
	}
	if err = trashAuthorizeItem(d.user, idx, scope, item); err != nil {
		return trashStatus(err)
	}
	item, err = s.Restore(item.OperationID, request.RestoreOperationID, destination, d.user.ID, d.user.Username)
	if err != nil {
		return trashStatus(err)
	}
	if item.State == "restored" {
		_ = idx.RefreshDirectory("/"+parent, false)
	}
	return renderTrashItem(w, r, d.user, idx, scope, item, s, request.RestoreOperationID)
}

// trashListHandler searches only the recycle journal and current authorization.
// @Summary List and search authorized recycle records, including restored items
// @Tags Trash
// @Produce json
// @Param source query string true "Configured Source display name"
// @Param query query string false "Original path, file name or operation ID substring"
// @Param offset query int false "Record offset"
// @Param limit query int false "Page size, 1 to 200, default 50"
// @Success 200 {object} trashListResponse
// @Failure 403 {object} HttpResponse
// @Router /api/trash [get]
func trashListHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if d.user == nil || !d.user.Permissions.Browse {
		return http.StatusForbidden, os.ErrPermission
	}
	idx, scope, err := trashScope(d.user, r.URL.Query().Get("source"), false)
	if err != nil {
		return trashStatus(err)
	}
	limit, offset, err := trashPage(r)
	if err != nil {
		return http.StatusBadRequest, err
	}
	query := strings.ToLower(r.URL.Query().Get("query"))
	order := r.URL.Query().Get("sort")
	if order != "" && order != "size" {
		return http.StatusBadRequest, trash.ErrInvalid
	}
	return renderTrashList(w, r, d.user, idx, scope, query, order, limit, offset)
}

func trashPage(r *http.Request) (limit, offset int, err error) {
	limit = 50
	if value := r.URL.Query().Get("limit"); value != "" {
		limit, err = strconv.Atoi(value)
		if err != nil || limit < 1 || limit > 200 {
			return 0, 0, trash.ErrInvalid
		}
	}
	if value := r.URL.Query().Get("offset"); value != "" {
		offset, err = strconv.Atoi(value)
		if err != nil || offset < 0 {
			return 0, 0, trash.ErrInvalid
		}
	}
	return limit, offset, nil
}

func renderTrashList(w http.ResponseWriter, r *http.Request, user *users.User, idx *indexing.Index, scope, query, order string, limit, offset int) (int, error) {
	s, err := trash.Open(idx.Path)
	if err != nil {
		return trashStatus(err)
	}
	defer s.Close()
	ids, err := s.IDs()
	if err != nil {
		return trashStatus(err)
	}
	policy, err := s.RetentionPolicy()
	if err != nil {
		return trashStatus(err)
	}
	result := trashListResponse{
		Retention: policy, CanPurge: user.Permissions.Admin && !idx.Config.ReadOnly && !idx.Config.Disabled,
	}
	result.CanManageRetention = result.CanPurge && scope == "" && store.Access.PermittedFresh(idx.Path, "/", user.Username)
	if policy.Enabled {
		_, next := trashCleanupWindow(time.Now())
		result.NextCleanupAt = &next
	}
	items := []trashListItem{}
	for _, id := range ids {
		item, loadErr := s.Peek(id)
		if loadErr != nil {
			return trashStatus(loadErr)
		}
		if trashAuthorizeItem(user, idx, scope, item) != nil {
			continue
		}
		item, loadErr = s.Get(id)
		if loadErr != nil {
			return trashStatus(loadErr)
		}
		occupied, loadErr := s.OccupiedBytes(item)
		if loadErr != nil {
			return trashStatus(loadErr)
		}
		result.UsageBytes += occupied
		deadline := policy.Deadline(item)
		if deadline != nil && result.NextCleanupAt != nil && !deadline.After(*result.NextCleanupAt) {
			result.DueBytes += occupied
		}
		if query == "" || strings.Contains(strings.ToLower(item.OriginalPath+" "+item.OperationID), query) {
			items = append(items, trashListItem{Item: trashClientItem(item, scope, idx, user), ExpiresAt: deadline})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if order == "size" && items[i].Size != items[j].Size {
			return items[i].Size > items[j].Size
		}
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].OperationID < items[j].OperationID
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	total := len(items)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	result.Items, result.Total = items[offset:end], total
	return renderJSON(w, r, result)
}
