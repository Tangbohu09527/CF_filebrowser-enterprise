package http

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
)

const (
	uploadCancelled  = "cancelled"
	uploadCompleted  = "completed"
	uploadCommitting = "committing"
	uploadFailed     = "failed"
)

type uploadSessionStatus struct {
	State  string `json:"state"`
	Offset int64  `json:"offset"`
}

func requestChunkUploadKey(r *http.Request, d *requestContext, targetPath string, totalSize int64) (string, bool, error) {
	principal := chunkUploadPrincipal(d)
	id := r.Header.Get("X-File-Upload-ID")
	if id == "" {
		return chunkUploadSessionKey(principal, targetPath, totalSize), false, nil
	}
	parsed, err := uuid.Parse(id)
	if err != nil || len(id) != 36 || parsed.Version() != 4 || parsed.Variant() != uuid.RFC4122 {
		return "", false, fmt.Errorf("invalid upload ID")
	}
	return chunkUploadSessionKey(principal+"\x00"+parsed.String(), targetPath, totalSize), true, nil
}

func resourceUploadSessionHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	return manageUploadSession(w, r, d, r.URL.Query().Get("source"), r.URL.Query().Get("path"))
}

func publicUploadSessionHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if d.share.ShareType != "upload" && !d.share.AllowCreate {
		return http.StatusForbidden, fmt.Errorf("uploading is disabled for this share")
	}
	src, ok := config.Server.SourceMap[d.share.Source]
	if !ok {
		return http.StatusNotFound, fmt.Errorf("source not found")
	}
	return manageUploadSession(w, r, d, src.Name, d.IndexPath)
}

func manageUploadSession(w http.ResponseWriter, r *http.Request, d *requestContext, source, path string) (int, error) {
	action := r.URL.Query().Get("action")
	if action != "cancel" && action != "status" {
		return http.StatusBadRequest, fmt.Errorf("invalid upload action")
	}
	path, err := utils.SanitizeUserPath(path)
	if err != nil {
		return http.StatusBadRequest, err
	}
	idx := indexing.GetIndex(source)
	if idx == nil {
		return http.StatusNotFound, fmt.Errorf("source not found")
	}
	if idx.Config.ReadOnly {
		return http.StatusForbidden, fmt.Errorf("source is read-only")
	}
	user := d.user
	if d.share != nil {
		user = d.shareUser
	} else if !user.Permissions.Create && !user.Permissions.Modify {
		return http.StatusForbidden, fmt.Errorf("user is not allowed to upload")
	}
	scope, err := user.GetScopeForSourceName(source)
	if err != nil || !store.Access.Permitted(idx.Path, path, user.Username) {
		return http.StatusForbidden, fmt.Errorf("upload access denied")
	}
	targetPath, _, err := idx.GetRealPath(utils.JoinPathAsUnix(strings.TrimRight(scope, "/"), path))
	if err == errors.ErrAccessDenied {
		return http.StatusForbidden, err
	}
	if targetPath == "" {
		return http.StatusBadRequest, fmt.Errorf("could not resolve upload target")
	}
	totalSize, err := strconv.ParseInt(r.Header.Get("X-File-Total-Size"), 10, 64)
	if err != nil || totalSize < 0 {
		return http.StatusBadRequest, fmt.Errorf("invalid total size")
	}
	sessionKey, tracked, err := requestChunkUploadKey(r, d, targetPath, totalSize)
	if err != nil || !tracked {
		return http.StatusBadRequest, fmt.Errorf("valid upload ID required")
	}
	unlock, ok := tryLockChunkUploadTarget(targetPath)
	if !ok {
		return http.StatusLocked, fmt.Errorf("upload request is still active")
	}
	defer unlock()
	state, err := store.ChunkUploads.State(sessionKey)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if state == uploadCompleted || state == uploadCommitting || state == uploadFailed {
		return renderJSON(w, r, uploadSessionStatus{State: state})
	}
	return managePartialUpload(w, r, action, targetPath, sessionKey, state)
}

func managePartialUpload(w http.ResponseWriter, r *http.Request, action, targetPath, sessionKey, state string) (int, error) {
	temps, err := chunkUploadTempsForTarget(targetPath)
	if err != nil && !os.IsNotExist(err) {
		return http.StatusInternalServerError, err
	}
	if action == "cancel" {
		if state != uploadCancelled {
			// Record cancellation before unlinking. A retry can finish the unlink
			// if interrupted without letting an in-flight first chunk recreate it.
			if err := store.ChunkUploads.SetState(sessionKey, uploadCancelled, chunkUploadTempTTL); err != nil {
				return http.StatusInternalServerError, err
			}
		}
		for _, temp := range temps {
			if temp.sessionKey == sessionKey {
				if err := os.Remove(temp.path); err != nil && !os.IsNotExist(err) {
					return http.StatusInternalServerError, err
				}
				stopChunkUploadTempCleanup(temp.path)
			}
		}
		return renderJSON(w, r, uploadSessionStatus{State: uploadCancelled})
	}
	if state == uploadCancelled {
		return renderJSON(w, r, uploadSessionStatus{State: state})
	}
	for _, temp := range temps {
		if temp.sessionKey == sessionKey {
			info, err := os.Lstat(temp.path)
			if err != nil || !info.Mode().IsRegular() {
				return http.StatusConflict, fmt.Errorf("upload session is no longer available")
			}
			return renderJSON(w, r, uploadSessionStatus{State: "partial", Offset: info.Size()})
		}
	}
	return renderJSON(w, r, uploadSessionStatus{State: "missing"})
}
