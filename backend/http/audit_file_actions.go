package http

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
)

func registerCoreFileActionRoutes(api, publicAPI *http.ServeMux) {
	api.HandleFunc("GET /resources", withCoreFileAuditRead(auditdb.ActionFileBrowse, resourceGetHandler))
	api.HandleFunc("GET /resources/items", withCoreFileAuditRead(auditdb.ActionFileBrowse, itemsGetHandler))
	api.HandleFunc("DELETE /resources", withCoreFileAuditUser(auditdb.ActionFileDelete, resourceDeleteHandler))
	api.HandleFunc("POST /resources", withCoreFileAuditUser(auditdb.ActionFileUpload, resourcePostHandler))
	api.HandleFunc("PUT /resources", withCoreFileAuditUser(auditdb.ActionFileModify, resourcePutHandler))
	api.HandleFunc("PATCH /resources", withCoreFileAuditUser("", resourcePatchHandler))
	api.HandleFunc("DELETE /resources/bulk", withCoreFileAuditUser(auditdb.ActionFileDelete, resourceBulkDeleteHandler))
	api.HandleFunc("POST /resources/archive", withCoreFileAuditUser(auditdb.ActionArchiveCreate, archiveCreateHandler))
	api.HandleFunc("POST /resources/unarchive", withCoreFileAuditUser(auditdb.ActionArchiveExtract, unarchiveHandler))
	api.HandleFunc("GET /resources/download", withCoreFileAuditRead(auditdb.ActionFileDownload, downloadHandler))
	api.HandleFunc("GET /resources/preview", withTimeout(30*time.Second,
		withCoreFileAuditReadHelper(auditdb.ActionFilePreview, previewHandler)))
	api.HandleFunc("GET /resources/preview-source/{ticket}", authenticatedPreviewSnapshotHandler)
	api.HandleFunc("POST /resources/pause", withUser(resourcePauseHandler))
	api.HandleFunc("GET /raw", withCoreFileAuditRead(auditdb.ActionFileDownload, downloadHandler))

	publicAPI.HandleFunc("GET /resources", withAuditHashFile(publicGetResourceHandler))
	publicAPI.HandleFunc("GET /resources/items", withAuditHashFile(publicItemsGetHandler))
	publicAPI.HandleFunc("POST /resources", withAuditHashFile(publicUploadHandler))
	publicAPI.HandleFunc("PUT /resources", withAuditHashFile(publicPutHandler))
	publicAPI.HandleFunc("DELETE /resources", withAuditHashFile(publicDeleteHandler))
	publicAPI.HandleFunc("DELETE /resources/bulk", withAuditHashFile(publicBulkDeleteHandler))
	publicAPI.HandleFunc("PATCH /resources", withAuditHashFile(publicPatchHandler))
	publicAPI.HandleFunc("GET /resources/download", withAuditHashFile(publicDownloadHandler))
	publicAPI.HandleFunc("GET /resources/preview", withTimeout(30*time.Second, withAuditHashFileHelper(publicPreviewHandler)))
	publicAPI.HandleFunc("POST /resources/pause", withHashFile(publicPauseHandler))
	publicAPI.HandleFunc("GET /raw", withAuditHashFile(publicDownloadHandler))
	publicAPI.HandleFunc("GET /share/info", withAuditShareAccess(shareInfoHandler))
	publicAPI.HandleFunc("GET /share/image", withAuditHashFile(getShareImage))
	publicAPI.HandleFunc("GET /media/subtitles", withAuditHashFile(publicSubtitlesHandler))
	publicAPI.HandleFunc("GET /media/metadata", withAuditHashFile(publicMetadataHandler))
	publicAPI.HandleFunc("GET /media/lyrics", withAuditHashFile(publicLyricsHandler))
}

func withCoreFileAuditUser(action auditdb.Action, fn handleFunc) http.HandlerFunc {
	wrapped := withUserHelper(withAuditAuthenticatedUser(fn))
	if action != "" {
		wrapped = withAuditDefaultActionHelper(action, wrapped)
	}
	return wrapHandler(wrapped)
}

func withCoreFileAuditRead(action auditdb.Action, fn handleFunc) http.HandlerFunc {
	return wrapHandler(withCoreFileAuditReadHelper(action, fn))
}

func withCoreFileAuditReadHelper(action auditdb.Action, fn handleFunc) handleFunc {
	return withAuditDefaultActionHelper(action, withUserHelper(withAuditAuthenticatedUser(fn)))
}

func setCoreFileAuditReadTarget(request *http.Request, target authenticatedReadTarget, metadata *auditdb.MetadataV1) error {
	if target.Index == nil || target.Index.Name == "" || target.LogicalPath == "" || target.CanonicalPath == "" {
		return ErrAuditUnavailable
	}
	recorder := AuditRecorderFromRequest(request)
	if recorder == nil {
		return nil
	}
	if err := recorder.SetResource(target.Index.Name, target.LogicalPath, target.CanonicalPath); err != nil {
		return ErrAuditUnavailable
	}
	if metadata != nil {
		if err := recorder.MergeMetadata(metadata); err != nil {
			return ErrAuditUnavailable
		}
	}
	return nil
}

func mergeAuditResponseRangeMetadata(recorder *AuditRecorder, contentRange string) {
	if !auditRecorderRecordsResponseRange(recorder) {
		return
	}
	start, end, ok := parseAuditContentRange(contentRange)
	if !ok {
		return
	}
	_ = recorder.MergeMetadata(&auditdb.MetadataV1{
		SchemaVersion: auditdb.CurrentMetadataSchemaVersion,
		RangeStart:    &start,
		RangeEnd:      &end,
	})
}

func auditRecorderRecordsResponseRange(recorder *AuditRecorder) bool {
	if recorder == nil {
		return false
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.event.Action == auditdb.ActionFileDownload || recorder.event.Action == auditdb.ActionShareAccess
}

func parseAuditContentRange(value string) (int64, int64, bool) {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "bytes") {
		return 0, 0, false
	}
	rangeAndSize := strings.Split(fields[1], "/")
	if len(rangeAndSize) != 2 || rangeAndSize[0] == "*" {
		return 0, 0, false
	}
	bounds := strings.Split(rangeAndSize[0], "-")
	if len(bounds) != 2 {
		return 0, 0, false
	}
	start, ok := parseAuditNonNegativeDecimal(bounds[0])
	if !ok {
		return 0, 0, false
	}
	end, ok := parseAuditNonNegativeDecimal(bounds[1])
	if !ok || end < start {
		return 0, 0, false
	}
	if rangeAndSize[1] != "*" {
		size, validSize := parseAuditNonNegativeDecimal(rangeAndSize[1])
		if !validSize || size == 0 || end >= size {
			return 0, 0, false
		}
	}
	return start, end, true
}

func parseAuditNonNegativeDecimal(value string) (int64, bool) {
	if value == "" {
		return 0, false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	return parsed, err == nil
}
