package http

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
)

func TestCoreFileActionAuditWritesVerifiedRealPath(t *testing.T) {
	environment := newCoreFileAuditEnvironment(t)

	tests := []struct {
		name       string
		method     string
		logical    string
		initial    string
		headers    map[string]string
		wantAction auditdb.Action
	}{
		{
			name:       "upload",
			method:     http.MethodPost,
			logical:    "/public/audit-verified-upload.txt",
			wantAction: auditdb.ActionFileUpload,
		},
		{
			name:    "completed chunk upload",
			method:  http.MethodPost,
			logical: "/public/audit-verified-chunk.txt",
			headers: map[string]string{
				"X-File-Chunk-Offset": "0",
				"X-File-Total-Size":   "19",
			},
			wantAction: auditdb.ActionFileUpload,
		},
		{
			name:       "modify",
			method:     http.MethodPut,
			logical:    "/public/audit-verified-modify.txt",
			initial:    "original target",
			wantAction: auditdb.ActionFileModify,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const body = "verified audit body"
			intendedRealPath := coreFileAuditRealPath(environment.sourcePath, test.logical)
			staleRealPath := coreFileAuditRealPath(environment.sourcePath, "/public/audit-stale-"+strings.ReplaceAll(test.name, " ", "-")+".txt")
			if test.initial != "" {
				if err := os.WriteFile(intendedRealPath, []byte(test.initial), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(staleRealPath, []byte("stale target must remain unchanged"), 0o644); err != nil {
				t.Fatal(err)
			}

			cacheKey := filepath.Join(environment.sourcePath, filepath.FromSlash(strings.TrimPrefix(test.logical, "/")))
			indexing.RealPathCache.Set(cacheKey, staleRealPath)
			indexing.IsDirCache.Set(cacheKey+":isdir", false)
			t.Cleanup(func() {
				indexing.RealPathCache.Delete(cacheKey)
				indexing.IsDirCache.Delete(cacheKey + ":isdir")
			})
			idx := indexing.GetIndex("source1")
			if idx == nil {
				t.Fatal("source index missing")
			}
			cachedRealPath, _, cacheErr := idx.GetRealPath(test.logical)
			if cacheErr != nil || cachedRealPath != staleRealPath {
				t.Fatalf("stale real path fixture: got %q, err=%v, want %q", cachedRealPath, cacheErr, staleRealPath)
			}

			auditStore := newAuditStoreStub()
			response := coreFileAuditRequest(t, newCoreFileAuditRouter(auditStore), environment.token,
				test.method, "/api/resources", url.Values{
					"source": {"source1"}, "path": {test.logical}, "override": {"true"},
				}, strings.NewReader(body), test.headers)
			requireCoreFileAuditStatus(t, response, http.StatusOK)
			assertAPITokenFileState(t, intendedRealPath, true, body)
			assertAPITokenFileState(t, staleRealPath, true, "stale target must remain unchanged")

			event := requireCoreFileAuditWriteEvent(t, auditStore)
			requireCoreFileAuditEvent(t, event, test.wantAction, auditdb.ResultSuccess,
				http.StatusOK, "source1", test.logical)
		})
	}
}
