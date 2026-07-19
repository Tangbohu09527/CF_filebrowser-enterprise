package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	dbshare "github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func TestPermissionShareLifecycleHardening(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	h := newPermissionShareSecurityHarness(t, sourcePath)

	t.Run("narrow token cannot create wider share capabilities", func(t *testing.T) {
		owner := h.newOwner(t, "share-token-cap-owner", users.Permissions{
			Api: true, Share: true, Browse: true, Preview: true, Download: true, Create: true,
		})
		narrow := issueShareSecurityToken(t, owner, "share-token-cap-narrow", users.Permissions{
			Api: true, Share: true, Browse: true,
		})

		uploadBody, err := json.Marshal(dbshare.CreateBody{CommonShare: dbshare.CommonShare{
			Source: "source1", Path: "/public", ShareType: "upload",
		}})
		if err != nil {
			t.Fatal(err)
		}
		uploadResponse := h.request(http.MethodPost, "/api/share", nil, bytes.NewReader(uploadBody), map[string]string{
			"Authorization": "Bearer " + narrow,
			"Content-Type":  "application/json",
		})
		assertPermissionShareStatus(t, "narrow token upload share", uploadResponse, http.StatusForbidden)

		readBody, err := json.Marshal(dbshare.CreateBody{CommonShare: dbshare.CommonShare{
			Source:            "source1",
			Path:              "/public",
			ShareType:         "normal",
			DisableThumbnails: true,
			DisableFileViewer: true,
			DisableDownload:   true,
		}})
		if err != nil {
			t.Fatal(err)
		}
		readResponse := h.request(http.MethodPost, "/api/share", nil, bytes.NewReader(readBody), map[string]string{
			"Authorization": "Bearer " + narrow,
			"Content-Type":  "application/json",
		})
		requirePermissionShareStatus(t, "narrow browse-only share", readResponse, http.StatusOK)
		var created struct {
			Hash string `json:"hash"`
		}
		if err := json.NewDecoder(readResponse.Body).Decode(&created); err != nil || created.Hash == "" {
			t.Fatalf("decode narrow share: hash=%q err=%v", created.Hash, err)
		}

		widenBody, err := json.Marshal(dbshare.CreateBody{
			Hash: created.Hash,
			CommonShare: dbshare.CommonShare{
				ShareType: "normal",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		widenRecorder := httptest.NewRecorder()
		status, updateErr := sharePostHandler(widenRecorder, httptest.NewRequest(http.MethodPost, "/api/share", bytes.NewReader(widenBody)), &requestContext{user: owner})
		if updateErr != nil || status != http.StatusOK {
			t.Fatalf("owner policy update: status=%d err=%v body=%q", status, updateErr, widenRecorder.Body.String())
		}
		denied := h.download(created.Hash, "/secret.txt")
		assertPermissionShareReadDenied(t, "creation token download ceiling", denied)
	})

	t.Run("owner Share revocation disables existing share", func(t *testing.T) {
		owner := h.newOwner(t, "share-owner-share-revoke", users.Permissions{
			Share: true, Browse: true, Preview: true, Download: true,
		})
		h.saveShare(t, owner, "owner-share-revoke", "/public", nil)
		allowed := h.download("owner-share-revoke", "/secret.txt")
		requirePermissionShareStatus(t, "share before Share revocation", allowed, http.StatusOK)

		owner.Permissions.Share = false
		h.updateOwnerPermissions(t, owner)
		denied := h.download("owner-share-revoke", "/secret.txt")
		assertPermissionShareReadDenied(t, "share after Share revocation", denied)
	})

	t.Run("owner Create revocation disables upload share", func(t *testing.T) {
		owner := h.newOwner(t, "share-owner-create-revoke", users.Permissions{Share: true, Create: true})
		h.saveShare(t, owner, "owner-create-revoke", "/public", func(common *dbshare.CommonShare) {
			common.ShareType = "upload"
			common.AllowCreate = true
		})
		first := h.request(http.MethodPost, "/public/api/resources", url.Values{
			"hash": {"owner-create-revoke"}, "path": {"/create-before-revoke.txt"},
		}, strings.NewReader("allowed before revoke"), nil)
		requirePermissionShareStatus(t, "upload before Create revocation", first, http.StatusOK)

		owner.Permissions.Create = false
		h.updateOwnerPermissions(t, owner)
		secondPath := filepath.Join(sourcePath, "public", "create-after-revoke.txt")
		second := h.request(http.MethodPost, "/public/api/resources", url.Values{
			"hash": {"owner-create-revoke"}, "path": {"/create-after-revoke.txt"},
		}, strings.NewReader("must not be created"), nil)
		assertPermissionShareStatus(t, "upload after Create revocation", second, http.StatusForbidden)
		if _, err := os.Stat(secondPath); !os.IsNotExist(err) {
			t.Fatalf("revoked upload created %s: %v", secondPath, err)
		}
	})

	t.Run("share path update reauthorizes target and rejects IDOR", func(t *testing.T) {
		owner := h.newOwner(t, "share-path-owner", users.Permissions{Share: true, Browse: true, Download: true})
		attacker := h.newOwner(t, "share-path-attacker", users.Permissions{Share: true, Browse: true, Download: true})
		link := h.saveShare(t, owner, "share-path-rebind", "/public", nil)
		if err := store.Access.DenyUser(sourcePath, "/outside-scope.txt", owner.Username); err != nil {
			t.Fatal(err)
		}

		payload := []byte(`{"hash":"share-path-rebind","path":"/outside-scope.txt"}`)
		attackerRecorder := httptest.NewRecorder()
		status, err := sharePatchHandler(attackerRecorder, httptest.NewRequest(http.MethodPatch, "/api/share", bytes.NewReader(payload)), &requestContext{user: attacker})
		if status != http.StatusForbidden || err == nil {
			t.Fatalf("non-owner path update: status=%d err=%v", status, err)
		}

		ownerRecorder := httptest.NewRecorder()
		status, err = sharePatchHandler(ownerRecorder, httptest.NewRequest(http.MethodPatch, "/api/share", bytes.NewReader(payload)), &requestContext{user: owner})
		if status != http.StatusForbidden || err == nil {
			t.Fatalf("Access-denied path update: status=%d err=%v body=%q", status, err, ownerRecorder.Body.String())
		}
		stored, loadErr := store.Share.GetByHash(link.Hash)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if normalizePublicShareIndexPath(stored.Path) != "/public" {
			t.Fatalf("rejected path update changed share root to %q", stored.Path)
		}
	})

	t.Run("share info exposes final capabilities", func(t *testing.T) {
		owner := h.newOwner(t, "share-info-cap-owner", users.Permissions{
			Share: true, Browse: true, Preview: true, Download: true,
		})
		h.saveShare(t, owner, "share-info-cap", "/public", func(common *dbshare.CommonShare) {
			common.DisableDownload = true
		})
		response := h.request(http.MethodGet, "/public/api/share/info", url.Values{"hash": {"share-info-cap"}}, nil, nil)
		requirePermissionShareStatus(t, "share info capabilities", response, http.StatusOK)
		var payload map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		capabilities, ok := payload["capabilities"].(map[string]any)
		if !ok {
			t.Fatalf("share info lacks capabilities: %s", response.Body.String())
		}
		want := map[string]bool{"browse": true, "preview": true, "download": false, "thumbnail": true, "viewer": true}
		for name, expected := range want {
			if got, exists := capabilities[name].(bool); !exists || got != expected {
				t.Errorf("capability %s: got %v, want %v", name, capabilities[name], expected)
			}
		}
	})

	t.Run("archive resume rejects same-path member replacement", func(t *testing.T) {
		owner := h.newOwner(t, "archive-identity-owner", users.Permissions{Share: true, Browse: true, Download: true})
		directory := filepath.Join(sourcePath, "public", "archive-identity")
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		memberPath := filepath.Join(directory, "member.bin")
		if err := os.WriteFile(memberPath, permissionShareNoise(128*1024), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(settings.DownloadCacheDir(), 0o755); err != nil {
			t.Fatal(err)
		}
		h.saveShare(t, owner, "archive-identity-share", "/public/archive-identity", nil)

		first := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {"archive-identity-share"}, "file": {"/"},
		}, nil, map[string]string{"Range": "bytes=0-31"})
		requirePermissionShareStatus(t, "archive identity first range", first, http.StatusPartialContent)
		token := first.Header().Get("X-Archive-Token")
		if token == "" {
			t.Fatal("archive identity response did not return X-Archive-Token")
		}
		if session, ok := archiveSpoolCache.Get(token); ok {
			t.Cleanup(func() { removeSpooledArchiveNow(token, session.tmpPath) })
		}

		if err := os.Remove(memberPath); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(memberPath, bytes.Repeat([]byte{0xA5}, 128*1024), 0o644); err != nil {
			t.Fatal(err)
		}
		resume := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {"archive-identity-share"}, "file": {"/"}, "archiveToken": {token},
		}, nil, map[string]string{"Range": "bytes=32-63"})
		assertPermissionShareReadDenied(t, "archive identity replacement", resume)
	})
}

func issueShareSecurityToken(t *testing.T, user *users.User, name string, permissions users.Permissions) string {
	t.Helper()
	tokenString, metadata, err := auth.MakeSignedTokenAPI(user, name, time.Hour, permissions, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Users.AddApiToken(user.ID, name, tokenString, metadata); err != nil {
		t.Fatal(err)
	}
	if err := store.Access.AddApiToken(tokenString, user.ID); err != nil {
		t.Fatal(err)
	}
	return tokenString
}
