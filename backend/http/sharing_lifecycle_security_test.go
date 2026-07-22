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
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
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

	t.Run("narrow token cannot rebind a wider share", func(t *testing.T) {
		owner := h.newOwner(t, "share-path-token-owner", users.Permissions{
			Api: true, Share: true, Browse: true, Preview: true, Download: true,
		})
		if err := os.MkdirAll(filepath.Join(sourcePath, "public", "rebind-target"), 0o755); err != nil {
			t.Fatal(err)
		}
		link := h.saveShare(t, owner, "share-path-token-rebind", "/public", nil)
		narrow := issueShareSecurityToken(t, owner, "share-path-narrow-token", users.Permissions{Api: true, Share: true})
		payload := []byte(`{"hash":"share-path-token-rebind","path":"/public/rebind-target"}`)
		request := httptest.NewRequest(http.MethodPatch, "/api/share", bytes.NewReader(payload))
		request.Header.Set("Authorization", "Bearer "+narrow)
		status, err := withUserHelper(sharePatchHandler)(httptest.NewRecorder(), request, &requestContext{})
		if status != http.StatusForbidden || err == nil {
			t.Fatalf("narrow token path rebind: status=%d err=%v", status, err)
		}
		stored, loadErr := store.Share.GetByHash(link.Hash)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if normalizePublicShareIndexPath(stored.Path) != "/public" {
			t.Fatalf("narrow token changed share path to %q", stored.Path)
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

	t.Run("share info enforces audience policy after token revocation", func(t *testing.T) {
		owner := h.newOwner(t, "share-info-audience-owner", users.Permissions{
			Api: true, Share: true, Browse: true,
		})
		link := h.saveShare(t, owner, "share-info-audience", "/public", func(common *dbshare.CommonShare) {
			common.DisableAnonymous = true
			common.AllowedUsernames = []string{owner.Username}
		})
		token := issueShareSecurityToken(t, owner, "share-info-audience-token", users.Permissions{
			Api: true, Share: true, Browse: true,
		})
		query := url.Values{"hash": {link.Hash}}
		allowed := h.request(http.MethodGet, "/public/api/share/info", query, nil, map[string]string{
			"Authorization": "Bearer " + token,
		})
		requirePermissionShareStatus(t, "allowed share info audience", allowed, http.StatusOK)

		if err := store.Access.RevokeToken(token); err != nil {
			t.Fatalf("revoke info token: %v", err)
		}
		revoked := h.request(http.MethodGet, "/public/api/share/info", query, nil, map[string]string{
			"Authorization": "Bearer " + token,
		})
		assertPermissionShareStatus(t, "revoked share info audience", revoked, http.StatusForbidden)
		anonymous := h.request(http.MethodGet, "/public/api/share/info", query, nil, nil)
		assertPermissionShareStatus(t, "anonymous share info audience", anonymous, http.StatusForbidden)
	})

	t.Run("future share capability version fails closed", func(t *testing.T) {
		owner := h.newOwner(t, "share-future-version-owner", users.Permissions{
			Share: true, Browse: true, Preview: true, Download: true,
		})
		link := h.saveShare(t, owner, "share-future-version", "/public", nil)
		link.CapabilityVersion = dbshare.CurrentCapabilityVersion + 1
		if err := store.Share.Save(link); err != nil {
			t.Fatalf("save future-version share: %v", err)
		}
		payload, err := json.Marshal(dbshare.CreateBody{
			Hash: link.Hash,
			CommonShare: dbshare.CommonShare{
				ShareType: "normal",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		status, updateErr := sharePostHandler(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/share", bytes.NewReader(payload)), &requestContext{user: owner})
		if status != http.StatusForbidden || updateErr == nil {
			t.Fatalf("future-version update: status=%d err=%v", status, updateErr)
		}
		stored, err := store.Share.GetByHash(link.Hash)
		if err != nil {
			t.Fatal(err)
		}
		if stored.CapabilityVersion != dbshare.CurrentCapabilityVersion+1 {
			t.Fatalf("future capability version was rewritten to %d", stored.CapabilityVersion)
		}
	})

	t.Run("legacy share requires explicit owner rebind", func(t *testing.T) {
		owner := h.newOwner(t, "legacy-share-rebind-owner", users.Permissions{
			Share: true, Browse: true, Preview: true, Download: true,
		})
		link := h.saveShare(t, owner, "legacy-share-rebind", "/public", nil)
		legacy := link.Clone()
		legacy.CapabilityVersion = 0
		legacy.CreatorCapabilities = dbshare.CapabilitySnapshot{}
		if err := store.Share.Save(legacy); err != nil {
			t.Fatalf("save legacy share: %v", err)
		}

		before := h.download(link.Hash, "/secret.txt")
		assertPermissionShareReadDenied(t, "legacy share before rebind", before)

		payload, err := json.Marshal(dbshare.CreateBody{
			Hash:        link.Hash,
			CommonShare: legacy.CommonShare,
		})
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		status, rebindErr := sharePostHandler(recorder, httptest.NewRequest(http.MethodPost, "/api/share", bytes.NewReader(payload)), &requestContext{user: owner})
		if rebindErr != nil || status != http.StatusOK {
			t.Fatalf("explicit owner rebind: status=%d err=%v body=%q", status, rebindErr, recorder.Body.String())
		}

		rebound, err := store.Share.GetByHash(link.Hash)
		if err != nil {
			t.Fatal(err)
		}
		wantCapabilities := dbshare.CapabilitiesFromPermissions(owner.Permissions)
		if rebound.CapabilityVersion != dbshare.CurrentCapabilityVersion || rebound.CreatorCapabilities != wantCapabilities {
			t.Fatalf("legacy share was not rebound to current owner capabilities: version=%d capabilities=%+v want=%+v", rebound.CapabilityVersion, rebound.CreatorCapabilities, wantCapabilities)
		}
		after := h.download(link.Hash, "/secret.txt")
		requirePermissionShareStatus(t, "legacy share after rebind", after, http.StatusOK)
		if after.Body.String() != permissionShareSecret {
			t.Fatalf("rebound legacy share returned %q", after.Body.String())
		}
	})

	t.Run("narrow caller does not reuse wider quick download share", func(t *testing.T) {
		idx := indexing.GetIndex("source1")
		if idx == nil {
			t.Fatal("source index not found")
		}
		indexingDisabled := idx.Config.ResolvedRules.IndexingDisabled
		idx.Config.ResolvedRules.IndexingDisabled = false
		t.Cleanup(func() { idx.Config.ResolvedRules.IndexingDisabled = indexingDisabled })
		if err := idx.RefreshDirectory("/public", false); err != nil {
			t.Fatalf("index quick-download fixture: %v", err)
		}
		owner := h.newOwner(t, "quick-download-owner", users.Permissions{
			Share: true, Browse: true, Preview: true, Download: true, Create: true,
		})
		existing := h.saveShare(t, owner, "quick-download-wide", "/public/secret.txt", func(common *dbshare.CommonShare) {
			common.QuickDownload = true
		})
		caller := *owner
		caller.Permissions = users.Permissions{Share: true, Browse: true, Download: true}
		request := httptest.NewRequest(http.MethodGet, "/api/share/direct?"+url.Values{
			"path":     {"/public/secret.txt"},
			"source":   {"source1"},
			"duration": {"60"},
		}.Encode(), nil)
		recorder := httptest.NewRecorder()
		status, err := shareDirectDownloadHandler(recorder, request, &requestContext{user: &caller, apiToken: true})
		if err != nil || status != http.StatusOK {
			t.Fatalf("create narrow quick share: status=%d err=%v body=%s", status, err, recorder.Body.String())
		}
		var response DirectDownloadResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Hash == existing.Hash {
			t.Fatalf("narrow caller reused wider share %q", response.Hash)
		}
		created, err := store.Share.GetByHash(response.Hash)
		if err != nil {
			t.Fatal(err)
		}
		if created.CreatorCapabilities.Preview || created.CreatorCapabilities.Create {
			t.Fatalf("quick share widened caller capabilities: %+v", created.CreatorCapabilities)
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

	t.Run("archive resume counts one download session", func(t *testing.T) {
		owner := h.newOwner(t, "archive-limit-owner", users.Permissions{Share: true, Browse: true, Download: true})
		directory := filepath.Join(sourcePath, "public", "archive-limit")
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "member.bin"), permissionShareNoise(128*1024), 0o644); err != nil {
			t.Fatal(err)
		}
		link := h.saveShare(t, owner, "archive-limit-share", "/public/archive-limit", func(common *dbshare.CommonShare) {
			common.DownloadsLimit = 1
		})
		first := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {link.Hash}, "file": {"/"},
		}, nil, map[string]string{"Range": "bytes=0-31"})
		requirePermissionShareStatus(t, "archive limit first range", first, http.StatusPartialContent)
		token := first.Header().Get("X-Archive-Token")
		if token == "" {
			t.Fatal("archive limit response did not return X-Archive-Token")
		}
		if session, ok := archiveSpoolCache.Get(token); ok {
			t.Cleanup(func() { removeSpooledArchiveNow(token, session.tmpPath) })
		}
		resume := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {link.Hash}, "file": {"/"}, "archiveToken": {token},
		}, nil, map[string]string{"Range": "bytes=32-63"})
		requirePermissionShareStatus(t, "archive limit resume", resume, http.StatusPartialContent)
		if link.Downloads != 1 {
			t.Fatalf("archive session download count: got %d, want 1", link.Downloads)
		}
		newSession := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {link.Hash}, "file": {"/"},
		}, nil, map[string]string{"Range": "bytes=0-31"})
		assertPermissionShareReadDenied(t, "archive limit new session", newSession)
	})

	t.Run("archive resume rejects in-place content replacement with restored metadata", func(t *testing.T) {
		owner := h.newOwner(t, "archive-fingerprint-owner", users.Permissions{Share: true, Browse: true, Download: true})
		directory := filepath.Join(sourcePath, "public", "archive-fingerprint")
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		memberPath := filepath.Join(directory, "member.bin")
		original := permissionShareNoise(128 * 1024)
		if err := os.WriteFile(memberPath, original, 0o644); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(memberPath)
		if err != nil {
			t.Fatal(err)
		}
		h.saveShare(t, owner, "archive-fingerprint-share", "/public/archive-fingerprint", nil)
		first := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {"archive-fingerprint-share"}, "file": {"/"},
		}, nil, map[string]string{"Range": "bytes=0-31"})
		requirePermissionShareStatus(t, "archive fingerprint first range", first, http.StatusPartialContent)
		token := first.Header().Get("X-Archive-Token")
		if token == "" {
			t.Fatal("archive fingerprint response did not return X-Archive-Token")
		}
		if session, ok := archiveSpoolCache.Get(token); ok {
			t.Cleanup(func() { removeSpooledArchiveNow(token, session.tmpPath) })
		}

		replacement := bytes.Repeat([]byte{0x5A}, len(original))
		if err := os.WriteFile(memberPath, replacement, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(memberPath, before.ModTime(), before.ModTime()); err != nil {
			t.Fatal(err)
		}
		after, err := os.Stat(memberPath)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			t.Fatalf("fingerprint fixture did not preserve identity: before=%+v after=%+v", before, after)
		}
		resume := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {"archive-fingerprint-share"}, "file": {"/"}, "archiveToken": {token},
		}, nil, map[string]string{"Range": "bytes=32-63"})
		assertPermissionShareReadDenied(t, "archive in-place replacement", resume)
	})

	t.Run("archive audience revocation permanently invalidates the session", func(t *testing.T) {
		owner := h.newOwner(t, "archive-audience-owner", users.Permissions{Share: true, Browse: true, Download: true})
		directory := filepath.Join(sourcePath, "public", "archive-audience")
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "member.bin"), permissionShareNoise(128*1024), 0o644); err != nil {
			t.Fatal(err)
		}
		link := h.saveShare(t, owner, "archive-audience-share", "/public/archive-audience", nil)
		first := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {link.Hash}, "file": {"/"},
		}, nil, map[string]string{"Range": "bytes=0-31"})
		requirePermissionShareStatus(t, "archive audience first range", first, http.StatusPartialContent)
		token := first.Header().Get("X-Archive-Token")
		if token == "" {
			t.Fatal("archive audience response did not return X-Archive-Token")
		}
		if session, ok := archiveSpoolCache.Get(token); ok {
			t.Cleanup(func() { removeSpooledArchiveNow(token, session.tmpPath) })
		}

		revoked := link.Clone()
		revoked.DisableAnonymous = true
		if err := store.Share.Save(revoked); err != nil {
			t.Fatal(err)
		}
		query := url.Values{"hash": {link.Hash}, "file": {"/"}, "archiveToken": {token}}
		denied := h.request(http.MethodGet, "/public/api/resources/download", query, nil, map[string]string{"Range": "bytes=32-63"})
		assertPermissionShareReadDenied(t, "archive audience revocation", denied)
		if _, ok := archiveSpoolCache.Get(token); ok {
			t.Error("audience revocation retained the archive session")
		}

		restored := revoked.Clone()
		restored.DisableAnonymous = false
		if err := store.Share.Save(restored); err != nil {
			t.Fatal(err)
		}
		resumed := h.request(http.MethodGet, "/public/api/resources/download", query, nil, map[string]string{"Range": "bytes=32-63"})
		assertPermissionShareReadDenied(t, "archive audience regrant", resumed)
	})

	t.Run("archive token cannot survive same-hash share recreation", func(t *testing.T) {
		owner := h.newOwner(t, "archive-recreate-owner", users.Permissions{Share: true, Browse: true, Download: true})
		directory := filepath.Join(sourcePath, "public", "archive-recreate")
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "member.bin"), permissionShareNoise(128*1024), 0o644); err != nil {
			t.Fatal(err)
		}
		link := h.saveShare(t, owner, "archive-recreate-share", "/public/archive-recreate", nil)
		first := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {link.Hash}, "file": {"/"},
		}, nil, map[string]string{"Range": "bytes=0-31"})
		requirePermissionShareStatus(t, "archive recreation first range", first, http.StatusPartialContent)
		token := first.Header().Get("X-Archive-Token")
		if token == "" {
			t.Fatal("archive recreation response did not return X-Archive-Token")
		}
		if session, ok := archiveSpoolCache.Get(token); ok {
			t.Cleanup(func() { removeSpooledArchiveNow(token, session.tmpPath) })
		}
		if err := store.Share.Delete(link.Hash); err != nil {
			t.Fatal(err)
		}
		h.saveShare(t, owner, link.Hash, "/public/archive-recreate", nil)
		resume := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {link.Hash}, "file": {"/"}, "archiveToken": {token},
		}, nil, map[string]string{"Range": "bytes=32-63"})
		assertPermissionShareReadDenied(t, "archive same-hash recreation", resume)
	})

	t.Run("invalid archive format does not consume the download limit", func(t *testing.T) {
		owner := h.newOwner(t, "archive-format-limit-owner", users.Permissions{Share: true, Browse: true, Download: true})
		directory := filepath.Join(sourcePath, "public", "archive-format-limit")
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "member.bin"), permissionShareNoise(128*1024), 0o644); err != nil {
			t.Fatal(err)
		}
		link := h.saveShare(t, owner, "archive-format-limit-share", "/public/archive-format-limit", func(common *dbshare.CommonShare) {
			common.DownloadsLimit = 1
		})
		invalid := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {link.Hash}, "file": {"/"}, "algo": {"invalid"},
		}, nil, map[string]string{"Range": "bytes=0-31"})
		if invalid.Code < http.StatusBadRequest {
			t.Fatalf("invalid archive format status: got %d, want failure", invalid.Code)
		}
		if link.Downloads != 0 {
			t.Fatalf("invalid archive format consumed downloads: got %d, want 0", link.Downloads)
		}
		valid := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {link.Hash}, "file": {"/"},
		}, nil, map[string]string{"Range": "bytes=0-31"})
		requirePermissionShareStatus(t, "valid archive after invalid format", valid, http.StatusPartialContent)
		if token := valid.Header().Get("X-Archive-Token"); token != "" {
			if session, ok := archiveSpoolCache.Get(token); ok {
				removeSpooledArchiveNow(token, session.tmpPath)
			}
		}
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
