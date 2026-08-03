package http

import (
	"bytes"
	"encoding/json"
	"errors"
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	dbshare "github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
)

const (
	auditSharePasswordSecret     = "AUDIT-SHARE-PASSWORD-SECRET"
	auditSharePasswordHashSecret = "AUDIT-SHARE-PASSWORD-HASH-SECRET"
	auditShareLegacyTokenSecret  = "AUDIT-SHARE-LEGACY-TOKEN-SECRET"
	auditShareURLSecret          = "AUDIT-SHARE-URL-SECRET"
)

func TestAuditShareActionsSuccessAndSecretBoundary(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		fixture := newAuditShareTestFixture(t, nil)
		owner := fixture.newUser(t, "audit-share-create-owner", auditShareFullPermissions())
		session := auditTokenSession(t, owner)
		body := auditShareCreateBody("source1", "/public")
		password := auditSharePasswordSecret
		body.Password = &password
		body.DownloadURL = "https://download.invalid/" + auditShareURLSecret
		body.ShareURL = "https://share.invalid/" + auditShareURLSecret

		pendingBeforeMutation := false
		fixture.auditStore.onCreate = func(event auditdb.Event) {
			shares, _ := store.Share.All()
			pendingBeforeMutation = len(shares) == 0
			if event.Action != auditdb.ActionShareCreate {
				t.Errorf("pending create action: got %q", event.Action)
			}
		}
		response := fixture.request(t, stdhttp.MethodPost, "/api/share", mustJSON(t, body), session)
		if response.Code != stdhttp.StatusOK {
			t.Fatalf("create status: got %d, want 200; body=%s", response.Code, response.Body.String())
		}
		var created ShareResponse
		if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil || created.Hash == "" {
			t.Fatalf("decode created share: hash=%q err=%v body=%s", created.Hash, err, response.Body.String())
		}
		if !pendingBeforeMutation {
			t.Error("create side effect was not proven to occur after pending reservation")
		}
		stored, err := store.Share.GetByHash(created.Hash)
		if err != nil {
			t.Fatal("load created share")
		}
		event := fixture.requireReservedTerminal(t)
		assertAuditShareTerminal(t, event, auditdb.ActionShareCreate, owner, created.Hash, "source1", stored.Path, stdhttp.StatusOK)
		assertAuditShareSecretsAbsent(t, event, created.Hash, auditSharePasswordSecret, stored.PasswordHash,
			auditShareURLSecret, session, fixture.sourcePath)
	})

	t.Run("post update", func(t *testing.T) {
		fixture := newAuditShareTestFixture(t, nil)
		owner := fixture.newUser(t, "audit-share-post-update-owner", auditShareFullPermissions())
		session := auditTokenSession(t, owner)
		const shareHash = "AUDIT-SHARE-POST-UPDATE-HASH-SECRET"
		link := fixture.saveShare(t, owner, shareHash, "/public/")
		link.Title = "before-update"
		link.PasswordHash = auditSharePasswordHashSecret
		link.Token = auditShareLegacyTokenSecret
		if err := store.Share.Save(link); err != nil {
			t.Fatal("save update secrets")
		}

		body := auditShareCreateBody("ignored-source", "/ignored-path")
		body.Hash = shareHash
		body.Title = "after-update"
		password := auditSharePasswordSecret
		body.Password = &password
		body.DownloadURL = "https://download.invalid/" + auditShareURLSecret
		body.ShareURL = "https://share.invalid/" + auditShareURLSecret
		pendingBeforeMutation := false
		fixture.auditStore.onCreate = func(event auditdb.Event) {
			stored, err := store.Share.GetByHash(shareHash)
			pendingBeforeMutation = err == nil && stored.Title == "before-update" &&
				stored.PasswordHash == auditSharePasswordHashSecret && stored.Token == auditShareLegacyTokenSecret
			if event.Action != auditdb.ActionShareUpdate {
				t.Errorf("pending post-update action: got %q", event.Action)
			}
		}
		response := fixture.request(t, stdhttp.MethodPost, "/api/share", mustJSON(t, body), session)
		if response.Code != stdhttp.StatusOK {
			t.Fatalf("post update status: got %d, want 200; body=%s", response.Code, response.Body.String())
		}
		if !pendingBeforeMutation {
			t.Error("post update side effect was not proven to occur after pending reservation")
		}
		stored, err := store.Share.GetByHash(shareHash)
		if err != nil || stored.Title != "after-update" {
			t.Fatalf("post update state: title=%q err=%v", stored.Title, err)
		}
		event := fixture.requireReservedTerminal(t)
		assertAuditShareTerminal(t, event, auditdb.ActionShareUpdate, owner, shareHash, "source1", stored.Path, stdhttp.StatusOK)
		assertAuditShareSecretsAbsent(t, event, shareHash, auditSharePasswordSecret, auditSharePasswordHashSecret,
			auditShareLegacyTokenSecret, auditShareURLSecret, session, fixture.sourcePath)
	})

	t.Run("patch path", func(t *testing.T) {
		fixture := newAuditShareTestFixture(t, nil)
		owner := fixture.newUser(t, "audit-share-patch-owner", auditShareFullPermissions())
		session := auditTokenSession(t, owner)
		const shareHash = "AUDIT-SHARE-PATCH-HASH-SECRET"
		fixture.saveShare(t, owner, shareHash, "/public/")
		if err := os.MkdirAll(filepath.Join(fixture.sourcePath, "public", "moved"), 0o755); err != nil {
			t.Fatal("create patch target")
		}
		pendingBeforeMutation := false
		fixture.auditStore.onCreate = func(event auditdb.Event) {
			stored, err := store.Share.GetByHash(shareHash)
			pendingBeforeMutation = err == nil && normalizePublicShareIndexPath(stored.Path) == "/public"
		}
		response := fixture.request(t, stdhttp.MethodPatch, "/api/share", mustJSON(t, map[string]string{
			"hash": shareHash,
			"path": "/public/moved",
		}), session)
		if response.Code != stdhttp.StatusOK {
			t.Fatalf("patch status: got %d, want 200; body=%s", response.Code, response.Body.String())
		}
		if !pendingBeforeMutation {
			t.Error("patch side effect was not proven to occur after pending reservation")
		}
		stored, err := store.Share.GetByHash(shareHash)
		if err != nil || normalizePublicShareIndexPath(stored.Path) != "/public/moved" {
			t.Fatalf("patch state: path=%q err=%v", stored.Path, err)
		}
		event := fixture.requireReservedTerminal(t)
		assertAuditShareTerminal(t, event, auditdb.ActionShareUpdate, owner, shareHash, "source1", stored.Path, stdhttp.StatusOK)
		assertAuditShareSecretsAbsent(t, event, shareHash, session, fixture.sourcePath)
	})

	t.Run("delete", func(t *testing.T) {
		fixture := newAuditShareTestFixture(t, nil)
		owner := fixture.newUser(t, "audit-share-delete-owner", auditShareFullPermissions())
		session := auditTokenSession(t, owner)
		const shareHash = "AUDIT-SHARE-DELETE-HASH-SECRET"
		link := fixture.saveShare(t, owner, shareHash, "/public/")
		link.PasswordHash = auditSharePasswordHashSecret
		link.Token = auditShareLegacyTokenSecret
		if err := store.Share.Save(link); err != nil {
			t.Fatal("save delete secrets")
		}
		pendingBeforeMutation := false
		fixture.auditStore.onCreate = func(event auditdb.Event) {
			stored, err := store.Share.GetByHash(shareHash)
			pendingBeforeMutation = err == nil && stored.Token == auditShareLegacyTokenSecret
		}
		path := "/api/share?" + url.Values{"hash": {shareHash}}.Encode()
		response := fixture.request(t, stdhttp.MethodDelete, path, nil, session)
		if response.Code != stdhttp.StatusOK {
			t.Fatalf("delete status: got %d, want 200; body=%s", response.Code, response.Body.String())
		}
		if !pendingBeforeMutation {
			t.Error("delete side effect was not proven to occur after pending reservation")
		}
		if _, err := store.Share.GetByHash(shareHash); err == nil {
			t.Fatal("delete left the share in storage")
		}
		event := fixture.requireReservedTerminal(t)
		assertAuditShareTerminal(t, event, auditdb.ActionShareDelete, owner, shareHash, "source1", link.Path, stdhttp.StatusOK)
		assertAuditShareSecretsAbsent(t, event, shareHash, auditSharePasswordHashSecret,
			auditShareLegacyTokenSecret, session, fixture.sourcePath)
	})

	t.Run("direct quick share create", func(t *testing.T) {
		fixture := newAuditShareTestFixture(t, nil)
		owner := fixture.newUser(t, "audit-share-direct-owner", auditShareFullPermissions())
		session := auditTokenSession(t, owner)
		logicalPath := fixture.prepareDirectFile(t, "direct-audit.txt")
		pendingBeforeMutation := false
		fixture.auditStore.onCreate = func(event auditdb.Event) {
			shares, _ := store.Share.All()
			pendingBeforeMutation = len(shares) == 0
		}
		path := "/api/share/direct?" + url.Values{
			"path":     {logicalPath},
			"source":   {"source1"},
			"duration": {"60"},
		}.Encode()
		response := fixture.request(t, stdhttp.MethodGet, path, nil, session)
		if response.Code != stdhttp.StatusOK {
			t.Fatalf("direct create status: got %d, want 200; body=%s", response.Code, response.Body.String())
		}
		var created DirectDownloadResponse
		if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil || created.Hash == "" {
			t.Fatalf("decode direct share: hash=%q err=%v body=%s", created.Hash, err, response.Body.String())
		}
		if !pendingBeforeMutation {
			t.Error("direct create side effect was not proven to occur after pending reservation")
		}
		event := fixture.requireReservedTerminal(t)
		assertAuditShareTerminal(t, event, auditdb.ActionShareCreate, owner, created.Hash, "source1", logicalPath, stdhttp.StatusOK)
		assertAuditShareSecretsAbsent(t, event, created.Hash, created.DownloadURL, created.ShareURL, session, fixture.sourcePath)
	})
}

func TestAuditSharePermissionDenied(t *testing.T) {
	fixture := newAuditShareTestFixture(t, nil)
	deniedUser := fixture.newUser(t, "audit-share-permission-denied", users.Permissions{Browse: true, Preview: true, Download: true})
	session := auditTokenSession(t, deniedUser)
	body := auditShareCreateBody("source1", "/public")
	password := auditSharePasswordSecret
	body.Password = &password

	response := fixture.request(t, stdhttp.MethodPost, "/api/share", mustJSON(t, body), session)
	if response.Code != stdhttp.StatusForbidden {
		t.Fatalf("permission denied status: got %d, want 403; body=%s", response.Code, response.Body.String())
	}
	shares, _ := store.Share.All()
	if len(shares) != 0 {
		t.Fatal("permission denied request created a share")
	}
	creates, finalizes, appends, pending, terminal := fixture.auditStore.state()
	if creates != 0 || finalizes != 0 || appends != 1 || pending != 0 || terminal != 1 {
		t.Errorf("denied audit lifecycle: create=%d finalize=%d append=%d pending=%d terminal=%d",
			creates, finalizes, appends, pending, terminal)
	}
	event := fixture.auditStore.singleAppended(t)
	assertAuditShareTerminal(t, event, auditdb.ActionShareCreate, deniedUser, "", "", "", stdhttp.StatusForbidden)
	assertAuditShareSecretsAbsent(t, event, auditSharePasswordSecret, session, fixture.sourcePath)
}

func TestAuditShareReservationFailureHasZeroSideEffects(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		fixture := newFailingAuditShareTestFixture(t)
		owner := fixture.newUser(t, "audit-share-create-reservation", auditShareFullPermissions())
		response := fixture.request(t, stdhttp.MethodPost, "/api/share",
			mustJSON(t, auditShareCreateBody("source1", "/public")), auditTokenSession(t, owner))
		fixture.assertReservationFailure(t, response)
		shares, _ := store.Share.All()
		if len(shares) != 0 {
			t.Fatal("create reservation failure produced a share")
		}
	})

	t.Run("post update", func(t *testing.T) {
		fixture := newFailingAuditShareTestFixture(t)
		owner := fixture.newUser(t, "audit-share-update-reservation", auditShareFullPermissions())
		const shareHash = "AUDIT-SHARE-UPDATE-RESERVATION-HASH"
		link := fixture.saveShare(t, owner, shareHash, "/public/")
		link.Title = "before-reservation"
		if err := store.Share.Save(link); err != nil {
			t.Fatal("save update reservation fixture")
		}
		body := auditShareCreateBody("ignored-source", "/ignored-path")
		body.Hash = shareHash
		body.Title = "after-reservation"
		response := fixture.request(t, stdhttp.MethodPost, "/api/share", mustJSON(t, body), auditTokenSession(t, owner))
		fixture.assertReservationFailure(t, response)
		stored, err := store.Share.GetByHash(shareHash)
		if err != nil || stored.Title != "before-reservation" {
			t.Fatalf("update reservation failure changed share: title=%q err=%v", stored.Title, err)
		}
	})

	t.Run("patch", func(t *testing.T) {
		fixture := newFailingAuditShareTestFixture(t)
		owner := fixture.newUser(t, "audit-share-patch-reservation", auditShareFullPermissions())
		const shareHash = "AUDIT-SHARE-PATCH-RESERVATION-HASH"
		fixture.saveShare(t, owner, shareHash, "/public/")
		if err := os.MkdirAll(filepath.Join(fixture.sourcePath, "public", "reservation-target"), 0o755); err != nil {
			t.Fatal("create reservation patch target")
		}
		response := fixture.request(t, stdhttp.MethodPatch, "/api/share", mustJSON(t, map[string]string{
			"hash": shareHash,
			"path": "/public/reservation-target",
		}), auditTokenSession(t, owner))
		fixture.assertReservationFailure(t, response)
		stored, err := store.Share.GetByHash(shareHash)
		if err != nil || normalizePublicShareIndexPath(stored.Path) != "/public" {
			t.Fatalf("patch reservation failure changed path: path=%q err=%v", stored.Path, err)
		}
	})

	t.Run("delete", func(t *testing.T) {
		fixture := newFailingAuditShareTestFixture(t)
		owner := fixture.newUser(t, "audit-share-delete-reservation", auditShareFullPermissions())
		const shareHash = "AUDIT-SHARE-DELETE-RESERVATION-HASH"
		fixture.saveShare(t, owner, shareHash, "/public/")
		path := "/api/share?" + url.Values{"hash": {shareHash}}.Encode()
		response := fixture.request(t, stdhttp.MethodDelete, path, nil, auditTokenSession(t, owner))
		fixture.assertReservationFailure(t, response)
		if _, err := store.Share.GetByHash(shareHash); err != nil {
			t.Fatal("delete reservation failure removed the share")
		}
	})

	t.Run("direct quick share", func(t *testing.T) {
		fixture := newFailingAuditShareTestFixture(t)
		owner := fixture.newUser(t, "audit-share-direct-reservation", auditShareFullPermissions())
		logicalPath := fixture.prepareDirectFile(t, "reservation-direct.txt")
		path := "/api/share/direct?" + url.Values{
			"path":     {logicalPath},
			"source":   {"source1"},
			"duration": {"60"},
		}.Encode()
		response := fixture.request(t, stdhttp.MethodGet, path, nil, auditTokenSession(t, owner))
		fixture.assertReservationFailure(t, response)
		shares, _ := store.Share.All()
		if len(shares) != 0 {
			t.Fatal("direct reservation failure produced a share")
		}
	})
}

type auditShareTestFixture struct {
	sourcePath string
	auditStore *observingAuditShareStore
	service    *AuditService
	handler    stdhttp.Handler
}

type observingAuditShareStore struct {
	*auditStoreStub
	onCreate func(auditdb.Event)
}

func (store *observingAuditShareStore) CreatePending(event auditdb.Event) error {
	if err := store.auditStoreStub.CreatePending(event); err != nil {
		return err
	}
	if store.onCreate != nil {
		store.onCreate(cloneAuditEvent(event))
	}
	return nil
}

func (store *observingAuditShareStore) state() (creates, finalizes, appends, pending, terminal int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.createCalls, store.finalizeCalls, store.appendCalls, len(store.pending), len(store.appended)
}

func newAuditShareTestFixture(t *testing.T, auditStore *observingAuditShareStore) *auditShareTestFixture {
	t.Helper()
	sourcePath := setupResourcePutTestEnv(t)
	if auditStore == nil {
		auditStore = &observingAuditShareStore{auditStoreStub: newAuditStoreStub()}
	}
	service := NewAuditService(auditStore)
	previousAuditRuntime := auditRuntime
	previousConfigAuth := config.Auth
	previousSettingsAuth := settings.Config.Auth
	testAuth := settings.Auth{Key: "audit-share-actions-signing-key"}
	auditRuntime = service
	config.Auth = testAuth
	settings.Config.Auth = testAuth
	t.Cleanup(func() {
		auditRuntime = previousAuditRuntime
		config.Auth = previousConfigAuth
		settings.Config.Auth = previousSettingsAuth
	})

	api := stdhttp.NewServeMux()
	api.HandleFunc("POST /share", auditShareTestRoute(auditdb.ActionShareCreate, sharePostHandler))
	api.HandleFunc("PATCH /share", auditShareTestRoute(auditdb.ActionShareUpdate, sharePatchHandler))
	api.HandleFunc("DELETE /share", auditShareTestRoute(auditdb.ActionShareDelete, shareDeleteHandler))
	api.HandleFunc("GET /share/direct", auditShareTestRoute(auditdb.ActionShareCreate, shareDirectDownloadHandler))
	root := stdhttp.NewServeMux()
	root.Handle("/api/", stdhttp.StripPrefix("/api", api))

	return &auditShareTestFixture{
		sourcePath: sourcePath,
		auditStore: auditStore,
		service:    service,
		handler:    AuditMiddleware(LoggingMiddleware(root), service),
	}
}

func newFailingAuditShareTestFixture(t *testing.T) *auditShareTestFixture {
	t.Helper()
	auditStore := &observingAuditShareStore{auditStoreStub: newAuditStoreStub()}
	auditStore.createErr = errors.New("forced share audit reservation failure")
	return newAuditShareTestFixture(t, auditStore)
}

func auditShareTestRoute(action auditdb.Action, handler handleFunc) stdhttp.HandlerFunc {
	permissionChecked := func(w stdhttp.ResponseWriter, r *stdhttp.Request, data *requestContext) (int, error) {
		if !data.user.Permissions.Share {
			return stdhttp.StatusForbidden, nil
		}
		return handler(w, r, data)
	}
	return withAuditDefaultAction(action, withUserHelper(withAuditAuthenticatedUser(permissionChecked)))
}

func (fixture *auditShareTestFixture) newUser(t *testing.T, username string, permissions users.Permissions) *users.User {
	t.Helper()
	user := &users.User{
		Username:    username,
		Permissions: permissions,
		Scopes: []users.SourceScope{
			{Name: fixture.sourcePath, Scope: "/"},
		},
	}
	if err := store.Users.Save(user, false, false); err != nil {
		t.Fatalf("save audit share user: %v", err)
	}
	if err := store.Access.AllowUser(fixture.sourcePath, "/", username); err != nil {
		t.Fatalf("allow audit share user on source: %v", err)
	}
	return user
}

func (fixture *auditShareTestFixture) saveShare(t *testing.T, owner *users.User, hash, path string) *dbshare.Link {
	t.Helper()
	link := &dbshare.Link{
		Hash:   hash,
		UserID: owner.ID,
		CommonShare: dbshare.CommonShare{
			Source:    fixture.sourcePath,
			Path:      path,
			ShareType: "normal",
		},
		Version:             1,
		CapabilityVersion:   dbshare.CurrentCapabilityVersion,
		CreatorCapabilities: dbshare.CapabilitiesFromPermissions(owner.Permissions),
	}
	if err := store.Share.Save(link); err != nil {
		t.Fatalf("save audit share fixture: %v", err)
	}
	return link
}

func (fixture *auditShareTestFixture) prepareDirectFile(t *testing.T, name string) string {
	t.Helper()
	logicalPath := "/public/" + name
	if err := os.WriteFile(filepath.Join(fixture.sourcePath, "public", name), []byte("audit direct fixture"), 0o644); err != nil {
		t.Fatalf("write direct share fixture: %v", err)
	}
	idx := indexing.GetIndex("source1")
	if idx == nil {
		t.Fatal("source index not found")
	}
	indexingDisabled := idx.Config.ResolvedRules.IndexingDisabled
	idx.Config.ResolvedRules.IndexingDisabled = false
	t.Cleanup(func() { idx.Config.ResolvedRules.IndexingDisabled = indexingDisabled })
	if err := idx.RefreshDirectory("/public", false); err != nil {
		t.Fatalf("index direct share fixture: %v", err)
	}
	return logicalPath
}

func (fixture *auditShareTestFixture) request(t *testing.T, method, path string, payload []byte, session string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	if session != "" {
		request.AddCookie(&stdhttp.Cookie{Name: "filebrowser_quantum_jwt", Value: session})
	}
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	return response
}

func (fixture *auditShareTestFixture) requireReservedTerminal(t *testing.T) auditdb.Event {
	t.Helper()
	creates, finalizes, appends, pending, terminal := fixture.auditStore.state()
	if creates != 1 || finalizes != 1 || appends != 0 || pending != 0 || terminal != 1 {
		t.Errorf("audit lifecycle: create=%d finalize=%d append=%d pending=%d terminal=%d",
			creates, finalizes, appends, pending, terminal)
	}
	return fixture.auditStore.singleAppended(t)
}

func (fixture *auditShareTestFixture) assertReservationFailure(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != stdhttp.StatusServiceUnavailable {
		t.Errorf("reservation failure status: got %d, want 503; body=%s", response.Code, response.Body.String())
	}
	if !fixture.service.IsDegraded() || fixture.service.LastFailureCategory() != AuditFailureReservation {
		t.Errorf("reservation degraded state: got %t/%q", fixture.service.IsDegraded(), fixture.service.LastFailureCategory())
	}
	creates, finalizes, appends, pending, terminal := fixture.auditStore.state()
	if creates != 1 || finalizes != 0 || appends != 0 || pending != 0 || terminal != 0 {
		t.Errorf("reservation audit state: create=%d finalize=%d append=%d pending=%d terminal=%d",
			creates, finalizes, appends, pending, terminal)
	}
}

func auditShareFullPermissions() users.Permissions {
	return users.Permissions{
		Api: true, Share: true, Browse: true, Preview: true, Download: true,
		Create: true, Modify: true, Delete: true,
	}
}

func auditShareCreateBody(source, path string) dbshare.CreateBody {
	return dbshare.CreateBody{CommonShare: dbshare.CommonShare{
		Source: source, Path: path, ShareType: "normal",
	}}
}

func assertAuditShareTerminal(
	t *testing.T,
	event auditdb.Event,
	action auditdb.Action,
	actor *users.User,
	shareHash, source, path string,
	status int,
) {
	t.Helper()
	if event.Action != action || event.Result != classifyAuditResult(status, false, false) {
		t.Errorf("terminal action/result: got %q/%q, want %q/%q",
			event.Action, event.Result, action, classifyAuditResult(status, false, false))
	}
	if event.HTTPStatus == nil || *event.HTTPStatus != status {
		t.Errorf("terminal HTTP status: got %v, want %d", event.HTTPStatus, status)
	}
	if event.UserID == nil || *event.UserID != actor.ID || event.Username != actor.Username {
		t.Errorf("terminal actor: id=%v username=%q, want %d/%q", event.UserID, event.Username, actor.ID, actor.Username)
	}
	if event.AuthMethod != auditdb.AuthMethodSession || event.TokenRef != "" {
		t.Errorf("terminal authentication: method=%q tokenRef=%q", event.AuthMethod, event.TokenRef)
	}
	wantPermissions := auditPermissions(actor.Permissions)
	if event.EffectivePermissions == nil || *event.EffectivePermissions != wantPermissions {
		t.Errorf("terminal effective permissions: got %+v, want %+v", event.EffectivePermissions, wantPermissions)
	}
	if shareHash != "" {
		wantRef := auditdb.DeriveShareRef(shareHash)
		if event.ShareRef != wantRef || event.ShareRef == shareHash {
			t.Errorf("terminal ShareRef: got %q, want derived %q", event.ShareRef, wantRef)
		}
	}
	if event.Source != source {
		t.Errorf("terminal source: got %q, want %q", event.Source, source)
	}
	if path != "" && normalizePublicShareIndexPath(event.Path) != normalizePublicShareIndexPath(path) {
		t.Errorf("terminal logical path: got %q, want %q", event.Path, path)
	}
}

func assertAuditShareSecretsAbsent(t *testing.T, event auditdb.Event, secrets ...string) {
	t.Helper()
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal("marshal audit share event")
	}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		candidates := []string{
			secret,
			filepath.ToSlash(secret),
			strings.ReplaceAll(secret, `\`, `\\`),
		}
		for _, candidate := range candidates {
			if candidate != "" && bytes.Contains(data, []byte(candidate)) {
				t.Errorf("audit event leaked forbidden value %q: %s", secret, data)
				break
			}
		}
	}
}
