package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	storm "github.com/asdine/storm/v3"
	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	"github.com/gtsteffaniak/filebrowser/backend/database/storage/bolt"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	logpkg "github.com/gtsteffaniak/go-logger/logger"
	bbolt "go.etcd.io/bbolt"
)

func TestAuditTokenCreateLifecycle(t *testing.T) {
	t.Run("session success reserves before token side effects", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		fixture := newAuditTokenHTTPFixture(t, func(auditdb.Store, *storm.DB) auditdb.Store {
			return auditStore
		})
		permissions := users.Permissions{Api: true, Create: true, Browse: true, Download: true}
		user := savePermissionContractUser(t, "audit-token-create-success", permissions)
		session := auditTokenSession(t, user)
		pendingObserved := false
		auditStore.onCreate = func(event auditdb.Event) {
			pendingObserved = true
			stored, err := store.Users.Get(user.ID)
			if err != nil {
				t.Error("load user while observing token reservation")
				return
			}
			if _, exists := stored.Tokens["audit-create-success"]; exists {
				t.Error("token metadata existed before audit reservation completed")
			}
			assertAuditTokenPending(t, event, auditdb.ActionTokenCreate, user, auditdb.AuthMethodSession, permissions, "")
		}

		response := fixture.request(t, stdhttp.MethodPost, auditTokenCreatePath("audit-create-success", "api,browse", "1"), session, true)
		if response.status != stdhttp.StatusOK {
			t.Fatalf("create status: got %d, want 200", response.status)
		}
		if response.header.Get("Cache-Control") != "no-store" {
			t.Errorf("create response is missing Cache-Control: no-store")
		}
		createdToken := decodeAuditTokenResponse(t, response.body).Token
		if createdToken == "" {
			t.Fatal("create response did not return the one-time token")
		}
		if !pendingObserved {
			t.Fatal("create request did not reserve a pending audit event")
		}
		stored, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal("load created token owner")
		}
		metadata, exists := stored.Tokens["audit-create-success"]
		if !exists {
			t.Fatal("created token metadata was not persisted")
		}
		createdHash := utils.HashSHA256(createdToken)
		if !metadata.MatchesTokenHash(createdHash) || !store.Access.IsApiTokenHashActive(createdHash, user.ID) {
			t.Fatal("created token metadata and access mapping are not active")
		}

		event := auditStore.singleAppended(t)
		assertAuditTokenTerminal(t, event, auditdb.ActionTokenCreate, auditdb.ResultSuccess, stdhttp.StatusOK,
			user, auditdb.AuthMethodSession, permissions, "", "")
		assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 1, 1, 0, 0, 1)
		assertNamedSecretsAbsent(t, mustJSON(t, event), []namedAuditSecret{
			{name: "created bearer", value: createdToken},
			{name: "created token hash", value: createdHash},
			{name: "created token prefix", value: metadata.TokenPrefix},
			{name: "token name", value: "audit-create-success"},
		})
	})

	t.Run("unauthenticated request is denied", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		fixture := newAuditTokenStubFixture(t, auditStore)
		response := fixture.request(t, stdhttp.MethodPost, auditTokenCreatePath("unauthenticated-child", "api", "1"), "", false)
		if response.status != stdhttp.StatusUnauthorized {
			t.Fatalf("unauthenticated create status: got %d, want 401", response.status)
		}
		event := auditStore.singleAppended(t)
		assertAuditTokenTerminal(t, event, auditdb.ActionTokenDenied, auditdb.ResultDenied, stdhttp.StatusUnauthorized,
			nil, auditdb.AuthMethodAnonymous, users.Permissions{}, "", auditErrorCodeAuthenticationRequired)
		assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 0, 0, 1, 0, 1)
	})

	t.Run("session without API permission is denied", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		fixture := newAuditTokenStubFixture(t, auditStore)
		permissions := users.Permissions{Browse: true, Download: true}
		user := savePermissionContractUser(t, "audit-token-create-no-api", permissions)
		session := auditTokenSession(t, user)
		response := fixture.request(t, stdhttp.MethodPost, auditTokenCreatePath("no-api-child", "browse", "1"), session, true)
		if response.status != stdhttp.StatusForbidden {
			t.Fatalf("no-API create status: got %d, want 403", response.status)
		}
		stored, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal("load denied token owner")
		}
		if len(stored.Tokens) != 0 {
			t.Fatal("no-API request created token metadata")
		}
		event := auditStore.singleAppended(t)
		assertAuditTokenTerminal(t, event, auditdb.ActionTokenDenied, auditdb.ResultDenied, stdhttp.StatusForbidden,
			user, auditdb.AuthMethodSession, permissions, "", auditErrorCodeAPIPermissionRequired)
		assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 0, 0, 1, 0, 1)
	})

	t.Run("API token chaining is denied with intersected permissions", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		fixture := newAuditTokenStubFixture(t, auditStore)
		userPermissions := users.Permissions{Api: true, Browse: true, Download: true}
		user := savePermissionContractUser(t, "audit-token-create-chaining", userPermissions)
		parentPermissions := users.Permissions{Api: true, Browse: true}
		parent, parentHash := persistAuditAPIToken(t, user, "audit-parent-token", parentPermissions)
		response := fixture.request(t, stdhttp.MethodPost, auditTokenCreatePath("forbidden-child", "api", "1"), parent, false)
		if response.status != stdhttp.StatusForbidden {
			t.Fatalf("token chaining status: got %d, want 403", response.status)
		}
		stored, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal("load token chaining owner")
		}
		if len(stored.Tokens) != 1 {
			t.Fatal("token chaining changed token metadata")
		}
		wantRef := auditdb.DeriveTokenRef(parentHash)
		event := auditStore.singleAppended(t)
		assertAuditTokenTerminal(t, event, auditdb.ActionTokenDenied, auditdb.ResultDenied, stdhttp.StatusForbidden,
			user, auditdb.AuthMethodToken, parentPermissions, wantRef, auditErrorCodeTokenChainingDenied)
		assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 0, 0, 1, 0, 1)
		assertNamedSecretsAbsent(t, mustJSON(t, event), []namedAuditSecret{
			{name: "parent bearer", value: parent},
			{name: "parent token hash", value: parentHash},
		})
	})

	t.Run("authorized invalid parameters are create failures without pending", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		fixture := newAuditTokenStubFixture(t, auditStore)
		permissions := users.Permissions{Api: true, Browse: true}
		user := savePermissionContractUser(t, "audit-token-create-invalid", permissions)
		session := auditTokenSession(t, user)
		response := fixture.request(t, stdhttp.MethodPost, "/api/auth/token?days=1&permissions=api", session, true)
		if response.status != stdhttp.StatusBadRequest {
			t.Fatalf("invalid create status: got %d, want 400", response.status)
		}
		event := auditStore.singleAppended(t)
		assertAuditTokenTerminal(t, event, auditdb.ActionTokenCreate, auditdb.ResultFailed, stdhttp.StatusBadRequest,
			user, auditdb.AuthMethodSession, permissions, "", auditErrorCodeInvalidTokenRequest)
		assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 0, 0, 1, 0, 1)
	})

	t.Run("reservation failure returns 503 with zero token side effects", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		auditStore.createErr = errors.New("AUDIT-RESERVATION-INTERNAL-SECRET")
		fixture := newAuditTokenStubFixture(t, auditStore)
		permissions := users.Permissions{Api: true, Browse: true}
		user := savePermissionContractUser(t, "audit-token-create-reservation", permissions)
		session := auditTokenSession(t, user)
		accessMappingsBefore := len(store.Access.HashedTokens)
		revocationsBefore := len(store.Access.RevokedTokens)

		response := fixture.request(t, stdhttp.MethodPost, auditTokenCreatePath("reservation-child", "api", "1"), session, true)
		if response.status != stdhttp.StatusServiceUnavailable {
			t.Fatalf("reservation failure status: got %d, want 503", response.status)
		}
		payload := decodeAuditTokenResponse(t, response.body)
		if payload.Token != "" {
			t.Fatal("reservation failure returned a token")
		}
		stored, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal("load reservation failure owner")
		}
		if len(stored.Tokens) != 0 || len(store.Access.HashedTokens) != accessMappingsBefore || len(store.Access.RevokedTokens) != revocationsBefore {
			t.Fatal("reservation failure changed token metadata or access state")
		}
		if !fixture.service.IsDegraded() || fixture.service.LastFailureCategory() != AuditFailureReservation {
			t.Fatalf("reservation degraded state: got %v/%q", fixture.service.IsDegraded(), fixture.service.LastFailureCategory())
		}
		assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 1, 0, 0, 0, 0)
		assertNamedSecretsAbsent(t, response.body, []namedAuditSecret{{name: "audit store failure", value: "AUDIT-RESERVATION-INTERNAL-SECRET"}})
	})

	t.Run("finalize failure preserves successful response and pending", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		auditStore.finalizeErr = errors.New("AUDIT-FINALIZE-INTERNAL-SECRET")
		fixture := newAuditTokenStubFixture(t, auditStore)
		permissions := users.Permissions{Api: true, Browse: true}
		user := savePermissionContractUser(t, "audit-token-create-finalize", permissions)
		session := auditTokenSession(t, user)

		response := fixture.request(t, stdhttp.MethodPost, auditTokenCreatePath("finalize-child", "api", "1"), session, true)
		if response.status != stdhttp.StatusOK || response.header.Get("Cache-Control") != "no-store" {
			t.Fatalf("finalize failure changed create response: status=%d cache=%q", response.status, response.header.Get("Cache-Control"))
		}
		createdToken := decodeAuditTokenResponse(t, response.body).Token
		if createdToken == "" {
			t.Fatal("finalize failure removed the successful one-time token response")
		}
		createdHash := utils.HashSHA256(createdToken)
		stored, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal("load finalize failure owner")
		}
		if _, exists := stored.Tokens["finalize-child"]; !exists || !store.Access.IsApiTokenHashActive(createdHash, user.ID) {
			t.Fatal("finalize failure rolled back successful token creation")
		}
		if !fixture.service.IsDegraded() || fixture.service.LastFailureCategory() != AuditFailureFinalize {
			t.Fatalf("finalize degraded state: got %v/%q", fixture.service.IsDegraded(), fixture.service.LastFailureCategory())
		}
		assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 1, 1, 0, 1, 0)
		pending := auditStore.singlePending(t)
		assertNamedSecretsAbsent(t, mustJSON(t, pending), []namedAuditSecret{
			{name: "created bearer", value: createdToken},
			{name: "created token hash", value: createdHash},
			{name: "audit store failure", value: "AUDIT-FINALIZE-INTERNAL-SECRET"},
		})
	})
}

func TestAuditTokenRevokeLifecycle(t *testing.T) {
	t.Run("session success reserves before revoke side effects", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		fixture := newAuditTokenStubFixture(t, auditStore)
		permissions := users.Permissions{Api: true, Browse: true, Download: true}
		user := savePermissionContractUser(t, "audit-token-revoke-success", permissions)
		target, targetHash := persistAuditAPIToken(t, user, "audit-revoke-target", users.Permissions{Browse: true})
		session := auditTokenSession(t, user)
		pendingObserved := false
		auditStore.onCreate = func(event auditdb.Event) {
			pendingObserved = true
			stored, err := store.Users.Get(user.ID)
			if err != nil {
				t.Error("load revoke target while observing reservation")
				return
			}
			if _, exists := stored.Tokens["audit-revoke-target"]; !exists || !store.Access.IsApiTokenHashActive(targetHash, user.ID) {
				t.Error("revoke side effect occurred before audit reservation completed")
			}
			assertAuditTokenPending(t, event, auditdb.ActionTokenRevoke, user, auditdb.AuthMethodSession, permissions, "")
		}

		response := fixture.request(t, stdhttp.MethodDelete, auditTokenDeletePath("audit-revoke-target"), session, true)
		if response.status != stdhttp.StatusOK {
			t.Fatalf("revoke status: got %d, want 200", response.status)
		}
		if !pendingObserved {
			t.Fatal("revoke request did not reserve a pending audit event")
		}
		stored, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal("load revoked token owner")
		}
		if _, exists := stored.Tokens["audit-revoke-target"]; exists || store.Access.IsApiTokenHashActive(targetHash, user.ID) {
			t.Fatal("revoke did not remove metadata and deactivate the token")
		}
		if _, revoked := store.Access.GetRevokedTokens()[targetHash]; !revoked {
			t.Fatal("revoke did not persist the target hash in the revoked set")
		}
		event := auditStore.singleAppended(t)
		assertAuditTokenTerminal(t, event, auditdb.ActionTokenRevoke, auditdb.ResultSuccess, stdhttp.StatusOK,
			user, auditdb.AuthMethodSession, permissions, "", "")
		assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 1, 1, 0, 0, 1)
		assertNamedSecretsAbsent(t, mustJSON(t, event), []namedAuditSecret{
			{name: "revoked bearer", value: target},
			{name: "revoked token hash", value: targetHash},
			{name: "target token name", value: "audit-revoke-target"},
		})
	})

	for _, test := range []struct {
		name            string
		unauthenticated bool
	}{
		{name: "unauthenticated", unauthenticated: true},
		{name: "no API permission"},
	} {
		t.Run(test.name+" request is denied without revoke side effects", func(t *testing.T) {
			auditStore := newObservingAuditTokenStore()
			fixture := newAuditTokenStubFixture(t, auditStore)
			userPermissions := users.Permissions{Api: true, Browse: true}
			if !test.unauthenticated {
				userPermissions.Api = false
			}
			user := savePermissionContractUser(t, "audit-token-revoke-denied-"+strings.ReplaceAll(test.name, " ", "-"), userPermissions)
			var target, targetHash string
			if test.unauthenticated {
				target, targetHash = persistAuditAPIToken(t, user, "denied-revoke-target", users.Permissions{Browse: true})
			} else {
				target, targetHash = persistAuditAPITokenWithoutPermissionCheck(t, user, "denied-revoke-target", users.Permissions{Browse: true})
			}
			credential := ""
			if !test.unauthenticated {
				credential = auditTokenSession(t, user)
			}
			response := fixture.request(t, stdhttp.MethodDelete, auditTokenDeletePath("denied-revoke-target"), credential, !test.unauthenticated)
			wantStatus := stdhttp.StatusForbidden
			wantMethod := auditdb.AuthMethodSession
			wantCode := auditErrorCodeAPIPermissionRequired
			var wantUser *users.User = user
			wantPermissions := user.Permissions
			if test.unauthenticated {
				wantStatus = stdhttp.StatusUnauthorized
				wantMethod = auditdb.AuthMethodAnonymous
				wantCode = auditErrorCodeAuthenticationRequired
				wantUser = nil
				wantPermissions = users.Permissions{}
			}
			if response.status != wantStatus {
				t.Fatalf("denied revoke status: got %d, want %d", response.status, wantStatus)
			}
			stored, err := store.Users.Get(user.ID)
			if err != nil {
				t.Fatal("load denied revoke owner")
			}
			if _, exists := stored.Tokens["denied-revoke-target"]; !exists || !store.Access.IsApiTokenHashActive(targetHash, user.ID) {
				t.Fatal("denied revoke changed token metadata or access mapping")
			}
			event := auditStore.singleAppended(t)
			assertAuditTokenTerminal(t, event, auditdb.ActionTokenDenied, auditdb.ResultDenied, wantStatus,
				wantUser, wantMethod, wantPermissions, "", wantCode)
			assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 0, 0, 1, 0, 1)
			assertNamedSecretsAbsent(t, mustJSON(t, event), []namedAuditSecret{
				{name: "target bearer", value: target},
				{name: "target token hash", value: targetHash},
			})
		})
	}

	t.Run("missing token is a revoke failure without pending", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		fixture := newAuditTokenStubFixture(t, auditStore)
		permissions := users.Permissions{Api: true, Browse: true}
		user := savePermissionContractUser(t, "audit-token-revoke-missing", permissions)
		session := auditTokenSession(t, user)
		response := fixture.request(t, stdhttp.MethodDelete, auditTokenDeletePath("does-not-exist"), session, true)
		if response.status != stdhttp.StatusNotFound {
			t.Fatalf("missing revoke status: got %d, want 404", response.status)
		}
		event := auditStore.singleAppended(t)
		assertAuditTokenTerminal(t, event, auditdb.ActionTokenRevoke, auditdb.ResultFailed, stdhttp.StatusNotFound,
			user, auditdb.AuthMethodSession, permissions, "", auditErrorCodeTokenNotFound)
		assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 0, 0, 1, 0, 1)
	})

	t.Run("reservation failure leaves target active and metadata unchanged", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		auditStore.createErr = errors.New("AUDIT-REVOKE-RESERVATION-SECRET")
		fixture := newAuditTokenStubFixture(t, auditStore)
		permissions := users.Permissions{Api: true, Browse: true}
		user := savePermissionContractUser(t, "audit-token-revoke-reservation", permissions)
		target, targetHash := persistAuditAPIToken(t, user, "reservation-revoke-target", users.Permissions{Browse: true})
		session := auditTokenSession(t, user)
		revocationsBefore := len(store.Access.GetRevokedTokens())

		response := fixture.request(t, stdhttp.MethodDelete, auditTokenDeletePath("reservation-revoke-target"), session, true)
		if response.status != stdhttp.StatusServiceUnavailable {
			t.Fatalf("revoke reservation status: got %d, want 503", response.status)
		}
		stored, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal("load revoke reservation owner")
		}
		metadata, exists := stored.Tokens["reservation-revoke-target"]
		if !exists || !metadata.MatchesTokenHash(targetHash) || !store.Access.IsApiTokenHashActive(targetHash, user.ID) || len(store.Access.GetRevokedTokens()) != revocationsBefore {
			t.Fatal("revoke reservation failure changed target state")
		}
		if !fixture.service.IsDegraded() || fixture.service.LastFailureCategory() != AuditFailureReservation {
			t.Fatalf("revoke reservation degraded state: got %v/%q", fixture.service.IsDegraded(), fixture.service.LastFailureCategory())
		}
		assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 1, 0, 0, 0, 0)
		assertNamedSecretsAbsent(t, response.body, []namedAuditSecret{
			{name: "target bearer", value: target},
			{name: "target hash", value: targetHash},
			{name: "audit store failure", value: "AUDIT-REVOKE-RESERVATION-SECRET"},
		})
	})
}

func TestAuditTokenSecretBoundaryAndRouteIsolation(t *testing.T) {
	var captureStore *capturingAuditTokenStore
	fixture := newAuditTokenHTTPFixture(t, func(actual auditdb.Store, db *storm.DB) auditdb.Store {
		captureStore = &capturingAuditTokenStore{Store: actual, db: db}
		return captureStore
	})
	capture := &securityCaptureLogger{}
	logpkg.SetGlobalLogger(capture)
	t.Cleanup(func() { logpkg.SetGlobalLogger(nil) })

	permissions := users.Permissions{Api: true, Browse: true, Preview: true, Download: true}
	user := savePermissionContractUser(t, "audit-token-secret-boundary", permissions)
	session := auditTokenSession(t, user)
	createName := "AUDIT-CREATED-TOKEN-NAME"
	createResponse := fixture.request(t, stdhttp.MethodPost, auditTokenCreatePath(createName, "api,browse", "1"), session, true)
	if createResponse.status != stdhttp.StatusOK || createResponse.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("secret-boundary create response: status=%d cache=%q", createResponse.status, createResponse.header.Get("Cache-Control"))
	}
	createdToken := decodeAuditTokenResponse(t, createResponse.body).Token
	if createdToken == "" {
		t.Fatal("secret-boundary create returned no token")
	}
	createdHash := utils.HashSHA256(createdToken)
	stored, err := store.Users.Get(user.ID)
	if err != nil {
		t.Fatal("load secret-boundary owner")
	}
	createdMetadata := stored.Tokens[createName]

	revokeResponse := fixture.request(t, stdhttp.MethodDelete, auditTokenDeletePath(createName), session, true)
	if revokeResponse.status != stdhttp.StatusOK {
		t.Fatalf("secret-boundary revoke status: got %d, want 200", revokeResponse.status)
	}

	auditBytes, err := auditTokenBucketSnapshot(fixture.db)
	if err != nil {
		t.Fatal("read audit buckets for secret scan")
	}
	pendingSnapshots, captureErr := captureStore.pendingData()
	if captureErr != nil {
		t.Fatal("capture pending audit bucket for secret scan")
	}
	auditBytes = append(auditBytes, pendingSnapshots...)
	terminalEvents, err := fixture.auditStore.ListTerminal(10)
	if err != nil {
		t.Fatal("list terminal audit events for secret scan")
	}
	auditBytes = append(auditBytes, mustJSON(t, terminalEvents)...)

	auditOnlySecrets := []namedAuditSecret{
		{name: "created bearer", value: createdToken},
		{name: "created token hash", value: createdHash},
		{name: "created token prefix", value: createdMetadata.TokenPrefix},
		{name: "created token name", value: createName},
		{name: "session bearer", value: session},
		{name: "session token hash", value: utils.HashSHA256(session)},
		{name: "Authorization header", value: "Authorization"},
		{name: "Cookie header", value: "Cookie"},
		{name: "password marker", value: "AUDIT-PASSWORD-SECRET"},
		{name: "share marker", value: "AUDIT-SHARE-SECRET"},
		{name: "OnlyOffice marker", value: "AUDIT-ONLYOFFICE-SECRET"},
	}
	assertNamedSecretsAbsent(t, auditBytes, auditOnlySecrets)
	assertNamedSecretsAbsent(t, []byte(capture.String()), []namedAuditSecret{
		{name: "created bearer", value: createdToken},
		{name: "created token hash", value: createdHash},
		{name: "session bearer", value: session},
		{name: "Authorization header", value: "Authorization"},
		{name: "Cookie header", value: "Cookie"},
	})
	degradedState := []byte(fmt.Sprintf("%v/%s", fixture.service.IsDegraded(), fixture.service.LastFailureCategory()))
	assertNamedSecretsAbsent(t, degradedState, auditOnlySecrets)

	writesBefore := auditStoreWriteCount(fixture.auditStore)
	listResponse := fixture.request(t, stdhttp.MethodGet, "/api/auth/token/list", session, true)
	if listResponse.status != stdhttp.StatusNotFound {
		t.Fatalf("post-revoke token list status: got %d, want 404", listResponse.status)
	}
	getResponse := fixture.request(t, stdhttp.MethodGet, "/api/auth/token?name="+url.QueryEscape(createName), session, true)
	if getResponse.status != stdhttp.StatusNotFound {
		t.Fatalf("post-revoke token get status: got %d, want 404", getResponse.status)
	}
	probeResponse := fixture.request(t, stdhttp.MethodGet, "/probe", "", false)
	if probeResponse.status != stdhttp.StatusNoContent {
		t.Fatalf("ordinary probe status: got %d, want 204", probeResponse.status)
	}
	if writesAfter := auditStoreWriteCount(fixture.auditStore); writesAfter != writesBefore {
		t.Fatalf("list/get or ordinary no-action route wrote audit data: before=%d after=%d", writesBefore, writesAfter)
	}
}

type auditTokenHTTPFixture struct {
	db         *storm.DB
	server     *httptest.Server
	service    *AuditService
	auditStore auditdb.Store
}

type auditTokenHTTPResponse struct {
	status int
	header stdhttp.Header
	body   []byte
}

func newAuditTokenStubFixture(t *testing.T, auditStore auditdb.Store) *auditTokenHTTPFixture {
	t.Helper()
	return newAuditTokenHTTPFixture(t, func(auditdb.Store, *storm.DB) auditdb.Store { return auditStore })
}

func newAuditTokenHTTPFixture(t *testing.T, auditStoreFactory func(auditdb.Store, *storm.DB) auditdb.Store) *auditTokenHTTPFixture {
	t.Helper()
	db, err := storm.Open(filepath.Join(t.TempDir(), "audit-token.db"))
	if err != nil {
		t.Fatal("open audit token database")
	}
	testStore, err := bolt.NewStorage(db)
	if err != nil {
		_ = db.Close()
		t.Fatal("create audit token storage")
	}
	auditStore := testStore.Audit
	if auditStoreFactory != nil {
		auditStore = auditStoreFactory(auditStore, db)
	}
	service := NewAuditService(auditStore)

	previousStore := store
	previousAuditRuntime := auditRuntime
	previousConfig := config
	previousAuth := settings.Config.Auth
	testAuth := settings.Auth{Key: "audit-token-test-signing-key"}
	store = testStore
	auditRuntime = service
	config = &settings.Settings{Auth: testAuth, Http: settings.Http{DisableRateLimit: true}}
	settings.Config.Auth = testAuth

	api := stdhttp.NewServeMux()
	registerAPITokenRoutes(api)
	root := stdhttp.NewServeMux()
	root.Handle("/api/", stdhttp.StripPrefix("/api", api))
	root.HandleFunc("GET /probe", func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		w.WriteHeader(stdhttp.StatusNoContent)
	})
	server := httptest.NewServer(AuditMiddleware(LoggingMiddleware(root), service))
	fixture := &auditTokenHTTPFixture{db: db, server: server, service: service, auditStore: auditStore}
	t.Cleanup(func() {
		server.Close()
		store = previousStore
		auditRuntime = previousAuditRuntime
		config = previousConfig
		settings.Config.Auth = previousAuth
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("close audit token database")
		}
	})
	return fixture
}

func (fixture *auditTokenHTTPFixture) request(t *testing.T, method, path, credential string, session bool) auditTokenHTTPResponse {
	t.Helper()
	request, err := stdhttp.NewRequest(method, fixture.server.URL+path, nil)
	if err != nil {
		t.Fatal("build audit token HTTP request")
	}
	if credential != "" {
		if session {
			request.AddCookie(&stdhttp.Cookie{Name: "filebrowser_quantum_jwt", Value: credential})
		} else {
			request.Header.Set("Authorization", "Bearer "+credential)
		}
	}
	response, err := fixture.server.Client().Do(request)
	if err != nil {
		t.Fatal("execute audit token HTTP request")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal("read audit token HTTP response")
	}
	return auditTokenHTTPResponse{status: response.StatusCode, header: response.Header.Clone(), body: body}
}

func auditTokenCreatePath(name, permissionNames, days string) string {
	query := url.Values{"name": {name}, "days": {days}}
	if permissionNames != "" {
		query.Set("permissions", permissionNames)
	}
	return "/api/auth/token?" + query.Encode()
}

func auditTokenDeletePath(name string) string {
	return "/api/auth/token?" + url.Values{"name": {name}}.Encode()
}

func auditTokenSession(t *testing.T, user *users.User) string {
	t.Helper()
	token, _, err := auth.MakeSignedTokenAPI(user, "WEB_TOKEN_audit_session", time.Hour, user.Permissions, false)
	if err != nil {
		t.Fatal("create audit test session")
	}
	return token
}

func persistAuditAPIToken(t *testing.T, user *users.User, name string, permissions users.Permissions) (string, string) {
	t.Helper()
	token, metadata, err := auth.MakeSignedTokenAPI(user, name, time.Hour, permissions, false)
	if err != nil {
		t.Fatal("create audit test API token")
	}
	if err := store.Users.AddApiToken(user.ID, name, token, metadata); err != nil {
		t.Fatal("persist audit test API token metadata")
	}
	if err := store.Access.AddApiToken(token, user.ID); err != nil {
		t.Fatal("persist audit test API token access mapping")
	}
	return token, utils.HashSHA256(token)
}

func persistAuditAPITokenWithoutPermissionCheck(t *testing.T, user *users.User, name string, permissions users.Permissions) (string, string) {
	t.Helper()
	token, metadata, err := auth.MakeSignedTokenAPI(user, name, time.Hour, permissions, false)
	if err != nil {
		t.Fatal("create permission-denied audit test API token")
	}
	tokenHash := utils.HashSHA256(token)
	metadata.TokenHash = tokenHash
	stored, err := store.Users.Get(user.ID)
	if err != nil {
		t.Fatal("load permission-denied token owner")
	}
	if stored.Tokens == nil {
		stored.Tokens = make(map[string]users.AuthToken)
	}
	stored.Tokens[name] = metadata
	if err := store.Users.Update(stored, true, "Tokens"); err != nil {
		t.Fatal("persist permission-denied token metadata")
	}
	if err := store.Access.AddApiToken(token, user.ID); err != nil {
		t.Fatal("persist permission-denied token access mapping")
	}
	return token, tokenHash
}

func decodeAuditTokenResponse(t *testing.T, body []byte) HttpResponse {
	t.Helper()
	var response HttpResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal("decode audit token response")
	}
	return response
}

func assertAuditTokenPending(
	t *testing.T,
	event auditdb.Event,
	action auditdb.Action,
	user *users.User,
	method auditdb.AuthMethod,
	permissions users.Permissions,
	tokenRef string,
) {
	t.Helper()
	if event.Action != action || event.AuthMethod != method || event.TokenRef != tokenRef {
		t.Errorf("pending routing facts: action=%q authMethod=%q tokenRef=%q", event.Action, event.AuthMethod, event.TokenRef)
	}
	assertAuditTokenActorAndPermissions(t, event, user, permissions)
	if event.Result != "" || event.HTTPStatus != nil || event.ErrorCode != "" {
		t.Errorf("pending contains terminal fields: result=%q status=%v errorCode=%q", event.Result, event.HTTPStatus, event.ErrorCode)
	}
}

func assertAuditTokenTerminal(
	t *testing.T,
	event auditdb.Event,
	action auditdb.Action,
	result auditdb.Result,
	status int,
	user *users.User,
	method auditdb.AuthMethod,
	permissions users.Permissions,
	tokenRef string,
	errorCode string,
) {
	t.Helper()
	if event.Action != action || event.Result != result || event.AuthMethod != method || event.TokenRef != tokenRef || event.ErrorCode != errorCode {
		t.Errorf("terminal facts: action=%q result=%q authMethod=%q tokenRef=%q errorCode=%q",
			event.Action, event.Result, event.AuthMethod, event.TokenRef, event.ErrorCode)
	}
	if event.HTTPStatus == nil || *event.HTTPStatus != status {
		t.Errorf("terminal HTTP status: got %v, want %d", event.HTTPStatus, status)
	}
	assertAuditTokenActorAndPermissions(t, event, user, permissions)
}

func assertAuditTokenActorAndPermissions(t *testing.T, event auditdb.Event, user *users.User, permissions users.Permissions) {
	t.Helper()
	if user == nil {
		if event.UserID != nil || event.Username != "" || event.EffectivePermissions != nil {
			t.Errorf("anonymous event retained actor data: userID=%v username=%q permissions=%+v", event.UserID, event.Username, event.EffectivePermissions)
		}
		return
	}
	if event.UserID == nil || *event.UserID != user.ID || event.Username != user.Username {
		t.Errorf("event actor: userID=%v username=%q", event.UserID, event.Username)
	}
	want := auditPermissionsForTest(permissions)
	if event.EffectivePermissions == nil || *event.EffectivePermissions != want {
		t.Errorf("effective permissions: got %+v, want %+v", event.EffectivePermissions, want)
	}
}

func auditPermissionsForTest(permissions users.Permissions) auditdb.Permissions {
	return auditdb.Permissions{
		API: permissions.Api, Admin: permissions.Admin, Modify: permissions.Modify,
		Share: permissions.Share, Realtime: permissions.Realtime, Delete: permissions.Delete,
		Create: permissions.Create, Browse: permissions.Browse, Preview: permissions.Preview,
		Download: permissions.Download,
	}
}

type observingAuditTokenStore struct {
	*auditStoreStub
	onCreate func(auditdb.Event)
}

func newObservingAuditTokenStore() *observingAuditTokenStore {
	return &observingAuditTokenStore{auditStoreStub: newAuditStoreStub()}
}

func (store *observingAuditTokenStore) CreatePending(event auditdb.Event) error {
	if err := store.auditStoreStub.CreatePending(event); err != nil {
		return err
	}
	if store.onCreate != nil {
		store.onCreate(cloneAuditEvent(event))
	}
	return nil
}

func assertAuditTokenStoreCounts(t *testing.T, store *auditStoreStub, creates, finalizes, appends, pending, terminal int) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.createCalls != creates || store.finalizeCalls != finalizes || store.appendCalls != appends ||
		len(store.pending) != pending || len(store.appended) != terminal {
		t.Errorf("audit store calls/state: create=%d finalize=%d append=%d pending=%d terminal=%d",
			store.createCalls, store.finalizeCalls, store.appendCalls, len(store.pending), len(store.appended))
	}
}

type capturingAuditTokenStore struct {
	auditdb.Store
	db *storm.DB

	mu               sync.Mutex
	pendingSnapshots [][]byte
	captureErr       error
}

func (store *capturingAuditTokenStore) CreatePending(event auditdb.Event) error {
	if err := store.Store.CreatePending(event); err != nil {
		return err
	}
	snapshot, err := auditTokenBucketSnapshot(store.db)
	store.mu.Lock()
	defer store.mu.Unlock()
	if err != nil {
		store.captureErr = err
		return nil
	}
	store.pendingSnapshots = append(store.pendingSnapshots, append([]byte(nil), snapshot...))
	return nil
}

func (store *capturingAuditTokenStore) pendingData() ([]byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var data []byte
	for _, snapshot := range store.pendingSnapshots {
		data = append(data, snapshot...)
	}
	return data, store.captureErr
}

func auditTokenBucketSnapshot(db *storm.DB) ([]byte, error) {
	bucketNames := []string{
		"audit_events", "audit_pending", "audit_request_ids", "audit_index_actor",
		"audit_index_action", "audit_index_token_ref", "audit_index_share_ref",
		"audit_index_source", "audit_index_result", "audit_metadata",
	}
	var data bytes.Buffer
	err := db.Bolt.View(func(transaction *bbolt.Tx) error {
		for _, name := range bucketNames {
			bucket := transaction.Bucket([]byte(name))
			if bucket == nil {
				return fmt.Errorf("audit bucket missing")
			}
			_, _ = data.WriteString(name)
			if err := appendAuditTokenBucketData(&data, bucket); err != nil {
				return err
			}
		}
		return nil
	})
	return data.Bytes(), err
}

func appendAuditTokenBucketData(destination *bytes.Buffer, bucket *bbolt.Bucket) error {
	return bucket.ForEach(func(key, value []byte) error {
		_, _ = destination.Write(key)
		if value != nil {
			_, _ = destination.Write(value)
			return nil
		}
		nested := bucket.Bucket(key)
		if nested == nil {
			return nil
		}
		return appendAuditTokenBucketData(destination, nested)
	})
}

func auditStoreWriteCount(store auditdb.Store) int {
	if stub, ok := store.(*observingAuditTokenStore); ok {
		return stub.totalWriteCalls()
	}
	events, err := store.ListTerminal(1000)
	if err != nil {
		return -1
	}
	return len(events)
}

type namedAuditSecret struct {
	name  string
	value string
}

func assertNamedSecretsAbsent(t *testing.T, data []byte, secrets []namedAuditSecret) {
	t.Helper()
	for _, secret := range secrets {
		if secret.value != "" && bytes.Contains(data, []byte(secret.value)) {
			t.Errorf("audit output contains %s", secret.name)
		}
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal("marshal audit test value")
	}
	return data
}
