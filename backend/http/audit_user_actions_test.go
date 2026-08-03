package http

import (
	"encoding/json"
	"errors"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	storm "github.com/asdine/storm/v3"
	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	storagepkg "github.com/gtsteffaniak/filebrowser/backend/database/storage"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

type auditUserHTTPFixture struct {
	server     *httptest.Server
	service    *AuditService
	auditStore auditdb.Store
}

type auditUserHTTPResponse struct {
	status int
	header stdhttp.Header
	body   []byte
}

func newAuditUserStubFixture(t *testing.T, auditStore auditdb.Store) *auditUserHTTPFixture {
	t.Helper()
	return newAuditUserHTTPFixture(t, func(auditdb.Store, *storm.DB) auditdb.Store { return auditStore })
}

func newAuditUserHTTPFixture(t *testing.T, auditStoreFactory func(auditdb.Store, *storm.DB) auditdb.Store) *auditUserHTTPFixture {
	t.Helper()

	previousStore := store
	previousAuditRuntime := auditRuntime
	previousConfig := config
	previousSettings := settings.Config
	previousFirstLoad := settings.Env.IsFirstLoad

	settings.Config = settings.Settings{
		Auth: settings.Auth{Key: "audit-user-actions-signing-key"},
	}
	testStore, _, err := storagepkg.InitializeDb(filepath.Join(t.TempDir(), "audit-user-actions.db"))
	if err != nil {
		t.Fatalf("initialize audit user database: %v", err)
	}
	db := testStore.Access.DB
	auditStore := testStore.Audit
	if auditStoreFactory != nil {
		auditStore = auditStoreFactory(auditStore, db)
	}
	service := NewAuditService(auditStore)
	store = testStore
	auditRuntime = service
	config = &settings.Config

	api := stdhttp.NewServeMux()
	api.HandleFunc("POST /users", auditUserRoute(auditdb.ActionUserCreate, usersPostHandler))
	api.HandleFunc("PUT /users", auditUserRoute(auditdb.ActionUserUpdate, userPutHandler))
	api.HandleFunc("DELETE /users", auditUserRoute(auditdb.ActionUserDelete, userDeleteHandler))
	root := stdhttp.NewServeMux()
	root.Handle("/api/", stdhttp.StripPrefix("/api", api))
	server := httptest.NewServer(AuditMiddleware(LoggingMiddleware(root), service))

	fixture := &auditUserHTTPFixture{server: server, service: service, auditStore: auditStore}
	t.Cleanup(func() {
		server.Close()
		store = previousStore
		auditRuntime = previousAuditRuntime
		config = previousConfig
		settings.Config = previousSettings
		settings.Env.IsFirstLoad = previousFirstLoad
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("close audit user database: %v", closeErr)
		}
	})
	return fixture
}

func auditUserRoute(action auditdb.Action, handler handleFunc) stdhttp.HandlerFunc {
	return withAuditDefaultAction(action, withUserHelper(withAuditAuthenticatedUser(handler)))
}

func (fixture *auditUserHTTPFixture) request(
	t *testing.T,
	method string,
	path string,
	body []byte,
	credential string,
	headers stdhttp.Header,
) auditUserHTTPResponse {
	t.Helper()
	request, err := stdhttp.NewRequest(method, fixture.server.URL+path, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("build audit user request: %v", err)
	}
	if credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
	}
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	response, err := fixture.server.Client().Do(request)
	if err != nil {
		t.Fatalf("execute audit user request: %v", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read audit user response: %v", err)
	}
	return auditUserHTTPResponse{status: response.StatusCode, header: response.Header.Clone(), body: responseBody}
}

func saveAuditUser(t *testing.T, username string, permissions users.Permissions) *users.User {
	t.Helper()
	user := &users.User{
		Username:    username,
		LoginMethod: users.LoginMethodProxy,
		Permissions: permissions,
	}
	if err := store.Users.Save(user, false, false); err != nil {
		t.Fatalf("save audit user %q: %v", username, err)
	}
	return user
}

func auditUserSession(t *testing.T, user *users.User) string {
	t.Helper()
	token, _, err := auth.MakeSignedTokenAPI(user, "WEB_TOKEN_audit_user_actions", time.Hour, user.Permissions, false)
	if err != nil {
		t.Fatalf("create audit user session: %v", err)
	}
	return token
}

func auditUserBody(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal audit user request: %v", err)
	}
	return body
}

func assertAuditUserTerminal(
	t *testing.T,
	event auditdb.Event,
	action auditdb.Action,
	result auditdb.Result,
	status int,
	actor *users.User,
	changedFields ...auditdb.ChangedField,
) {
	t.Helper()
	if event.Action != action || event.Result != result || event.AuthMethod != auditdb.AuthMethodSession {
		t.Errorf("audit user terminal routing: action=%q result=%q authMethod=%q", event.Action, event.Result, event.AuthMethod)
	}
	if event.HTTPStatus == nil || *event.HTTPStatus != status {
		t.Errorf("audit user HTTP status: got %v, want %d", event.HTTPStatus, status)
	}
	if event.UserID == nil || *event.UserID != actor.ID || event.Username != actor.Username {
		t.Errorf("audit user actor: userID=%v username=%q", event.UserID, event.Username)
	}
	wantPermissions := auditPermissions(actor.Permissions)
	if event.EffectivePermissions == nil || *event.EffectivePermissions != wantPermissions {
		t.Errorf("audit user effective permissions: got %+v, want %+v", event.EffectivePermissions, wantPermissions)
	}
	assertAuditUserChangedFields(t, event, changedFields...)
}

func assertAuditUserChangedFields(t *testing.T, event auditdb.Event, want ...auditdb.ChangedField) {
	t.Helper()
	var got []auditdb.ChangedField
	if event.Metadata != nil {
		got = event.Metadata.ChangedFields
	}
	if len(got) != len(want) {
		t.Fatalf("audit user changed fields: got %v, want %v", got, want)
	}
	counts := make(map[auditdb.ChangedField]int, len(got))
	for _, field := range got {
		counts[field]++
	}
	for _, field := range want {
		if counts[field] == 0 {
			t.Errorf("audit user changed fields missing %q: got %v", field, got)
		}
		counts[field]--
	}
	for field, count := range counts {
		if count != 0 {
			t.Errorf("audit user changed fields contained unexpected %q: got %v", field, got)
		}
	}
}

func TestAuditUserActionsSuccess(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		fixture := newAuditUserStubFixture(t, auditStore)
		actor := saveAuditUser(t, "audit-user-create-admin", users.Permissions{Admin: true, Browse: true})
		body := auditUserBody(t, UserRequest{User: users.User{
			Username:    "audit-user-created-target",
			LoginMethod: users.LoginMethodProxy,
			Permissions: users.Permissions{Browse: true},
		}})
		response := fixture.request(t, stdhttp.MethodPost, "/api/users", body, auditUserSession(t, actor), nil)
		if response.status != stdhttp.StatusCreated {
			t.Fatalf("create status: got %d, want 201: %s", response.status, response.body)
		}
		if _, err := store.Users.Get("audit-user-created-target"); err != nil {
			t.Fatalf("created user missing: %v", err)
		}
		event := auditStore.singleAppended(t)
		assertAuditUserTerminal(t, event, auditdb.ActionUserCreate, auditdb.ResultSuccess, stdhttp.StatusCreated, actor)
		assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 1, 1, 0, 0, 1)
	})

	t.Run("update", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		fixture := newAuditUserStubFixture(t, auditStore)
		actor := saveAuditUser(t, "audit-user-update-admin", users.Permissions{Admin: true})
		target := saveAuditUser(t, "audit-user-update-target", users.Permissions{Browse: true})
		body := auditUserBody(t, UserRequest{Which: []string{"locale"}, User: users.User{NonAdminEditable: users.NonAdminEditable{Locale: "fr"}}})
		path := "/api/users?id=" + strconv.FormatUint(uint64(target.ID), 10)
		response := fixture.request(t, stdhttp.MethodPut, path, body, auditUserSession(t, actor), nil)
		if response.status != stdhttp.StatusNoContent {
			t.Fatalf("update status: got %d, want 204: %s", response.status, response.body)
		}
		updated, err := store.Users.Get(target.ID)
		if err != nil || updated.Locale != "fr" {
			t.Fatalf("updated locale: user=%+v err=%v", updated, err)
		}
		event := auditStore.singleAppended(t)
		assertAuditUserTerminal(t, event, auditdb.ActionUserUpdate, auditdb.ResultSuccess, stdhttp.StatusNoContent, actor, auditdb.ChangedFieldLocale)
		assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 1, 1, 0, 0, 1)
	})

	t.Run("permission update", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		fixture := newAuditUserStubFixture(t, auditStore)
		actor := saveAuditUser(t, "audit-permission-update-admin", users.Permissions{Admin: true})
		target := saveAuditUser(t, "audit-permission-update-target", users.Permissions{Browse: true})
		body := auditUserBody(t, UserRequest{Which: []string{"permissions"}, User: users.User{Permissions: users.Permissions{Browse: false}}})
		path := "/api/users?id=" + strconv.FormatUint(uint64(target.ID), 10)
		response := fixture.request(t, stdhttp.MethodPut, path, body, auditUserSession(t, actor), nil)
		if response.status != stdhttp.StatusNoContent {
			t.Fatalf("permission update status: got %d, want 204: %s", response.status, response.body)
		}
		event := auditStore.singleAppended(t)
		assertAuditUserTerminal(t, event, auditdb.ActionPermissionUpdate, auditdb.ResultSuccess, stdhttp.StatusNoContent, actor, auditdb.ChangedFieldPermissions)
		assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 1, 1, 0, 0, 1)
	})

	t.Run("delete", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		fixture := newAuditUserStubFixture(t, auditStore)
		actor := saveAuditUser(t, "audit-user-delete-admin", users.Permissions{Admin: true})
		target := saveAuditUser(t, "audit-user-delete-target", users.Permissions{})
		path := "/api/users?id=" + strconv.FormatUint(uint64(target.ID), 10)
		response := fixture.request(t, stdhttp.MethodDelete, path, nil, auditUserSession(t, actor), nil)
		if response.status != stdhttp.StatusOK {
			t.Fatalf("delete status: got %d, want 200: %s", response.status, response.body)
		}
		if _, err := store.Users.Get(target.ID); err == nil {
			t.Fatal("deleted user still exists")
		}
		event := auditStore.singleAppended(t)
		assertAuditUserTerminal(t, event, auditdb.ActionUserDelete, auditdb.ResultSuccess, stdhttp.StatusOK, actor)
		assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 1, 1, 0, 0, 1)
	})
}

func TestAuditUserActionsNonAdminDenied(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		fixture := newAuditUserStubFixture(t, auditStore)
		actor := saveAuditUser(t, "audit-user-create-non-admin", users.Permissions{Browse: true})
		body := auditUserBody(t, UserRequest{User: users.User{Username: "audit-user-denied-create", LoginMethod: users.LoginMethodProxy}})
		response := fixture.request(t, stdhttp.MethodPost, "/api/users", body, auditUserSession(t, actor), nil)
		if response.status != stdhttp.StatusForbidden {
			t.Fatalf("denied create status: got %d, want 403", response.status)
		}
		if _, err := store.Users.Get("audit-user-denied-create"); err == nil {
			t.Fatal("denied create persisted a user")
		}
		assertAuditUserTerminal(t, auditStore.singleAppended(t), auditdb.ActionUserCreate, auditdb.ResultDenied, stdhttp.StatusForbidden, actor)
		assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 0, 0, 1, 0, 1)
	})

	t.Run("update another user", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		fixture := newAuditUserStubFixture(t, auditStore)
		actor := saveAuditUser(t, "audit-user-update-non-admin", users.Permissions{Browse: true})
		target := saveAuditUser(t, "audit-user-denied-update", users.Permissions{})
		body := auditUserBody(t, UserRequest{Which: []string{"locale"}, User: users.User{NonAdminEditable: users.NonAdminEditable{Locale: "fr"}}})
		path := "/api/users?id=" + strconv.FormatUint(uint64(target.ID), 10)
		response := fixture.request(t, stdhttp.MethodPut, path, body, auditUserSession(t, actor), nil)
		if response.status != stdhttp.StatusForbidden {
			t.Fatalf("denied update status: got %d, want 403", response.status)
		}
		assertAuditUserTerminal(t, auditStore.singleAppended(t), auditdb.ActionUserUpdate, auditdb.ResultDenied, stdhttp.StatusForbidden, actor)
		assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 0, 0, 1, 0, 1)
	})

	t.Run("permission update", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		fixture := newAuditUserStubFixture(t, auditStore)
		actor := saveAuditUser(t, "audit-permission-update-non-admin", users.Permissions{Browse: true})
		body := auditUserBody(t, UserRequest{Which: []string{"permissions"}, User: users.User{Permissions: users.Permissions{Admin: true}}})
		path := "/api/users?id=" + strconv.FormatUint(uint64(actor.ID), 10)
		response := fixture.request(t, stdhttp.MethodPut, path, body, auditUserSession(t, actor), nil)
		if response.status != stdhttp.StatusForbidden {
			t.Fatalf("denied permission update status: got %d, want 403: %s", response.status, response.body)
		}
		stored, err := store.Users.Get(actor.ID)
		if err != nil || stored.Permissions.Admin {
			t.Fatalf("denied permission update changed actor: user=%+v err=%v", stored, err)
		}
		assertAuditUserTerminal(t, auditStore.singleAppended(t), auditdb.ActionPermissionUpdate, auditdb.ResultDenied, stdhttp.StatusForbidden, actor, auditdb.ChangedFieldPermissions)
		assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 0, 0, 1, 0, 1)
	})

	t.Run("delete", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		fixture := newAuditUserStubFixture(t, auditStore)
		actor := saveAuditUser(t, "audit-user-delete-non-admin", users.Permissions{Browse: true})
		target := saveAuditUser(t, "audit-user-denied-delete", users.Permissions{})
		path := "/api/users?id=" + strconv.FormatUint(uint64(target.ID), 10)
		response := fixture.request(t, stdhttp.MethodDelete, path, nil, auditUserSession(t, actor), nil)
		if response.status != stdhttp.StatusForbidden {
			t.Fatalf("denied delete status: got %d, want 403", response.status)
		}
		if _, err := store.Users.Get(target.ID); err != nil {
			t.Fatalf("denied delete removed target: %v", err)
		}
		assertAuditUserTerminal(t, auditStore.singleAppended(t), auditdb.ActionUserDelete, auditdb.ResultDenied, stdhttp.StatusForbidden, actor)
		assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 0, 0, 1, 0, 1)
	})
}

func TestAuditUserActionsReservationFailureHasZeroSideEffects(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		auditStore.createErr = errors.New("AUDIT-USER-CREATE-RESERVATION-SECRET")
		fixture := newAuditUserStubFixture(t, auditStore)
		actor := saveAuditUser(t, "audit-user-create-reservation-admin", users.Permissions{Admin: true})
		body := auditUserBody(t, UserRequest{User: users.User{Username: "audit-user-reservation-create-target", LoginMethod: users.LoginMethodProxy}})
		response := fixture.request(t, stdhttp.MethodPost, "/api/users", body, auditUserSession(t, actor), nil)
		if response.status != stdhttp.StatusServiceUnavailable {
			t.Fatalf("create reservation status: got %d, want 503", response.status)
		}
		if _, err := store.Users.Get("audit-user-reservation-create-target"); err == nil {
			t.Fatal("create reservation failure persisted target")
		}
		assertAuditUserReservationFailure(t, fixture, auditStore, response.body, "AUDIT-USER-CREATE-RESERVATION-SECRET")
	})

	t.Run("update", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		auditStore.createErr = errors.New("AUDIT-USER-UPDATE-RESERVATION-SECRET")
		fixture := newAuditUserStubFixture(t, auditStore)
		actor := saveAuditUser(t, "audit-user-update-reservation-admin", users.Permissions{Admin: true})
		target := saveAuditUser(t, "audit-user-reservation-update-target", users.Permissions{})
		body := auditUserBody(t, UserRequest{Which: []string{"locale"}, User: users.User{NonAdminEditable: users.NonAdminEditable{Locale: "de"}}})
		path := "/api/users?id=" + strconv.FormatUint(uint64(target.ID), 10)
		response := fixture.request(t, stdhttp.MethodPut, path, body, auditUserSession(t, actor), nil)
		if response.status != stdhttp.StatusServiceUnavailable {
			t.Fatalf("update reservation status: got %d, want 503", response.status)
		}
		stored, err := store.Users.Get(target.ID)
		if err != nil || stored.Locale != "" {
			t.Fatalf("update reservation failure changed target: user=%+v err=%v", stored, err)
		}
		assertAuditUserReservationFailure(t, fixture, auditStore, response.body, "AUDIT-USER-UPDATE-RESERVATION-SECRET")
	})

	t.Run("permission update before token revocation", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		auditStore.createErr = errors.New("AUDIT-PERMISSION-RESERVATION-SECRET")
		fixture := newAuditUserStubFixture(t, auditStore)
		actor := saveAuditUser(t, "audit-permission-reservation-admin", users.Permissions{Admin: true})
		target := saveAuditUser(t, "audit-permission-reservation-target", users.Permissions{Api: true, Browse: true})
		_, tokenHash := persistAuditAPIToken(t, target, "audit-permission-reservation-token", users.Permissions{Api: true})
		body := auditUserBody(t, UserRequest{Which: []string{"permissions"}, User: users.User{Permissions: users.Permissions{Api: false, Browse: true}}})
		path := "/api/users?id=" + strconv.FormatUint(uint64(target.ID), 10)
		response := fixture.request(t, stdhttp.MethodPut, path, body, auditUserSession(t, actor), nil)
		if response.status != stdhttp.StatusServiceUnavailable {
			t.Fatalf("permission reservation status: got %d, want 503", response.status)
		}
		stored, err := store.Users.Get(target.ID)
		if err != nil || !stored.Permissions.Api || !store.Access.IsApiTokenHashActive(tokenHash, target.ID) {
			t.Fatalf("permission reservation failure changed user or token: user=%+v active=%t err=%v", stored, store.Access.IsApiTokenHashActive(tokenHash, target.ID), err)
		}
		assertAuditUserReservationFailure(t, fixture, auditStore, response.body, "AUDIT-PERMISSION-RESERVATION-SECRET")
	})

	t.Run("delete", func(t *testing.T) {
		auditStore := newObservingAuditTokenStore()
		auditStore.createErr = errors.New("AUDIT-USER-DELETE-RESERVATION-SECRET")
		fixture := newAuditUserStubFixture(t, auditStore)
		actor := saveAuditUser(t, "audit-user-delete-reservation-admin", users.Permissions{Admin: true})
		target := saveAuditUser(t, "audit-user-reservation-delete-target", users.Permissions{})
		path := "/api/users?id=" + strconv.FormatUint(uint64(target.ID), 10)
		response := fixture.request(t, stdhttp.MethodDelete, path, nil, auditUserSession(t, actor), nil)
		if response.status != stdhttp.StatusServiceUnavailable {
			t.Fatalf("delete reservation status: got %d, want 503", response.status)
		}
		if _, err := store.Users.Get(target.ID); err != nil {
			t.Fatalf("delete reservation failure removed target: %v", err)
		}
		assertAuditUserReservationFailure(t, fixture, auditStore, response.body, "AUDIT-USER-DELETE-RESERVATION-SECRET")
	})
}

func assertAuditUserReservationFailure(
	t *testing.T,
	fixture *auditUserHTTPFixture,
	auditStore *observingAuditTokenStore,
	responseBody []byte,
	storeSecret string,
) {
	t.Helper()
	if !fixture.service.IsDegraded() || fixture.service.LastFailureCategory() != AuditFailureReservation {
		t.Errorf("reservation degraded state: got %v/%q", fixture.service.IsDegraded(), fixture.service.LastFailureCategory())
	}
	assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 1, 0, 0, 0, 0)
	assertNamedSecretsAbsent(t, responseBody, []namedAuditSecret{{name: "audit reservation failure", value: storeSecret}})
}

func TestAuditUserActionFinalizeFailurePreservesPending(t *testing.T) {
	auditStore := newObservingAuditTokenStore()
	auditStore.finalizeErr = errors.New("AUDIT-USER-FINALIZE-SECRET")
	fixture := newAuditUserStubFixture(t, auditStore)
	actor := saveAuditUser(t, "audit-user-finalize-admin", users.Permissions{Admin: true})
	target := saveAuditUser(t, "audit-user-finalize-target", users.Permissions{Browse: true})
	body := auditUserBody(t, UserRequest{Which: []string{"permissions"}, User: users.User{Permissions: users.Permissions{Browse: false}}})
	path := "/api/users?id=" + strconv.FormatUint(uint64(target.ID), 10)
	response := fixture.request(t, stdhttp.MethodPut, path, body, auditUserSession(t, actor), nil)
	if response.status != stdhttp.StatusNoContent {
		t.Fatalf("finalize failure changed response: got %d, want 204", response.status)
	}
	stored, err := store.Users.Get(target.ID)
	if err != nil || stored.Permissions.Browse {
		t.Fatalf("finalize failure rolled back permission update: user=%+v err=%v", stored, err)
	}
	if !fixture.service.IsDegraded() || fixture.service.LastFailureCategory() != AuditFailureFinalize {
		t.Fatalf("finalize degraded state: got %v/%q", fixture.service.IsDegraded(), fixture.service.LastFailureCategory())
	}
	assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 1, 1, 0, 1, 0)
	pending := auditStore.singlePending(t)
	if pending.Action != auditdb.ActionPermissionUpdate {
		t.Errorf("pending action: got %q, want %q", pending.Action, auditdb.ActionPermissionUpdate)
	}
	assertAuditUserChangedFields(t, pending, auditdb.ChangedFieldPermissions)
	assertNamedSecretsAbsent(t, mustJSON(t, pending), []namedAuditSecret{{name: "audit finalize failure", value: "AUDIT-USER-FINALIZE-SECRET"}})
}

func TestAuditUserChangedFieldsWhitelistAndSecretBoundary(t *testing.T) {
	auditStore := newObservingAuditTokenStore()
	fixture := newAuditUserStubFixture(t, auditStore)
	actor := saveAuditUser(t, "audit-user-secret-admin", users.Permissions{Admin: true})
	target := saveAuditUser(t, "audit-user-secret-target", users.Permissions{})
	target.LoginMethod = users.LoginMethodPassword
	if err := store.Users.Update(target, true, "LoginMethod"); err != nil {
		t.Fatalf("set target login method: %v", err)
	}

	secrets := []namedAuditSecret{
		{name: "password", value: "TARGET-PASSWORD-SECRET-48391"},
		{name: "TOTP secret", value: "TOTP-SECRET-59382"},
		{name: "TOTP nonce", value: "TOTP-NONCE-69382"},
		{name: "WebAuthn public key", value: "WEBAUTHN-PUBLIC-KEY-79382"},
		{name: "legacy token", value: "LEGACY-TOKEN-89382"},
		{name: "legacy key", value: "LEGACY-KEY-99382"},
		{name: "token hash", value: "TOKEN-HASH-19382"},
		{name: "actor confirmation", value: "ACTOR-X-PASSWORD-29382"},
	}
	requestUser := users.User{
		NonAdminEditable: users.NonAdminEditable{
			Password:   secrets[0].value,
			Locale:     "fr",
			OtpEnabled: true,
			PasskeyCredentials: []users.WebAuthnCredential{{
				ID: "credential-id", PublicKey: secrets[3].value,
			}},
		},
		LoginMethod: users.LoginMethodPassword,
		TOTPSecret:  secrets[1].value,
		TOTPNonce:   secrets[2].value,
		Tokens: map[string]users.AuthToken{
			"legacy-secret": {Token: secrets[4].value, Key: secrets[5].value, TokenHash: secrets[6].value},
		},
	}
	body := auditUserBody(t, UserRequest{
		Which: []string{"password", "tokens", "passkeyCredentials", "locale"},
		User:  requestUser,
	})
	path := "/api/users?id=" + strconv.FormatUint(uint64(target.ID), 10)
	session := auditUserSession(t, actor)
	secrets = append(secrets, namedAuditSecret{name: "Authorization bearer", value: session})
	var pending auditdb.Event
	auditStore.onCreate = func(event auditdb.Event) { pending = event }
	response := fixture.request(t, stdhttp.MethodPut, path, body, session, stdhttp.Header{"X-Password": {secrets[7].value}})
	if response.status != stdhttp.StatusNoContent {
		t.Fatalf("secret-boundary update status: got %d, want 204: %s", response.status, response.body)
	}
	wantFields := []auditdb.ChangedField{
		auditdb.ChangedFieldPassword,
		auditdb.ChangedFieldTokens,
		auditdb.ChangedFieldAuthentication,
		auditdb.ChangedFieldLocale,
	}
	assertAuditUserChangedFields(t, pending, wantFields...)
	event := auditStore.singleAppended(t)
	assertAuditUserTerminal(t, event, auditdb.ActionUserUpdate, auditdb.ResultSuccess, stdhttp.StatusNoContent, actor, wantFields...)
	assertAuditTokenStoreCounts(t, auditStore.auditStoreStub, 1, 1, 0, 0, 1)
	assertNamedSecretsAbsent(t, mustJSON(t, pending), secrets)
	assertNamedSecretsAbsent(t, mustJSON(t, event), secrets)
}
