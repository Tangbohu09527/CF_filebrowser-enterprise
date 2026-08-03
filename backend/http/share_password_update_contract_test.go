package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	dbshare "github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"golang.org/x/crypto/bcrypt"
)

const (
	sharePasswordContractOldPassword = "share-password-contract-old-secret"
	sharePasswordContractNewPassword = "share-password-contract-new-secret"
	sharePasswordContractLegacyToken = "SHARE-PASSWORD-CONTRACT-LEGACY-TOKEN-SECRET"
)

type sharePasswordContractFixture struct {
	harness *permissionShareSecurityHarness
	owner   *users.User
	link    *dbshare.Link
	before  *dbshare.Link
}

func TestSharePasswordCreateContract(t *testing.T) {
	tests := []struct {
		name            string
		includePassword bool
		password        any
		wantPassword    bool
	}{
		{name: "missing", includePassword: false},
		{name: "null", includePassword: true, password: nil},
		{name: "empty", includePassword: true, password: ""},
		{name: "non-empty", includePassword: true, password: sharePasswordContractNewPassword, wantPassword: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sourcePath := setupResourcePutTestEnv(t)
			harness := newPermissionShareSecurityHarness(t, sourcePath)
			owner := harness.newOwner(t, "share-password-create-owner", auditShareFullPermissions())
			payload := map[string]any{
				"source":    "source1",
				"path":      "/public",
				"shareType": "normal",
				"title":     "password contract create",
			}
			if test.includePassword {
				payload["password"] = test.password
			}

			response, status, handlerErr := requestSharePasswordMutation(t, owner, payload)
			if handlerErr != nil || status != http.StatusOK {
				t.Fatalf("create share: status=%d err=%v body=%s", status, handlerErr, response.Body.String())
			}
			decoded := decodeCredentialSafeJSON(t, response.Body.Bytes(), sharePasswordContractNewPassword)
			object, ok := decoded.(map[string]any)
			if !ok {
				t.Fatalf("create response = %#v, want object", decoded)
			}
			hash, _ := object["hash"].(string)
			if hash == "" {
				t.Fatalf("create response has no hash: %#v", object)
			}
			stored, err := store.Share.GetByHash(hash)
			if err != nil {
				t.Fatalf("load created share: %v", err)
			}
			if stored.HasPassword() != test.wantPassword {
				t.Errorf("stored HasPassword = %t, want %t", stored.HasPassword(), test.wantPassword)
			}
			assertSharePasswordResponseState(t, response.Body.Bytes(), test.wantPassword,
				sharePasswordContractNewPassword, stored.PasswordHash, stored.Token)
			if stored.Token != "" {
				t.Errorf("new share persisted legacy token %q", stored.Token)
			}
			if !test.wantPassword {
				if stored.PasswordHash != "" {
					t.Errorf("password-free create persisted hash %q", stored.PasswordHash)
				}
				return
			}
			if stored.PasswordHash == "" || stored.PasswordHash == sharePasswordContractNewPassword {
				t.Fatalf("non-empty password was not persisted exclusively as a hash: %q", stored.PasswordHash)
			}
			if err := bcrypt.CompareHashAndPassword([]byte(stored.PasswordHash), []byte(sharePasswordContractNewPassword)); err != nil {
				t.Errorf("created password hash does not authenticate: %v", err)
			}
		})
	}
}

func TestSharePasswordUpdateKeepAndNullContract(t *testing.T) {
	tests := []struct {
		name            string
		includePassword bool
	}{
		{name: "missing keeps password", includePassword: false},
		{name: "null keeps password", includePassword: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSharePasswordContractFixture(t, "share-password-keep-"+strings.ReplaceAll(test.name, " ", "-"))
			payload := sharePasswordUpdatePayload(fixture.link.Hash, "after keep")
			if test.includePassword {
				payload["password"] = nil
			}

			response, status, handlerErr := requestSharePasswordMutation(t, fixture.owner, payload)
			if handlerErr != nil || status != http.StatusOK {
				t.Fatalf("keep password update: status=%d err=%v body=%s", status, handlerErr, response.Body.String())
			}
			stored := requireSharePasswordStoredLink(t, fixture.link.Hash)
			if stored.PasswordHash != fixture.before.PasswordHash {
				t.Errorf("keep changed password hash: got %q, want exact original %q", stored.PasswordHash, fixture.before.PasswordHash)
			}
			if stored.Token != "" {
				t.Errorf("keep left legacy token %q", stored.Token)
			}
			if stored.Title != "after keep" || stored.Description != "updated password contract description" {
				t.Errorf("keep did not update other settings: title=%q description=%q", stored.Title, stored.Description)
			}
			assertSharePasswordAuthentication(t, stored, sharePasswordContractOldPassword, http.StatusOK)
			assertSharePasswordResponseState(t, response.Body.Bytes(), true,
				sharePasswordContractOldPassword, stored.PasswordHash, sharePasswordContractLegacyToken)
		})
	}
}

func TestSharePasswordUpdateRemoveContract(t *testing.T) {
	fixture := newSharePasswordContractFixture(t, "share-password-remove")
	payload := sharePasswordUpdatePayload(fixture.link.Hash, "after remove")
	payload["password"] = ""

	response, status, handlerErr := requestSharePasswordMutation(t, fixture.owner, payload)
	if handlerErr != nil || status != http.StatusOK {
		t.Fatalf("remove password update: status=%d err=%v body=%s", status, handlerErr, response.Body.String())
	}
	stored := requireSharePasswordStoredLink(t, fixture.link.Hash)
	if stored.PasswordHash != "" || stored.HasPassword() {
		t.Errorf("remove left password protection: hash=%q hasPassword=%t", stored.PasswordHash, stored.HasPassword())
	}
	if stored.Token != "" {
		t.Errorf("remove left legacy token %q", stored.Token)
	}
	assertSharePasswordAuthentication(t, stored, "", http.StatusOK)
	assertSharePasswordResponseState(t, response.Body.Bytes(), false,
		sharePasswordContractOldPassword, fixture.before.PasswordHash, sharePasswordContractLegacyToken)
}

func TestSharePasswordUpdateReplaceContract(t *testing.T) {
	fixture := newSharePasswordContractFixture(t, "share-password-replace")
	payload := sharePasswordUpdatePayload(fixture.link.Hash, "after replace")
	payload["password"] = sharePasswordContractNewPassword

	response, status, handlerErr := requestSharePasswordMutation(t, fixture.owner, payload)
	if handlerErr != nil || status != http.StatusOK {
		t.Fatalf("replace password update: status=%d err=%v body=%s", status, handlerErr, response.Body.String())
	}
	stored := requireSharePasswordStoredLink(t, fixture.link.Hash)
	if stored.PasswordHash == "" || stored.PasswordHash == fixture.before.PasswordHash || stored.PasswordHash == sharePasswordContractNewPassword {
		t.Errorf("replace produced invalid password hash %q", stored.PasswordHash)
	}
	if stored.Token != "" {
		t.Errorf("replace left legacy token %q", stored.Token)
	}
	assertSharePasswordAuthentication(t, stored, sharePasswordContractOldPassword, http.StatusUnauthorized)
	assertSharePasswordAuthentication(t, stored, sharePasswordContractNewPassword, http.StatusOK)
	assertSharePasswordResponseState(t, response.Body.Bytes(), true,
		sharePasswordContractOldPassword, sharePasswordContractNewPassword,
		fixture.before.PasswordHash, stored.PasswordHash, sharePasswordContractLegacyToken)
}

func TestSharePasswordUpdateHashFailureHasZeroSideEffects(t *testing.T) {
	fixture := newSharePasswordContractFixture(t, "share-password-hash-failure")
	payload := sharePasswordUpdatePayload(fixture.link.Hash, "must not persist")
	payload["password"] = strings.Repeat("x", 73)

	response, status, handlerErr := requestSharePasswordMutation(t, fixture.owner, payload)
	if handlerErr == nil || status != http.StatusInternalServerError {
		t.Fatalf("password hash failure: status=%d err=%v body=%s", status, handlerErr, response.Body.String())
	}
	after := requireSharePasswordStoredLink(t, fixture.link.Hash)
	assertSharePasswordLinkUnchanged(t, fixture.before, after)
	assertSecretsAbsentFromBytes(t, response.Body.Bytes(), strings.Repeat("x", 73),
		fixture.before.PasswordHash, sharePasswordContractLegacyToken)
}

func TestSharePasswordUpdateAuditContract(t *testing.T) {
	tests := []struct {
		name               string
		includePassword    bool
		password           any
		wantAuthentication bool
		wantPassword       bool
	}{
		{name: "keep", wantPassword: true},
		{name: "null keep", includePassword: true, password: nil, wantPassword: true},
		{name: "remove", includePassword: true, password: "", wantAuthentication: true},
		{name: "replace", includePassword: true, password: sharePasswordContractNewPassword, wantAuthentication: true, wantPassword: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAuditShareTestFixture(t, nil)
			owner := fixture.newUser(t, "share-password-audit-owner", auditShareFullPermissions())
			link, oldHash := saveAuditSharePasswordContractLink(t, fixture, owner, "share-password-audit-"+strings.ReplaceAll(test.name, " ", "-"))
			session := auditTokenSession(t, owner)
			payload := sharePasswordUpdatePayload(link.Hash, "after audit update")
			payload["shareURL"] = "https://share.invalid/SHARE-PASSWORD-AUDIT-URL-SECRET"
			payload["downloadURL"] = "https://download.invalid/SHARE-PASSWORD-AUDIT-URL-SECRET"
			payload["authorization"] = "SHARE-PASSWORD-AUDIT-AUTHORIZATION-SECRET"
			payload["cookie"] = "SHARE-PASSWORD-AUDIT-COOKIE-SECRET"
			if test.includePassword {
				payload["password"] = test.password
			}

			response := fixture.request(t, http.MethodPost, "/api/share", marshalSharePasswordPayload(t, payload), session)
			if response.Code != http.StatusOK {
				t.Fatalf("audit password update: status=%d body=%s", response.Code, response.Body.String())
			}
			stored := requireSharePasswordStoredLink(t, link.Hash)
			if stored.HasPassword() != test.wantPassword || stored.Token != "" {
				t.Errorf("audit update state: hasPassword=%t token=%q", stored.HasPassword(), stored.Token)
			}
			if !test.wantAuthentication && stored.PasswordHash != oldHash {
				t.Errorf("keep audit update changed password hash: got %q, want %q", stored.PasswordHash, oldHash)
			}
			event := fixture.requireReservedTerminal(t)
			if got := auditEventHasChangedField(event, auditdb.ChangedFieldAuthentication); got != test.wantAuthentication {
				t.Errorf("authentication changed field = %t, want %t; metadata=%+v", got, test.wantAuthentication, event.Metadata)
			}
			assertAuditShareSecretsAbsent(t, event,
				link.Hash, sharePasswordContractOldPassword, sharePasswordContractNewPassword,
				oldHash, stored.PasswordHash, sharePasswordContractLegacyToken,
				"SHARE-PASSWORD-AUDIT-URL-SECRET", "SHARE-PASSWORD-AUDIT-AUTHORIZATION-SECRET",
				"SHARE-PASSWORD-AUDIT-COOKIE-SECRET", session, fixture.sourcePath)
			assertSharePasswordResponseState(t, response.Body.Bytes(), test.wantPassword,
				sharePasswordContractOldPassword, sharePasswordContractNewPassword,
				oldHash, stored.PasswordHash, sharePasswordContractLegacyToken)
		})
	}
}

func TestSharePasswordUpdateAuditReservationFailureHasZeroSideEffects(t *testing.T) {
	fixture := newFailingAuditShareTestFixture(t)
	owner := fixture.newUser(t, "share-password-reservation-owner", auditShareFullPermissions())
	link, oldHash := saveAuditSharePasswordContractLink(t, fixture, owner, "share-password-reservation")
	before := requireSharePasswordStoredLink(t, link.Hash).Clone()
	payload := sharePasswordUpdatePayload(link.Hash, "must not persist")
	payload["password"] = sharePasswordContractNewPassword
	session := auditTokenSession(t, owner)

	response := fixture.request(t, http.MethodPost, "/api/share", marshalSharePasswordPayload(t, payload), session)
	fixture.assertReservationFailure(t, response)
	after := requireSharePasswordStoredLink(t, link.Hash)
	assertSharePasswordLinkUnchanged(t, before, after)
	assertSecretsAbsentFromBytes(t, response.Body.Bytes(), sharePasswordContractNewPassword,
		oldHash, sharePasswordContractLegacyToken, session)
}

func TestSharePasswordUpdateConflictHasZeroSideEffects(t *testing.T) {
	fixture := newAuditShareTestFixture(t, nil)
	owner := fixture.newUser(t, "contract-conflict-owner", auditShareFullPermissions())
	link, oldHash := saveAuditSharePasswordContractLink(t, fixture, owner, "share-password-conflict")
	before := requireSharePasswordStoredLink(t, link.Hash).Clone()
	fixture.auditStore.onCreate = func(auditdb.Event) {
		current := requireSharePasswordStoredLink(t, link.Hash)
		if err := store.Share.Save(current.Clone()); err != nil {
			t.Fatalf("replace cached share identity: %v", err)
		}
	}
	payload := sharePasswordUpdatePayload(link.Hash, "must lose conflict")
	payload["password"] = sharePasswordContractNewPassword
	session := auditTokenSession(t, owner)

	response := fixture.request(t, http.MethodPost, "/api/share", marshalSharePasswordPayload(t, payload), session)
	if response.Code != http.StatusConflict {
		t.Fatalf("conflict status=%d, want 409; body=%s", response.Code, response.Body.String())
	}
	after := requireSharePasswordStoredLink(t, link.Hash)
	assertSharePasswordLinkUnchanged(t, before, after)
	event := fixture.requireReservedTerminal(t)
	assertAuditShareSecretsAbsent(t, event, link.Hash, sharePasswordContractNewPassword,
		oldHash, sharePasswordContractLegacyToken, session, fixture.sourcePath)
	assertSecretsAbsentFromBytes(t, response.Body.Bytes(), sharePasswordContractNewPassword,
		oldHash, sharePasswordContractLegacyToken, session)
}

func TestSharePasswordUpdateAuditFinalizeFailureRetainsPending(t *testing.T) {
	auditStore := &observingAuditShareStore{auditStoreStub: newAuditStoreStub()}
	auditStore.finalizeErr = errors.New("SHARE-PASSWORD-AUDIT-FINALIZE-SECRET")
	fixture := newAuditShareTestFixture(t, auditStore)
	owner := fixture.newUser(t, "contract-finalize-owner", auditShareFullPermissions())
	link, oldHash := saveAuditSharePasswordContractLink(t, fixture, owner, "share-password-finalize")
	payload := sharePasswordUpdatePayload(link.Hash, "finalize failure persisted update")
	payload["password"] = sharePasswordContractNewPassword
	session := auditTokenSession(t, owner)

	response := fixture.request(t, http.MethodPost, "/api/share", marshalSharePasswordPayload(t, payload), session)
	if response.Code != http.StatusOK {
		t.Fatalf("finalize failure changed response: status=%d body=%s", response.Code, response.Body.String())
	}
	stored := requireSharePasswordStoredLink(t, link.Hash)
	if stored.PasswordHash == oldHash || stored.Token != "" {
		t.Errorf("finalize failure changed successful persistence semantics: hashChanged=%t token=%q",
			stored.PasswordHash != oldHash, stored.Token)
	}
	if !fixture.service.IsDegraded() || fixture.service.LastFailureCategory() != AuditFailureFinalize {
		t.Errorf("finalize degraded state: got %t/%q", fixture.service.IsDegraded(), fixture.service.LastFailureCategory())
	}
	creates, finalizes, appends, pending, terminal := fixture.auditStore.state()
	if creates != 1 || finalizes != 1 || appends != 0 || pending != 1 || terminal != 0 {
		t.Fatalf("finalize audit state: create=%d finalize=%d append=%d pending=%d terminal=%d",
			creates, finalizes, appends, pending, terminal)
	}
	pendingEvent := fixture.auditStore.singlePending(t)
	if !auditEventHasChangedField(pendingEvent, auditdb.ChangedFieldAuthentication) {
		t.Errorf("pending event omits authentication change: %+v", pendingEvent.Metadata)
	}
	assertAuditShareSecretsAbsent(t, pendingEvent, link.Hash, sharePasswordContractOldPassword,
		sharePasswordContractNewPassword, oldHash, stored.PasswordHash, sharePasswordContractLegacyToken,
		"SHARE-PASSWORD-AUDIT-FINALIZE-SECRET", session, fixture.sourcePath)
	assertSharePasswordResponseState(t, response.Body.Bytes(), true,
		sharePasswordContractOldPassword, sharePasswordContractNewPassword,
		oldHash, stored.PasswordHash, sharePasswordContractLegacyToken,
		"SHARE-PASSWORD-AUDIT-FINALIZE-SECRET")
}

func newSharePasswordContractFixture(t *testing.T, hash string) *sharePasswordContractFixture {
	t.Helper()
	sourcePath := setupResourcePutTestEnv(t)
	harness := newPermissionShareSecurityHarness(t, sourcePath)
	owner := harness.newOwner(t, "share-password-contract-owner", auditShareFullPermissions())
	link := harness.saveShare(t, owner, hash, "/public", func(common *dbshare.CommonShare) {
		common.Title = "before password contract update"
		common.Description = "before password contract description"
	})
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(sharePasswordContractOldPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	link.PasswordHash = string(passwordHash)
	link.Token = sharePasswordContractLegacyToken
	if err := store.Share.Save(link); err != nil {
		t.Fatalf("save password contract fixture: %v", err)
	}
	return &sharePasswordContractFixture{
		harness: harness,
		owner:   owner,
		link:    link,
		before:  link.Clone(),
	}
}

func saveAuditSharePasswordContractLink(t *testing.T, fixture *auditShareTestFixture, owner *users.User, hash string) (*dbshare.Link, string) {
	t.Helper()
	link := fixture.saveShare(t, owner, hash, "/public/")
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(sharePasswordContractOldPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	link.PasswordHash = string(passwordHash)
	link.Token = sharePasswordContractLegacyToken
	link.Title = "before audit password update"
	link.Description = "before audit password description"
	if err := store.Share.Save(link); err != nil {
		t.Fatalf("save audit password contract fixture: %v", err)
	}
	return link, string(passwordHash)
}

func sharePasswordUpdatePayload(hash, title string) map[string]any {
	return map[string]any{
		"hash":        hash,
		"source":      "ignored-source",
		"path":        "/ignored-path",
		"shareType":   "normal",
		"title":       title,
		"description": "updated password contract description",
	}
}

func requestSharePasswordMutation(t *testing.T, owner *users.User, payload map[string]any) (*httptest.ResponseRecorder, int, error) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "https://files.example/api/share",
		bytes.NewReader(marshalSharePasswordPayload(t, payload)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	status, err := sharePostHandler(response, request, &requestContext{user: owner})
	return response, status, err
}

func marshalSharePasswordPayload(t *testing.T, payload any) []byte {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal share password payload: %v", err)
	}
	return encoded
}

func requireSharePasswordStoredLink(t *testing.T, hash string) *dbshare.Link {
	t.Helper()
	link, err := store.Share.GetByHash(hash)
	if err != nil {
		t.Fatalf("load share %q: %v", hash, err)
	}
	return link
}

func assertSharePasswordResponseState(t *testing.T, body []byte, wantHasPassword bool, secrets ...string) {
	t.Helper()
	decoded := decodeCredentialSafeJSON(t, body, secrets...)
	object, ok := decoded.(map[string]any)
	if !ok {
		t.Fatalf("share response = %#v, want object", decoded)
	}
	hasPassword, ok := object["hasPassword"].(bool)
	if !ok || hasPassword != wantHasPassword {
		t.Errorf("response hasPassword = %#v, want %t", object["hasPassword"], wantHasPassword)
	}
}

func assertSharePasswordAuthentication(t *testing.T, link *dbshare.Link, password string, wantStatus int) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/public/api/resources", nil)
	if password != "" {
		request.Header.Set("X-SHARE-PASSWORD", password)
	}
	status, err := authenticateShareRequest(request, link)
	if err != nil {
		t.Fatalf("authenticate share password: %v", err)
	}
	if status != wantStatus {
		t.Errorf("authenticate status = %d, want %d", status, wantStatus)
	}
}

func assertSharePasswordLinkUnchanged(t *testing.T, before, after *dbshare.Link) {
	t.Helper()
	beforeJSON := marshalSharePasswordPayload(t, before.Clone())
	afterJSON := marshalSharePasswordPayload(t, after.Clone())
	if !bytes.Equal(beforeJSON, afterJSON) {
		t.Errorf("share changed unexpectedly:\nbefore=%s\nafter=%s", beforeJSON, afterJSON)
	}
}

func auditEventHasChangedField(event auditdb.Event, want auditdb.ChangedField) bool {
	if event.Metadata == nil {
		return false
	}
	for _, field := range event.Metadata.ChangedFields {
		if field == want {
			return true
		}
	}
	return false
}

func assertSecretsAbsentFromBytes(t *testing.T, data []byte, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret != "" && bytes.Contains(data, []byte(secret)) {
			t.Errorf("response leaked forbidden value %q: %s", secret, data)
		}
	}
}
