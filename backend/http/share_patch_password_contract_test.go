package http

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	dbshare "github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	logpkg "github.com/gtsteffaniak/go-logger/logger"
)

const (
	sharePasswordPatchIgnoredPasswordSecret = "SHARE-PASSWORD-PATCH-IGNORED-PASSWORD-SECRET"
	sharePasswordPatchURLSecret             = "SHARE-PASSWORD-PATCH-URL-SECRET"
	sharePasswordPatchAuthorizationSecret   = "SHARE-PASSWORD-PATCH-AUTHORIZATION-SECRET"
	sharePasswordPatchCookieSecret          = "SHARE-PASSWORD-PATCH-COOKIE-SECRET"
)

func TestSharePasswordPatchClearsLegacyTokenAndPreservesPassword(t *testing.T) {
	fixture := newAuditShareTestFixture(t, nil)
	owner := fixture.newUser(t, "share-password-patch-owner", auditShareFullPermissions())
	link, oldHash := saveSharePasswordPatchContractLink(t, fixture, owner, "share-password-patch-success", "patch-target")
	before := requireSharePasswordStoredLink(t, link.Hash).Clone()
	session := auditTokenSession(t, owner)

	assertSharePasswordAuthentication(t, before, sharePasswordContractOldPassword, http.StatusOK)
	assertSharePasswordAuthentication(t, before, sharePasswordContractLegacyToken, http.StatusUnauthorized)

	capture := &securityCaptureLogger{}
	logpkg.SetGlobalLogger(capture)
	t.Cleanup(func() { logpkg.SetGlobalLogger(nil) })
	response := fixture.request(t, http.MethodPatch, "/api/share", marshalSharePasswordPayload(t, sharePasswordPatchPayload(
		link.Hash, "/public/patch-target",
	)), session)
	if response.Code != http.StatusOK {
		t.Fatalf("patch status=%d, want 200; body=%s", response.Code, response.Body.String())
	}

	stored := requireSharePasswordStoredLink(t, link.Hash)
	expected := before.Clone()
	expected.Path = "/public/patch-target/"
	expected.Token = ""
	assertSharePasswordLinkUnchanged(t, expected, stored)
	if stored.PasswordHash != oldHash || !stored.HasPassword() {
		t.Errorf("patch changed password state: hashPreserved=%t hasPassword=%t", stored.PasswordHash == oldHash, stored.HasPassword())
	}
	assertSharePasswordAuthentication(t, stored, sharePasswordContractOldPassword, http.StatusOK)
	assertSharePasswordAuthentication(t, stored, sharePasswordContractLegacyToken, http.StatusUnauthorized)

	responseSecrets := []string{
		sharePasswordContractOldPassword,
		sharePasswordPatchIgnoredPasswordSecret,
		oldHash,
		sharePasswordContractLegacyToken,
		sharePasswordPatchURLSecret,
		sharePasswordPatchAuthorizationSecret,
		sharePasswordPatchCookieSecret,
		session,
		fixture.sourcePath,
	}
	decoded := decodeCredentialSafeJSON(t, response.Body.Bytes(), responseSecrets...)
	object, ok := decoded.(map[string]any)
	if !ok {
		t.Fatalf("patch response = %#v, want object", decoded)
	}
	if got, _ := object["path"].(string); got != stored.Path {
		t.Errorf("patch response path=%q, want %q", got, stored.Path)
	}
	if got, _ := object["hasPassword"].(bool); !got {
		t.Errorf("patch response hasPassword=%#v, want true", object["hasPassword"])
	}
	assertPasswordShareManagementURLsSafe(t, object,
		sharePasswordContractOldPassword, sharePasswordPatchIgnoredPasswordSecret,
		oldHash, sharePasswordContractLegacyToken)

	event := fixture.requireReservedTerminal(t)
	assertAuditShareTerminal(t, event, auditdb.ActionShareUpdate, owner, link.Hash, "source1", stored.Path, http.StatusOK)
	if event.Metadata == nil || len(event.Metadata.ChangedFields) != 1 ||
		event.Metadata.ChangedFields[0] != auditdb.ChangedFieldPath {
		t.Errorf("patch audit changed fields=%+v, want only path", event.Metadata)
	}
	serverShareURL, _ := object["shareURL"].(string)
	serverDownloadURL, _ := object["downloadURL"].(string)
	auditAndLogSecrets := append(responseSecrets, link.Hash, serverShareURL, serverDownloadURL)
	assertAuditShareSecretsAbsent(t, event, auditAndLogSecrets...)
	assertSecretsAbsentFromBytes(t, []byte(capture.String()), auditAndLogSecrets...)
}

func TestSharePasswordPatchAuditReservationFailureHasZeroSideEffects(t *testing.T) {
	fixture := newFailingAuditShareTestFixture(t)
	owner := fixture.newUser(t, "share-password-patch-reservation-owner", auditShareFullPermissions())
	link, oldHash := saveSharePasswordPatchContractLink(t, fixture, owner, "share-password-patch-reservation", "reservation-target")
	before := requireSharePasswordStoredLink(t, link.Hash).Clone()
	session := auditTokenSession(t, owner)

	response := fixture.request(t, http.MethodPatch, "/api/share", marshalSharePasswordPayload(t, sharePasswordPatchPayload(
		link.Hash, "/public/reservation-target",
	)), session)
	fixture.assertReservationFailure(t, response)
	after := requireSharePasswordStoredLink(t, link.Hash)
	assertSharePasswordLinkUnchanged(t, before, after)
	assertSecretsAbsentFromBytes(t, response.Body.Bytes(),
		sharePasswordContractOldPassword, sharePasswordPatchIgnoredPasswordSecret,
		oldHash, sharePasswordContractLegacyToken, sharePasswordPatchURLSecret,
		sharePasswordPatchAuthorizationSecret, sharePasswordPatchCookieSecret,
		session, fixture.sourcePath)
}

func TestSharePasswordPatchConflictHasZeroSideEffects(t *testing.T) {
	fixture := newAuditShareTestFixture(t, nil)
	owner := fixture.newUser(t, "patch-conflict-owner", auditShareFullPermissions())
	link, oldHash := saveSharePasswordPatchContractLink(t, fixture, owner, "share-password-patch-conflict", "conflict-target")
	before := requireSharePasswordStoredLink(t, link.Hash).Clone()
	fixture.auditStore.onCreate = func(auditdb.Event) {
		current := requireSharePasswordStoredLink(t, link.Hash)
		concurrentWinner := current.Clone()
		concurrentWinner.Title = "concurrent winner title"
		concurrentWinner.Description = "concurrent winner description"
		if err := store.Share.Save(concurrentWinner); err != nil {
			t.Fatalf("replace cached share identity: %v", err)
		}
	}
	session := auditTokenSession(t, owner)

	response := fixture.request(t, http.MethodPatch, "/api/share", marshalSharePasswordPayload(t, sharePasswordPatchPayload(
		link.Hash, "/public/conflict-target",
	)), session)
	if response.Code != http.StatusConflict {
		t.Fatalf("patch conflict status=%d, want 409; body=%s", response.Code, response.Body.String())
	}
	after := requireSharePasswordStoredLink(t, link.Hash)
	expected := before.Clone()
	expected.Title = "concurrent winner title"
	expected.Description = "concurrent winner description"
	assertSharePasswordLinkUnchanged(t, expected, after)
	assertSharePasswordAuthentication(t, after, sharePasswordContractOldPassword, http.StatusOK)
	assertSharePasswordAuthentication(t, after, sharePasswordContractLegacyToken, http.StatusUnauthorized)

	event := fixture.requireReservedTerminal(t)
	assertAuditShareTerminal(t, event, auditdb.ActionShareUpdate, owner, link.Hash, "source1", "/public/conflict-target/", http.StatusConflict)
	assertAuditShareSecretsAbsent(t, event,
		link.Hash, sharePasswordContractOldPassword, sharePasswordPatchIgnoredPasswordSecret,
		oldHash, sharePasswordContractLegacyToken, sharePasswordPatchURLSecret,
		sharePasswordPatchAuthorizationSecret, sharePasswordPatchCookieSecret,
		session, fixture.sourcePath)
	assertSecretsAbsentFromBytes(t, response.Body.Bytes(),
		sharePasswordContractOldPassword, sharePasswordPatchIgnoredPasswordSecret,
		oldHash, sharePasswordContractLegacyToken, sharePasswordPatchURLSecret,
		sharePasswordPatchAuthorizationSecret, sharePasswordPatchCookieSecret,
		session, fixture.sourcePath)
}

func saveSharePasswordPatchContractLink(
	t *testing.T,
	fixture *auditShareTestFixture,
	owner *users.User,
	hash, targetDirectory string,
) (*dbshare.Link, string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(fixture.sourcePath, "public", targetDirectory), 0o755); err != nil {
		t.Fatalf("create patch target: %v", err)
	}
	link, oldHash := saveAuditSharePasswordContractLink(t, fixture, owner, hash)
	link.DownloadsLimit = 11
	link.MaxBandwidth = 2048
	link.AllowedUsernames = []string{owner.Username}
	link.AllowCreate = true
	link.AllowModify = true
	link.AllowDelete = true
	link.AllowReplacements = true
	link.Downloads = 7
	link.UserDownloads = map[string]int{owner.Username: 3}
	link.Expire = 2_000_000_000
	link.Version = 9
	link.CapabilityVersion = dbshare.CurrentCapabilityVersion
	link.CreatorCapabilities = dbshare.CapabilitySnapshot{
		Share: true, Browse: true, Preview: true, Download: true,
		Create: true, Modify: true, Delete: true,
	}
	if err := store.Share.Save(link); err != nil {
		t.Fatalf("save patch contract fixture: %v", err)
	}
	return link, oldHash
}

func sharePasswordPatchPayload(hash, path string) map[string]any {
	return map[string]any{
		"hash":          hash,
		"path":          path,
		"password":      sharePasswordPatchIgnoredPasswordSecret,
		"shareURL":      "https://share.invalid/" + sharePasswordPatchURLSecret,
		"authorization": sharePasswordPatchAuthorizationSecret,
		"cookie":        sharePasswordPatchCookieSecret,
	}
}
