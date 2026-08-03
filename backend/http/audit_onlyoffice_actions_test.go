package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

type auditOnlyOfficeHarness struct {
	fixture *previewSecurityFixture
	file    previewSecurityFile
}

type auditOnlyOfficeCallbackFixture struct {
	callbackURL *url.URL
	claims      *onlyOfficeCapabilityClaims
	body        []byte
	signed      string
	documentKey string
	downloadURL string
	tokenRef    string
	parentToken string
	user        *users.User
	target      authenticatedReadTarget
}

func TestAuditOnlyOfficeActions(t *testing.T) {
	harness := newAuditOnlyOfficeHarness(t)

	t.Run("trusted close save records one terminal event", func(t *testing.T) {
		callback := harness.newCallback(t, "close-save", onlyOfficeStatusDocumentClosedWithChanges)
		replacement := []byte("audit-onlyoffice-close-save-replacement")
		harness.useDownloadBody(t, replacement)
		auditStore := newAuditStoreStub()
		handler, _ := newAuditOnlyOfficeHandler(auditStore)

		response := invokeAuditOnlyOfficeCallback(t, handler, callback)

		requireAuditOnlyOfficeHTTPStatus(t, response, http.StatusOK)
		requireAuditOnlyOfficeFileContent(t, harness.file.realPath, replacement)
		requireAuditOnlyOfficeStoreCounts(t, auditStore, 1, 1, 0, 0, 1)
		event := auditStore.singleAppended(t)
		requireAuditOnlyOfficeEvent(t, event, callback, auditdb.ResultSuccess, http.StatusOK, int64(len(replacement)), true)
		if event.RequestID == "" || event.RequestID != response.Header().Get(auditRequestIDHeader) {
			t.Errorf("request ID: event=%q response=%q", event.RequestID, response.Header().Get(auditRequestIDHeader))
		}
		requireAuditOnlyOfficeNoSecrets(t, event,
			callback.callbackURL.String(), callback.callbackURL.Query().Get("capability"), callback.signed,
			"Bearer "+callback.signed, callback.documentKey, callback.downloadURL,
			config.Integrations.OnlyOffice.Secret, harness.file.realPath, harness.fixture.sourcePath)
		if _, ok := utils.OnlyOfficeCache.Get(harness.file.realPath); ok {
			t.Error("successful close save retained the document key")
		}
		if _, err := onlyOfficeCapabilityStateForClaims(callback.claims); err == nil {
			t.Error("successful close save retained the callback capability")
		}
	})

	t.Run("trusted force save records reusable capability", func(t *testing.T) {
		callback := harness.newCallback(t, "force-save", onlyOfficeStatusForceSaveWhileDocumentStillOpen)
		replacement := []byte("audit-onlyoffice-force-save-replacement")
		harness.useDownloadBody(t, replacement)
		auditStore := newAuditStoreStub()
		handler, _ := newAuditOnlyOfficeHandler(auditStore)

		response := invokeAuditOnlyOfficeCallback(t, handler, callback)

		requireAuditOnlyOfficeHTTPStatus(t, response, http.StatusOK)
		requireAuditOnlyOfficeFileContent(t, harness.file.realPath, replacement)
		requireAuditOnlyOfficeStoreCounts(t, auditStore, 1, 1, 0, 0, 1)
		event := auditStore.singleAppended(t)
		requireAuditOnlyOfficeEvent(t, event, callback, auditdb.ResultSuccess, http.StatusOK, int64(len(replacement)), true)
		if key, ok := utils.OnlyOfficeCache.Get(harness.file.realPath); !ok || key != callback.documentKey {
			t.Errorf("successful force save changed document key: key=%q present=%v", key, ok)
		}
		if _, err := onlyOfficeCapabilityStateForClaims(callback.claims); err != nil {
			t.Errorf("successful force save did not retain updated callback capability: %v", err)
		}
	})

	t.Run("API token parent records safe actor and token reference", func(t *testing.T) {
		callback := harness.newAPITokenCallback(t, "api-token", onlyOfficeStatusForceSaveWhileDocumentStillOpen)
		replacement := []byte("audit-onlyoffice-api-token-replacement")
		harness.useDownloadBody(t, replacement)
		auditStore := newAuditStoreStub()
		handler, _ := newAuditOnlyOfficeHandler(auditStore)

		response := invokeAuditOnlyOfficeCallback(t, handler, callback)

		requireAuditOnlyOfficeHTTPStatus(t, response, http.StatusOK)
		requireAuditOnlyOfficeStoreCounts(t, auditStore, 1, 1, 0, 0, 1)
		event := auditStore.singleAppended(t)
		requireAuditOnlyOfficeEvent(t, event, callback, auditdb.ResultSuccess, http.StatusOK, int64(len(replacement)), true)
		requireAuditOnlyOfficeNoSecrets(t, event, callback.parentToken, utils.HashSHA256(callback.parentToken))
	})

	t.Run("untrusted capability and callback JWT create no event", func(t *testing.T) {
		t.Run("invalid capability", func(t *testing.T) {
			if err := os.WriteFile(harness.file.realPath, harness.file.content, 0o644); err != nil {
				t.Fatal(err)
			}
			documentKey := "audit-onlyoffice-invalid-capability-key"
			utils.OnlyOfficeCache.Set(harness.file.realPath, documentKey)
			t.Cleanup(func() { utils.OnlyOfficeCache.Delete(harness.file.realPath) })
			body, signed := signedOnlyOfficeSecurityCallback(t, OnlyOfficeCallback{
				Key:    documentKey,
				Status: onlyOfficeStatusDocumentClosedWithChanges,
				URL:    "http://office.test/cache/invalid-capability.docx",
			})
			var downloadCalls int
			harness.useDownloadTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				downloadCalls++
				return nil, errors.New("unexpected download")
			}))
			auditStore := newAuditStoreStub()
			handler, _ := newAuditOnlyOfficeHandler(auditStore)

			response := invokeRawAuditOnlyOfficeCallback(t, handler,
				"/api/office/callback?capability=invalid-capability-secret", body, "Bearer "+signed)

			requireAuditOnlyOfficeHTTPStatus(t, response, http.StatusForbidden)
			requireAuditOnlyOfficeStoreCounts(t, auditStore, 0, 0, 0, 0, 0)
			requireAuditOnlyOfficeFileContent(t, harness.file.realPath, harness.file.content)
			if downloadCalls != 0 {
				t.Errorf("invalid capability made %d outbound request(s)", downloadCalls)
			}
			requireAuditOnlyOfficeResponseNoSecrets(t, response, documentKey, signed,
				"invalid-capability-secret", config.Integrations.OnlyOffice.Secret)
		})

		t.Run("invalid callback JWT", func(t *testing.T) {
			callback := harness.newCallback(t, "invalid-jwt", onlyOfficeStatusDocumentClosedWithChanges)
			var downloadCalls int
			harness.useDownloadTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				downloadCalls++
				return nil, errors.New("unexpected download")
			}))
			auditStore := newAuditStoreStub()
			handler, _ := newAuditOnlyOfficeHandler(auditStore)

			response := invokeRawAuditOnlyOfficeCallback(t, handler, callback.callbackURL.RequestURI(), callback.body,
				"Bearer invalid-onlyoffice-callback-jwt")

			requireAuditOnlyOfficeHTTPStatus(t, response, http.StatusForbidden)
			requireAuditOnlyOfficeStoreCounts(t, auditStore, 0, 0, 0, 0, 0)
			requireAuditOnlyOfficeFileContent(t, harness.file.realPath, harness.file.content)
			if downloadCalls != 0 {
				t.Errorf("invalid callback JWT made %d outbound request(s)", downloadCalls)
			}
			if _, err := onlyOfficeCapabilityStateForClaims(callback.claims); err != nil {
				t.Errorf("invalid callback JWT consumed capability: %v", err)
			}
			requireAuditOnlyOfficeResponseNoSecrets(t, response, callback.documentKey,
				callback.callbackURL.Query().Get("capability"), "invalid-onlyoffice-callback-jwt")
		})

		t.Run("revoked signed capability state", func(t *testing.T) {
			callback := harness.newCallback(t, "revoked-capability-state", onlyOfficeStatusDocumentClosedWithChanges)
			onlyOfficeCapabilityCache.Delete(callback.claims.ID)
			var downloadCalls int
			harness.useDownloadTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				downloadCalls++
				return nil, errors.New("unexpected download")
			}))
			auditStore := newAuditStoreStub()
			handler, _ := newAuditOnlyOfficeHandler(auditStore)

			response := invokeAuditOnlyOfficeCallback(t, handler, callback)

			requireAuditOnlyOfficeHTTPStatus(t, response, http.StatusForbidden)
			requireAuditOnlyOfficeStoreCounts(t, auditStore, 0, 0, 0, 0, 0)
			requireAuditOnlyOfficeFileContent(t, harness.file.realPath, harness.file.content)
			if downloadCalls != 0 {
				t.Errorf("revoked capability state made %d outbound request(s)", downloadCalls)
			}
			requireAuditOnlyOfficeResponseNoSecrets(t, response, callback.documentKey,
				callback.signed, callback.callbackURL.Query().Get("capability"))
		})
	})

	t.Run("revoked owner modify permission records denied without pending", func(t *testing.T) {
		callback := harness.newCallback(t, "modify-revoked", onlyOfficeStatusDocumentClosedWithChanges)
		current, err := store.Users.Get(callback.user.ID)
		if err != nil {
			t.Fatal(err)
		}
		current.Permissions.Modify = false
		if err := store.Users.Update(current, true, "Permissions"); err != nil {
			t.Fatal(err)
		}
		var downloadCalls int
		harness.useDownloadTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			downloadCalls++
			return nil, errors.New("unexpected download")
		}))
		auditStore := newAuditStoreStub()
		handler, _ := newAuditOnlyOfficeHandler(auditStore)

		response := invokeAuditOnlyOfficeCallback(t, handler, callback)

		requireAuditOnlyOfficeHTTPStatus(t, response, http.StatusForbidden)
		requireAuditOnlyOfficeFileContent(t, harness.file.realPath, harness.file.content)
		if downloadCalls != 0 {
			t.Errorf("permission denial made %d outbound request(s)", downloadCalls)
		}
		requireAuditOnlyOfficeStoreCounts(t, auditStore, 0, 0, 1, 0, 1)
		event := auditStore.singleAppended(t)
		requireAuditOnlyOfficeEvent(t, event, callback, auditdb.ResultDenied, http.StatusForbidden, 0, false)
		if _, err := onlyOfficeCapabilityStateForClaims(callback.claims); err != nil {
			t.Errorf("permission denial consumed callback capability: %v", err)
		}
	})

	t.Run("reservation failure has zero side effects", func(t *testing.T) {
		callback := harness.newCallback(t, "reservation-failure", onlyOfficeStatusDocumentClosedWithChanges)
		var downloadCalls int
		harness.useDownloadTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			downloadCalls++
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("must-not-be-downloaded")),
			}, nil
		}))
		auditStore := newAuditStoreStub()
		auditStore.createErr = errors.New("injected OnlyOffice audit reservation failure")
		handler, service := newAuditOnlyOfficeHandler(auditStore)

		response := invokeAuditOnlyOfficeCallback(t, handler, callback)

		requireAuditOnlyOfficeHTTPStatus(t, response, http.StatusServiceUnavailable)
		if downloadCalls != 0 {
			t.Errorf("reservation failure made %d outbound download request(s), want 0", downloadCalls)
		}
		requireAuditOnlyOfficeFileContent(t, harness.file.realPath, harness.file.content)
		requireAuditOnlyOfficeStoreCounts(t, auditStore, 1, 0, 0, 0, 0)
		if !service.IsDegraded() || service.LastFailureCategory() != AuditFailureReservation {
			t.Errorf("audit service state: degraded=%v category=%q", service.IsDegraded(), service.LastFailureCategory())
		}
		requireAuditOnlyOfficeResponseNoSecrets(t, response, "injected OnlyOffice audit reservation failure")
		if key, ok := utils.OnlyOfficeCache.Get(harness.file.realPath); !ok || key != callback.documentKey {
			t.Errorf("reservation failure changed document key: key=%q present=%v", key, ok)
		}
		if _, err := onlyOfficeCapabilityStateForClaims(callback.claims); err != nil {
			t.Errorf("reservation failure consumed callback capability: %v", err)
		}
	})

	t.Run("download failure finalizes failed event without changing target", func(t *testing.T) {
		callback := harness.newCallback(t, "download-failure", onlyOfficeStatusDocumentClosedWithChanges)
		var downloadCalls int
		harness.useDownloadTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			downloadCalls++
			return nil, errors.New("injected OnlyOffice download failure")
		}))
		auditStore := newAuditStoreStub()
		handler, _ := newAuditOnlyOfficeHandler(auditStore)

		response := invokeAuditOnlyOfficeCallback(t, handler, callback)

		requireAuditOnlyOfficeHTTPStatus(t, response, http.StatusInternalServerError)
		requireAuditOnlyOfficeFileContent(t, harness.file.realPath, harness.file.content)
		if downloadCalls != 1 {
			t.Errorf("download calls: got %d, want 1", downloadCalls)
		}
		requireAuditOnlyOfficeStoreCounts(t, auditStore, 1, 1, 0, 0, 1)
		event := auditStore.singleAppended(t)
		requireAuditOnlyOfficeEvent(t, event, callback, auditdb.ResultFailed, http.StatusInternalServerError, 0, true)
		requireAuditOnlyOfficeNoSecrets(t, event, callback.documentKey, callback.downloadURL,
			callback.signed, callback.callbackURL.Query().Get("capability"))
	})

	t.Run("document write failure finalizes failed event and removes temporary file", func(t *testing.T) {
		callback := harness.newCallback(t, "write-failure", onlyOfficeStatusDocumentClosedWithChanges)
		partial := []byte("partial-audit-onlyoffice-write")
		harness.useDownloadTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       &auditOnlyOfficeFailingBody{content: partial},
			}, nil
		}))
		auditStore := newAuditStoreStub()
		handler, _ := newAuditOnlyOfficeHandler(auditStore)

		response := invokeAuditOnlyOfficeCallback(t, handler, callback)

		requireAuditOnlyOfficeHTTPStatus(t, response, http.StatusInternalServerError)
		requireAuditOnlyOfficeFileContent(t, harness.file.realPath, harness.file.content)
		temporary, err := filepath.Glob(filepath.Join(filepath.Dir(harness.file.realPath), ".filebrowser-write-*"))
		if err != nil {
			t.Fatal(err)
		}
		if len(temporary) != 0 {
			t.Errorf("failed write retained temporary files: %v", temporary)
		}
		requireAuditOnlyOfficeStoreCounts(t, auditStore, 1, 1, 0, 0, 1)
		event := auditStore.singleAppended(t)
		requireAuditOnlyOfficeEvent(t, event, callback, auditdb.ResultFailed, http.StatusInternalServerError, 0, true)
	})

	t.Run("formal replacement failure records zero committed bytes", func(t *testing.T) {
		callback := harness.newCallback(t, "replace-failure", onlyOfficeStatusDocumentClosedWithChanges)
		replacement := []byte("audit-onlyoffice-uncommitted-replacement")
		harness.useDownloadBody(t, replacement)
		previousWrite := onlyOfficeWriteFileWithPreCommit
		onlyOfficeWriteFileWithPreCommit = func(_ string, _ string, _ string, reader io.Reader, preCommit func() error) error {
			if _, err := io.Copy(io.Discard, reader); err != nil {
				return err
			}
			if err := preCommit(); err != nil {
				return err
			}
			return errors.New("injected OnlyOffice formal replacement failure")
		}
		t.Cleanup(func() { onlyOfficeWriteFileWithPreCommit = previousWrite })
		auditStore := newAuditStoreStub()
		handler, _ := newAuditOnlyOfficeHandler(auditStore)

		response := invokeAuditOnlyOfficeCallback(t, handler, callback)

		requireAuditOnlyOfficeHTTPStatus(t, response, http.StatusInternalServerError)
		requireAuditOnlyOfficeFileContent(t, harness.file.realPath, harness.file.content)
		requireAuditOnlyOfficeStoreCounts(t, auditStore, 1, 1, 0, 0, 1)
		event := auditStore.singleAppended(t)
		requireAuditOnlyOfficeEvent(t, event, callback, auditdb.ResultFailed, http.StatusInternalServerError, 0, true)
		requireAuditOnlyOfficeNoSecrets(t, event, callback.documentKey, callback.downloadURL,
			callback.signed, callback.callbackURL.Query().Get("capability"), harness.file.realPath)
	})

	t.Run("post-commit index failure records committed bytes", func(t *testing.T) {
		callback := harness.newCallback(t, "post-commit-index-failure", onlyOfficeStatusDocumentClosedWithChanges)
		replacement := []byte("audit-onlyoffice-committed-before-index-failure")
		harness.useDownloadBody(t, replacement)
		previousWrite := onlyOfficeWriteFileWithPreCommit
		onlyOfficeWriteFileWithPreCommit = func(_ string, _ string, realPath string, reader io.Reader, preCommit func() error) error {
			content, err := io.ReadAll(reader)
			if err != nil {
				return err
			}
			if err := preCommit(); err != nil {
				return err
			}
			if err := os.WriteFile(realPath, content, 0o644); err != nil {
				return err
			}
			return errors.Join(files.ErrWriteCommitted, errors.New("injected OnlyOffice index refresh failure"))
		}
		t.Cleanup(func() { onlyOfficeWriteFileWithPreCommit = previousWrite })
		auditStore := newAuditStoreStub()
		handler, _ := newAuditOnlyOfficeHandler(auditStore)

		response := invokeAuditOnlyOfficeCallback(t, handler, callback)

		requireAuditOnlyOfficeHTTPStatus(t, response, http.StatusInternalServerError)
		requireAuditOnlyOfficeFileContent(t, harness.file.realPath, replacement)
		requireAuditOnlyOfficeStoreCounts(t, auditStore, 1, 1, 0, 0, 1)
		event := auditStore.singleAppended(t)
		requireAuditOnlyOfficeEvent(t, event, callback, auditdb.ResultFailed, http.StatusInternalServerError,
			int64(len(replacement)), true)
	})

	t.Run("non-save callbacks do not record save action", func(t *testing.T) {
		for _, status := range []int{
			onlyOfficeStatusDocumentBeingEdited,
			onlyOfficeStatusDocumentSavingError,
			onlyOfficeStatusDocumentClosedWithNoChanges,
			onlyOfficeStatusForceSaveError,
		} {
			status := status
			t.Run(string(rune('0'+status)), func(t *testing.T) {
				callback := harness.newCallback(t, "non-save-"+string(rune('0'+status)), status)
				var downloadCalls int
				harness.useDownloadTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
					downloadCalls++
					return nil, errors.New("unexpected download")
				}))
				auditStore := newAuditStoreStub()
				handler, _ := newAuditOnlyOfficeHandler(auditStore)

				response := invokeAuditOnlyOfficeCallback(t, handler, callback)

				requireAuditOnlyOfficeHTTPStatus(t, response, http.StatusOK)
				requireAuditOnlyOfficeStoreCounts(t, auditStore, 0, 0, 0, 0, 0)
				requireAuditOnlyOfficeFileContent(t, harness.file.realPath, harness.file.content)
				if downloadCalls != 0 {
					t.Errorf("non-save status %d made %d download request(s)", status, downloadCalls)
				}
			})
		}
	})

	t.Run("cancelled callback stops download before formal replacement", func(t *testing.T) {
		callback := harness.newCallback(t, "cancelled", onlyOfficeStatusDocumentClosedWithChanges)
		downloadStarted := make(chan struct{})
		downstreamCancelled := make(chan struct{}, 1)
		harness.useDownloadTransport(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
			close(downloadStarted)
			select {
			case <-request.Context().Done():
				downstreamCancelled <- struct{}{}
				return nil, request.Context().Err()
			case <-time.After(250 * time.Millisecond):
				return nil, errors.New("OnlyOffice download did not observe callback cancellation")
			}
		}))
		auditStore := newAuditStoreStub()
		handler, _ := newAuditOnlyOfficeHandler(auditStore)
		request := httptest.NewRequest(http.MethodPost, callback.callbackURL.RequestURI(), bytes.NewReader(callback.body))
		request.Header.Set("Authorization", "Bearer "+callback.signed)
		ctx, cancel := context.WithCancel(request.Context())
		request = request.WithContext(ctx)
		response := httptest.NewRecorder()
		done := make(chan struct{})

		go func() {
			handler.ServeHTTP(response, request)
			close(done)
		}()
		select {
		case <-downloadStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("OnlyOffice callback did not start its download")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("cancelled OnlyOffice callback did not finish")
		}

		requireAuditOnlyOfficeHTTPStatus(t, response, http.StatusInternalServerError)
		requireAuditOnlyOfficeFileContent(t, harness.file.realPath, harness.file.content)
		requireAuditOnlyOfficeStoreCounts(t, auditStore, 1, 1, 0, 0, 1)
		event := auditStore.singleAppended(t)
		requireAuditOnlyOfficeEvent(t, event, callback, auditdb.ResultCancelled, http.StatusInternalServerError, 0, true)
		if event.Metadata == nil || event.Metadata.ClientCancelled == nil || !*event.Metadata.ClientCancelled {
			t.Errorf("cancelled callback metadata: %+v", event.Metadata)
		}
		select {
		case <-downstreamCancelled:
		default:
			t.Error("OnlyOffice download did not inherit callback cancellation")
		}
	})

	t.Run("cancelled callback after download stops formal replacement", func(t *testing.T) {
		callback := harness.newCallback(t, "cancelled-before-commit", onlyOfficeStatusDocumentClosedWithChanges)
		replacement := []byte("audit-onlyoffice-must-not-commit-after-cancellation")
		harness.useDownloadBody(t, replacement)
		auditStore := newAuditStoreStub()
		handler, _ := newAuditOnlyOfficeHandler(auditStore)
		request := httptest.NewRequest(http.MethodPost, callback.callbackURL.RequestURI(), bytes.NewReader(callback.body))
		request.Header.Set("Authorization", "Bearer "+callback.signed)
		ctx, cancel := context.WithCancel(request.Context())
		request = request.WithContext(ctx)
		previousWrite := onlyOfficeWriteFileWithPreCommit
		onlyOfficeWriteFileWithPreCommit = func(_ string, _ string, realPath string, reader io.Reader, preCommit func() error) error {
			content, err := io.ReadAll(reader)
			if err != nil {
				return err
			}
			cancel()
			if err := preCommit(); err != nil {
				return err
			}
			return os.WriteFile(realPath, content, 0o644)
		}
		t.Cleanup(func() { onlyOfficeWriteFileWithPreCommit = previousWrite })
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		requireAuditOnlyOfficeHTTPStatus(t, response, http.StatusInternalServerError)
		requireAuditOnlyOfficeFileContent(t, harness.file.realPath, harness.file.content)
		requireAuditOnlyOfficeStoreCounts(t, auditStore, 1, 1, 0, 0, 1)
		event := auditStore.singleAppended(t)
		requireAuditOnlyOfficeEvent(t, event, callback, auditdb.ResultCancelled, http.StatusInternalServerError, 0, true)
		if event.Metadata == nil || event.Metadata.ClientCancelled == nil || !*event.Metadata.ClientCancelled {
			t.Errorf("cancelled callback metadata: %+v", event.Metadata)
		}
	})

	t.Run("finalize failure retains pending event", func(t *testing.T) {
		callback := harness.newCallback(t, "finalize-failure", onlyOfficeStatusDocumentClosedWithChanges)
		replacement := []byte("audit-onlyoffice-finalize-failure-replacement")
		harness.useDownloadBody(t, replacement)
		auditStore := newAuditStoreStub()
		auditStore.finalizeErr = errors.New("injected OnlyOffice audit finalize failure")
		handler, service := newAuditOnlyOfficeHandler(auditStore)

		response := invokeAuditOnlyOfficeCallback(t, handler, callback)

		requireAuditOnlyOfficeHTTPStatus(t, response, http.StatusOK)
		requireAuditOnlyOfficeFileContent(t, harness.file.realPath, replacement)
		requireAuditOnlyOfficeStoreCounts(t, auditStore, 1, 1, 0, 1, 0)
		pending := auditStore.singlePending(t)
		requireAuditOnlyOfficePendingEvent(t, pending, callback)
		if pending.RequestID == "" || pending.RequestID != response.Header().Get(auditRequestIDHeader) {
			t.Errorf("pending request ID: event=%q response=%q", pending.RequestID, response.Header().Get(auditRequestIDHeader))
		}
		if !service.IsDegraded() || service.LastFailureCategory() != AuditFailureFinalize {
			t.Errorf("audit service state: degraded=%v category=%q", service.IsDegraded(), service.LastFailureCategory())
		}
		requireAuditOnlyOfficeNoSecrets(t, pending,
			callback.callbackURL.String(), callback.callbackURL.Query().Get("capability"), callback.signed,
			callback.documentKey, callback.downloadURL, config.Integrations.OnlyOffice.Secret,
			harness.file.realPath, harness.fixture.sourcePath)
	})
}

func newAuditOnlyOfficeHarness(t *testing.T) *auditOnlyOfficeHarness {
	t.Helper()
	fixture := setupPreviewSecurityFixture(t)
	previousOffice := config.Integrations.OnlyOffice
	config.Integrations.OnlyOffice = settings.OnlyOffice{
		Url:    "http://office.test",
		Secret: "audit-onlyoffice-signing-secret",
	}
	t.Cleanup(func() { config.Integrations.OnlyOffice = previousOffice })
	return &auditOnlyOfficeHarness{fixture: fixture, file: fixture.files["Office"]}
}

func (harness *auditOnlyOfficeHarness) newCallback(t *testing.T, suffix string, status int) auditOnlyOfficeCallbackFixture {
	t.Helper()
	if err := os.WriteFile(harness.file.realPath, harness.file.content, 0o644); err != nil {
		t.Fatal(err)
	}
	documentKey := "audit-onlyoffice-document-key-" + suffix
	utils.OnlyOfficeCache.Set(harness.file.realPath, documentKey)
	t.Cleanup(func() { utils.OnlyOfficeCache.Delete(harness.file.realPath) })

	user := harness.fixture.user(t, true, true, true)
	user.Username = "audit-onlyoffice-user-" + suffix
	user.Permissions.Modify = true
	if err := store.Users.Save(user, false, false); err != nil {
		t.Fatalf("save OnlyOffice audit user: %v", err)
	}
	target, err := resolveAuthenticatedWriteTarget(user, "source1", harness.file.indexPath)
	if err != nil {
		t.Fatalf("resolve OnlyOffice audit target: %v", err)
	}
	_, callbackURL := issueOnlyOfficeSecurityURLs(t, user, harness.file.indexPath)
	claimsRequest := httptest.NewRequest(http.MethodPost, callbackURL.RequestURI(), nil)
	claims, err := parseOnlyOfficeCapability(claimsRequest, onlyOfficeCallbackAudience, http.MethodPost)
	if err != nil {
		t.Fatalf("parse OnlyOffice audit capability: %v", err)
	}
	t.Cleanup(func() { onlyOfficeCapabilityCache.Delete(claims.ID) })

	downloadURL := "http://office.test/cache/audit-" + suffix + ".docx"
	body, signed := signedOnlyOfficeSecurityCallback(t, OnlyOfficeCallback{
		Key:        documentKey,
		Status:     status,
		URL:        downloadURL,
		ChangesURL: "http://office.test/changes/" + suffix + "?secret=audit-onlyoffice-changes-secret-" + suffix,
		UserData:   "audit-onlyoffice-userdata-secret-" + suffix,
	})
	return auditOnlyOfficeCallbackFixture{
		callbackURL: callbackURL,
		claims:      claims,
		body:        body,
		signed:      signed,
		documentKey: documentKey,
		downloadURL: downloadURL,
		user:        user,
		target:      target,
	}
}

func (harness *auditOnlyOfficeHarness) newAPITokenCallback(t *testing.T, suffix string, status int) auditOnlyOfficeCallbackFixture {
	t.Helper()
	if err := os.WriteFile(harness.file.realPath, harness.file.content, 0o644); err != nil {
		t.Fatal(err)
	}
	documentKey := "audit-onlyoffice-document-key-" + suffix
	utils.OnlyOfficeCache.Set(harness.file.realPath, documentKey)
	t.Cleanup(func() { utils.OnlyOfficeCache.Delete(harness.file.realPath) })

	user := harness.fixture.user(t, true, true, true)
	user.Username = "audit-onlyoffice-user-" + suffix
	user.Permissions.Modify = true
	if err := store.Users.Save(user, false, false); err != nil {
		t.Fatalf("save OnlyOffice API token audit user: %v", err)
	}
	parentToken := issueShareSecurityToken(t, user, "audit-onlyoffice-parent-"+suffix, users.Permissions{
		Api: true, Browse: true, Download: true, Modify: true,
	})
	target, err := resolveAuthenticatedWriteTarget(user, "source1", harness.file.indexPath)
	if err != nil {
		t.Fatalf("resolve OnlyOffice API token audit target: %v", err)
	}
	query := url.Values{"source": {"source1"}, "path": {harness.file.indexPath}}
	configResponse := httptest.NewRecorder()
	configStatus, configErr := onlyofficeClientConfigGetHandler(configResponse,
		httptest.NewRequest(http.MethodGet, "/api/office/config?"+query.Encode(), nil),
		&requestContext{user: user, token: parentToken, apiToken: true})
	if configErr != nil || configStatus != http.StatusOK {
		t.Fatalf("OnlyOffice API token config: status=%d err=%v body=%s", configStatus, configErr, configResponse.Body.String())
	}
	_, callbackURL := onlyOfficeSecurityConfigURLs(t, configResponse)
	claimsRequest := httptest.NewRequest(http.MethodPost, callbackURL.RequestURI(), nil)
	claims, err := parseOnlyOfficeCapability(claimsRequest, onlyOfficeCallbackAudience, http.MethodPost)
	if err != nil {
		t.Fatalf("parse OnlyOffice API token audit capability: %v", err)
	}
	t.Cleanup(func() { onlyOfficeCapabilityCache.Delete(claims.ID) })

	downloadURL := "http://office.test/cache/audit-" + suffix + ".docx"
	body, signed := signedOnlyOfficeSecurityCallback(t, OnlyOfficeCallback{
		Key:        documentKey,
		Status:     status,
		URL:        downloadURL,
		ChangesURL: "http://office.test/changes/" + suffix + "?secret=audit-onlyoffice-changes-secret-" + suffix,
		UserData:   "audit-onlyoffice-userdata-secret-" + suffix,
	})
	return auditOnlyOfficeCallbackFixture{
		callbackURL: callbackURL,
		claims:      claims,
		body:        body,
		signed:      signed,
		documentKey: documentKey,
		downloadURL: downloadURL,
		tokenRef:    auditdb.DeriveTokenRef(utils.HashSHA256(parentToken)),
		parentToken: parentToken,
		user:        user,
		target:      target,
	}
}

func (harness *auditOnlyOfficeHarness) useDownloadBody(t *testing.T, content []byte) {
	t.Helper()
	harness.useDownloadTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(content)),
		}, nil
	}))
}

func (*auditOnlyOfficeHarness) useDownloadTransport(t *testing.T, transport http.RoundTripper) {
	t.Helper()
	previousClient := onlyOfficeDownloadClient
	onlyOfficeDownloadClient = &http.Client{Transport: transport}
	t.Cleanup(func() { onlyOfficeDownloadClient = previousClient })
}

func newAuditOnlyOfficeHandler(auditStore auditdb.Store) (http.Handler, *AuditService) {
	api := http.NewServeMux()
	api.HandleFunc("POST /office/callback", withoutUser(onlyofficeCallbackHandler))
	root := http.NewServeMux()
	root.Handle("/api/", http.StripPrefix("/api", api))
	service := NewAuditService(auditStore)
	return AuditMiddleware(LoggingMiddleware(root), service), service
}

func invokeAuditOnlyOfficeCallback(t *testing.T, handler http.Handler, callback auditOnlyOfficeCallbackFixture) *httptest.ResponseRecorder {
	t.Helper()
	return invokeRawAuditOnlyOfficeCallback(t, handler, callback.callbackURL.RequestURI(), callback.body, "Bearer "+callback.signed)
}

func invokeRawAuditOnlyOfficeCallback(
	t *testing.T,
	handler http.Handler,
	requestURI string,
	body []byte,
	authorization string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, requestURI, bytes.NewReader(body))
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func requireAuditOnlyOfficeEvent(
	t *testing.T,
	event auditdb.Event,
	callback auditOnlyOfficeCallbackFixture,
	result auditdb.Result,
	httpStatus int,
	writtenBytes int64,
	wantModify bool,
) {
	t.Helper()
	if event.Action != auditdb.ActionOnlyOfficeSave || event.Origin != auditdb.OriginOnlyOffice ||
		event.AuthMethod != auditdb.AuthMethodOnlyOffice || event.Result != result {
		t.Errorf("action/origin/auth/result: got %q/%q/%q/%q", event.Action, event.Origin, event.AuthMethod, event.Result)
	}
	if event.UserID == nil || *event.UserID != callback.user.ID || event.Username != callback.user.Username {
		t.Errorf("actor: got id=%v username=%q, want id=%d username=%q", event.UserID, event.Username, callback.user.ID, callback.user.Username)
	}
	if event.TokenRef != callback.tokenRef || event.ShareRef != "" {
		t.Errorf("references: got token=%q share=%q, want token=%q and no share", event.TokenRef, event.ShareRef, callback.tokenRef)
	}
	if event.Source != "source1" || event.Path != callback.target.LogicalPath || event.CanonicalPath != callback.target.CanonicalPath {
		t.Errorf("resource: got %q %q %q, want %q %q %q", event.Source, event.Path, event.CanonicalPath,
			"source1", callback.target.LogicalPath, callback.target.CanonicalPath)
	}
	if event.HTTPStatus == nil || *event.HTTPStatus != httpStatus {
		t.Errorf("HTTP status: got %v, want %d", event.HTTPStatus, httpStatus)
	}
	if event.EffectivePermissions == nil || !event.EffectivePermissions.Browse ||
		!event.EffectivePermissions.Download || event.EffectivePermissions.Modify != wantModify {
		t.Errorf("effective permissions: got %+v, want Browse+Download and Modify=%v", event.EffectivePermissions, wantModify)
	}
	if event.Metadata == nil || event.Metadata.Method != auditdb.MethodPOST ||
		event.Metadata.OnlyOfficeStatus == nil || *event.Metadata.OnlyOfficeStatus != callbackStatus(callback) ||
		event.Metadata.Bytes == nil || *event.Metadata.Bytes != writtenBytes {
		t.Errorf("metadata: got %+v, want method=POST status=%d bytes=%d", event.Metadata, callbackStatus(callback), writtenBytes)
	}
	requireAuditOnlyOfficeCallbackPayloadAbsent(t, event, callback)
}

func requireAuditOnlyOfficePendingEvent(t *testing.T, event auditdb.Event, callback auditOnlyOfficeCallbackFixture) {
	t.Helper()
	if event.Action != auditdb.ActionOnlyOfficeSave || event.Origin != auditdb.OriginOnlyOffice ||
		event.AuthMethod != auditdb.AuthMethodOnlyOffice {
		t.Errorf("pending action/origin/auth: got %q/%q/%q", event.Action, event.Origin, event.AuthMethod)
	}
	if event.UserID == nil || *event.UserID != callback.user.ID || event.Username != callback.user.Username {
		t.Errorf("pending actor: got id=%v username=%q", event.UserID, event.Username)
	}
	if event.Source != "source1" || event.Path != callback.target.LogicalPath || event.CanonicalPath != callback.target.CanonicalPath {
		t.Errorf("pending resource: got %q %q %q", event.Source, event.Path, event.CanonicalPath)
	}
	if event.Result != "" || event.HTTPStatus != nil || !event.TimestampUTC.IsZero() {
		t.Errorf("pending terminal fields were populated: result=%q status=%v timestamp=%v", event.Result, event.HTTPStatus, event.TimestampUTC)
	}
	if event.Metadata == nil || event.Metadata.Method != auditdb.MethodPOST ||
		event.Metadata.OnlyOfficeStatus == nil || *event.Metadata.OnlyOfficeStatus != callbackStatus(callback) {
		t.Errorf("pending metadata: got %+v", event.Metadata)
	}
	requireAuditOnlyOfficeCallbackPayloadAbsent(t, event, callback)
}

func requireAuditOnlyOfficeCallbackPayloadAbsent(t *testing.T, event auditdb.Event, callback auditOnlyOfficeCallbackFixture) {
	t.Helper()
	var payload OnlyOfficeCallback
	if err := json.Unmarshal(callback.body, &payload); err != nil {
		t.Fatal(err)
	}
	requireAuditOnlyOfficeNoSecrets(t, event, string(callback.body), payload.Key, payload.URL,
		payload.ChangesURL, payload.UserData)
}

func callbackStatus(callback auditOnlyOfficeCallbackFixture) int {
	var payload OnlyOfficeCallback
	_ = json.Unmarshal(callback.body, &payload)
	return payload.Status
}

func requireAuditOnlyOfficeStoreCounts(
	t *testing.T,
	store *auditStoreStub,
	creates, finalizes, appends, pending, terminal int,
) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.createCalls != creates || store.finalizeCalls != finalizes || store.appendCalls != appends ||
		len(store.pending) != pending || len(store.appended) != terminal {
		t.Errorf("audit writes: create=%d finalize=%d append=%d pending=%d terminal=%d; want %d,%d,%d,%d,%d",
			store.createCalls, store.finalizeCalls, store.appendCalls, len(store.pending), len(store.appended),
			creates, finalizes, appends, pending, terminal)
	}
}

func requireAuditOnlyOfficeHTTPStatus(t *testing.T, response *httptest.ResponseRecorder, want int) {
	t.Helper()
	if response.Code != want {
		t.Errorf("HTTP status: got %d, want %d (body: %q)", response.Code, want, response.Body.String())
	}
}

func requireAuditOnlyOfficeFileContent(t *testing.T, realPath string, want []byte) {
	t.Helper()
	content, err := os.ReadFile(realPath)
	if err != nil {
		t.Errorf("read OnlyOffice target: %v", err)
		return
	}
	if !bytes.Equal(content, want) {
		t.Errorf("OnlyOffice target content: got %q, want %q", content, want)
	}
}

func requireAuditOnlyOfficeNoSecrets(t *testing.T, event auditdb.Event, secrets ...string) {
	t.Helper()
	serialized, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		encoded, err := json.Marshal(secret)
		if err != nil {
			t.Fatal(err)
		}
		needle := string(encoded[1 : len(encoded)-1])
		if strings.Contains(string(serialized), needle) {
			t.Errorf("audit event leaked sensitive value %q: %s", secret, serialized)
		}
	}
	for name, value := range map[string]string{
		"path": event.Path, "canonicalPath": event.CanonicalPath,
		"targetPath": event.TargetPath, "targetCanonicalPath": event.TargetCanonicalPath,
	} {
		if filepath.VolumeName(value) != "" || strings.Contains(value, `\`) ||
			strings.Contains(value, "://") || strings.ContainsAny(value, "\r\n") {
			t.Errorf("unsafe audit %s %q", name, value)
		}
	}
}

func requireAuditOnlyOfficeResponseNoSecrets(t *testing.T, response *httptest.ResponseRecorder, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(response.Body.String(), secret) {
			t.Errorf("OnlyOffice response leaked sensitive value %q: %q", secret, response.Body.String())
		}
	}
}

type auditOnlyOfficeFailingBody struct {
	content []byte
	sent    bool
}

func (body *auditOnlyOfficeFailingBody) Read(buffer []byte) (int, error) {
	if !body.sent {
		body.sent = true
		return copy(buffer, body.content), nil
	}
	return 0, errors.New("injected OnlyOffice response body failure")
}

func (*auditOnlyOfficeFailingBody) Close() error { return nil }
