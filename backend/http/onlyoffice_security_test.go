package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	dbshare "github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
)

func TestOnlyOfficeSecurityCapabilities(t *testing.T) {
	fixture := setupPreviewSecurityFixture(t)
	officeFile := fixture.files["Office"]
	previousOffice := config.Integrations.OnlyOffice
	config.Integrations.OnlyOffice = settings.OnlyOffice{
		Url:    "http://office.test",
		Secret: "onlyoffice-security-secret",
	}
	t.Cleanup(func() { config.Integrations.OnlyOffice = previousOffice })
	utils.OnlyOfficeCache.Set(officeFile.realPath, "onlyoffice-security-document-key")
	t.Cleanup(func() { utils.OnlyOfficeCache.Delete(officeFile.realPath) })

	t.Run("config uses distinct scoped capabilities instead of the parent bearer", func(t *testing.T) {
		user := fixture.user(t, true, true, true)
		user.Permissions.Modify = true
		if err := store.Users.Save(user, false, false); err != nil {
			t.Fatalf("save OnlyOffice capability user: %v", err)
		}
		const parentBearer = "parent.full.bearer"
		query := url.Values{"source": {"source1"}, "path": {officeFile.indexPath}}
		request := httptest.NewRequest(http.MethodGet, "/api/office/config?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()
		status, err := onlyofficeClientConfigGetHandler(recorder, request, &requestContext{user: user, token: parentBearer})
		if err != nil || status != http.StatusOK {
			t.Fatalf("OnlyOffice config: status=%d err=%v body=%q", status, err, recorder.Body.String())
		}

		var payload map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		document, ok := payload["document"].(map[string]any)
		if !ok {
			t.Fatalf("OnlyOffice config lacks document: %v", payload)
		}
		editor, ok := payload["editorConfig"].(map[string]any)
		if !ok {
			t.Fatalf("OnlyOffice config lacks editorConfig: %v", payload)
		}
		downloadURL, _ := document["url"].(string)
		callbackURL, _ := editor["callbackUrl"].(string)
		if downloadURL == "" || callbackURL == "" {
			t.Fatalf("OnlyOffice config URLs are missing: download=%q callback=%q", downloadURL, callbackURL)
		}
		if strings.Contains(downloadURL, parentBearer) || strings.Contains(callbackURL, parentBearer) {
			t.Fatalf("OnlyOffice URL exposed parent bearer: download=%q callback=%q", downloadURL, callbackURL)
		}

		downloadParsed, err := url.Parse(downloadURL)
		if err != nil {
			t.Fatal(err)
		}
		callbackParsed, err := url.Parse(callbackURL)
		if err != nil {
			t.Fatal(err)
		}
		if downloadParsed.Query().Get("auth") != "" || callbackParsed.Query().Get("auth") != "" {
			t.Fatalf("OnlyOffice URL retained auth credential: download=%q callback=%q", downloadURL, callbackURL)
		}
		downloadCapability := downloadParsed.Query().Get("capability")
		callbackCapability := callbackParsed.Query().Get("capability")
		if downloadCapability == "" || callbackCapability == "" || downloadCapability == callbackCapability {
			t.Fatalf("OnlyOffice capabilities are missing or reused: download=%q callback=%q", downloadCapability, callbackCapability)
		}

		downloadRequest := httptest.NewRequest(http.MethodGet, downloadParsed.RequestURI(), nil)
		downloadClaims, err := parseOnlyOfficeCapability(downloadRequest, onlyOfficeDownloadAudience, http.MethodGet)
		if err != nil || downloadClaims.DocumentKey != "onlyoffice-security-document-key" || !downloadClaims.Browse || !downloadClaims.Download {
			t.Fatalf("parse download capability: claims=%+v err=%v", downloadClaims, err)
		}
		callbackRequest := httptest.NewRequest(http.MethodPost, callbackParsed.RequestURI(), nil)
		callbackClaims, err := parseOnlyOfficeCapability(callbackRequest, onlyOfficeCallbackAudience, http.MethodPost)
		if err != nil || callbackClaims.DocumentKey != downloadClaims.DocumentKey || callbackClaims.ID == downloadClaims.ID {
			t.Fatalf("parse callback capability: claims=%+v err=%v", callbackClaims, err)
		}

		downloadRecorder := httptest.NewRecorder()
		status, downloadErr := onlyOfficeCapabilityDownloadHandler(downloadRecorder, downloadRequest, &requestContext{})
		if downloadErr != nil || status != http.StatusOK || !bytes.Equal(downloadRecorder.Body.Bytes(), officeFile.content) {
			t.Fatalf("capability download: status=%d err=%v body=%q", status, downloadErr, downloadRecorder.Body.Bytes())
		}
		swapped := httptest.NewRequest(http.MethodGet, "/api/office/download?capability="+url.QueryEscape(callbackCapability), nil)
		status, swappedErr := onlyOfficeCapabilityDownloadHandler(httptest.NewRecorder(), swapped, &requestContext{})
		if status != http.StatusForbidden || swappedErr == nil {
			t.Fatalf("callback capability used for download: status=%d err=%v", status, swappedErr)
		}

		callback := OnlyOfficeCallback{
			Key:    "onlyoffice-security-document-key",
			Status: onlyOfficeStatusDocumentBeingEdited,
		}
		callbackBody, err := json.Marshal(callback)
		if err != nil {
			t.Fatal(err)
		}
		payloadToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"payload": callback})
		signedPayload, err := payloadToken.SignedString([]byte(config.Integrations.OnlyOffice.Secret))
		if err != nil {
			t.Fatal(err)
		}
		verifiedCallbackRequest := httptest.NewRequest(http.MethodPost, callbackParsed.RequestURI(), bytes.NewReader(callbackBody))
		verifiedCallbackRequest.Header.Set("Authorization", "Bearer "+signedPayload)
		status, callbackErr := onlyofficeCallbackHandler(httptest.NewRecorder(), verifiedCallbackRequest, &requestContext{})
		if callbackErr != nil || status != http.StatusOK {
			t.Fatalf("verified capability callback: status=%d err=%v", status, callbackErr)
		}
	})

	t.Run("config fails closed without a callback signing secret", func(t *testing.T) {
		user := fixture.user(t, true, true, true)
		user.Username = "onlyoffice-empty-secret-user"
		user.Permissions.Modify = true
		if err := store.Users.Save(user, false, false); err != nil {
			t.Fatal(err)
		}
		secret := config.Integrations.OnlyOffice.Secret
		config.Integrations.OnlyOffice.Secret = ""
		defer func() { config.Integrations.OnlyOffice.Secret = secret }()
		query := url.Values{"source": {"source1"}, "path": {officeFile.indexPath}}
		status, configErr := onlyofficeClientConfigGetHandler(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/office/config?"+query.Encode(), nil), &requestContext{user: user})
		if status != http.StatusInternalServerError || configErr == nil {
			t.Fatalf("config without secret: status=%d err=%v", status, configErr)
		}
	})

	t.Run("oversized callback body is rejected before signature verification", func(t *testing.T) {
		user := fixture.user(t, true, true, true)
		user.Username = "onlyoffice-oversized-callback-user"
		user.Permissions.Modify = true
		if err := store.Users.Save(user, false, false); err != nil {
			t.Fatal(err)
		}
		_, callbackURL := issueOnlyOfficeSecurityURLs(t, user, officeFile.indexPath)
		body := bytes.Repeat([]byte("x"), (1<<20)+1)
		request := httptest.NewRequest(http.MethodPost, callbackURL.RequestURI(), bytes.NewReader(body))
		status, callbackErr := onlyofficeCallbackHandler(httptest.NewRecorder(), request, &requestContext{})
		if status != http.StatusRequestEntityTooLarge || callbackErr == nil {
			t.Fatalf("oversized callback: status=%d err=%v", status, callbackErr)
		}
	})

	t.Run("force save error never writes in view-only mode", func(t *testing.T) {
		user := fixture.user(t, true, true, true)
		user.Username = "onlyoffice-view-only-status-seven-user"
		user.Permissions.Modify = true
		if err := store.Users.Save(user, false, false); err != nil {
			t.Fatal(err)
		}
		viewOnly := config.Integrations.OnlyOffice.ViewOnly
		config.Integrations.OnlyOffice.ViewOnly = true
		defer func() { config.Integrations.OnlyOffice.ViewOnly = viewOnly }()
		_, callbackURL := issueOnlyOfficeSecurityURLs(t, user, officeFile.indexPath)
		callback := OnlyOfficeCallback{
			Key:    "onlyoffice-security-document-key",
			Status: onlyOfficeStatusForceSaveError,
			URL:    "http://office.test/cache/status-seven.docx",
		}
		body, signed := signedOnlyOfficeSecurityCallback(t, callback)
		var requests atomic.Int32
		previousClient := onlyOfficeDownloadClient
		onlyOfficeDownloadClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			requests.Add(1)
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("status seven replacement")), Header: make(http.Header)}, nil
		})}
		defer func() { onlyOfficeDownloadClient = previousClient }()

		request := httptest.NewRequest(http.MethodPost, callbackURL.RequestURI(), bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+signed)
		status, callbackErr := onlyofficeCallbackHandler(httptest.NewRecorder(), request, &requestContext{})
		if status != http.StatusOK || callbackErr != nil {
			t.Fatalf("status-seven callback: status=%d err=%v", status, callbackErr)
		}
		if requests.Load() != 0 {
			t.Fatalf("status-seven callback made %d outbound requests", requests.Load())
		}
		content, err := os.ReadFile(officeFile.realPath)
		if err != nil || !bytes.Equal(content, officeFile.content) {
			t.Fatalf("status-seven callback changed document: content=%q err=%v", content, err)
		}
	})

	t.Run("failed close callback keeps capability for retry", func(t *testing.T) {
		if err := os.WriteFile(officeFile.realPath, officeFile.content, 0o644); err != nil {
			t.Fatal(err)
		}
		utils.OnlyOfficeCache.Set(officeFile.realPath, "onlyoffice-security-document-key")
		user := fixture.user(t, true, true, true)
		user.Username = "onlyoffice-callback-retry-user"
		user.Permissions.Modify = true
		if err := store.Users.Save(user, false, false); err != nil {
			t.Fatal(err)
		}
		_, callbackURL := issueOnlyOfficeSecurityURLs(t, user, officeFile.indexPath)
		callback := OnlyOfficeCallback{
			Key:    "onlyoffice-security-document-key",
			Status: onlyOfficeStatusDocumentClosedWithChanges,
			URL:    "http://office.test/cache/retry.docx",
		}
		body, signed := signedOnlyOfficeSecurityCallback(t, callback)
		var requests atomic.Int32
		previousClient := onlyOfficeDownloadClient
		onlyOfficeDownloadClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			if requests.Add(1) == 1 {
				return nil, errors.New("temporary OnlyOffice download failure")
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("saved after retry")), Header: make(http.Header)}, nil
		})}
		defer func() { onlyOfficeDownloadClient = previousClient }()

		first := httptest.NewRequest(http.MethodPost, callbackURL.RequestURI(), bytes.NewReader(body))
		first.Header.Set("Authorization", "Bearer "+signed)
		status, _ := onlyofficeCallbackHandler(httptest.NewRecorder(), first, &requestContext{})
		if status != http.StatusInternalServerError {
			t.Fatalf("first callback status: got %d, want %d", status, http.StatusInternalServerError)
		}
		second := httptest.NewRequest(http.MethodPost, callbackURL.RequestURI(), bytes.NewReader(body))
		second.Header.Set("Authorization", "Bearer "+signed)
		status, callbackErr := onlyofficeCallbackHandler(httptest.NewRecorder(), second, &requestContext{})
		if status != http.StatusOK || callbackErr != nil {
			t.Fatalf("retry callback: status=%d err=%v", status, callbackErr)
		}
		content, err := os.ReadFile(officeFile.realPath)
		if err != nil || string(content) != "saved after retry" {
			t.Fatalf("retry did not save document: content=%q err=%v", content, err)
		}
	})

	t.Run("unsigned callback cannot delete document state", func(t *testing.T) {
		utils.OnlyOfficeCache.Set(officeFile.realPath, "onlyoffice-security-document-key")
		user := fixture.user(t, true, true, true)
		user.Permissions.Modify = true
		body, err := json.Marshal(OnlyOfficeCallback{
			Key:    "attacker-controlled-key",
			Status: onlyOfficeStatusDocumentClosedWithNoChanges,
		})
		if err != nil {
			t.Fatal(err)
		}
		query := url.Values{"source": {"source1"}, "path": {officeFile.indexPath}}
		request := httptest.NewRequest(http.MethodPost, "/api/office/callback?"+query.Encode(), bytes.NewReader(body))
		recorder := httptest.NewRecorder()
		status, callbackErr := onlyofficeCallbackHandler(recorder, request, &requestContext{user: user})
		if status != http.StatusForbidden || callbackErr == nil {
			t.Fatalf("unsigned callback: status=%d err=%v body=%q", status, callbackErr, recorder.Body.String())
		}
		if key, ok := utils.OnlyOfficeCache.Get(officeFile.realPath); !ok || key != "onlyoffice-security-document-key" {
			t.Fatalf("unsigned callback changed document cache: key=%q present=%v", key, ok)
		}
	})

	t.Run("unsigned callback is rejected before outbound fetch", func(t *testing.T) {
		user := fixture.user(t, true, true, true)
		user.Permissions.Modify = true
		var requests atomic.Int32
		previousClient := onlyOfficeDownloadClient
		onlyOfficeDownloadClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			requests.Add(1)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("attacker replacement")),
				Header:     make(http.Header),
			}, nil
		})}
		defer func() { onlyOfficeDownloadClient = previousClient }()

		body, err := json.Marshal(OnlyOfficeCallback{
			Key:    "onlyoffice-security-document-key",
			Status: onlyOfficeStatusForceSaveWhileDocumentStillOpen,
			URL:    "http://office.test/cache/attacker.docx",
		})
		if err != nil {
			t.Fatal(err)
		}
		query := url.Values{"source": {"source1"}, "path": {officeFile.indexPath}}
		request := httptest.NewRequest(http.MethodPost, "/api/office/callback?"+query.Encode(), bytes.NewReader(body))
		status, callbackErr := onlyofficeCallbackHandler(httptest.NewRecorder(), request, &requestContext{user: user})
		if status != http.StatusForbidden || callbackErr == nil {
			t.Fatalf("unsigned save callback: status=%d err=%v", status, callbackErr)
		}
		if requests.Load() != 0 {
			t.Fatalf("unsigned callback made %d outbound requests", requests.Load())
		}
	})

	t.Run("parent API token revocation invalidates capabilities", func(t *testing.T) {
		user := fixture.user(t, true, true, true)
		user.Username = "onlyoffice-parent-token-user"
		user.Permissions.Api = true
		if err := store.Users.Save(user, false, false); err != nil {
			t.Fatal(err)
		}
		parent := issueShareSecurityToken(t, user, "onlyoffice-parent-token", users.Permissions{
			Api: true, Browse: true, Preview: true, Download: true,
		})
		query := url.Values{"source": {"source1"}, "path": {officeFile.indexPath}}
		recorder := httptest.NewRecorder()
		status, err := onlyofficeClientConfigGetHandler(recorder, httptest.NewRequest(http.MethodGet, "/api/office/config?"+query.Encode(), nil), &requestContext{
			user: user, token: parent, apiToken: true,
		})
		if err != nil || status != http.StatusOK {
			t.Fatalf("OnlyOffice API token config: status=%d err=%v body=%s", status, err, recorder.Body.String())
		}
		downloadURL, _ := onlyOfficeSecurityConfigURLs(t, recorder)
		if err := store.Access.RevokeToken(parent); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, downloadURL.RequestURI(), nil)
		status, downloadErr := onlyOfficeCapabilityDownloadHandler(httptest.NewRecorder(), request, &requestContext{})
		if status != http.StatusForbidden || downloadErr == nil {
			t.Fatalf("capability after parent token revocation: status=%d err=%v", status, downloadErr)
		}
	})

	t.Run("download capability rejects in-place content replacement with restored metadata", func(t *testing.T) {
		if err := os.WriteFile(officeFile.realPath, officeFile.content, 0o644); err != nil {
			t.Fatal(err)
		}
		utils.OnlyOfficeCache.Set(officeFile.realPath, "onlyoffice-security-document-key")
		before, err := os.Stat(officeFile.realPath)
		if err != nil {
			t.Fatal(err)
		}
		user := fixture.user(t, true, true, true)
		user.Username = "onlyoffice-content-binding-user"
		if err := store.Users.Save(user, false, false); err != nil {
			t.Fatal(err)
		}
		downloadURL, _ := issueOnlyOfficeSecurityURLs(t, user, officeFile.indexPath)
		replacement := bytes.Repeat([]byte{0x5A}, len(officeFile.content))
		if err := os.WriteFile(officeFile.realPath, replacement, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(officeFile.realPath, before.ModTime(), before.ModTime()); err != nil {
			t.Fatal(err)
		}
		after, err := os.Stat(officeFile.realPath)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			t.Fatalf("content binding fixture did not preserve identity: before=%+v after=%+v", before, after)
		}
		request := httptest.NewRequest(http.MethodGet, downloadURL.RequestURI(), nil)
		recorder := httptest.NewRecorder()
		status, downloadErr := onlyOfficeCapabilityDownloadHandler(recorder, request, &requestContext{})
		if status != http.StatusForbidden || downloadErr == nil {
			t.Fatalf("capability after in-place replacement: status=%d err=%v body=%q", status, downloadErr, recorder.Body.Bytes())
		}
	})

	t.Run("ViewOnly change revokes an issued edit callback", func(t *testing.T) {
		if err := os.WriteFile(officeFile.realPath, officeFile.content, 0o644); err != nil {
			t.Fatal(err)
		}
		utils.OnlyOfficeCache.Set(officeFile.realPath, "onlyoffice-security-document-key")
		user := fixture.user(t, true, true, true)
		user.Username = "onlyoffice-view-only-transition-user"
		user.Permissions.Modify = true
		if err := store.Users.Save(user, false, false); err != nil {
			t.Fatal(err)
		}
		_, callbackURL := issueOnlyOfficeSecurityURLs(t, user, officeFile.indexPath)
		config.Integrations.OnlyOffice.ViewOnly = true
		defer func() { config.Integrations.OnlyOffice.ViewOnly = false }()
		callback := OnlyOfficeCallback{
			Key:    "onlyoffice-security-document-key",
			Status: onlyOfficeStatusForceSaveWhileDocumentStillOpen,
			URL:    "http://office.test/cache/view-only-transition.docx",
		}
		body, signed := signedOnlyOfficeSecurityCallback(t, callback)
		var requests atomic.Int32
		previousClient := onlyOfficeDownloadClient
		onlyOfficeDownloadClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			requests.Add(1)
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("must not be written")), Header: make(http.Header)}, nil
		})}
		defer func() { onlyOfficeDownloadClient = previousClient }()
		request := httptest.NewRequest(http.MethodPost, callbackURL.RequestURI(), bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+signed)
		status, callbackErr := onlyofficeCallbackHandler(httptest.NewRecorder(), request, &requestContext{})
		if status != http.StatusForbidden || callbackErr == nil {
			t.Fatalf("callback after ViewOnly change: status=%d err=%v", status, callbackErr)
		}
		if requests.Load() != 0 {
			t.Fatalf("ViewOnly callback made %d outbound requests", requests.Load())
		}
	})

	t.Run("concurrent terminal callback is single-flight", func(t *testing.T) {
		if err := os.WriteFile(officeFile.realPath, officeFile.content, 0o644); err != nil {
			t.Fatal(err)
		}
		utils.OnlyOfficeCache.Set(officeFile.realPath, "onlyoffice-security-document-key")
		user := fixture.user(t, true, true, true)
		user.Username = "onlyoffice-concurrent-callback-user"
		user.Permissions.Modify = true
		if err := store.Users.Save(user, false, false); err != nil {
			t.Fatal(err)
		}
		_, callbackURL := issueOnlyOfficeSecurityURLs(t, user, officeFile.indexPath)
		callback := OnlyOfficeCallback{
			Key:    "onlyoffice-security-document-key",
			Status: onlyOfficeStatusDocumentClosedWithChanges,
			URL:    "http://office.test/cache/concurrent.docx",
		}
		body, signed := signedOnlyOfficeSecurityCallback(t, callback)
		started := make(chan struct{}, 2)
		release := make(chan struct{})
		previousClient := onlyOfficeDownloadClient
		onlyOfficeDownloadClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			started <- struct{}{}
			<-release
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("single-flight-save")), Header: make(http.Header)}, nil
		})}
		defer func() { onlyOfficeDownloadClient = previousClient }()
		type callbackResult struct {
			status int
			err    error
		}
		invoke := func(result chan<- callbackResult) {
			request := httptest.NewRequest(http.MethodPost, callbackURL.RequestURI(), bytes.NewReader(body))
			request.Header.Set("Authorization", "Bearer "+signed)
			status, err := onlyofficeCallbackHandler(httptest.NewRecorder(), request, &requestContext{})
			result <- callbackResult{status: status, err: err}
		}
		firstResult := make(chan callbackResult, 1)
		secondResult := make(chan callbackResult, 1)
		go invoke(firstResult)
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("first callback did not reach the document fetch")
		}
		go invoke(secondResult)
		select {
		case <-started:
			close(release)
			<-firstResult
			<-secondResult
			t.Fatal("two concurrent callbacks entered the document fetch")
		case second := <-secondResult:
			close(release)
			first := <-firstResult
			if second.status != http.StatusForbidden || second.err == nil {
				t.Fatalf("concurrent replay: status=%d err=%v", second.status, second.err)
			}
			if first.status != http.StatusOK || first.err != nil {
				t.Fatalf("first callback: status=%d err=%v", first.status, first.err)
			}
		case <-time.After(5 * time.Second):
			close(release)
			<-firstResult
			t.Fatal("concurrent callback did not resolve")
		}
	})

	t.Run("two capabilities for one document are single-flight", func(t *testing.T) {
		if err := os.WriteFile(officeFile.realPath, officeFile.content, 0o644); err != nil {
			t.Fatal(err)
		}
		utils.OnlyOfficeCache.Set(officeFile.realPath, "onlyoffice-security-document-key")
		user := fixture.user(t, true, true, true)
		user.Username = "onlyoffice-cross-capability-user"
		user.Permissions.Modify = true
		if err := store.Users.Save(user, false, false); err != nil {
			t.Fatal(err)
		}
		_, firstCallbackURL := issueOnlyOfficeSecurityURLs(t, user, officeFile.indexPath)
		_, secondCallbackURL := issueOnlyOfficeSecurityURLs(t, user, officeFile.indexPath)
		if firstCallbackURL.Query().Get("capability") == secondCallbackURL.Query().Get("capability") {
			t.Fatal("two configs reused one callback capability")
		}
		callback := OnlyOfficeCallback{
			Key:    "onlyoffice-security-document-key",
			Status: onlyOfficeStatusForceSaveWhileDocumentStillOpen,
			URL:    "http://office.test/cache/cross-capability.docx",
		}
		body, signed := signedOnlyOfficeSecurityCallback(t, callback)
		started := make(chan struct{}, 2)
		release := make(chan struct{})
		previousClient := onlyOfficeDownloadClient
		onlyOfficeDownloadClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			started <- struct{}{}
			<-release
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("cross-capability-save")), Header: make(http.Header)}, nil
		})}
		defer func() { onlyOfficeDownloadClient = previousClient }()
		type callbackResult struct {
			status int
			err    error
		}
		invoke := func(callbackURL *url.URL, result chan<- callbackResult) {
			request := httptest.NewRequest(http.MethodPost, callbackURL.RequestURI(), bytes.NewReader(body))
			request.Header.Set("Authorization", "Bearer "+signed)
			status, err := onlyofficeCallbackHandler(httptest.NewRecorder(), request, &requestContext{})
			result <- callbackResult{status: status, err: err}
		}
		firstResult := make(chan callbackResult, 1)
		secondResult := make(chan callbackResult, 1)
		go invoke(firstCallbackURL, firstResult)
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("first capability did not reach the document fetch")
		}
		go invoke(secondCallbackURL, secondResult)
		select {
		case <-started:
			close(release)
			<-firstResult
			<-secondResult
			t.Fatal("two capabilities for one document entered the fetch concurrently")
		case second := <-secondResult:
			close(release)
			first := <-firstResult
			if second.status != http.StatusForbidden || second.err == nil {
				t.Fatalf("cross-capability replay: status=%d err=%v", second.status, second.err)
			}
			if first.status != http.StatusOK || first.err != nil {
				t.Fatalf("first capability: status=%d err=%v", first.status, first.err)
			}
		case <-time.After(5 * time.Second):
			close(release)
			<-firstResult
			t.Fatal("second capability did not resolve")
		}
	})

	t.Run("permission revocation during callback fetch prevents write", func(t *testing.T) {
		if err := os.WriteFile(officeFile.realPath, officeFile.content, 0o644); err != nil {
			t.Fatal(err)
		}
		utils.OnlyOfficeCache.Set(officeFile.realPath, "onlyoffice-security-document-key")
		user := fixture.user(t, true, true, true)
		user.Username = "onlyoffice-mid-fetch-revocation-user"
		user.Permissions.Modify = true
		if err := store.Users.Save(user, false, false); err != nil {
			t.Fatal(err)
		}
		_, callbackURL := issueOnlyOfficeSecurityURLs(t, user, officeFile.indexPath)
		callback := OnlyOfficeCallback{
			Key:    "onlyoffice-security-document-key",
			Status: onlyOfficeStatusForceSaveWhileDocumentStillOpen,
			URL:    "http://office.test/cache/mid-fetch-revocation.docx",
		}
		body, signed := signedOnlyOfficeSecurityCallback(t, callback)
		started := make(chan struct{}, 1)
		release := make(chan struct{})
		previousClient := onlyOfficeDownloadClient
		onlyOfficeDownloadClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			started <- struct{}{}
			<-release
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("must-not-survive-revocation")), Header: make(http.Header)}, nil
		})}
		defer func() { onlyOfficeDownloadClient = previousClient }()
		type callbackResult struct {
			status       int
			responseCode int
			body         string
			err          error
		}
		result := make(chan callbackResult, 1)
		go func() {
			request := httptest.NewRequest(http.MethodPost, callbackURL.RequestURI(), bytes.NewReader(body))
			request.Header.Set("Authorization", "Bearer "+signed)
			recorder := httptest.NewRecorder()
			status, err := onlyofficeCallbackHandler(recorder, request, &requestContext{})
			result <- callbackResult{status: status, responseCode: recorder.Code, body: recorder.Body.String(), err: err}
		}()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("callback did not reach the document fetch")
		}
		current, err := store.Users.Get(user.ID)
		if err != nil {
			t.Fatal(err)
		}
		current.Permissions.Modify = false
		if err := store.Users.Update(current, true, "Permissions"); err != nil {
			t.Fatal(err)
		}
		close(release)
		got := <-result
		if got.status != http.StatusForbidden || got.responseCode != http.StatusForbidden || got.err != nil {
			t.Fatalf("callback after mid-fetch revocation: status=%d response=%d err=%v", got.status, got.responseCode, got.err)
		}
		var response map[string]int
		if err := json.Unmarshal([]byte(got.body), &response); err != nil || response["error"] != 1 {
			t.Fatalf("callback after mid-fetch revocation body: body=%q err=%v", got.body, err)
		}
		content, err := os.ReadFile(officeFile.realPath)
		if err != nil || !bytes.Equal(content, officeFile.content) {
			t.Fatalf("mid-fetch revocation changed document: content=%q err=%v", content, err)
		}
	})
}

func TestPublicOnlyOfficeCapabilities(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	h := newPermissionShareSecurityHarness(t, sourcePath)
	previousOffice := config.Integrations.OnlyOffice
	config.Integrations.OnlyOffice = settings.OnlyOffice{Url: "http://office.test", Secret: "public-onlyoffice-secret"}
	t.Cleanup(func() { config.Integrations.OnlyOffice = previousOffice })

	documentPath := filepath.Join(sourcePath, "public", "shared.docx")
	const documentContent = "PUBLIC-ONLYOFFICE-DOCUMENT"
	if err := os.WriteFile(documentPath, []byte(documentContent), 0o644); err != nil {
		t.Fatal(err)
	}
	idx := indexing.GetIndex("source1")
	if idx == nil {
		t.Fatal("source1 index is unavailable")
	}
	if err := idx.RefreshDirectory("/public", false); err != nil {
		t.Fatal(err)
	}
	owner := h.newOwner(t, "public-onlyoffice-owner", users.Permissions{
		Share: true, Browse: true, Preview: true, Download: true, Modify: true,
	})
	h.saveShare(t, owner, "public-onlyoffice-share", "/public", func(common *dbshare.CommonShare) {
		common.EnableOnlyOffice = true
		common.AllowModify = true
	})
	utils.OnlyOfficeCache.Set(documentPath, "public-onlyoffice-document-key")
	t.Cleanup(func() { utils.OnlyOfficeCache.Delete(documentPath) })

	response := h.request(http.MethodGet, "/public/api/office/config", url.Values{
		"hash": {"public-onlyoffice-share"}, "path": {"/shared.docx"},
	}, nil, nil)
	requirePermissionShareStatus(t, "public OnlyOffice config", response, http.StatusOK)
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	document := payload["document"].(map[string]any)
	editor := payload["editorConfig"].(map[string]any)
	downloadURL, err := url.Parse(document["url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	callbackURL, err := url.Parse(editor["callbackUrl"].(string))
	if err != nil {
		t.Fatal(err)
	}

	owner.Permissions.Download = false
	h.updateOwnerPermissions(t, owner)
	downloadRequest := httptest.NewRequest(http.MethodGet, downloadURL.RequestURI(), nil)
	status, downloadErr := onlyOfficeCapabilityDownloadHandler(httptest.NewRecorder(), downloadRequest, &requestContext{})
	if status != http.StatusForbidden || downloadErr == nil {
		t.Fatalf("public capability after Download revocation: status=%d err=%v", status, downloadErr)
	}

	owner.Permissions.Download = true
	owner.Permissions.Modify = false
	h.updateOwnerPermissions(t, owner)
	callback := OnlyOfficeCallback{
		Key:    "public-onlyoffice-document-key",
		Status: onlyOfficeStatusForceSaveWhileDocumentStillOpen,
		URL:    "http://office.test/cache/shared.docx",
	}
	body, err := json.Marshal(callback)
	if err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"payload": callback})
	signed, err := token.SignedString([]byte(config.Integrations.OnlyOffice.Secret))
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	previousClient := onlyOfficeDownloadClient
	onlyOfficeDownloadClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("unexpected request")
	})}
	defer func() { onlyOfficeDownloadClient = previousClient }()
	callbackRequest := httptest.NewRequest(http.MethodPost, callbackURL.RequestURI(), bytes.NewReader(body))
	callbackRequest.Header.Set("Authorization", "Bearer "+signed)
	status, callbackErr := onlyofficeCallbackHandler(httptest.NewRecorder(), callbackRequest, &requestContext{})
	if status != http.StatusForbidden || callbackErr == nil {
		t.Fatalf("public callback after Modify revocation: status=%d err=%v", status, callbackErr)
	}
	if requests.Load() != 0 {
		t.Fatalf("revoked public callback made %d outbound requests", requests.Load())
	}
}

func TestPublicOnlyOfficeDownloadCapabilityIsSingleUse(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	h := newPermissionShareSecurityHarness(t, sourcePath)
	previousOffice := config.Integrations.OnlyOffice
	config.Integrations.OnlyOffice = settings.OnlyOffice{Url: "http://office.test", Secret: "public-onlyoffice-limit-secret"}
	t.Cleanup(func() { config.Integrations.OnlyOffice = previousOffice })

	documentPath := filepath.Join(sourcePath, "public", "limited.docx")
	const documentContent = "PUBLIC-ONLYOFFICE-LIMITED-DOCUMENT"
	if err := os.WriteFile(documentPath, []byte(documentContent), 0o644); err != nil {
		t.Fatal(err)
	}
	idx := indexing.GetIndex("source1")
	if idx == nil {
		t.Fatal("source1 index is unavailable")
	}
	if err := idx.RefreshDirectory("/public", false); err != nil {
		t.Fatal(err)
	}
	owner := h.newOwner(t, "public-onlyoffice-limit-owner", users.Permissions{
		Share: true, Browse: true, Preview: true, Download: true,
	})
	link := h.saveShare(t, owner, "public-onlyoffice-limit-share", "/public", func(common *dbshare.CommonShare) {
		common.EnableOnlyOffice = true
		common.DownloadsLimit = 1
	})
	utils.OnlyOfficeCache.Set(documentPath, "public-onlyoffice-limit-key")
	t.Cleanup(func() { utils.OnlyOfficeCache.Delete(documentPath) })

	response := h.request(http.MethodGet, "/public/api/office/config", url.Values{
		"hash": {link.Hash}, "path": {"/limited.docx"},
	}, nil, nil)
	requirePermissionShareStatus(t, "limited public OnlyOffice config", response, http.StatusOK)
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	document := payload["document"].(map[string]any)
	downloadURL, err := url.Parse(document["url"].(string))
	if err != nil {
		t.Fatal(err)
	}

	first := httptest.NewRequest(http.MethodGet, downloadURL.RequestURI(), nil)
	firstRecorder := httptest.NewRecorder()
	status, downloadErr := onlyOfficeCapabilityDownloadHandler(firstRecorder, first, &requestContext{})
	if status != http.StatusOK || downloadErr != nil || firstRecorder.Body.String() != documentContent {
		t.Fatalf("first capability download: status=%d err=%v body=%q", status, downloadErr, firstRecorder.Body.String())
	}
	second := httptest.NewRequest(http.MethodGet, downloadURL.RequestURI(), nil)
	status, downloadErr = onlyOfficeCapabilityDownloadHandler(httptest.NewRecorder(), second, &requestContext{})
	if status != http.StatusForbidden || downloadErr == nil {
		t.Fatalf("reused capability: status=%d err=%v", status, downloadErr)
	}
	if link.Downloads != 1 {
		t.Fatalf("OnlyOffice capability download count: got %d, want 1", link.Downloads)
	}
}

func TestPublicOnlyOfficeRequesterLifecycle(t *testing.T) {
	t.Run("PerUser count belongs to the authenticated visitor", func(t *testing.T) {
		link, owner, visitor, _, downloadURL := setupPublicOnlyOfficeRequesterCapability(t, "per-user", true)
		request := httptest.NewRequest(http.MethodGet, downloadURL.RequestURI(), nil)
		status, err := onlyOfficeCapabilityDownloadHandler(httptest.NewRecorder(), request, &requestContext{})
		if status != http.StatusOK || err != nil {
			t.Fatalf("visitor capability download: status=%d err=%v", status, err)
		}
		if got := link.GetUserDownloadCount(visitor.Username); got != 1 {
			t.Fatalf("visitor download count: got %d, want 1", got)
		}
		if got := link.GetUserDownloadCount(owner.Username); got != 0 {
			t.Fatalf("owner download count: got %d, want 0", got)
		}
	})

	t.Run("AllowedUsernames removal invalidates an issued capability", func(t *testing.T) {
		link, _, _, _, downloadURL := setupPublicOnlyOfficeRequesterCapability(t, "audience", false)
		updated := link.Clone()
		updated.AllowedUsernames = []string{"different-user"}
		if err := store.Share.Save(updated); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, downloadURL.RequestURI(), nil)
		status, err := onlyOfficeCapabilityDownloadHandler(httptest.NewRecorder(), request, &requestContext{})
		if status != http.StatusForbidden || err == nil {
			t.Fatalf("capability after audience removal: status=%d err=%v", status, err)
		}
	})

	t.Run("visitor API token revocation invalidates an issued capability", func(t *testing.T) {
		_, _, _, parent, downloadURL := setupPublicOnlyOfficeRequesterCapability(t, "token-revoke", false)
		if err := store.Access.RevokeToken(parent); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, downloadURL.RequestURI(), nil)
		status, err := onlyOfficeCapabilityDownloadHandler(httptest.NewRecorder(), request, &requestContext{})
		if status != http.StatusForbidden || err == nil {
			t.Fatalf("capability after visitor token revocation: status=%d err=%v", status, err)
		}
	})
}

func TestPublicOnlyOfficeCapabilitiesRejectRecreatedShare(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	h := newPermissionShareSecurityHarness(t, sourcePath)
	previousOffice := config.Integrations.OnlyOffice
	config.Integrations.OnlyOffice = settings.OnlyOffice{Url: "http://office.test", Secret: "public-recreated-share-secret"}
	t.Cleanup(func() { config.Integrations.OnlyOffice = previousOffice })

	documentPath := filepath.Join(sourcePath, "public", "recreated.docx")
	if err := os.WriteFile(documentPath, []byte("PUBLIC-ONLYOFFICE-RECREATED-DOCUMENT"), 0o644); err != nil {
		t.Fatal(err)
	}
	idx := indexing.GetIndex("source1")
	if idx == nil {
		t.Fatal("source1 index is unavailable")
	}
	if err := idx.RefreshDirectory("/public", false); err != nil {
		t.Fatal(err)
	}
	owner := h.newOwner(t, "public-onlyoffice-recreated-owner", users.Permissions{
		Share: true, Browse: true, Preview: true, Download: true, Modify: true,
	})
	const shareHash = "public-onlyoffice-recreated-share"
	configure := func(common *dbshare.CommonShare) {
		common.EnableOnlyOffice = true
		common.AllowModify = true
	}
	original := h.saveShare(t, owner, shareHash, "/public", configure)
	utils.OnlyOfficeCache.Set(documentPath, "public-onlyoffice-recreated-key")
	t.Cleanup(func() { utils.OnlyOfficeCache.Delete(documentPath) })

	response := h.request(http.MethodGet, "/public/api/office/config", url.Values{
		"hash": {shareHash}, "path": {"/recreated.docx"},
	}, nil, nil)
	requirePermissionShareStatus(t, "public recreated-share OnlyOffice config", response, http.StatusOK)
	downloadURL, callbackURL := onlyOfficeSecurityConfigURLs(t, response)

	if err := store.Share.Delete(shareHash); err != nil {
		t.Fatal(err)
	}
	recreated := h.saveShare(t, owner, shareHash, "/public", configure)
	if recreated == original {
		t.Fatal("same-hash recreation reused the original share instance")
	}

	downloadRequest := httptest.NewRequest(http.MethodGet, downloadURL.RequestURI(), nil)
	status, downloadErr := onlyOfficeCapabilityDownloadHandler(httptest.NewRecorder(), downloadRequest, &requestContext{})
	if status != http.StatusForbidden || downloadErr == nil {
		t.Errorf("download capability survived same-hash share recreation: status=%d err=%v", status, downloadErr)
	}

	callback := OnlyOfficeCallback{
		Key:    "public-onlyoffice-recreated-key",
		Status: onlyOfficeStatusDocumentBeingEdited,
	}
	body, signed := signedOnlyOfficeSecurityCallback(t, callback)
	callbackRequest := httptest.NewRequest(http.MethodPost, callbackURL.RequestURI(), bytes.NewReader(body))
	callbackRequest.Header.Set("Authorization", "Bearer "+signed)
	status, callbackErr := onlyofficeCallbackHandler(httptest.NewRecorder(), callbackRequest, &requestContext{})
	if status != http.StatusForbidden || callbackErr == nil {
		t.Errorf("callback capability survived same-hash share recreation: status=%d err=%v", status, callbackErr)
	}
}

func TestOnlyOfficeCapabilityURLOriginTrust(t *testing.T) {
	previousConfig := config
	config = &settings.Settings{}
	t.Cleanup(func() { config = previousConfig })
	config.Server.BaseURL = "/files/"

	tests := []struct {
		name        string
		internalURL string
		externalURL string
		trusted     map[string]bool
		wantOrigin  string
	}{
		{
			name:       "untrusted forwarded origin is ignored",
			trusted:    map[string]bool{},
			wantOrigin: "https://files.example.test",
		},
		{
			name: "configured forwarded origin is trusted",
			trusted: map[string]bool{
				"x-forwarded-host":  true,
				"x-forwarded-proto": true,
			},
			wantOrigin: "http://proxy.example.test",
		},
		{
			name:        "internal URL has highest priority",
			internalURL: "http://filebrowser.internal:8080",
			externalURL: "https://files.external.example",
			trusted: map[string]bool{
				"x-forwarded-host":  true,
				"x-forwarded-proto": true,
			},
			wantOrigin: "http://filebrowser.internal:8080",
		},
		{
			name:        "external URL precedes request headers",
			externalURL: "https://files.external.example",
			trusted: map[string]bool{
				"x-forwarded-host":  true,
				"x-forwarded-proto": true,
			},
			wantOrigin: "https://files.external.example",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config.Server.InternalUrl = test.internalURL
			config.Server.ExternalUrl = test.externalURL
			config.Http.TrustedHeaders = test.trusted
			request := httptest.NewRequest(http.MethodGet, "https://files.example.test/api/office/config", nil)
			request.Header.Set("X-Forwarded-Host", "proxy.example.test")
			request.Header.Set("X-Forwarded-Proto", "http")

			urls := map[string]string{
				"download": buildOnlyOfficeDownloadURL(request, "origin-test-capability"),
				"callback": buildOnlyOfficeCallbackURL(request, "origin-test-capability"),
			}
			for name, rawURL := range urls {
				parsed, err := url.Parse(rawURL)
				if err != nil {
					t.Fatalf("parse %s URL %q: %v", name, rawURL, err)
				}
				if got := parsed.Scheme + "://" + parsed.Host; got != test.wantOrigin {
					t.Errorf("%s origin: got %q, want %q", name, got, test.wantOrigin)
				}
				if !strings.HasPrefix(parsed.Path, "/files/api/office/") {
					t.Errorf("%s URL lost configured base path: %q", name, parsed.Path)
				}
				if got := parsed.Query().Get("capability"); got != "origin-test-capability" {
					t.Errorf("%s capability: got %q", name, got)
				}
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func onlyOfficeSecurityConfigURLs(t *testing.T, recorder *httptest.ResponseRecorder) (*url.URL, *url.URL) {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	document, ok := payload["document"].(map[string]any)
	if !ok {
		t.Fatalf("OnlyOffice config lacks document: %v", payload)
	}
	editor, ok := payload["editorConfig"].(map[string]any)
	if !ok {
		t.Fatalf("OnlyOffice config lacks editorConfig: %v", payload)
	}
	downloadURL, err := url.Parse(document["url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	callbackURL, err := url.Parse(editor["callbackUrl"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return downloadURL, callbackURL
}

func setupPublicOnlyOfficeRequesterCapability(t *testing.T, suffix string, perUser bool) (*dbshare.Link, *users.User, *users.User, string, *url.URL) {
	t.Helper()
	sourcePath := setupResourcePutTestEnv(t)
	h := newPermissionShareSecurityHarness(t, sourcePath)
	previousOffice := config.Integrations.OnlyOffice
	config.Integrations.OnlyOffice = settings.OnlyOffice{Url: "http://office.test", Secret: "public-requester-secret"}
	t.Cleanup(func() { config.Integrations.OnlyOffice = previousOffice })

	fileName := "requester-" + suffix + ".docx"
	documentPath := filepath.Join(sourcePath, "public", fileName)
	if err := os.WriteFile(documentPath, []byte("PUBLIC-ONLYOFFICE-REQUESTER-"+suffix), 0o644); err != nil {
		t.Fatal(err)
	}
	idx := indexing.GetIndex("source1")
	if idx == nil {
		t.Fatal("source1 index is unavailable")
	}
	if err := idx.RefreshDirectory("/public", false); err != nil {
		t.Fatal(err)
	}
	owner := h.newOwner(t, "public-onlyoffice-owner-"+suffix, users.Permissions{
		Share: true, Browse: true, Preview: true, Download: true,
	})
	visitor := h.newOwner(t, "public-onlyoffice-visitor-"+suffix, users.Permissions{Api: true})
	parent := issueShareSecurityToken(t, visitor, "public-onlyoffice-token-"+suffix, users.Permissions{Api: true})
	link := h.saveShare(t, owner, "public-onlyoffice-share-"+suffix, "/public", func(common *dbshare.CommonShare) {
		common.EnableOnlyOffice = true
		common.DisableAnonymous = true
		common.AllowedUsernames = []string{visitor.Username}
		common.PerUserDownloadLimit = perUser
		if perUser {
			common.DownloadsLimit = 2
		}
	})
	documentKey := "public-onlyoffice-key-" + suffix
	utils.OnlyOfficeCache.Set(documentPath, documentKey)
	t.Cleanup(func() { utils.OnlyOfficeCache.Delete(documentPath) })

	response := h.request(http.MethodGet, "/public/api/office/config", url.Values{
		"hash": {link.Hash}, "path": {"/" + fileName},
	}, nil, map[string]string{"Authorization": "Bearer " + parent})
	requirePermissionShareStatus(t, "public requester OnlyOffice config", response, http.StatusOK)
	downloadURL, _ := onlyOfficeSecurityConfigURLs(t, response)
	return link, owner, visitor, parent, downloadURL
}

func issueOnlyOfficeSecurityURLs(t *testing.T, user *users.User, indexPath string) (*url.URL, *url.URL) {
	t.Helper()
	query := url.Values{"source": {"source1"}, "path": {indexPath}}
	recorder := httptest.NewRecorder()
	status, err := onlyofficeClientConfigGetHandler(recorder, httptest.NewRequest(http.MethodGet, "/api/office/config?"+query.Encode(), nil), &requestContext{user: user})
	if err != nil || status != http.StatusOK {
		t.Fatalf("OnlyOffice config: status=%d err=%v body=%s", status, err, recorder.Body.String())
	}
	return onlyOfficeSecurityConfigURLs(t, recorder)
}

func signedOnlyOfficeSecurityCallback(t *testing.T, callback OnlyOfficeCallback) ([]byte, string) {
	t.Helper()
	body, err := json.Marshal(callback)
	if err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"payload": callback})
	signed, err := token.SignedString([]byte(config.Integrations.OnlyOffice.Secret))
	if err != nil {
		t.Fatal(err)
	}
	return body, signed
}
