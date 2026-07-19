package http

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
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
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}
