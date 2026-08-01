package http

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/access"
	dbshare "github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
	logpkg "github.com/gtsteffaniak/go-logger/logger"
)

func TestLoggingMiddlewareRedactsSensitiveQueryValues(t *testing.T) {
	previousConfig := config
	config = &settings.Settings{}
	t.Cleanup(func() { config = previousConfig })
	capture := &securityCaptureLogger{}
	logpkg.SetGlobalLogger(capture)
	t.Cleanup(func() { logpkg.SetGlobalLogger(nil) })

	query := strings.Join([]string{
		"auth=AUTH-SECRET",
		"jwt=JWT-SECRET",
		"token=TOKEN-SECRET",
		"password=PASSWORD-SECRET",
		"code=CODE-SECRET",
		"archiveToken=ARCHIVE-SECRET",
		"capability=CAPABILITY-SECRET",
		"a%75th=ENCODED-AUTH-SECRET",
		"TOKEN=CASE-TOKEN-SECRET",
		"safe=visible",
	}, "&")
	secrets := []string{
		"AUTH-SECRET", "JWT-SECRET", "TOKEN-SECRET", "PASSWORD-SECRET", "CODE-SECRET",
		"ARCHIVE-SECRET", "CAPABILITY-SECRET", "ENCODED-AUTH-SECRET", "CASE-TOKEN-SECRET",
	}

	t.Run("normal request", func(t *testing.T) {
		capture.reset()
		handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/probe?"+query, nil))
		assertSensitiveLogValuesAbsent(t, capture.String(), secrets)
	})

	t.Run("panic request", func(t *testing.T) {
		capture.reset()
		handler := LoggingMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			panic(r.URL.Query().Get("token"))
		}))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/probe?"+query, nil))
		assertSensitiveLogValuesAbsent(t, capture.String(), secrets)
	})

	t.Run("malformed sensitive query", func(t *testing.T) {
		capture.reset()
		handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		request := httptest.NewRequest(http.MethodGet, "/api/probe", nil)
		request.URL.RawQuery = "auth=%ZZ&safe=visible"
		handler.ServeHTTP(httptest.NewRecorder(), request)
		if output := capture.String(); strings.Contains(output, "%ZZ") {
			t.Fatalf("malformed credential query reached logs: %s", output)
		}
	})
}

func TestAuditQueryRejectedRequestLogsRedactAllQueryValues(t *testing.T) {
	tests := []struct {
		name       string
		baseURL    string
		routePath  string
		requestURL string
		credential func(*testing.T, *auditQueryHTTPFixture) string
		wantStatus int
	}{
		{
			name:       "anonymous",
			baseURL:    "/",
			routePath:  "/api/audit",
			requestURL: "/api/audit",
			credential: func(*testing.T, *auditQueryHTTPFixture) string { return "" },
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "ordinary user with base URL",
			baseURL:    "/company/files/",
			routePath:  "/company/files/api/audit",
			requestURL: "/company/files/api/audit",
			credential: func(t *testing.T, fixture *auditQueryHTTPFixture) string {
				return fixture.sessionToken(t, fixture.user)
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "dot segment redirect",
			baseURL:    "/",
			routePath:  "/api/audit",
			requestURL: "/api/ignored/../audit",
			credential: func(*testing.T, *auditQueryHTTPFixture) string { return "" },
			wantStatus: http.StatusTemporaryRedirect,
		},
		{
			name:       "repeated slash redirect with base URL",
			baseURL:    "/company/files/",
			routePath:  "/company/files/api/audit",
			requestURL: "/company/files/api//audit",
			credential: func(*testing.T, *auditQueryHTTPFixture) string { return "" },
			wantStatus: http.StatusTemporaryRedirect,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAuditQueryHTTPFixture(t)
			config.Server.BaseURL = test.baseURL
			capture := &securityCaptureLogger{}
			logpkg.SetGlobalLogger(capture)
			t.Cleanup(func() { logpkg.SetGlobalLogger(nil) })

			secrets := map[string]string{
				"actor":   "AUDIT-ACTOR-LOG-SECRET",
				"path":    "/AUDIT-PATH-LOG-SECRET",
				"cursor":  "AUDIT-CURSOR-LOG-SECRET",
				"unknown": "AUDIT-UNKNOWN-LOG-SECRET",
			}
			query := make(url.Values, len(secrets))
			for key, secret := range secrets {
				query.Set(key, secret)
			}
			request := httptest.NewRequest(http.MethodGet, test.requestURL+"?"+query.Encode(), nil)
			if credential := test.credential(t, fixture); credential != "" {
				request.Header.Set("Authorization", "Bearer "+credential)
			}
			response := httptest.NewRecorder()
			mux := http.NewServeMux()
			mux.Handle(test.routePath, withAdmin(auditQueryHandler))
			handler := AuditMiddleware(LoggingMiddleware(mux), NewAuditService(store.Audit))
			handler.ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status: got %d, want %d; body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			requestID := response.Header().Get(auditRequestIDHeader)
			if requestID == "" {
				t.Fatal("audit request ID header is empty")
			}
			output := capture.String()
			for key, secret := range secrets {
				if strings.Contains(output, secret) {
					t.Errorf("audit query log exposed %s value %q: %s", key, secret, output)
				}
				if !strings.Contains(output, key+"=%5BREDACTED%5D") {
					t.Errorf("audit query log did not retain redacted %s parameter: %s", key, output)
				}
			}
			for _, expected := range []string{
				test.requestURL,
				http.MethodGet,
				fmt.Sprintf("| %3d |", test.wantStatus),
				"request_id=" + requestID,
			} {
				if !strings.Contains(output, expected) {
					t.Errorf("audit query log missing %q: %s", expected, output)
				}
			}
		})
	}
}

func TestOnlyOfficeCallbackTransportErrorRedactsSensitiveURL(t *testing.T) {
	fixture := setupPreviewSecurityFixture(t)
	officeFile := fixture.files["Office"]
	previousOffice := config.Integrations.OnlyOffice
	config.Integrations.OnlyOffice = settings.OnlyOffice{
		Url:    "http://office.test",
		Secret: "onlyoffice-logging-security-secret",
	}
	t.Cleanup(func() { config.Integrations.OnlyOffice = previousOffice })
	utils.OnlyOfficeCache.Set(officeFile.realPath, "onlyoffice-logging-document-key")
	t.Cleanup(func() { utils.OnlyOfficeCache.Delete(officeFile.realPath) })

	user := fixture.user(t, true, true, true)
	user.Username = "onlyoffice-logging-security-user"
	user.Permissions.Modify = true
	if err := store.Users.Save(user, false, false); err != nil {
		t.Fatal(err)
	}
	_, callbackURL := issueOnlyOfficeSecurityURLs(t, user, officeFile.indexPath)

	const secret = "ONLYOFFICE-TRANSPORT-URL-SECRET"
	callback := OnlyOfficeCallback{
		Key:    "onlyoffice-logging-document-key",
		Status: onlyOfficeStatusForceSaveWhileDocumentStillOpen,
		URL:    "http://office.test/cache/logging.docx?token=" + secret + "&expires=9999999999",
	}
	body, signed := signedOnlyOfficeSecurityCallback(t, callback)
	called := false
	previousClient := onlyOfficeDownloadClient
	onlyOfficeDownloadClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("forced transport failure")
	})}
	t.Cleanup(func() { onlyOfficeDownloadClient = previousClient })

	capture := &securityCaptureLogger{}
	logpkg.SetGlobalLogger(capture)
	t.Cleanup(func() { logpkg.SetGlobalLogger(nil) })
	request := httptest.NewRequest(http.MethodPost, callbackURL.RequestURI(), bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+signed)
	status, _ := onlyofficeCallbackHandler(httptest.NewRecorder(), request, &requestContext{})
	if status != http.StatusInternalServerError {
		t.Fatalf("callback transport failure status: got %d, want %d", status, http.StatusInternalServerError)
	}
	if !called {
		t.Fatal("callback did not reach the failing OnlyOffice transport")
	}
	if output := capture.String(); strings.Contains(output, secret) {
		t.Fatalf("OnlyOffice transport error exposed URL credential: %s", output)
	}
}

func TestPublicShareInternalLogsRedactHash(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	h := newPermissionShareSecurityHarness(t, sourcePath)
	owner := h.newOwner(t, "share-log-redaction-owner", users.Permissions{
		Browse: true, Preview: true, Download: true,
	})
	const secretHash = "PUBLIC-SHARE-HASH-SECRET"
	link := h.saveShare(t, owner, secretHash, "/public", nil)

	capture := &securityCaptureLogger{}
	logpkg.SetGlobalLogger(capture)
	t.Cleanup(func() { logpkg.SetGlobalLogger(nil) })

	t.Run("public API query hash", func(t *testing.T) {
		capture.reset()
		handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet,
			"/public/api/resources?hash="+secretHash+"&path=%2Fsecret.txt", nil))
		if output := capture.String(); strings.Contains(output, secretHash) {
			t.Fatalf("public API access log exposed share hash: %s", output)
		}
	})

	t.Run("public page path hash", func(t *testing.T) {
		capture.reset()
		handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet,
			"/public/share/"+secretHash+"/folder", nil))
		if output := capture.String(); strings.Contains(output, secretHash) {
			t.Fatalf("public page access log exposed share hash: %s", output)
		}
	})

	t.Run("file info error", func(t *testing.T) {
		capture.reset()
		originalFileInfoFaster := FileInfoFasterFunc
		FileInfoFasterFunc = func(utils.FileOptions, *access.Storage, *users.User, *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
			return nil, errors.New("forced file info failure")
		}
		defer func() { FileInfoFasterFunc = originalFileInfoFaster }()

		h.request(http.MethodGet, "/public/api/resources", url.Values{
			"hash": {secretHash},
			"path": {"/secret.txt"},
		}, nil, nil)
		if output := capture.String(); strings.Contains(output, secretHash) {
			t.Fatalf("file info error exposed share hash: %s", output)
		}
	})

	t.Run("legacy source warning", func(t *testing.T) {
		capture.reset()
		legacySource := link.Clone()
		legacySource.Source = "source1"
		if _, err := convertToFrontendShareResponse(httptest.NewRequest(http.MethodGet, "/api/share/list", nil), []*dbshare.Link{legacySource}, owner); err != nil {
			t.Fatal(err)
		}
		if output := capture.String(); strings.Contains(output, secretHash) {
			t.Fatalf("legacy source warning exposed share hash: %s", output)
		}
	})

	t.Run("share path update", func(t *testing.T) {
		capture.reset()
		if err := store.Share.UpdateSharePath(secretHash, "/public"); err != nil {
			t.Fatal(err)
		}
		if output := capture.String(); strings.Contains(output, secretHash) {
			t.Fatalf("share path update exposed share hash: %s", output)
		}
	})
}

func TestManagementShareAccessLogsRedactQuerySecrets(t *testing.T) {
	previousConfig := config
	config = &settings.Settings{}
	t.Cleanup(func() { config = previousConfig })
	capture := &securityCaptureLogger{}
	logpkg.SetGlobalLogger(capture)
	t.Cleanup(func() { logpkg.SetGlobalLogger(nil) })

	query := url.Values{
		"hash":     {"MANAGEMENT-SHARE-HASH-SECRET"},
		"token":    {"MANAGEMENT-SHARE-TOKEN-SECRET"},
		"password": {"MANAGEMENT-SHARE-PASSWORD-SECRET"},
		"cursor":   {"MANAGEMENT-SHARE-CURSOR-SECRET"},
		"safe":     {"visible"},
	}.Encode()
	secrets := []string{
		"MANAGEMENT-SHARE-HASH-SECRET",
		"MANAGEMENT-SHARE-TOKEN-SECRET",
		"MANAGEMENT-SHARE-PASSWORD-SECRET",
		"MANAGEMENT-SHARE-CURSOR-SECRET",
	}

	for _, test := range []struct {
		name   string
		status int
	}{
		{name: "authorized request", status: http.StatusNoContent},
		{name: "request rejected before handler", status: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			capture.reset()
			handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
			}))
			request := httptest.NewRequest(http.MethodDelete, "/api/share?"+query, nil)
			handler.ServeHTTP(httptest.NewRecorder(), request)

			output := capture.String()
			assertSensitiveLogValuesAbsent(t, output, secrets)
			for _, visible := range []string{http.MethodDelete, "/api/share", fmt.Sprintf("%d", test.status)} {
				if !strings.Contains(output, visible) {
					t.Errorf("management share access log omitted safe value %q: %s", visible, output)
				}
			}
		})
	}
}

func assertSensitiveLogValuesAbsent(t *testing.T, output string, secrets []string) {
	t.Helper()
	for _, secret := range secrets {
		if strings.Contains(output, secret) {
			t.Errorf("log output exposed %q: %s", secret, output)
		}
	}
	if !strings.Contains(output, "safe=visible") {
		t.Errorf("log redaction removed non-sensitive query value: %s", output)
	}
}

type securityCaptureLogger struct {
	mu       sync.Mutex
	messages []string
}

func (l *securityCaptureLogger) append(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.messages = append(l.messages, fmt.Sprintf(format, args...))
}

func (l *securityCaptureLogger) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.messages = nil
}

func (l *securityCaptureLogger) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.messages, "\n")
}

func (l *securityCaptureLogger) Debug(msg string, args ...any)                { l.append(msg, args...) }
func (l *securityCaptureLogger) Info(msg string, args ...any)                 { l.append(msg, args...) }
func (l *securityCaptureLogger) Warn(msg string, args ...any)                 { l.append(msg, args...) }
func (l *securityCaptureLogger) Error(msg string, args ...any)                { l.append(msg, args...) }
func (l *securityCaptureLogger) Fatal(string, ...any)                         {}
func (l *securityCaptureLogger) Debugf(format string, args ...any)            { l.append(format, args...) }
func (l *securityCaptureLogger) Infof(format string, args ...any)             { l.append(format, args...) }
func (l *securityCaptureLogger) Warnf(format string, args ...any)             { l.append(format, args...) }
func (l *securityCaptureLogger) Errorf(format string, args ...any)            { l.append(format, args...) }
func (l *securityCaptureLogger) Fatalf(string, ...any)                        {}
func (l *securityCaptureLogger) DebugContext(context.Context, string, ...any) {}
func (l *securityCaptureLogger) InfoContext(context.Context, string, ...any)  {}
func (l *securityCaptureLogger) WarnContext(context.Context, string, ...any)  {}
func (l *securityCaptureLogger) ErrorContext(_ context.Context, msg string, args ...any) {
	l.append(msg, args...)
}
func (l *securityCaptureLogger) FatalContext(context.Context, string, ...any)  {}
func (l *securityCaptureLogger) DebugfContext(context.Context, string, ...any) {}
func (l *securityCaptureLogger) InfofContext(context.Context, string, ...any)  {}
func (l *securityCaptureLogger) WarnfContext(context.Context, string, ...any)  {}
func (l *securityCaptureLogger) ErrorfContext(_ context.Context, format string, args ...any) {
	l.append(format, args...)
}
func (l *securityCaptureLogger) FatalfContext(context.Context, string, ...any) {}
func (l *securityCaptureLogger) With(...any) logpkg.Logger                     { return l }
func (l *securityCaptureLogger) WithGroup(string) logpkg.Logger                { return l }
func (l *securityCaptureLogger) API(_ int, msg string, args ...any)            { l.append(msg, args...) }
func (l *securityCaptureLogger) APIPath(_ int, requestPath, msg string, args ...any) {
	l.append("%s %s", requestPath, fmt.Sprintf(msg, args...))
}
func (l *securityCaptureLogger) APIf(_ int, format string, args ...any) {
	l.append(format, args...)
}
func (l *securityCaptureLogger) APIContext(_ context.Context, _ int, msg string, args ...any) {
	l.append(msg, args...)
}
func (l *securityCaptureLogger) APIfContext(_ context.Context, _ int, format string, args ...any) {
	l.append(format, args...)
}
