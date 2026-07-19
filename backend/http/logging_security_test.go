package http

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
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
		handler := LoggingMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("logging security panic")
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

func (l *securityCaptureLogger) Debug(string, ...any)                         {}
func (l *securityCaptureLogger) Info(string, ...any)                          {}
func (l *securityCaptureLogger) Warn(string, ...any)                          {}
func (l *securityCaptureLogger) Error(msg string, args ...any)                { l.append(msg, args...) }
func (l *securityCaptureLogger) Fatal(string, ...any)                         {}
func (l *securityCaptureLogger) Debugf(string, ...any)                        {}
func (l *securityCaptureLogger) Infof(string, ...any)                         {}
func (l *securityCaptureLogger) Warnf(string, ...any)                         {}
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
