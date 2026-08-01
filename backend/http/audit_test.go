package http

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
	logpkg "github.com/gtsteffaniak/go-logger/logger"
)

func TestRequestIDGenerationAndContext(t *testing.T) {
	previousConfig := config
	config = &settings.Settings{}
	t.Cleanup(func() { config = previousConfig })

	t.Run("server generated and stable in derived contexts", func(t *testing.T) {
		clientID := "client-controlled-request-id"
		var requestID string
		var derivedRecorder *AuditRecorder
		var rebuiltContextRecorder *AuditRecorder
		handler := AuditMiddleware(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			recorder := AuditRecorderFromRequest(r)
			if recorder == nil {
				t.Fatal("recorder missing from request context")
			}
			requestID = recorder.RequestID()
			derivedRecorder = AuditRecorderFromRequest(r.WithContext(context.WithValue(r.Context(), struct{}{}, "derived")))
			rebuilt := &requestContext{}
			_ = rebuilt
			rebuiltContextRecorder = AuditRecorderFromContext(r.Context())
			if got := w.Header().Get(auditRequestIDHeader); got != requestID {
				t.Fatalf("request ID was not set before response write: got %q, want %q", got, requestID)
			}
			w.WriteHeader(stdhttp.StatusNoContent)
		}), nil)

		response := httptest.NewRecorder()
		request := httptest.NewRequest(stdhttp.MethodGet, "/probe", nil)
		request.Header.Set(auditRequestIDHeader, clientID)
		handler.ServeHTTP(response, request)

		if len(requestID) != 32 {
			t.Fatalf("request ID length: got %d, want 32", len(requestID))
		}
		for _, character := range requestID {
			if !strings.ContainsRune("0123456789abcdef", character) {
				t.Fatalf("request ID is not lower-case hex: %q", requestID)
			}
		}
		if requestID == clientID {
			t.Fatal("client-supplied request ID was trusted")
		}
		if got := response.Header().Get(auditRequestIDHeader); got != requestID {
			t.Fatalf("response request ID: got %q, want %q", got, requestID)
		}
		if derivedRecorder == nil || derivedRecorder.RequestID() != requestID {
			t.Fatal("derived request context lost recorder")
		}
		if rebuiltContextRecorder == nil || rebuiltContextRecorder.RequestID() != requestID {
			t.Fatal("custom requestContext rebuild lost standard context recorder")
		}
	})

	t.Run("concurrent IDs are unique", func(t *testing.T) {
		const requests = 256
		ids := make(chan string, requests)
		handler := AuditMiddleware(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			ids <- AuditRecorderFromRequest(r).RequestID()
			w.WriteHeader(stdhttp.StatusNoContent)
		}), nil)
		var group sync.WaitGroup
		group.Add(requests)
		for index := 0; index < requests; index++ {
			go func() {
				defer group.Done()
				handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(stdhttp.MethodGet, "/probe", nil))
			}()
		}
		group.Wait()
		close(ids)
		seen := make(map[string]struct{}, requests)
		for id := range ids {
			if _, exists := seen[id]; exists {
				t.Fatalf("duplicate request ID %q", id)
			}
			seen[id] = struct{}{}
		}
		if len(seen) != requests {
			t.Fatalf("unique request IDs: got %d, want %d", len(seen), requests)
		}
	})

	t.Run("random source failure is fail closed", func(t *testing.T) {
		called := false
		handler := auditMiddlewareWithRandom(stdhttp.HandlerFunc(func(stdhttp.ResponseWriter, *stdhttp.Request) {
			called = true
		}), nil, errorReader{err: errors.New("random source unavailable Authorization: secret")})
		response := httptest.NewRecorder()
		request := httptest.NewRequest(stdhttp.MethodGet, "/probe", nil)
		request.Header.Set(auditRequestIDHeader, "attacker-request-id")
		handler.ServeHTTP(response, request)
		if called {
			t.Fatal("handler ran after request ID generation failure")
		}
		if response.Code != stdhttp.StatusInternalServerError {
			t.Fatalf("status: got %d, want 500", response.Code)
		}
		if got := response.Header().Get(auditRequestIDHeader); got != "" {
			t.Fatalf("failed request reflected untrusted request ID %q", got)
		}
		if strings.Contains(response.Body.String(), "Authorization") || strings.Contains(response.Body.String(), "secret") {
			t.Fatalf("random source error leaked to response: %s", response.Body.String())
		}
	})
}

func TestResponseWriterStatusBytesAndErrors(t *testing.T) {
	tests := []struct {
		name       string
		write      func(stdhttp.ResponseWriter)
		wantStatus int
		wantBytes  int64
	}{
		{name: "no write defaults to 200", write: func(stdhttp.ResponseWriter) {}, wantStatus: 200},
		{name: "implicit 200", write: func(w stdhttp.ResponseWriter) { _, _ = w.Write([]byte("hello")) }, wantStatus: 200, wantBytes: 5},
		{name: "explicit 201", write: func(w stdhttp.ResponseWriter) { w.WriteHeader(201) }, wantStatus: 201},
		{name: "range 206", write: func(w stdhttp.ResponseWriter) { w.WriteHeader(206); _, _ = w.Write([]byte("part")) }, wantStatus: 206, wantBytes: 4},
		{name: "unauthorized", write: func(w stdhttp.ResponseWriter) { w.WriteHeader(401) }, wantStatus: 401},
		{name: "forbidden", write: func(w stdhttp.ResponseWriter) { w.WriteHeader(403) }, wantStatus: 403},
		{name: "not found", write: func(w stdhttp.ResponseWriter) { w.WriteHeader(404) }, wantStatus: 404},
		{name: "internal error", write: func(w stdhttp.ResponseWriter) { w.WriteHeader(500) }, wantStatus: 500},
		{name: "first header wins", write: func(w stdhttp.ResponseWriter) { w.WriteHeader(201); w.WriteHeader(500) }, wantStatus: 201},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			wrapped, state := wrapResponseWriter(response)
			test.write(wrapped)
			if state.StatusCode != test.wantStatus {
				t.Fatalf("status: got %d, want %d", state.StatusCode, test.wantStatus)
			}
			if state.PayloadSize != test.wantBytes {
				t.Fatalf("bytes: got %d, want %d", state.PayloadSize, test.wantBytes)
			}
		})
	}

	t.Run("actual bytes and write error", func(t *testing.T) {
		underlying := &shortErrorResponseWriter{maximum: 3, err: errors.New("write failed with bearer secret")}
		wrapped, state := wrapResponseWriter(underlying)
		n, err := wrapped.Write([]byte("abcdef"))
		if n != 3 || err == nil {
			t.Fatalf("write result: n=%d err=%v", n, err)
		}
		if state.PayloadSize != 3 || !state.WriteFailed() {
			t.Fatalf("write capture: bytes=%d failed=%v", state.PayloadSize, state.WriteFailed())
		}
	})
}

func TestResponseWriterOptionalInterfaces(t *testing.T) {
	t.Run("individual capabilities are exact", func(t *testing.T) {
		tests := []struct {
			name          string
			writer        stdhttp.ResponseWriter
			flusher       bool
			hijacker      bool
			pusher        bool
			readerFrom    bool
			closeNotifier bool
		}{
			{name: "flusher", writer: &flusherOnlyResponseWriter{basicResponseWriter: newBasicResponseWriter()}, flusher: true},
			{name: "hijacker", writer: &hijackerOnlyResponseWriter{basicResponseWriter: newBasicResponseWriter()}, hijacker: true},
			{name: "pusher", writer: &pusherOnlyResponseWriter{basicResponseWriter: newBasicResponseWriter()}, pusher: true},
			{name: "reader from", writer: &readerFromOnlyResponseWriter{basicResponseWriter: newBasicResponseWriter()}, readerFrom: true},
			{name: "close notifier", writer: &closeNotifierOnlyResponseWriter{basicResponseWriter: newBasicResponseWriter(), closed: make(chan bool)}, closeNotifier: true},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				wrapped, _ := wrapResponseWriter(test.writer)
				if _, ok := wrapped.(stdhttp.Flusher); ok != test.flusher {
					t.Errorf("Flusher availability: got %v, want %v", ok, test.flusher)
				}
				if _, ok := wrapped.(stdhttp.Hijacker); ok != test.hijacker {
					t.Errorf("Hijacker availability: got %v, want %v", ok, test.hijacker)
				}
				if _, ok := wrapped.(stdhttp.Pusher); ok != test.pusher {
					t.Errorf("Pusher availability: got %v, want %v", ok, test.pusher)
				}
				if _, ok := wrapped.(io.ReaderFrom); ok != test.readerFrom {
					t.Errorf("ReaderFrom availability: got %v, want %v", ok, test.readerFrom)
				}
				if _, ok := wrapped.(stdhttp.CloseNotifier); ok != test.closeNotifier {
					t.Errorf("CloseNotifier availability: got %v, want %v", ok, test.closeNotifier)
				}
			})
		}
	})

	t.Run("all supported interfaces remain available", func(t *testing.T) {
		underlying := newAllOptionalResponseWriter()
		wrapped, state := wrapResponseWriter(underlying)
		if _, ok := wrapped.(stdhttp.Flusher); !ok {
			t.Fatal("Flusher was not preserved")
		}
		if _, ok := wrapped.(stdhttp.Hijacker); !ok {
			t.Fatal("Hijacker was not preserved")
		}
		if _, ok := wrapped.(stdhttp.Pusher); !ok {
			t.Fatal("Pusher was not preserved")
		}
		readerFrom, ok := wrapped.(io.ReaderFrom)
		if !ok {
			t.Fatal("ReaderFrom was not preserved")
		}
		if _, ok := wrapped.(stdhttp.CloseNotifier); !ok {
			t.Fatal("CloseNotifier was not preserved")
		}
		if err := stdhttp.NewResponseController(wrapped).Flush(); err != nil {
			t.Fatalf("ResponseController flush: %v", err)
		}
		if underlying.flushes != 1 {
			t.Fatalf("flush count: got %d, want 1", underlying.flushes)
		}
		n, err := readerFrom.ReadFrom(&plainReader{reader: strings.NewReader("reader-from")})
		if err != nil || n != 11 {
			t.Fatalf("ReaderFrom: n=%d err=%v", n, err)
		}
		if state.PayloadSize != 11 {
			t.Fatalf("ReaderFrom bytes: got %d, want 11", state.PayloadSize)
		}
		unwrapper, ok := wrapped.(interface{ Unwrap() stdhttp.ResponseWriter })
		if !ok || unwrapper.Unwrap() != underlying {
			t.Fatal("Unwrap did not return the underlying writer")
		}
	})

	t.Run("ResponseController preserves flush errors", func(t *testing.T) {
		sentinel := errors.New("flush failed")
		underlying := &flushErrorResponseWriter{
			basicResponseWriter: newBasicResponseWriter(),
			err:                 sentinel,
		}
		wrapped, state := wrapResponseWriter(underlying)
		if err := stdhttp.NewResponseController(wrapped).Flush(); !errors.Is(err, sentinel) {
			t.Fatalf("flush error: got %v, want %v", err, sentinel)
		}
		if state.StatusCode != stdhttp.StatusOK {
			t.Fatalf("flush status: got %d, want 200", state.StatusCode)
		}
	})

	t.Run("unsupported interfaces are not advertised", func(t *testing.T) {
		underlying := &basicResponseWriter{header: make(stdhttp.Header)}
		wrapped, _ := wrapResponseWriter(underlying)
		if _, ok := wrapped.(stdhttp.Flusher); ok {
			t.Fatal("wrapper falsely advertised Flusher")
		}
		if _, ok := wrapped.(stdhttp.Hijacker); ok {
			t.Fatal("wrapper falsely advertised Hijacker")
		}
		if _, ok := wrapped.(stdhttp.Pusher); ok {
			t.Fatal("wrapper falsely advertised Pusher")
		}
		if _, ok := wrapped.(io.ReaderFrom); ok {
			t.Fatal("wrapper falsely advertised ReaderFrom")
		}
		if _, ok := wrapped.(stdhttp.CloseNotifier); ok {
			t.Fatal("wrapper falsely advertised CloseNotifier")
		}
		if !errors.Is(stdhttp.NewResponseController(wrapped).Flush(), stdhttp.ErrNotSupported) {
			t.Fatal("ResponseController did not reach unsupported underlying writer")
		}
	})
}

func TestAuditMiddlewareFinalizePaths(t *testing.T) {
	previousConfig := config
	config = &settings.Settings{}
	t.Cleanup(func() { config = previousConfig })

	t.Run("no action is a store no-op", func(t *testing.T) {
		store := newAuditStoreStub()
		service := NewAuditService(store)
		handler := AuditMiddleware(LoggingMiddleware(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			if AuditRecorderFromRequest(r) == nil {
				t.Fatal("missing audit recorder")
			}
			w.WriteHeader(stdhttp.StatusNoContent)
		})), service)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(stdhttp.MethodGet, "/static/app.js", nil))
		if calls := store.totalWriteCalls(); calls != 0 {
			t.Fatalf("store writes without action: got %d, want 0", calls)
		}
	})

	t.Run("terminal append happens once", func(t *testing.T) {
		store := newAuditStoreStub()
		service := NewAuditService(store)
		var recorder *AuditRecorder
		handler := AuditMiddleware(LoggingMiddleware(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			recorder = AuditRecorderFromRequest(r)
			mustConfigureAuditRecorder(t, recorder, auditdb.ActionAuthLogin, auditdb.AuthMethodSession)
			w.WriteHeader(stdhttp.StatusCreated)
			_, _ = w.Write([]byte("created"))
		})), service)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(stdhttp.MethodPost, "/probe", nil))
		if err := recorder.Finalize(AuditFinalization{HTTPStatus: 500}); err != nil {
			t.Fatalf("repeat finalize returned a different error: %v", err)
		}
		store.mu.Lock()
		defer store.mu.Unlock()
		if store.appendCalls != 1 || store.finalizeCalls != 0 {
			t.Fatalf("calls: append=%d finalize=%d", store.appendCalls, store.finalizeCalls)
		}
		if len(store.appended) != 1 {
			t.Fatalf("appended events: got %d, want 1", len(store.appended))
		}
		event := store.appended[0]
		if event.Result != auditdb.ResultSuccess || event.HTTPStatus == nil || *event.HTTPStatus != 201 {
			t.Fatalf("terminal outcome: result=%q status=%v", event.Result, event.HTTPStatus)
		}
		if event.Metadata == nil || event.Metadata.Bytes == nil || *event.Metadata.Bytes != 7 {
			t.Fatalf("terminal bytes: %#v", event.Metadata)
		}
	})

	t.Run("pending finalizes once", func(t *testing.T) {
		store := newAuditStoreStub()
		service := NewAuditService(store)
		var recorder *AuditRecorder
		handler := AuditMiddleware(LoggingMiddleware(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			recorder = AuditRecorderFromRequest(r)
			mustConfigureAuditRecorder(t, recorder, auditdb.ActionFileModify, auditdb.AuthMethodSession)
			if err := recorder.SetResource("source", "/file.txt", "/file.txt"); err != nil {
				t.Fatal(err)
			}
			if err := recorder.ReservePending(); err != nil {
				t.Fatal(err)
			}
			if err := recorder.ReservePending(); err != nil {
				t.Fatalf("repeat reservation: %v", err)
			}
			w.WriteHeader(stdhttp.StatusNoContent)
		})), service)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(stdhttp.MethodPut, "/probe", nil))
		if err := recorder.Finalize(AuditFinalization{HTTPStatus: 500}); err != nil {
			t.Fatalf("repeat finalize: %v", err)
		}
		store.mu.Lock()
		defer store.mu.Unlock()
		if store.createCalls != 1 || store.finalizeCalls != 1 || store.appendCalls != 0 {
			t.Fatalf("calls: create=%d finalize=%d append=%d", store.createCalls, store.finalizeCalls, store.appendCalls)
		}
	})

	t.Run("panic recovery captures final 500", func(t *testing.T) {
		store := newAuditStoreStub()
		service := NewAuditService(store)
		handler := AuditMiddleware(LoggingMiddleware(stdhttp.HandlerFunc(func(_ stdhttp.ResponseWriter, r *stdhttp.Request) {
			mustConfigureAuditRecorder(t, AuditRecorderFromRequest(r), auditdb.ActionAuthLogin, auditdb.AuthMethodAnonymous)
			panic("panic bearer secret must not be logged")
		})), service)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(stdhttp.MethodPost, "/probe", nil))
		if response.Code != stdhttp.StatusInternalServerError {
			t.Fatalf("response status: got %d, want 500", response.Code)
		}
		event := store.singleAppended(t)
		if event.HTTPStatus == nil || *event.HTTPStatus != 500 || event.Result != auditdb.ResultFailed {
			t.Fatalf("panic outcome: status=%v result=%q", event.HTTPStatus, event.Result)
		}
	})

	t.Run("handler error captures written status", func(t *testing.T) {
		store := newAuditStoreStub()
		service := NewAuditService(store)
		wrapped := wrapHandler(func(_ stdhttp.ResponseWriter, r *stdhttp.Request, _ *requestContext) (int, error) {
			mustConfigureAuditRecorder(t, AuditRecorderFromRequest(r), auditdb.ActionAuthLogin, auditdb.AuthMethodAnonymous)
			return stdhttp.StatusForbidden, errors.New("stable handler failure")
		})
		handler := AuditMiddleware(LoggingMiddleware(wrapped), service)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(stdhttp.MethodPost, "/probe", nil))
		event := store.singleAppended(t)
		if event.HTTPStatus == nil || *event.HTTPStatus != 403 || event.Result != auditdb.ResultDenied {
			t.Fatalf("handler error outcome: status=%v result=%q", event.HTTPStatus, event.Result)
		}
	})

	t.Run("range captures 206 and actual bytes", func(t *testing.T) {
		store := newAuditStoreStub()
		service := NewAuditService(store)
		handler := AuditMiddleware(LoggingMiddleware(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			mustConfigureAuditRecorder(t, AuditRecorderFromRequest(r), auditdb.ActionFileDownload, auditdb.AuthMethodSession)
			if err := AuditRecorderFromRequest(r).SetResource("source", "/file.txt", "/file.txt"); err != nil {
				t.Fatal(err)
			}
			stdhttp.ServeContent(w, r, "file.txt", time.Unix(0, 0), strings.NewReader("0123456789"))
		})), service)
		request := httptest.NewRequest(stdhttp.MethodGet, "/file.txt", nil)
		request.Header.Set("Range", "bytes=2-5")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		event := store.singleAppended(t)
		if event.HTTPStatus == nil || *event.HTTPStatus != 206 || event.Metadata == nil || event.Metadata.Bytes == nil || *event.Metadata.Bytes != 4 {
			t.Fatalf("range outcome: status=%v metadata=%#v", event.HTTPStatus, event.Metadata)
		}
	})

	t.Run("cancellation overrides partial success", func(t *testing.T) {
		store := newAuditStoreStub()
		service := NewAuditService(store)
		ctx, cancel := context.WithCancel(context.Background())
		handler := AuditMiddleware(LoggingMiddleware(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			mustConfigureAuditRecorder(t, AuditRecorderFromRequest(r), auditdb.ActionFileDownload, auditdb.AuthMethodSession)
			_, _ = w.Write([]byte("part"))
			cancel()
		})), service)
		request := httptest.NewRequest(stdhttp.MethodGet, "/file.txt", nil).WithContext(ctx)
		handler.ServeHTTP(httptest.NewRecorder(), request)
		event := store.singleAppended(t)
		if event.Result != auditdb.ResultCancelled || event.Metadata == nil || event.Metadata.ClientCancelled == nil || !*event.Metadata.ClientCancelled {
			t.Fatalf("cancelled outcome: result=%q metadata=%#v", event.Result, event.Metadata)
		}
		if event.Metadata.Bytes == nil || *event.Metadata.Bytes != 4 {
			t.Fatalf("cancelled bytes: %#v", event.Metadata.Bytes)
		}
	})

	t.Run("write failure records stable outcome and actual bytes", func(t *testing.T) {
		store := newAuditStoreStub()
		service := NewAuditService(store)
		handler := AuditMiddleware(LoggingMiddleware(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			mustConfigureAuditRecorder(t, AuditRecorderFromRequest(r), auditdb.ActionAuthLogin, auditdb.AuthMethodAnonymous)
			_, _ = w.Write([]byte("abcdef"))
		})), service)
		writer := &shortErrorResponseWriter{maximum: 3, err: errors.New("raw write error bearer secret")}
		handler.ServeHTTP(writer, httptest.NewRequest(stdhttp.MethodPost, "/probe", nil))
		event := store.singleAppended(t)
		if event.Result != auditdb.ResultFailed || event.ErrorCode != auditErrorCodeResponseWriteFailed {
			t.Fatalf("write failure outcome: result=%q errorCode=%q", event.Result, event.ErrorCode)
		}
		if event.Metadata == nil || event.Metadata.Bytes == nil || *event.Metadata.Bytes != 3 {
			t.Fatalf("write failure bytes: %#v", event.Metadata)
		}
	})

	t.Run("append failure after response does not alter business status", func(t *testing.T) {
		store := newAuditStoreStub()
		store.appendErr = errors.New("append failed with Cookie secret")
		service := NewAuditService(store)
		handler := AuditMiddleware(LoggingMiddleware(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			mustConfigureAuditRecorder(t, AuditRecorderFromRequest(r), auditdb.ActionAuthLogin, auditdb.AuthMethodAnonymous)
			w.WriteHeader(stdhttp.StatusNoContent)
		})), service)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(stdhttp.MethodPost, "/probe", nil))
		if response.Code != stdhttp.StatusNoContent {
			t.Fatalf("audit append failure changed response: got %d, want 204", response.Code)
		}
		if !service.IsDegraded() || service.LastFailureCategory() != AuditFailureAppend {
			t.Fatalf("append failure degraded state: %v %q", service.IsDegraded(), service.LastFailureCategory())
		}
	})
}

func TestAuditReservationFreezeAndFailure(t *testing.T) {
	previousConfig := config
	config = &settings.Settings{}
	t.Cleanup(func() { config = previousConfig })

	t.Run("successful reservation freezes critical fields", func(t *testing.T) {
		store := newAuditStoreStub()
		recorder := newAuditRecorder(NewAuditService(store), strings.Repeat("a", 32), "192.0.2.1", time.Now())
		mustConfigureAuditRecorder(t, recorder, auditdb.ActionFileModify, auditdb.AuthMethodSession)
		if err := recorder.SetActor(uintPointer(7), "actor"); err != nil {
			t.Fatal(err)
		}
		if err := recorder.SetTokenRef(strings.Repeat("b", 32)); err != nil {
			t.Fatal(err)
		}
		if err := recorder.SetShareRef(strings.Repeat("c", 32)); err != nil {
			t.Fatal(err)
		}
		if err := recorder.SetResource("source", "/file.txt", "/file.txt"); err != nil {
			t.Fatal(err)
		}
		if err := recorder.SetTarget("source", "/target.txt", "/target.txt"); err != nil {
			t.Fatal(err)
		}
		if err := recorder.ReservePending(); err != nil {
			t.Fatal(err)
		}
		mutations := []func() error{
			func() error { return recorder.SetActor(uintPointer(8), "other") },
			func() error { return recorder.SetAuthMethod(auditdb.AuthMethodToken) },
			func() error { return recorder.SetTokenRef(strings.Repeat("d", 32)) },
			func() error { return recorder.SetShareRef(strings.Repeat("e", 32)) },
			func() error { return recorder.SetAction(auditdb.ActionFileDelete) },
			func() error { return recorder.SetOrigin(auditdb.OriginWebDAV) },
			func() error { return recorder.SetResource("other", "/other", "/other") },
			func() error { return recorder.SetTarget("other", "/other", "/other") },
		}
		for index, mutate := range mutations {
			if err := mutate(); !errors.Is(err, ErrAuditFieldsFrozen) {
				t.Fatalf("mutation %d: got %v, want frozen error", index, err)
			}
		}
		pending := store.singlePending(t)
		if pending.Username != "actor" || pending.Source != "source" || pending.CanonicalPath != "/file.txt" || pending.TargetCanonicalPath != "/target.txt" {
			t.Fatalf("pending event changed: %#v", pending)
		}
	})

	t.Run("reservation failure is stable and prevents side effect", func(t *testing.T) {
		secret := "Authorization Bearer RESERVATION-SECRET"
		store := newAuditStoreStub()
		store.createErr = errors.New(secret)
		service := NewAuditService(store)
		sideEffect := false
		recorder := newAuditRecorder(service, strings.Repeat("f", 32), "192.0.2.2", time.Now())
		mustConfigureAuditRecorder(t, recorder, auditdb.ActionFileModify, auditdb.AuthMethodSession)
		if err := recorder.SetResource("source", "/file.txt", "/file.txt"); err != nil {
			t.Fatal(err)
		}
		if err := recorder.ReservePending(); !errors.Is(err, ErrAuditUnavailable) {
			t.Fatalf("reservation error: got %v, want audit unavailable", err)
		} else if strings.Contains(err.Error(), secret) {
			t.Fatalf("reservation error leaked secret: %v", err)
		}
		if !service.IsDegraded() || service.LastFailureCategory() != AuditFailureReservation {
			t.Fatalf("degraded state: degraded=%v category=%q", service.IsDegraded(), service.LastFailureCategory())
		}
		if service.IsDegraded() {
			// Future high-risk handlers return before this point.
		} else {
			sideEffect = true
		}
		if sideEffect {
			t.Fatal("business side effect ran after reservation failure")
		}
		if status := fmt.Sprintf("%v %s", service.IsDegraded(), service.LastFailureCategory()); strings.Contains(status, secret) {
			t.Fatalf("degraded state leaked secret: %s", status)
		}
	})

	t.Run("failing reservation handler returns before side effect", func(t *testing.T) {
		store := newAuditStoreStub()
		store.createErr = errors.New("reservation unavailable")
		store.appendErr = errors.New("terminal unavailable")
		service := NewAuditService(store)
		sideEffect := false
		handler := AuditMiddleware(LoggingMiddleware(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			recorder := AuditRecorderFromRequest(r)
			mustConfigureAuditRecorder(t, recorder, auditdb.ActionFileModify, auditdb.AuthMethodSession)
			if err := recorder.SetResource("source", "/file.txt", "/file.txt"); err != nil {
				t.Fatal(err)
			}
			if err := recorder.ReservePending(); err != nil {
				w.WriteHeader(stdhttp.StatusServiceUnavailable)
				return
			}
			sideEffect = true
			w.WriteHeader(stdhttp.StatusNoContent)
		})), service)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(stdhttp.MethodPut, "/file.txt", nil))
		if sideEffect {
			t.Fatal("side effect ran after reservation failure")
		}
		if response.Code != stdhttp.StatusServiceUnavailable {
			t.Fatalf("reservation failure status: got %d, want 503", response.Code)
		}
	})
}

func TestAuditClientIPTrustBoundary(t *testing.T) {
	previousConfig := config
	t.Cleanup(func() { config = previousConfig })
	tests := []struct {
		name    string
		trusted map[string]bool
		xff     string
		want    string
	}{
		{name: "untrusted proxy header ignored", xff: "203.0.113.10", want: "192.0.2.10"},
		{name: "configured proxy header used", trusted: map[string]bool{"x-forwarded-for": true}, xff: "203.0.113.10, 198.51.100.2", want: "203.0.113.10"},
		{name: "invalid trusted header falls back", trusted: map[string]bool{"x-forwarded-for": true}, xff: "not-an-ip", want: "192.0.2.10"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config = &settings.Settings{}
			config.Http.TrustedHeaders = test.trusted
			store := newAuditStoreStub()
			handler := AuditMiddleware(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				mustConfigureAuditRecorder(t, AuditRecorderFromRequest(r), auditdb.ActionAuthLogin, auditdb.AuthMethodAnonymous)
				w.WriteHeader(stdhttp.StatusNoContent)
			}), NewAuditService(store))
			request := httptest.NewRequest(stdhttp.MethodPost, "/probe", nil)
			request.RemoteAddr = "192.0.2.10:4242"
			request.Header.Set("X-Forwarded-For", test.xff)
			handler.ServeHTTP(httptest.NewRecorder(), request)
			if got := store.singleAppended(t).ClientIP; got != test.want {
				t.Fatalf("client IP: got %q, want %q", got, test.want)
			}
		})
	}
}

func TestAuditServiceDegradedLifecycle(t *testing.T) {
	store := newAuditStoreStub()
	service := NewAuditService(store)
	event := validTerminalEvent(strings.Repeat("1", 32))

	store.appendErr = errors.New("Cookie=password=APPEND-SECRET")
	if _, err := service.AppendTerminal(event); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("append failure: got %v", err)
	}
	if !service.IsDegraded() || service.LastFailureCategory() != AuditFailureAppend {
		t.Fatalf("append degraded state: %v %q", service.IsDegraded(), service.LastFailureCategory())
	}
	time.Sleep(time.Millisecond)
	if !service.IsDegraded() {
		t.Fatal("degraded state cleared merely because time passed")
	}

	store.appendErr = nil
	if _, err := service.AppendTerminal(validTerminalEvent(strings.Repeat("2", 32))); err != nil {
		t.Fatalf("successful append: %v", err)
	}
	if service.IsDegraded() || service.LastFailureCategory() != AuditFailureNone {
		t.Fatalf("successful persistence did not clear degraded state: %v %q", service.IsDegraded(), service.LastFailureCategory())
	}

	recorder := newAuditRecorder(service, strings.Repeat("3", 32), "192.0.2.3", time.Now())
	mustConfigureAuditRecorder(t, recorder, auditdb.ActionFileModify, auditdb.AuthMethodSession)
	if err := recorder.SetResource("source", "/file.txt", "/file.txt"); err != nil {
		t.Fatal(err)
	}
	if err := recorder.ReservePending(); err != nil {
		t.Fatal(err)
	}
	store.finalizeErr = errors.New("TokenHash FINALIZE-SECRET")
	if err := recorder.Finalize(AuditFinalization{HTTPStatus: 500}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("finalize failure: got %v", err)
	}
	if !service.IsDegraded() || service.LastFailureCategory() != AuditFailureFinalize {
		t.Fatalf("finalize degraded state: %v %q", service.IsDegraded(), service.LastFailureCategory())
	}
	store.mu.Lock()
	_, pendingRemains := store.pending[recorder.RequestID()]
	store.mu.Unlock()
	if !pendingRemains {
		t.Fatal("failed finalization removed pending event")
	}

	store.finalizeErr = nil
	store.appendErr = nil
	var group sync.WaitGroup
	for index := 0; index < 64; index++ {
		group.Add(2)
		go func() {
			defer group.Done()
			_, _ = service.AppendTerminal(validTerminalEvent(newTestRequestID()))
		}()
		go func() {
			defer group.Done()
			_ = service.IsDegraded()
			_ = service.LastFailureCategory()
		}()
	}
	group.Wait()
}

func TestAuditSecretLeakage(t *testing.T) {
	previousConfig := config
	config = &settings.Settings{}
	t.Cleanup(func() { config = previousConfig })
	secrets := []string{
		"BEARER-AUDIT-SECRET",
		"TOKENHASH-AUDIT-SECRET",
		"AUTHORIZATION-AUDIT-SECRET",
		"COOKIE-AUDIT-SECRET",
		"PASSWORD-AUDIT-SECRET",
		"SHAREHASH-AUDIT-SECRET",
		"ONLYOFFICE-AUDIT-SECRET",
	}
	store := newAuditStoreStub()
	service := NewAuditService(store)
	capture := &securityCaptureLogger{}
	logpkg.SetGlobalLogger(capture)
	t.Cleanup(func() { logpkg.SetGlobalLogger(nil) })

	handler := AuditMiddleware(LoggingMiddleware(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		recorder := AuditRecorderFromRequest(r)
		mustConfigureAuditRecorder(t, recorder, auditdb.ActionAuthLogin, auditdb.AuthMethodAnonymous)
		w.WriteHeader(stdhttp.StatusForbidden)
	})), service)
	request := httptest.NewRequest(stdhttp.MethodPost,
		"/probe?token="+secrets[0]+"&TokenHash="+secrets[1]+"&password="+secrets[4]+"&ShareHash="+secrets[5]+"&capability="+secrets[6], nil)
	request.Header.Set("Authorization", "Bearer "+secrets[2])
	request.Header.Set("Cookie", "session="+secrets[3])
	handler.ServeHTTP(httptest.NewRecorder(), request)

	event := store.singleAppended(t)
	serialized, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	assertAuditSecretsAbsent(t, serialized, secrets)
	assertAuditSecretsAbsent(t, []byte(capture.String()), secrets)

	store.appendErr = errors.New(strings.Join(secrets, " "))
	_, returnedErr := service.AppendTerminal(validTerminalEvent(newTestRequestID()))
	assertAuditSecretsAbsent(t, []byte(fmt.Sprint(returnedErr, service.LastFailureCategory())), secrets)

	recorder := newAuditRecorder(NewAuditService(newAuditStoreStub()), newTestRequestID(), "192.0.2.4", time.Now())
	mustConfigureAuditRecorder(t, recorder, auditdb.ActionAuthLogin, auditdb.AuthMethodAnonymous)
	err = recorder.Finalize(AuditFinalization{HTTPStatus: 500, ErrorCode: secrets[0]})
	if !errors.Is(err, ErrAuditInvalidFinalization) {
		t.Fatalf("unsafe error code: got %v, want invalid finalization", err)
	}
	assertAuditSecretsAbsent(t, []byte(err.Error()), secrets)

	pendingStore := newAuditStoreStub()
	pendingStore.finalizeErr = errors.New(strings.Join(secrets, " "))
	pendingService := NewAuditService(pendingStore)
	pendingHandler := AuditMiddleware(LoggingMiddleware(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		pendingRecorder := AuditRecorderFromRequest(r)
		mustConfigureAuditRecorder(t, pendingRecorder, auditdb.ActionFileModify, auditdb.AuthMethodSession)
		if err := pendingRecorder.SetResource("source", "/file.txt", "/file.txt"); err != nil {
			t.Fatal(err)
		}
		if err := pendingRecorder.ReservePending(); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(stdhttp.StatusNoContent)
	})), pendingService)
	pendingRequest := httptest.NewRequest(stdhttp.MethodPut,
		"/file.txt?token="+secrets[0]+"&TokenHash="+secrets[1]+"&password="+secrets[4]+"&ShareHash="+secrets[5]+"&capability="+secrets[6], nil)
	pendingRequest.Header.Set("Authorization", "Bearer "+secrets[2])
	pendingRequest.Header.Set("Cookie", "session="+secrets[3])
	pendingHandler.ServeHTTP(httptest.NewRecorder(), pendingRequest)
	pendingBytes, marshalErr := json.Marshal(pendingStore.singlePending(t))
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	assertAuditSecretsAbsent(t, pendingBytes, secrets)
	assertAuditSecretsAbsent(t, []byte(capture.String()), secrets)
	assertAuditSecretsAbsent(t, []byte(fmt.Sprintf("%v %s", pendingService.IsDegraded(), pendingService.LastFailureCategory())), secrets)
}

func TestAuditResultClassification(t *testing.T) {
	tests := []struct {
		status      int
		cancelled   bool
		writeFailed bool
		want        auditdb.Result
	}{
		{status: 200, want: auditdb.ResultSuccess},
		{status: 302, want: auditdb.ResultSuccess},
		{status: 401, want: auditdb.ResultDenied},
		{status: 403, want: auditdb.ResultDenied},
		{status: 404, want: auditdb.ResultFailed},
		{status: 429, want: auditdb.ResultFailed},
		{status: 500, want: auditdb.ResultFailed},
		{status: 0, want: auditdb.ResultUnknown},
		{status: 206, cancelled: true, want: auditdb.ResultCancelled},
		{status: 200, writeFailed: true, want: auditdb.ResultFailed},
	}
	for _, test := range tests {
		if got := classifyAuditResult(test.status, test.cancelled, test.writeFailed); got != test.want {
			t.Errorf("status=%d cancelled=%v writeFailed=%v: got %q, want %q", test.status, test.cancelled, test.writeFailed, got, test.want)
		}
	}
}

func mustConfigureAuditRecorder(t *testing.T, recorder *AuditRecorder, action auditdb.Action, method auditdb.AuthMethod) {
	t.Helper()
	if recorder == nil {
		t.Fatal("nil audit recorder")
	}
	if err := recorder.SetAction(action); err != nil {
		t.Fatal(err)
	}
	if err := recorder.SetAuthMethod(method); err != nil {
		t.Fatal(err)
	}
}

func validTerminalEvent(requestID string) auditdb.Event {
	status := stdhttp.StatusOK
	return auditdb.Event{
		SchemaVersion: auditdb.CurrentSchemaVersion,
		TimestampUTC:  time.Now().UTC(),
		RequestID:     requestID,
		AuthMethod:    auditdb.AuthMethodInternal,
		Action:        auditdb.ActionAuditQuery,
		Origin:        auditdb.OriginInternal,
		Result:        auditdb.ResultSuccess,
		HTTPStatus:    &status,
	}
}

func newTestRequestID() string {
	return fmt.Sprintf("%032x", time.Now().UnixNano())
}

func uintPointer(value uint) *uint {
	return &value
}

func assertAuditSecretsAbsent(t *testing.T, data []byte, secrets []string) {
	t.Helper()
	for _, secret := range secrets {
		if bytes.Contains(data, []byte(secret)) {
			t.Errorf("audit output contains secret %q: %s", secret, data)
		}
	}
}

type errorReader struct {
	err error
}

func (reader errorReader) Read([]byte) (int, error) {
	return 0, reader.err
}

type basicResponseWriter struct {
	header stdhttp.Header
	status int
	body   bytes.Buffer
}

func newBasicResponseWriter() *basicResponseWriter {
	return &basicResponseWriter{header: make(stdhttp.Header)}
}

func (writer *basicResponseWriter) Header() stdhttp.Header { return writer.header }

func (writer *basicResponseWriter) WriteHeader(status int) { writer.status = status }

func (writer *basicResponseWriter) Write(data []byte) (int, error) {
	if writer.status == 0 {
		writer.status = stdhttp.StatusOK
	}
	return writer.body.Write(data)
}

type shortErrorResponseWriter struct {
	header  stdhttp.Header
	maximum int
	err     error
}

func (writer *shortErrorResponseWriter) Header() stdhttp.Header {
	if writer.header == nil {
		writer.header = make(stdhttp.Header)
	}
	return writer.header
}

func (*shortErrorResponseWriter) WriteHeader(int) {}

func (writer *shortErrorResponseWriter) Write(data []byte) (int, error) {
	maximum := writer.maximum
	if maximum > len(data) {
		maximum = len(data)
	}
	return maximum, writer.err
}

type allOptionalResponseWriter struct {
	*basicResponseWriter
	flushes int
	closed  chan bool
}

func newAllOptionalResponseWriter() *allOptionalResponseWriter {
	return &allOptionalResponseWriter{
		basicResponseWriter: &basicResponseWriter{header: make(stdhttp.Header)},
		closed:              make(chan bool),
	}
}

func (writer *allOptionalResponseWriter) Flush() { writer.flushes++ }

func (*allOptionalResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	server, client := net.Pipe()
	_ = client.Close()
	return server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), nil
}

func (*allOptionalResponseWriter) Push(string, *stdhttp.PushOptions) error { return nil }

func (writer *allOptionalResponseWriter) ReadFrom(reader io.Reader) (int64, error) {
	return writer.body.ReadFrom(reader)
}

func (writer *allOptionalResponseWriter) CloseNotify() <-chan bool { return writer.closed }

type flusherOnlyResponseWriter struct {
	*basicResponseWriter
}

func (*flusherOnlyResponseWriter) Flush() {}

type flushErrorResponseWriter struct {
	*basicResponseWriter
	err error
}

func (*flushErrorResponseWriter) Flush() {}

func (writer *flushErrorResponseWriter) FlushError() error { return writer.err }

type hijackerOnlyResponseWriter struct {
	*basicResponseWriter
}

func (*hijackerOnlyResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	server, client := net.Pipe()
	_ = client.Close()
	return server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), nil
}

type pusherOnlyResponseWriter struct {
	*basicResponseWriter
}

func (*pusherOnlyResponseWriter) Push(string, *stdhttp.PushOptions) error { return nil }

type readerFromOnlyResponseWriter struct {
	*basicResponseWriter
}

func (writer *readerFromOnlyResponseWriter) ReadFrom(reader io.Reader) (int64, error) {
	return writer.body.ReadFrom(reader)
}

type closeNotifierOnlyResponseWriter struct {
	*basicResponseWriter
	closed chan bool
}

func (writer *closeNotifierOnlyResponseWriter) CloseNotify() <-chan bool { return writer.closed }

type plainReader struct {
	reader io.Reader
}

func (reader *plainReader) Read(data []byte) (int, error) { return reader.reader.Read(data) }

type auditStoreStub struct {
	mu sync.Mutex

	createCalls   int
	appendCalls   int
	finalizeCalls int
	recoverCalls  int

	createErr   error
	appendErr   error
	finalizeErr error
	recoverErr  error

	pending  map[string]auditdb.Event
	appended []auditdb.Event
}

func newAuditStoreStub() *auditStoreStub {
	return &auditStoreStub{pending: make(map[string]auditdb.Event)}
}

func (store *auditStoreStub) CreatePending(event auditdb.Event) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.createCalls++
	if store.createErr != nil {
		return store.createErr
	}
	store.pending[event.RequestID] = cloneAuditEvent(event)
	return nil
}

func (store *auditStoreStub) Finalize(requestID string, finalization auditdb.Finalization) (*auditdb.Event, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.finalizeCalls++
	if store.finalizeErr != nil {
		return nil, store.finalizeErr
	}
	pending, exists := store.pending[requestID]
	if !exists {
		return nil, auditdb.ErrPendingNotFound
	}
	pending.TimestampUTC = finalization.TimestampUTC
	pending.Result = finalization.Result
	pending.HTTPStatus = finalization.HTTPStatus
	pending.ErrorCode = finalization.ErrorCode
	pending.Metadata = auditdb.MergeMetadataV1(pending.Metadata, finalization.Metadata)
	delete(store.pending, requestID)
	store.appended = append(store.appended, cloneAuditEvent(pending))
	result := cloneAuditEvent(pending)
	return &result, nil
}

func (store *auditStoreStub) AppendTerminal(event auditdb.Event) (*auditdb.Event, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.appendCalls++
	if store.appendErr != nil {
		return nil, store.appendErr
	}
	store.appended = append(store.appended, cloneAuditEvent(event))
	result := cloneAuditEvent(event)
	return &result, nil
}

func (store *auditStoreStub) GetByID(string) (*auditdb.Event, error) {
	return nil, auditdb.ErrEventNotFound
}

func (store *auditStoreStub) GetByRequestID(requestID string) (*auditdb.Event, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, event := range store.appended {
		if event.RequestID == requestID {
			result := cloneAuditEvent(event)
			return &result, nil
		}
	}
	if event, exists := store.pending[requestID]; exists {
		result := cloneAuditEvent(event)
		return &result, nil
	}
	return nil, auditdb.ErrEventNotFound
}

func (store *auditStoreStub) ListTerminal(limit int) ([]auditdb.Event, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if limit > len(store.appended) {
		limit = len(store.appended)
	}
	result := make([]auditdb.Event, limit)
	for index := range result {
		result[index] = cloneAuditEvent(store.appended[index])
	}
	return result, nil
}

func (store *auditStoreStub) Query(context.Context, auditdb.QueryOptions) (auditdb.QueryResult, error) {
	return auditdb.QueryResult{Events: []auditdb.Event{}}, nil
}

func (store *auditStoreStub) RecoverPending() (int, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.recoverCalls++
	if store.recoverErr != nil {
		return 0, store.recoverErr
	}
	return len(store.pending), nil
}

func (store *auditStoreStub) totalWriteCalls() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.createCalls + store.appendCalls + store.finalizeCalls
}

func (store *auditStoreStub) singleAppended(t *testing.T) auditdb.Event {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.appended) != 1 {
		t.Fatalf("appended events: got %d, want 1", len(store.appended))
	}
	return cloneAuditEvent(store.appended[0])
}

func (store *auditStoreStub) singlePending(t *testing.T) auditdb.Event {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.pending) != 1 {
		t.Fatalf("pending events: got %d, want 1", len(store.pending))
	}
	for _, event := range store.pending {
		return cloneAuditEvent(event)
	}
	return auditdb.Event{}
}

func cloneAuditEvent(event auditdb.Event) auditdb.Event {
	if event.UserID != nil {
		value := *event.UserID
		event.UserID = &value
	}
	if event.HTTPStatus != nil {
		value := *event.HTTPStatus
		event.HTTPStatus = &value
	}
	if event.EffectivePermissions != nil {
		value := *event.EffectivePermissions
		event.EffectivePermissions = &value
	}
	event.Metadata = auditdb.MergeMetadataV1(nil, event.Metadata)
	return event
}
