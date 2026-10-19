package filebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestProductClientFixedRouteAndDryRun(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/api/resources/products" || r.Header.Get("Authorization") != "Bearer "+transferTestToken {
			t.Error("route or authentication mismatch")
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Fatal("body")
		}
		if body["source"] != "docs" || body["path"] != "/read/package.zip" || body["action"] != "import" {
			t.Error("request mapping")
		}
		transferTestWriteJSON(t, w, map[string]any{"state": "complete"})
	}))
	defer server.Close()
	runner := transferTestRunner(t, server.URL, nil, nil)
	input := transferTestInput("/read/package.zip")
	input.Product = &ProductInput{Destination: "/write/products", Brand: "brand", Product: "product", Specification: "500g", Version: "v1"}
	result := runner.Run(context.Background(), "product-import", input, false)
	if !result.OK || !result.DryRun || calls.Load() != 0 {
		t.Fatal("dry run touched service", result)
	}
	result = runner.Run(context.Background(), "product-import", input, true)
	if !result.OK || calls.Load() != 1 {
		t.Fatal("apply failed", result)
	}
	input.Product.Destination = "/other"
	result = runner.Run(context.Background(), "product-import", input, true)
	if result.OK || calls.Load() != 1 {
		t.Fatal("write scope expanded")
	}
}
func TestProductUploadStreamRejectsWrongBytesBeforeHTTP(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); t.Error("invalid stream reached service") }))
	defer server.Close()
	runner := transferTestRunner(t, server.URL, nil, nil)
	expected := []byte("original bytes")
	input := transferTestInput("/write/new.zip")
	transferTestSetApproval(&input, expected)
	for _, data := range [][]byte{[]byte("different bytes"), expected[:3], append(append([]byte{}, expected...), byte(0))} {
		runner.inputStream = bytes.NewReader(data)
		result := runner.Run(context.Background(), "upload-stream", input, true)
		if result.OK || result.Error.Code != "integrity_mismatch" {
			t.Fatal(result)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid stream had side effect")
	}
}
func TestProductCLIRejectsMissingFramingBeforeNetwork(t *testing.T) {
	// A model cannot pass an arbitrary local filename as a streaming source.
	input := Input{Source: "docs", Path: "/write/new.zip", LocalFile: "secret", Product: &ProductInput{}}
	if err := validateCommandInput("upload-stream", input); err == nil {
		t.Fatal("local file bypass accepted")
	}
	if err := validateCommandInput("product-inspect", Input{Source: "docs", Path: "/read/a.zip", LocalFile: "secret", Product: &ProductInput{}}); err == nil {
		t.Fatal("local path accepted")
	}
}

func TestProductOrganizeScopeAndApply(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["action"] != "organize" || body["operation"] != "copy" || body["operation_id"] != "op-transfer-test" {
			t.Error("bad scoped operation", body)
		}
		transferTestWriteJSON(t, w, map[string]any{"state": "complete"})
	}))
	defer server.Close()
	runner := transferTestRunner(t, server.URL, nil, nil)
	input := transferTestInput("/read/image.jpg")
	input.OperationID = "op-transfer-test"
	input.Product = &ProductInput{Operation: "copy", Destination: "/write/image.jpg", RecoveryRoot: "/write/recovery", ExpectedSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	result := runner.Run(context.Background(), "product-organize", input, false)
	if !result.OK || !result.DryRun || calls.Load() != 0 {
		t.Fatal(result)
	}
	result = runner.Run(context.Background(), "product-organize", input, true)
	if !result.OK || calls.Load() != 1 {
		t.Fatal(result)
	}
	input.Product.Operation = "move"
	result = runner.Run(context.Background(), "product-organize", input, true)
	if result.OK || calls.Load() != 1 {
		t.Fatal("read-only source mutated", result)
	}
	input.Product.Operation = "copy"
	input.Product.RecoveryRoot = "/outside"
	result = runner.Run(context.Background(), "product-organize", input, true)
	if result.OK || calls.Load() != 1 {
		t.Fatal("recovery scope bypass", result)
	}
}
