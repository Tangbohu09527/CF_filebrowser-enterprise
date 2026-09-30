package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeRejectsUnknownDuplicateAndTrailingData(t *testing.T) {
	for _, raw := range []string{`{"op":"download","task_context":{"task_id":"model-selected"}}`, `{"op":"download","op":"resolve"}`, `{"op":"download"} {}`, `{"op":"download","payload":{"value":1,"value":2}}`} {
		var request struct {
			Op      string         `json:"op"`
			Payload map[string]int `json:"payload,omitempty"`
		}
		if err := decode([]byte(raw), &request); err == nil {
			t.Fatalf("ambiguous/expanded protocol accepted: %s", raw)
		}
	}
	var request struct {
		Op           string `json:"op"`
		AttachmentID int64  `json:"attachment_id"`
	}
	if err := decode([]byte(`{"op":"download","attachment_id":2}`), &request); err != nil || request.AttachmentID != 2 {
		t.Fatal("valid model-independent request rejected")
	}
}

func TestWorkerInvalidInitializationAndOversizedLineDoNotLeakInputs(t *testing.T) {
	for _, raw := range []string{"", `{"authorization":"Bearer secret-capability","work_dir":"sensitive-directory"}` + "\n", strings.Repeat("x", 1<<20) + "secret-capability\n"} {
		var output bytes.Buffer
		run(context.Background(), strings.NewReader(raw), &output)
		if strings.Contains(output.String(), "secret-capability") || strings.Contains(output.String(), "sensitive-directory") {
			t.Fatal("invalid input echoed")
		}
		var response struct {
			OK    bool `json:"ok"`
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(output.Bytes(), &response); err != nil || response.OK || response.Error.Code != "invalid_binding" {
			t.Fatalf("invalid worker response: %q", output.String())
		}
	}
}
