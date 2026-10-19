package filebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

type ProductInput struct {
	Operation       string          `json:"operation,omitempty"`
	OperationID     string          `json:"operation_id,omitempty"`
	ExpectedSHA256  string          `json:"expected_sha256,omitempty"`
	ReplacementPath string          `json:"replacement_path,omitempty"`
	RecoveryRoot    string          `json:"recovery_root,omitempty"`
	RecoveryPath    string          `json:"recovery_path,omitempty"`
	SHA256          string          `json:"sha256,omitempty"`
	Destination     string          `json:"destination,omitempty"`
	Brand           string          `json:"brand,omitempty"`
	Product         string          `json:"product,omitempty"`
	Specification   string          `json:"specification,omitempty"`
	Version         string          `json:"version,omitempty"`
	Members         []ProductMember `json:"members,omitempty"`
	Categories      []string        `json:"categories,omitempty"`
	Name            string          `json:"name,omitempty"`
	Member          string          `json:"member,omitempty"`
}
type ProductMember struct {
	Path     string `json:"path"`
	Size     int64  `json:"size_bytes"`
	SHA256   string `json:"sha256"`
	Category string `json:"category,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

func (r *Runner) product(ctx context.Context, command string, input Input, apply bool, requestID string) (any, int64, error) {
	p := input.Product
	if p == nil {
		return nil, 0, bridgeError("invalid_input", "product input is required")
	}
	resourcePath, e := r.config.authorizeRemote(input.Source, input.Path, readAccess)
	if e != nil {
		return nil, 0, e
	}
	action := strings.TrimPrefix(command, "product-")
	if action == "organize" {
		copied := *p
		p = &copied
		p.OperationID = input.OperationID
		if p.Operation != "copy" && p.Operation != "move" && p.Operation != "rename" && p.Operation != "replace" && p.Operation != "delete" && p.Operation != "restore" {
			return nil, 0, bridgeError("invalid_input", "unsupported single-file operation")
		}
		if p.Operation != "copy" {
			if _, e = r.config.authorizeRemote(input.Source, input.Path, writeAccess); e != nil {
				return nil, 0, e
			}
		}
		if p.RecoveryRoot == "" {
			return nil, 0, bridgeError("invalid_input", "scoped recovery root required")
		}
		if _, e = r.config.authorizeRemote(input.Source, p.RecoveryRoot, writeAccess); e != nil {
			return nil, 0, e
		}
		for _, selected := range []string{p.ReplacementPath, p.RecoveryPath} {
			if selected != "" {
				if _, e = r.config.authorizeRemote(input.Source, selected, readAccess); e != nil {
					return nil, 0, e
				}
			}
		}
		if p.Destination != "" {
			if _, e = r.config.authorizeRemote(input.Source, p.Destination, writeAccess); e != nil {
				return nil, 0, e
			}
		}
		if !apply {
			return map[string]any{"action": action, "operation": p.Operation, "source": input.Source, "path": resourcePath, "requires_apply": true}, 0, nil
		}
	}
	if action == "import" || action == "export" {
		if p.Destination == "" {
			return nil, 0, bridgeError("invalid_input", "destination is required")
		}
		if _, e = r.config.authorizeRemote(input.Source, p.Destination, writeAccess); e != nil {
			return nil, 0, e
		}
		if !apply {
			return map[string]any{"action": action, "source": input.Source, "path": resourcePath, "destination": p.Destination, "requires_apply": true}, 0, nil
		}
	}
	b, e := json.Marshal(p)
	if e != nil {
		return nil, 0, bridgeError("invalid_input", "invalid product input")
	}
	var body map[string]any
	if json.Unmarshal(b, &body) != nil {
		return nil, 0, bridgeError("invalid_input", "invalid product input")
	}
	body["action"], body["source"], body["path"] = action, input.Source, resourcePath
	encoded, e := json.Marshal(body)
	if e != nil || len(encoded) > 2<<20 {
		return nil, 0, bridgeError("invalid_input", "product input too large")
	}
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	response, e := r.client.do(ctx, requestOptions{method: http.MethodPost, endpoint: "api/resources/products", query: make(url.Values), headers: headers, body: bytes.NewReader(encoded), contentLength: int64(len(encoded)), requestID: requestID})
	if e != nil {
		return nil, 0, e
	}
	var result map[string]any
	if e = r.client.expectJSON(response, &result); e != nil {
		return nil, 0, e
	}
	return result, 0, nil
}
