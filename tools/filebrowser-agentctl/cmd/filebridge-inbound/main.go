// filebridge-inbound is a private NDJSON worker. Its stdin is a trusted dispatch
// host pipe; it is not a model-facing CLI and accepts no credentials in arguments.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/signal"

	"github.com/gtsteffaniak/filebrowser/tools/filebrowser-agentctl/internal/inbound"
)

func decode(data []byte, value any) error {
	if err := uniqueKeys(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func uniqueKeys(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delimiter == '{' {
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return io.ErrUnexpectedEOF
			}
			seen[name] = true
			if err := uniqueKeys(decoder); err != nil {
				return err
			}
		}
	} else if delimiter == '[' {
		for decoder.More() {
			if err := uniqueKeys(decoder); err != nil {
				return err
			}
		}
	} else {
		return io.ErrUnexpectedEOF
	}
	_, err = decoder.Token()
	return err
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if len(os.Args) != 1 {
		return
	}
	run(ctx, os.Stdin, os.Stdout)
}

func run(parent context.Context, input io.Reader, output io.Writer) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	encoder := json.NewEncoder(output)
	fail := func(code string) {
		_ = encoder.Encode(map[string]any{"ok": false, "error": map[string]string{"code": code}})
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	if !scanner.Scan() {
		fail("invalid_binding")
		return
	}
	var binding inbound.Binding
	if decode(scanner.Bytes(), &binding) != nil {
		fail("invalid_binding")
		return
	}
	ctx, leaseCancel := context.WithDeadline(ctx, binding.ExpiresAt)
	defer leaseCancel()
	engine, err := inbound.New(ctx, binding)
	if err != nil {
		fail("initialization_failed")
		return
	}
	defer engine.Close()
	if encoder.Encode(map[string]bool{"ok": true}) != nil {
		return
	}
	type request struct {
		Op           string `json:"op"`
		AttachmentID int64  `json:"attachment_id,omitempty"`
		Handle       string `json:"handle,omitempty"`
	}
	requests := make(chan request, 16)
	results := make(map[string]inbound.Result)
	resolved := make(map[string]*os.File)
	defer func() {
		for _, f := range resolved {
			_ = f.Close()
		}
	}()
	// Only this goroutine reads stdin. EOF or cancel revokes the lease immediately,
	// including while the main goroutine is blocked inside TLS, reads or backoff.
	go func() {
		defer cancel()
		defer close(requests)
		for scanner.Scan() {
			var r request
			if decode(scanner.Bytes(), &r) != nil {
				return
			}
			if r.Op == "cancel" {
				return
			}
			select {
			case requests <- r:
			case <-ctx.Done():
				return
			default:
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case r, open := <-requests:
			if !open {
				return
			}
			switch r.Op {
			case "download":
				if r.AttachmentID <= 0 || r.Handle != "" {
					fail("invalid_request")
					continue
				}
				result := engine.Download(ctx, r.AttachmentID)
				if result.OK {
					results[result.Handle] = result
				}
				if encoder.Encode(result) != nil {
					return
				}
			case "resolve":
				if r.Handle == "" || r.AttachmentID != 0 {
					fail("invalid_request")
					continue
				}
				f, err := engine.Resolve(ctx, r.Handle)
				if err != nil {
					fail("not_authorized")
					continue
				}
				info, statErr := f.Stat()
				path := f.Name()
				if statErr != nil {
					_ = f.Close()
					fail("integrity_failed")
					continue
				}
				if previous := resolved[r.Handle]; previous != nil {
					_ = previous.Close()
				}
				resolved[r.Handle] = f
				// This path is only for the host's internal processing-tool adapter.
				if encoder.Encode(map[string]any{"ok": true, "path": path, "bytes_written": info.Size(), "sha256": results[r.Handle].SHA256}) != nil {
					return
				}
			default:
				fail("invalid_request")
			}
		}
	}
}
