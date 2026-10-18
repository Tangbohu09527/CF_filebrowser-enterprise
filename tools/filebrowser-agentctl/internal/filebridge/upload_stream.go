package filebridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

func (r *Runner) uploadStream(ctx context.Context, input Input, apply bool, requestID string) (any, int64, error) {
	remote, e := r.config.authorizeRemote(input.Source, input.Path, writeAccess)
	if e != nil {
		return nil, 0, e
	}
	if input.ExpectedBytes == nil || *input.ExpectedBytes < 1 || *input.ExpectedBytes > r.config.MaxUploadBytes || *input.ExpectedBytes > 128<<20 || len(input.ExpectedSHA256) != 64 {
		return nil, 0, bridgeError("invalid_input", "bounded size and SHA-256 required")
	}
	if !apply {
		return map[string]any{"source": input.Source, "path": remote, "requires_apply": true}, 0, nil
	}
	if r.inputStream == nil {
		return nil, 0, bridgeError("invalid_input", "trusted input stream required")
	}
	f, e := os.CreateTemp("", "filebridge-upload-*.zip")
	if e != nil {
		return nil, 0, bridgeError("local_io_failed", "cannot stage upload")
	}
	defer os.Remove(f.Name())
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(r.inputStream, *input.ExpectedBytes+1))
	if e != nil || n != *input.ExpectedBytes || hex.EncodeToString(h.Sum(nil)) != input.ExpectedSHA256 {
		return nil, n, bridgeError("integrity_mismatch", "upload stream differs from trusted descriptor")
	}
	existing, e := r.client.getResource(ctx, requestID, input.Source, remote, "sha256")
	if e == nil {
		sum, e := r.checksum(ctx, requestID, Input{Source: input.Source, Path: remote, Algorithm: "sha256"})
		if e != nil || existing.Size != n || sum.Checksums["sha256"] != input.ExpectedSHA256 {
			return nil, n, bridgeError("target_exists", "different bytes already exist")
		}
		return map[string]any{"source": input.Source, "path": remote, "size_bytes": n, "sha256": input.ExpectedSHA256, "reused": true}, n, nil
	}
	if !isErrorCode(e, "not_found") {
		return nil, n, e
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return nil, n, bridgeError("local_io_failed", "cannot rewind upload")
	}
	if e = r.client.uploadNew(ctx, requestID, input.Source, remote, f, n); e != nil {
		return nil, n, e
	}
	actual, e := r.checksum(ctx, requestID, Input{Source: input.Source, Path: remote, Algorithm: "sha256"})
	if e != nil || actual.Checksums["sha256"] != input.ExpectedSHA256 {
		return nil, n, bridgeError("write_outcome_unknown", "upload completed but verification failed; inspect before retry")
	}
	return map[string]any{"source": input.Source, "path": remote, "size_bytes": n, "sha256": input.ExpectedSHA256, "reused": false}, n, nil
}
