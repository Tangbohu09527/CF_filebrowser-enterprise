package http

// This is deliberately a single-regular-file extension of the existing product
// API. Recovery uses ordinary scoped files; there is no new database or scheduler.
import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"sync"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	commonerrors "github.com/gtsteffaniak/filebrowser/backend/common/errors"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
)

type productOperationIntent struct {
	Schema            string `json:"schema"`
	ActorID           uint   `json:"actor_id"`
	Actor             string `json:"actor"`
	Operation         string `json:"operation"`
	Source            string `json:"source"`
	Path              string `json:"path"`
	Destination       string `json:"destination,omitempty"`
	ExpectedSHA256    string `json:"expected_sha256"`
	ReplacementPath   string `json:"replacement_path,omitempty"`
	ReplacementSHA256 string `json:"replacement_sha256,omitempty"`
	RecoveryPath      string `json:"recovery_path"`
	RestoreFrom       string `json:"restore_from,omitempty"`
}
type productOperationResult struct {
	State        string `json:"state"`
	Operation    string `json:"operation"`
	Source       string `json:"source"`
	Path         string `json:"path"`
	Destination  string `json:"destination,omitempty"`
	SHA256       string `json:"sha256"`
	RecoveryPath string `json:"recovery_path"`
	Recoverable  bool   `json:"recoverable"`
}

func productValidSHA(value string) bool {
	raw, e := hex.DecodeString(value)
	return e == nil && len(raw) == 32 && value == fmt.Sprintf("%x", raw)
}
func productOrganize(w http.ResponseWriter, r *http.Request, d *requestContext, req productRequest) (int, error) {
	u, e := currentAuthenticatedArchiveUser(d)
	if e != nil {
		return http.StatusForbidden, e
	}
	if !u.Permissions.Create || !u.Permissions.Download || !u.Permissions.Browse {
		return http.StatusForbidden, commonerrors.ErrAccessDenied
	}
	destructive := req.Operation == "move" || req.Operation == "rename" || req.Operation == "replace" || req.Operation == "delete"
	if req.Operation != "copy" && req.Operation != "restore" && !destructive {
		return http.StatusBadRequest, fmt.Errorf("unsupported single-file operation")
	}
	if destructive && (!u.Permissions.Modify || !u.Permissions.Delete) {
		return http.StatusForbidden, commonerrors.ErrAccessDenied
	}
	if destructive {
		if _, err := resolveAuthenticatedWriteTarget(u, req.Source, req.Path); err != nil {
			return productErrorStatus(err), err
		}
	}
	if !productLabel(req.OperationID) || !productValidSHA(req.ExpectedSHA256) || req.RecoveryRoot == "" {
		return http.StatusBadRequest, fmt.Errorf("operation ID, expected SHA and scoped recovery root required")
	}
	if req.Operation == "rename" && path.Dir(req.Path) != path.Dir(req.Destination) {
		return http.StatusBadRequest, fmt.Errorf("rename must retain its directory; use move explicitly")
	}
	if req.Operation == "replace" && (!productValidSHA(req.SHA256) || req.ReplacementPath == "") {
		return http.StatusBadRequest, fmt.Errorf("replacement path and frozen digest required")
	}
	if req.Operation == "replace" {
		req.Destination = req.Path
	}
	if req.Operation == "restore" {
		req.Destination = req.Path
	}
	if req.Operation != "delete" && req.Destination == "" {
		return http.StatusBadRequest, fmt.Errorf("explicit destination required")
	}
	if (req.Operation == "copy" || req.Operation == "move" || req.Operation == "rename") && path.Clean(req.Path) == path.Clean(req.Destination) {
		return http.StatusBadRequest, fmt.Errorf("source and destination must differ")
	}
	for _, selected := range []string{req.Path, req.Destination, req.ReplacementPath} {
		if selected != "" && publicSharePathWithin(path.Clean(req.RecoveryRoot), path.Clean(selected)) {
			return http.StatusBadRequest, fmt.Errorf("recovery files are not operation inputs")
		}
	}
	recovery := path.Join(req.RecoveryRoot, req.OperationID)
	if req.Path == recovery || req.Destination == recovery {
		return http.StatusBadRequest, fmt.Errorf("invalid recovery target")
	}
	muAny, _ := productLocks.LoadOrStore(req.Source+"\x00operation\x00"+recovery, &sync.Mutex{})
	mu, validLock := muAny.(*sync.Mutex)
	if !validLock {
		return http.StatusInternalServerError, fmt.Errorf("product lock unavailable")
	}
	mu.Lock()
	defer mu.Unlock()
	intent := productOperationIntent{Schema: "cf-file-operation/v1", ActorID: u.ID, Actor: u.Username, Operation: req.Operation, Source: req.Source, Path: req.Path, Destination: req.Destination, ExpectedSHA256: req.ExpectedSHA256, ReplacementPath: req.ReplacementPath, ReplacementSHA256: req.SHA256, RecoveryPath: recovery, RestoreFrom: req.RecoveryPath}
	encoded, _ := json.Marshal(intent)
	intentPath := path.Join(recovery, "intent.json")
	backupPath := path.Join(recovery, "before.bin")
	retainedPath := path.Join(recovery, "retained-original.bin")
	completedPath := path.Join(recovery, "complete.json")
	known, knownErr := productRead(d, req.Source, intentPath, 64<<10)
	if knownErr == nil && string(known) != string(encoded) {
		return http.StatusConflict, fmt.Errorf("operation belongs to a different frozen intent")
	}
	if knownErr != nil && !errors.Is(knownErr, commonerrors.ErrNotExist) && !os.IsNotExist(knownErr) {
		return productErrorStatus(knownErr), knownErr
	}
	if complete, err := productRead(d, req.Source, completedPath, 64<<10); err == nil {
		var prior productOperationResult
		if json.Unmarshal(complete, &prior) != nil || prior.State != "complete" || prior.RecoveryPath != recovery {
			return http.StatusConflict, fmt.Errorf("invalid completion receipt")
		}
		if err = productVerifyOperation(d, intent, prior); err != nil {
			return productErrorStatus(err), err
		}
		return renderJSON(w, r, prior, http.StatusOK)
	}
	// Freeze the input. A pending destructive operation may already have moved
	// the original into its retained location; the immutable backup is then used.
	snapshotPath := req.Path
	if req.Operation == "restore" {
		raw, err := productRead(d, req.Source, path.Join(req.RecoveryPath, "intent.json"), 64<<10)
		if err != nil {
			return productErrorStatus(err), err
		}
		var previous productOperationIntent
		if json.Unmarshal(raw, &previous) != nil || previous.Schema != "cf-file-operation/v1" || previous.Source != req.Source || previous.ActorID != u.ID || previous.Actor != u.Username || previous.Path != req.Path || previous.ExpectedSHA256 != req.ExpectedSHA256 {
			return http.StatusForbidden, commonerrors.ErrAccessDenied
		}
		snapshotPath = path.Join(req.RecoveryPath, "before.bin")
	} else if knownErr == nil {
		// Resume only this operation's immutable before-image. The live source is
		// checked again before capture; it must never redefine the frozen intent.
		snapshotPath = backupPath
	}
	input, e := resolveAuthenticatedReadTarget(u, req.Source, snapshotPath)
	if e != nil {
		return productErrorStatus(e), e
	}
	if input.Info == nil || !input.Info.Mode().IsRegular() || input.Info.Size() > productArchiveLimit || authenticatedReadPathContainsSymlink(input.SourcePath, input.LogicalPath) {
		return http.StatusBadRequest, fmt.Errorf("bounded regular file required")
	}
	snapshot, _, cleanup, e := snapshotAuthenticatedReadTarget(input)
	if e != nil {
		return productErrorStatus(e), e
	}
	defer cleanup()
	hash, _, e := productFileHash(snapshot, productArchiveLimit)
	if e != nil || hash != req.ExpectedSHA256 {
		return http.StatusConflict, fmt.Errorf("source changed; requery before acting")
	}
	outputLocal, outputHash := snapshot, hash
	if req.Operation == "replace" {
		replacement, err := resolveAuthenticatedReadTarget(u, req.Source, req.ReplacementPath)
		if err != nil {
			return productErrorStatus(err), err
		}
		if replacement.Info == nil || !replacement.Info.Mode().IsRegular() || replacement.Info.Size() > productArchiveLimit || authenticatedReadPathContainsSymlink(replacement.SourcePath, replacement.LogicalPath) {
			return http.StatusBadRequest, fmt.Errorf("bounded regular replacement required")
		}
		local, _, release, err := snapshotAuthenticatedReadTarget(replacement)
		if err != nil {
			return productErrorStatus(err), err
		}
		defer release()
		digest, _, err := productFileHash(local, productArchiveLimit)
		if err != nil || digest != req.SHA256 {
			return http.StatusConflict, fmt.Errorf("replacement changed")
		}
		outputLocal, outputHash = local, digest
	}
	// Refuse a conflicting target before capturing the source. A later race
	// still fails closed at the no-replace publish and retains recovery evidence.
	if req.Operation != "delete" && req.Operation != "replace" {
		existing, err := resolveAuthenticatedReadTarget(u, req.Source, req.Destination)
		if err == nil {
			sum, hashErr := checksumAuthenticatedReadTarget(existing, "sha256")
			if hashErr != nil || sum != outputHash {
				return http.StatusConflict, fmt.Errorf("destination differs; no files changed")
			}
		} else if !os.IsNotExist(err) && !errors.Is(err, commonerrors.ErrNotExist) {
			return productErrorStatus(err), err
		}
	}
	action := auditdb.ActionFileUpload
	switch req.Operation {
	case "move":
		action = auditdb.ActionFileMove
	case "rename":
		action = auditdb.ActionFileRename
	case "replace":
		action = auditdb.ActionFileModify
	case "delete":
		action = auditdb.ActionFileDelete
	}
	if e = prepareResourceWriteAudit(r, action, req.Source, req.Path, req.Path, req.Source, req.Destination, req.Destination, resourceWriteAuditMetadata(auditdb.MethodPOST, 1)); e != nil {
		return http.StatusServiceUnavailable, e
	}
	if e = reserveResourceWriteAudit(r); e != nil {
		return http.StatusServiceUnavailable, e
	}
	if knownErr != nil {
		if e = productEnsureDirs(d, req.Source, path.Dir(recovery)); e != nil {
			return productErrorStatus(e), e
		}
		u, e = currentAuthenticatedArchiveUser(d)
		if e != nil {
			return http.StatusForbidden, e
		}
		target, err := resolveAuthenticatedWriteTarget(u, req.Source, recovery)
		if err != nil {
			return productErrorStatus(err), err
		}
		if authenticatedReadPathContainsSymlink(target.SourcePath, path.Dir(target.LogicalPath)) {
			return http.StatusForbidden, commonerrors.ErrAccessDenied
		}
		if e = os.Mkdir(target.RealPath, 0755); e != nil {
			return productErrorStatus(e), e
		}
		if e = files.RefreshIndex(req.Source, target.CanonicalPath, true, false); e != nil {
			return productErrorStatus(e), e
		}
		if e = productPublishBytes(d, req.Source, intentPath, encoded); e != nil {
			return productErrorStatus(e), e
		}
	}
	if e = productPublishLocal(d, req.Source, backupPath, snapshot, hash); e != nil {
		return productErrorStatus(e), e
	}
	if e = r.Context().Err(); e != nil {
		return http.StatusRequestTimeout, e
	}
	if destructive {
		u, e = currentAuthenticatedArchiveUser(d)
		if e != nil || !u.Permissions.Modify || !u.Permissions.Delete {
			return http.StatusForbidden, commonerrors.ErrAccessDenied
		}
		current, currentErr := resolveAuthenticatedReadTarget(u, req.Source, req.Path)
		retained, retainedErr := resolveAuthenticatedWriteTarget(u, req.Source, retainedPath)
		if retainedErr != nil {
			return productErrorStatus(retainedErr), retainedErr
		}
		if authenticatedReadPathContainsSymlink(retained.SourcePath, path.Dir(retained.LogicalPath)) {
			return http.StatusForbidden, commonerrors.ErrAccessDenied
		}
		if _, err := resolveAuthenticatedWriteTarget(u, req.Source, req.Path); err != nil {
			return productErrorStatus(err), err
		}
		capturedAlready := false
		if req.Operation == "replace" && knownErr == nil && currentErr == nil {
			liveHash, err := checksumAuthenticatedReadTarget(current, "sha256")
			oldHash, _, oldErr := productFileHash(retained.RealPath, productArchiveLimit)
			capturedAlready = err == nil && oldErr == nil && liveHash == outputHash && oldHash == hash
		}
		if currentErr == nil && !capturedAlready {
			fresh, err := checksumAuthenticatedReadTarget(current, "sha256")
			if err != nil || fresh != hash {
				return http.StatusConflict, fmt.Errorf("source changed before mutation")
			}
			if authenticatedReadPathContainsSymlink(current.SourcePath, current.LogicalPath) {
				return http.StatusForbidden, commonerrors.ErrAccessDenied
			}
			// Existing OS-specific no-replace primitive: never replace an employee's
			// newly created recovery target. A replaced source is detected after capture.
			if e = renameWebDAVNoReplace(current.RealPath, retained.RealPath); e != nil {
				return productErrorStatus(e), e
			}
			captured, _, err := productFileHash(retained.RealPath, productArchiveLimit)
			if err != nil || captured != hash {
				_ = renameWebDAVNoReplace(retained.RealPath, current.RealPath)
				return http.StatusConflict, fmt.Errorf("concurrent change retained or restored; inspect recovery before retry")
			}
			_ = files.RefreshIndex(req.Source, current.CanonicalPath, false, false)
			_ = files.RefreshIndex(req.Source, retained.CanonicalPath, false, false)
		} else if currentErr != nil && !os.IsNotExist(currentErr) && !errors.Is(currentErr, commonerrors.ErrNotExist) {
			return productErrorStatus(currentErr), currentErr
		}
		retainedHash, _, err := productFileHash(retained.RealPath, productArchiveLimit)
		if err != nil || retainedHash != hash {
			return http.StatusConflict, fmt.Errorf("pending original unavailable or changed")
		}
	}
	// Failures after capture retain the original and intent. They never remove
	// recovery data or overwrite a newly created destination to hide partial work.
	if e = r.Context().Err(); e != nil {
		return http.StatusRequestTimeout, e
	}
	if req.Operation != "delete" {
		if e = productPublishLocal(d, req.Source, req.Destination, outputLocal, outputHash); e != nil {
			return productErrorStatus(e), e
		}
	}
	result := productOperationResult{State: "complete", Operation: req.Operation, Source: req.Source, Path: req.Path, Destination: req.Destination, SHA256: outputHash, RecoveryPath: recovery, Recoverable: true}
	if e = productVerifyOperation(d, intent, result); e != nil {
		return productErrorStatus(e), e
	}
	receipt, _ := json.Marshal(result)
	if e = productPublishBytes(d, req.Source, completedPath, receipt); e != nil {
		return productErrorStatus(e), e
	}
	return renderJSON(w, r, result, http.StatusOK)
}
func productVerifyOperation(d *requestContext, intent productOperationIntent, result productOperationResult) error {
	u, e := currentAuthenticatedArchiveUser(d)
	if e != nil {
		return e
	}
	backup, e := resolveAuthenticatedReadTarget(u, intent.Source, path.Join(intent.RecoveryPath, "before.bin"))
	if e != nil {
		return e
	}
	sum, e := checksumAuthenticatedReadTarget(backup, "sha256")
	if e != nil || sum != intent.ExpectedSHA256 {
		return errArchiveExtractionConflict
	}
	if intent.Operation == "move" || intent.Operation == "rename" || intent.Operation == "delete" || intent.Operation == "replace" {
		retained, err := resolveAuthenticatedReadTarget(u, intent.Source, path.Join(intent.RecoveryPath, "retained-original.bin"))
		if err != nil {
			return err
		}
		original, err := checksumAuthenticatedReadTarget(retained, "sha256")
		if err != nil || original != intent.ExpectedSHA256 {
			return errArchiveExtractionConflict
		}
	}
	if intent.Operation == "move" || intent.Operation == "rename" || intent.Operation == "delete" {
		if _, err := resolveAuthenticatedReadTarget(u, intent.Source, intent.Path); err == nil {
			return errArchiveExtractionConflict
		} else if !os.IsNotExist(err) && !errors.Is(err, commonerrors.ErrNotExist) {
			return err
		}
	}
	if intent.Operation != "delete" {
		target, err := resolveAuthenticatedReadTarget(u, intent.Source, result.Destination)
		if err != nil {
			return err
		}
		hash, err := checksumAuthenticatedReadTarget(target, "sha256")
		if err != nil || hash != result.SHA256 {
			return errArchiveExtractionConflict
		}
	}
	return nil
}
