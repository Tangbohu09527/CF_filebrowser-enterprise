package filebridge

// Optional single-file creation. The operator approves a content-bound plan with
// a separate CLI command; neither approval nor a local path is an Agent tool.
// The journal is a local process-replay guard, not a distributed exactly-once
// service or an OS sandbox against other tools running as the same identity.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

const createPlanSchema = "filebridge-create-plan/v1"

var createIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,80}$`)
var createHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// CreateTextPolicy is operator-only. The existing read-only config need not be
// changed: a second, narrowly scoped config can be used by the creation tool.
type CreateTextPolicy struct {
	Enabled            bool   `json:"enabled"`
	StateDir           string `json:"state_dir"`
	Source             string `json:"source"`
	ServerScope        string `json:"server_scope"`
	UserID             uint   `json:"user_id"`
	MaxBytes           int64  `json:"max_bytes"`
	ApprovalTTLSeconds int    `json:"approval_ttl_seconds"`
}

type CreateTextPlan struct {
	Schema       string `json:"schema"`
	OperationID  string `json:"operation_id"`
	Source       string `json:"source"`
	Path         string `json:"path"`
	Content      string `json:"content"`
	Bytes        int64  `json:"bytes"`
	SHA256       string `json:"sha256"`
	ConfigSHA256 string `json:"config_sha256"`
	CreatedUnix  int64  `json:"created_unix"`
	ExpiresUnix  int64  `json:"expires_unix"`
}

type CreateTextResult struct {
	State             string `json:"state"`
	OperationID       string `json:"operation_id"`
	PlanSHA256        string `json:"plan_sha256"`
	Source            string `json:"source"`
	Path              string `json:"path"`
	Bytes             int64  `json:"bytes"`
	SHA256            string `json:"sha256"`
	ExpiresUnix       int64  `json:"expires_unix"`
	Applied           bool   `json:"applied"`
	Verified          bool   `json:"verified"`
	AlreadyDone       bool   `json:"already_done"`
	OriginalRequestID string `json:"original_request_id,omitempty"`
	VerificationScope string `json:"verification_scope,omitempty"`
}

type createApproval struct {
	PlanSHA256  string `json:"plan_sha256"`
	ExpiresUnix int64  `json:"expires_unix"`
}

type createOutcome struct {
	PlanSHA256 string `json:"plan_sha256"`
	RequestID  string `json:"request_id"`
	State      string `json:"state"`
	ErrorCode  string `json:"error_code,omitempty"`
}

func (c *Config) initializeCreatePolicy() error {
	p := c.CreateText
	if p == nil || !p.Enabled {
		return nil
	}
	if p.MaxBytes == 0 {
		p.MaxBytes = 65536
	}
	if p.ApprovalTTLSeconds == 0 {
		p.ApprovalTTLSeconds = 900
	}
	p.StateDir = resolveConfigRelative(c.configDir, p.StateDir)
	return c.validateCreatePolicy()
}

func (c *Config) validateCreatePolicy() error {
	p := c.CreateText
	if p == nil || !p.Enabled {
		return nil
	}
	if p.UserID == 0 || p.Source == "" || p.ServerScope == "" ||
		p.MaxBytes < 1 || p.MaxBytes > 65536 || p.MaxBytes > c.MaxInlineBytes ||
		p.MaxBytes > c.MaxUploadBytes || p.MaxBytes > c.MaxChecksumBytes ||
		p.ApprovalTTLSeconds < 60 || p.ApprovalTTLSeconds > 3600 {
		return bridgeError("invalid_create_policy", "creation identity, scope or limits are invalid")
	}
	scope, err := normalizeRemotePath(p.ServerScope)
	if err != nil || scope != p.ServerScope || scope == "/" {
		return bridgeError("invalid_create_policy", "creation requires an explicit non-root server scope")
	}
	allowed, ok := c.AllowedSources[p.Source]
	if !ok || len(allowed.ReadRoots) == 0 || len(allowed.WriteRoots) == 0 {
		return bridgeError("invalid_create_policy", "creation requires both read and write roots")
	}
	return checkCreatePath(p.StateDir, true)
}

func checkCreatePath(filename string, directory bool) error {
	if !filepath.IsAbs(filename) {
		return bridgeError("create_state_unavailable", "state paths must be absolute")
	}
	for current := filepath.Clean(filename); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || (current != filepath.Clean(filename) && !info.IsDir()) {
			return bridgeError("create_state_unavailable", "state path is unavailable or traverses a link")
		}
		if current == filepath.Clean(filename) {
			if (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
				return bridgeError("create_state_unavailable", "state object has an unexpected type")
			}
			// NTFS ACL validation belongs to the Windows provisioner, not POSIX mode bits.
			if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
				return bridgeError("create_state_permissions", "state objects must be private")
			}
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return nil
}

func createHash(value []byte) string { h := sha256.Sum256(value); return hex.EncodeToString(h[:]) }
func (r *Runner) createNow() time.Time {
	if r.createClock != nil {
		return r.createClock()
	}
	return time.Now()
}
func (r *Runner) createBinding() string { data, _ := json.Marshal(r.config); return createHash(data) }

func (r *Runner) createDirectory(id string) (string, error) {
	if r.config.CreateText == nil || !r.config.CreateText.Enabled {
		return "", bridgeError("create_disabled", "controlled text creation is not enabled")
	}
	if !createIDPattern.MatchString(id) {
		return "", bridgeError("invalid_operation_id", "a recorded creation operation_id is required")
	}
	if err := r.config.validateCreatePolicy(); err != nil {
		return "", err
	}
	return filepath.Join(r.config.CreateText.StateDir, id), nil
}

func writeCreateOnce(filename string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return bridgeError("create_state_unavailable", "cannot encode creation state")
	}
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		return bridgeError("create_record_exists", "creation record already exists; do not replay")
	}
	if err != nil {
		return bridgeError("create_state_unavailable", "cannot reserve creation state")
	}
	// Never delete a partial reservation: failure must not turn into permission to retry.
	defer file.Close()
	n, err := file.Write(raw)
	if err != nil || n != len(raw) {
		return bridgeError("create_state_unavailable", "cannot persist creation state; preserve the journal")
	}
	if err = file.Sync(); err != nil {
		return bridgeError("create_state_unavailable", "cannot sync creation state; preserve the journal")
	}
	if err = file.Close(); err != nil {
		return bridgeError("create_state_unavailable", "cannot close creation state")
	}
	return nil
}

func readCreateJSON(filename string, out any) ([]byte, error) {
	if err := checkCreatePath(filename, false); err != nil {
		return nil, err
	}
	before, err := os.Lstat(filename)
	if err != nil {
		return nil, bridgeError("create_state_unavailable", "cannot inspect creation record")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, bridgeError("create_state_unavailable", "cannot read creation record")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(before, info) {
		return nil, bridgeError("create_state_unavailable", "creation record changed")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil || len(raw) >= 1<<20 {
		return nil, bridgeError("create_state_unavailable", "invalid creation record size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || ensureJSONEOF(decoder) != nil {
		return nil, bridgeError("create_state_unavailable", "invalid creation record")
	}
	return raw, nil
}

func creationFileExists(filename string) (bool, error) {
	_, err := os.Lstat(filename)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, bridgeError("create_state_unavailable", "cannot inspect creation state")
	}
	return true, nil
}

func (r *Runner) validateCreateTarget(plan CreateTextPlan) error {
	p := r.config.CreateText
	if p == nil || !p.Enabled {
		return bridgeError("create_disabled", "controlled text creation is not enabled")
	}
	logical, err := r.config.authorizeRemote(plan.Source, plan.Path, writeAccess)
	if err != nil {
		return err
	}
	if _, err = r.config.authorizeRemote(plan.Source, plan.Path, readAccess); err != nil {
		return err
	}
	// First write stage deliberately handles plain UTF-8 .txt files only. It never
	// creates folders or treats content as a local filename/script.
	if plan.Source != p.Source || logical != plan.Path || logical == "/" || path.Ext(logical) != ".txt" ||
		strings.ContainsAny(logical, "%:") || strings.ContainsAny(plan.Content, "\x00") || !utf8.ValidString(plan.Content) ||
		int64(len(plan.Content)) > p.MaxBytes || plan.Bytes != int64(len(plan.Content)) || plan.SHA256 != createHash([]byte(plan.Content)) {
		return bridgeError("invalid_create_input", "creation requires an allowed .txt path and bounded UTF-8 text")
	}
	return nil
}

func (r *Runner) createIdentity(ctx context.Context, requestID string) error {
	identity, err := r.client.capabilities(ctx, requestID)
	if err != nil {
		return err
	}
	p := r.config.CreateText
	okScope := len(identity.Sources) == 1 && identity.Sources[0] == (Scope{Name: p.Source, Scope: p.ServerScope})
	if !identity.CapabilitiesExact || identity.UserID != p.UserID || !okScope || identity.Permissions.Admin ||
		!identity.Permissions.Create || !identity.Permissions.Browse || !identity.Permissions.Download {
		return bridgeError("create_identity_mismatch", "authenticated identity, scope or creation grants differ")
	}
	return nil
}

func planResult(plan CreateTextPlan, digest, state string) CreateTextResult {
	return CreateTextResult{State: state, OperationID: plan.OperationID, PlanSHA256: digest, Source: plan.Source, Path: plan.Path, Bytes: plan.Bytes, SHA256: plan.SHA256, ExpiresUnix: plan.ExpiresUnix}
}

func (r *Runner) planCreateText(ctx context.Context, requestID string, input Input) (CreateTextResult, error) {
	directory, err := r.createDirectory(input.OperationID)
	if err != nil {
		return CreateTextResult{}, err
	}
	if input.Content == nil {
		return CreateTextResult{}, bridgeError("invalid_create_input", "content is required")
	}
	now := r.createNow().Unix()
	plan := CreateTextPlan{Schema: createPlanSchema, OperationID: input.OperationID, Source: input.Source, Path: input.Path, Content: *input.Content,
		Bytes: int64(len(*input.Content)), SHA256: createHash([]byte(*input.Content)), ConfigSHA256: r.createBinding(), CreatedUnix: now, ExpiresUnix: now + int64(r.config.CreateText.ApprovalTTLSeconds)}
	if err = r.validateCreateTarget(plan); err != nil {
		return CreateTextResult{}, err
	}
	if err = r.createIdentity(ctx, requestID); err != nil {
		return CreateTextResult{}, err
	}
	if _, err = r.client.getResource(ctx, requestID, input.Source, input.Path, ""); err == nil {
		return CreateTextResult{}, bridgeError("target_exists", "new file already exists; no overwrite")
	} else if !isErrorCode(err, "not_found") {
		return CreateTextResult{}, err
	}
	// Plan only; no remote writes. Existing IDs are never overwritten, including
	// incomplete plans. A new plan does not authorize its own execution.
	if err = os.Mkdir(directory, 0700); err != nil {
		return CreateTextResult{}, bridgeError("create_record_exists", "operation_id already exists or state cannot be created")
	}
	if err = writeCreateOnce(filepath.Join(directory, "plan.json"), plan); err != nil {
		return CreateTextResult{}, err
	}
	raw, _ := json.Marshal(plan)
	return planResult(plan, createHash(raw), "awaiting_operator_approval"), nil
}

func (r *Runner) loadCreatePlan(input Input) (CreateTextPlan, string, error) {
	var plan CreateTextPlan
	directory, err := r.createDirectory(input.OperationID)
	if err != nil {
		return plan, "", err
	}
	if !createHashPattern.MatchString(input.PlanSHA256) {
		return plan, "", bridgeError("invalid_plan_sha256", "the exact proposed plan_sha256 is required")
	}
	if err = checkCreatePath(directory, true); err != nil {
		return plan, "", err
	}
	raw, err := readCreateJSON(filepath.Join(directory, "plan.json"), &plan)
	if err != nil {
		return plan, "", err
	}
	if createHash(raw) != input.PlanSHA256 || plan.Schema != createPlanSchema || plan.OperationID != input.OperationID || plan.ConfigSHA256 != r.createBinding() ||
		plan.ExpiresUnix-plan.CreatedUnix != int64(r.config.CreateText.ApprovalTTLSeconds) || plan.CreatedUnix > r.createNow().Unix()+5 {
		return plan, "", bridgeError("create_plan_changed", "creation plan, clock or operator configuration changed; do not approve or replay")
	}
	if err = r.validateCreateTarget(plan); err != nil {
		return plan, "", err
	}
	return plan, directory, nil
}

func (r *Runner) approveCreateText(input Input, apply bool) (CreateTextResult, error) {
	plan, directory, err := r.loadCreatePlan(input)
	if err != nil {
		return CreateTextResult{}, err
	}
	if r.createNow().Unix() >= plan.ExpiresUnix {
		return CreateTextResult{}, bridgeError("create_approval_expired", "creation plan has expired")
	}
	result := planResult(plan, input.PlanSHA256, "awaiting_operator_approval")
	if !apply {
		return result, nil
	}
	if exists, err := creationFileExists(filepath.Join(directory, "attempt.json")); err != nil {
		return result, err
	} else if exists {
		return result, bridgeError("create_already_attempted", "an attempt already exists; inspect status without replay")
	}
	if err = writeCreateOnce(filepath.Join(directory, "approval.json"), createApproval{PlanSHA256: input.PlanSHA256, ExpiresUnix: plan.ExpiresUnix}); err != nil {
		return result, err
	}
	result.State = "operator_approved"
	return result, nil
}

func (r *Runner) createTextStatus(input Input) (CreateTextResult, error) {
	plan, directory, err := r.loadCreatePlan(input)
	if err != nil {
		return CreateTextResult{}, err
	}
	result := planResult(plan, input.PlanSHA256, "awaiting_operator_approval")
	for _, name := range []string{"outcome.json", "attempt.json", "approval.json"} {
		exists, e := creationFileExists(filepath.Join(directory, name))
		if e != nil {
			return result, e
		}
		if !exists {
			continue
		}
		if name == "approval.json" {
			var a createApproval
			_, e = readCreateJSON(filepath.Join(directory, name), &a)
			if e != nil {
				return result, e
			}
			if a.PlanSHA256 != input.PlanSHA256 || a.ExpiresUnix != plan.ExpiresUnix {
				return result, bridgeError("create_plan_changed", "approval differs from plan")
			}
			result.State = "operator_approved"
			if r.createNow().Unix() >= plan.ExpiresUnix {
				result.State = "expired"
			}
			return result, nil
		}
		var outcome createOutcome
		_, e = readCreateJSON(filepath.Join(directory, name), &outcome)
		if e != nil {
			return result, e
		}
		if outcome.PlanSHA256 != input.PlanSHA256 || outcome.RequestID == "" {
			return result, bridgeError("create_plan_changed", "attempt differs from plan")
		}
		result.State = outcome.State
		result.OriginalRequestID = outcome.RequestID
		if name == "attempt.json" {
			result.State = "attempted_outcome_unknown"
			return result, nil
		}
		if outcome.State != "succeeded" && outcome.State != "failed" && outcome.State != "outcome_unknown" {
			return result, bridgeError("create_state_unavailable", "invalid terminal state")
		}
		if outcome.State == "succeeded" {
			result.Applied = true
			result.Verified = true
			result.VerificationScope = "at_original_completion_not_current_state"
		}
		return result, nil
	}
	if r.createNow().Unix() >= plan.ExpiresUnix {
		result.State = "expired"
	}
	return result, nil
}

func (r *Runner) applyCreateText(ctx context.Context, requestID string, input Input, apply bool) (CreateTextResult, int64, error) {
	plan, directory, err := r.loadCreatePlan(input)
	if err != nil {
		return CreateTextResult{}, 0, err
	}
	result, err := r.createTextStatus(input)
	if err != nil {
		return result, 0, err
	}
	if !apply {
		return result, 0, nil
	}
	if result.State == "succeeded" {
		if err = r.createIdentity(ctx, requestID); err != nil {
			return result, 0, err
		}
		result.AlreadyDone = true
		return result, 0, nil // Historical receipt, no second POST.
	}
	if result.State != "operator_approved" {
		return result, 0, bridgeError("create_not_approved", "missing approval, expired plan or prior attempt; inspect status, do not replay")
	}
	if r.createNow().Unix() >= plan.ExpiresUnix {
		return result, 0, bridgeError("create_approval_expired", "creation approval has expired")
	}
	if err = r.createIdentity(ctx, requestID); err != nil {
		return result, 0, err
	}
	// A reservation is synced BEFORE any write. Crash/timeout after this point is
	// never an authorization to repeat the POST. Operators reconcile separately.
	reservation := createOutcome{PlanSHA256: input.PlanSHA256, RequestID: requestID, State: "attempted_outcome_unknown"}
	if err = writeCreateOnce(filepath.Join(directory, "attempt.json"), reservation); err != nil {
		return result, 0, err
	}
	mayHaveWritten := false
	writeErr := r.audit.Log(AuditEvent{OperationID: input.OperationID, RequestID: requestID, Command: "create-approved:reserved", Source: plan.Source, Path: plan.Path, Result: "reserved"})
	if writeErr == nil {
		_, writeErr = r.client.getResource(ctx, requestID, plan.Source, plan.Path, "")
		if writeErr == nil {
			writeErr = bridgeError("target_exists", "target exists; no overwrite")
		} else if isErrorCode(writeErr, "not_found") {
			if r.createNow().Unix() >= plan.ExpiresUnix {
				writeErr = bridgeError("create_approval_expired", "approval expired before upload")
			} else {
				mayHaveWritten = true
				writeErr = r.client.uploadNew(ctx, requestID, plan.Source, plan.Path, strings.NewReader(plan.Content), plan.Bytes)
				if isErrorCode(writeErr, "conflict") || isErrorCode(writeErr, "forbidden") || isErrorCode(writeErr, "unauthorized") {
					mayHaveWritten = false
				}
				if writeErr == nil {
					var read ReadResult
					read, _, writeErr = r.read(ctx, requestID, Input{Source: plan.Source, Path: plan.Path})
					if writeErr == nil && (read.Content != plan.Content || read.Bytes != plan.Bytes || read.SHA256 != plan.SHA256) {
						writeErr = bridgeError("verification_failed", "created file did not match approved bytes")
					}
				}
			}
		}
	}
	outcome := reservation
	if writeErr == nil {
		outcome.State = "succeeded"
	} else {
		outcome.State = "outcome_unknown"
		outcome.ErrorCode = errorResponse(writeErr).Code
		// A successful POST followed by failed verification stays uncertain, even
		// when the verification GET is denied. Never label that "no write".
		if !mayHaveWritten {
			outcome.State = "failed"
		}
	}
	if err = writeCreateOnce(filepath.Join(directory, "outcome.json"), outcome); err != nil {
		return result, 0, bridgeError("create_outcome_unknown", "upload may have occurred; preserve journal and inspect without retry")
	}
	if writeErr != nil {
		if outcome.State == "outcome_unknown" {
			return result, 0, bridgeError("create_outcome_unknown", "creation may have occurred; no automatic retry; inspect status and remote file")
		}
		return result, 0, writeErr
	}
	result = planResult(plan, input.PlanSHA256, "succeeded")
	result.Applied = true
	result.Verified = true
	result.OriginalRequestID = requestID
	result.VerificationScope = "at_original_completion_not_current_state"
	return result, plan.Bytes, nil
}
