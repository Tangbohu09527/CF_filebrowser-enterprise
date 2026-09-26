package filebridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCreateTextDisabledByDefault(t *testing.T) {
	cfg := newSecurityTestConfig(t, "https://files.example.test", false, nil)
	r := NewRunner(cfg, NewClient(cfg, testToken), &AuditLogger{writer: discardCreate{}})
	response := r.Run(context.Background(), "create-text", Input{Source: "documents", Path: "/write/a.txt"}, false)
	if response.OK || response.Error == nil || response.Error.Code != "create_disabled" {
		t.Fatalf("default must reject before any request: %+v", response)
	}
}

type discardCreate struct{}

func (discardCreate) Write(p []byte) (int, error) { return len(p), nil }

type createFixture struct {
	r         *Runner
	server    *httptest.Server
	mu        sync.Mutex
	content   string
	exists    bool
	corrupt   bool
	denied    bool
	badScope  bool
	badUser   bool
	badCreate bool
	postCode  int
	readCode  int
	loseReply bool
	posts     int
	calls     int
	audit     bytes.Buffer
}

func newCreateFixture(t *testing.T) *createFixture {
	t.Helper()
	f := &createFixture{}
	ca, cert := trustFixture(t, false)
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		if req.Header.Get("Authorization") == "" {
			t.Error("missing Bearer")
		}
		if f.denied {
			w.WriteHeader(401)
			return
		}
		switch {
		case req.URL.Path == "/api/users":
			id := uint(2)
			if f.badUser {
				id = 3
			}
			scope := "/wechat-acceptance"
			if f.badScope {
				scope = "/"
			}
			writeCommandTestJSON(t, w, map[string]any{"id": id, "username": "synthetic-agent", "permissions": Permissions{Browse: true, Create: !f.badCreate, Download: true}, "scopes": []Scope{{Name: "files", Scope: scope}}})
		case req.URL.Path == "/api/resources" && req.Method == "GET":
			if !f.exists {
				w.WriteHeader(404)
				return
			}
			writeCommandTestJSON(t, w, map[string]any{"name": "new.txt", "type": "file", "size": len(f.content)})
		case req.URL.Path == "/api/resources" && req.Method == "POST":
			f.posts++
			if req.URL.Query().Get("override") != "" || req.URL.Query().Get("isDir") != "" || req.Header.Get("X-File-Chunk-Offset") != "0" {
				t.Error("unsafe create query")
			}
			if f.postCode != 0 {
				w.WriteHeader(f.postCode)
				return
			}
			if f.exists {
				w.WriteHeader(409)
				return
			}
			raw, _ := io.ReadAll(req.Body)
			f.content = string(raw)
			f.exists = true
			if req.ContentLength != int64(len(raw)) || req.Header.Get("X-File-Total-Size") != strconv.Itoa(len(raw)) {
				t.Error("incorrect length")
			}
			if f.loseReply {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
				} else {
					conn.Close()
				}
				return
			}
			w.WriteHeader(200)
		case req.URL.Path == "/api/resources/download" && req.Method == "GET":
			if f.readCode != 0 {
				w.WriteHeader(f.readCode)
				return
			}
			if !f.exists {
				w.WriteHeader(404)
				return
			}
			if f.corrupt {
				io.WriteString(w, "changed-file")
			} else {
				io.WriteString(w, f.content)
			}
		default:
			t.Errorf("unexpected API %s %s", req.Method, req.URL.Path)
			w.WriteHeader(404)
		}
	}))
	f.server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{BaseURL: f.server.URL, TrustOptions: saveTrust(t, ca), AllowedSources: map[string]SourcePolicy{"files": {ReadRoots: []string{"/"}, WriteRoots: []string{"/new.txt"}}}, CreateText: &CreateTextPolicy{Enabled: true, StateDir: state, UserID: 2, Source: "files", ServerScope: "/wechat-acceptance"}}
	if err := cfg.applyDefaultsAndValidate(false); err != nil {
		t.Fatal(err)
	}
	token := commandTestToken(t, map[string]any{"name": "test", "belongsTo": 2, "permissionsVersion": 4, "Permissions": Permissions{Browse: true, Create: true, Download: true}})
	f.r = NewRunner(cfg, NewClient(cfg, token), &AuditLogger{writer: &f.audit})
	return f
}
func (f *createFixture) do(t *testing.T, command string, input Input, apply bool) Response {
	t.Helper()
	return f.r.Run(context.Background(), command, input, apply)
}
func (f *createFixture) plan(t *testing.T) Input {
	t.Helper()
	content := "中文验收\nnew file only\n"
	response := f.do(t, "create-text", Input{Source: "files", Path: "/new.txt", Content: &content}, false)
	if !response.OK {
		t.Fatalf("plan error: %+v", response.Error)
	}
	plan := response.Result.(CreateTextResult)
	if plan.State != "awaiting_operator_approval" || plan.Bytes != int64(len(content)) || plan.Applied || !response.DryRun {
		t.Fatalf("bad plan: %+v", plan)
	}
	return Input{OperationID: response.OperationID, PlanSHA256: plan.PlanSHA256}
}
func (f *createFixture) approve(t *testing.T, input Input) {
	t.Helper()
	response := f.do(t, "approve-create", input, true)
	if !response.OK {
		t.Fatalf("approve error: %+v", response.Error)
	}
}
func assertCreateError(t *testing.T, response Response, code string) {
	t.Helper()
	if response.OK || response.Error == nil || response.Error.Code != code {
		t.Fatalf("want %s got %+v", code, response)
	}
}

func TestCreateTextLifecycleTLS(t *testing.T) {
	f := newCreateFixture(t)
	input := f.plan(t)
	if f.posts != 0 {
		t.Fatal("plan posted")
	}
	assertCreateError(t, f.do(t, "create-approved", input, true), "create_not_approved")
	if f.posts != 0 {
		t.Fatal("unapproved plan posted")
	}
	// approve without --apply is a preview, not approval.
	if !f.do(t, "approve-create", input, false).OK {
		t.Fatal("operator preview failed")
	}
	assertCreateError(t, f.do(t, "create-approved", input, true), "create_not_approved")
	f.approve(t, input)
	dry := f.do(t, "create-approved", input, false)
	if !dry.OK || f.posts != 0 {
		t.Fatal("dry apply posted")
	}
	got := f.do(t, "create-approved", input, true)
	if !got.OK {
		t.Fatalf("apply: %+v", got.Error)
	}
	receipt := got.Result.(CreateTextResult)
	if f.posts != 1 || !receipt.Applied || !receipt.Verified || receipt.AlreadyDone || !strings.Contains(f.content, "中文验收") {
		t.Fatalf("bad result: %+v", receipt)
	}
	// Repeat returns an explicit historical receipt. It does not read or recreate
	// a subsequently changed file, and must not claim its current state.
	f.content = "changed later"
	again := f.do(t, "create-approved", input, true)
	if !again.OK || !again.Result.(CreateTextResult).AlreadyDone || f.posts != 1 {
		t.Fatal("duplicate creation")
	}
	if !strings.Contains(again.Result.(CreateTextResult).VerificationScope, "not_current_state") {
		t.Fatal("historical result ambiguously labelled")
	}
	state := f.do(t, "create-status", input, false)
	if !state.OK || state.Result.(CreateTextResult).State != "succeeded" {
		t.Fatal("status did not retain receipt")
	}
	if strings.Contains(f.audit.String(), "中文验收") || strings.Contains(f.audit.String(), f.r.client.token) {
		t.Fatal("audit leaked contents/credential")
	}
}

func TestCreateTextRefusals(t *testing.T) {
	for _, kind := range []string{"missing-content", "traversal", "other-source", "outside-root", "wrong-extension", "nul", "too-large", "missing-approval", "bad-plan", "changed-plan", "changed-config", "expired", "wrong-user", "wide-scope", "no-create", "revoked", "existing", "created-after-plan", "no-reapproval"} {
		t.Run(kind, func(t *testing.T) {
			f := newCreateFixture(t)
			input := Input{}
			switch kind {
			case "missing-content", "traversal", "other-source", "outside-root", "wrong-extension", "nul", "too-large":
				text := "okay"
				in := Input{Source: "files", Path: "/new.txt", Content: &text}
				switch kind {
				case "missing-content":
					in.Content = nil
				case "traversal":
					in.Path = "/../new.txt"
				case "other-source":
					in.Source = "other"
				case "outside-root":
					in.Path = "/other.txt"
				case "wrong-extension":
					in.Path = "/new.txt/test.exe"
				case "nul":
					text = "a\x00b"
				case "too-large":
					text = strings.Repeat("x", 65537)
				}
				if r := f.do(t, "create-text", in, false); r.OK {
					t.Fatal("invalid plan accepted")
				}
				if f.posts != 0 {
					t.Fatal("invalid plan posted")
				}
				return
			case "existing":
				f.exists = true
				text := "new"
				assertCreateError(t, f.do(t, "create-text", Input{Source: "files", Path: "/new.txt", Content: &text}, false), "target_exists")
				return
			}
			input = f.plan(t)
			if kind == "missing-approval" {
				assertCreateError(t, f.do(t, "create-approved", input, true), "create_not_approved")
				return
			}
			f.approve(t, input)
			switch kind {
			case "bad-plan":
				input.PlanSHA256 = strings.Repeat("0", 64)
			case "changed-plan":
				p := filepath.Join(f.r.config.CreateText.StateDir, input.OperationID, "plan.json")
				raw, _ := os.ReadFile(p)
				os.WriteFile(p, append(raw, ' '), 0600)
			case "changed-config":
				f.r.config.BaseURL += "/changed"
			case "expired":
				f.r.createClock = func() time.Time { return time.Now().Add(time.Hour) }
			case "wrong-user":
				f.badUser = true
			case "wide-scope":
				f.badScope = true
			case "no-create":
				f.badCreate = true
			case "revoked":
				f.denied = true
			case "created-after-plan":
				f.exists = true
				f.content = "existing untouched"
			case "no-reapproval":
				assertCreateError(t, f.do(t, "approve-create", input, true), "create_record_exists")
				return
			}
			response := f.do(t, "create-approved", input, true)
			if response.OK {
				t.Fatal("unsafe apply accepted")
			}
			if f.posts != 0 {
				t.Fatal("refusal posted")
			}
			if kind == "created-after-plan" && f.content != "existing untouched" {
				t.Fatal("changed existing content")
			}
		})
	}
}

func TestCreateTextUnknownAndFailedNeverReplay(t *testing.T) {
	for _, kind := range []string{"lost-response", "mismatch", "500", "429", "403", "401", "409", "partial-attempt", "audit-unavailable", "readback-401", "readback-403"} {
		t.Run(kind, func(t *testing.T) {
			f := newCreateFixture(t)
			input := f.plan(t)
			f.approve(t, input)
			switch kind {
			case "lost-response":
				f.loseReply = true
			case "readback-401":
				f.readCode = 401
			case "readback-403":
				f.readCode = 403
			case "mismatch":
				f.corrupt = true
			case "500":
				f.postCode = 500
			case "429":
				f.postCode = 429
			case "403":
				f.postCode = 403
			case "401":
				f.postCode = 401
			case "409":
				f.postCode = 409
			case "partial-attempt":
				os.WriteFile(filepath.Join(f.r.config.CreateText.StateDir, input.OperationID, "attempt.json"), []byte("{"), 0600)
			case "audit-unavailable":
				f.r.audit = &AuditLogger{writer: failingCreateWriter{}}
			}
			response := f.do(t, "create-approved", input, true)
			if response.OK {
				t.Fatal("failed/unknown apply succeeded")
			}
			if strings.HasPrefix(kind, "readback-") {
				assertCreateError(t, response, "create_outcome_unknown")
				state := f.do(t, "create-status", input, false)
				if !state.OK || state.Result.(CreateTextResult).State != "outcome_unknown" || !f.exists {
					t.Fatal("accepted upload plus rejected readback must remain uncertain")
				}
			}
			count := f.posts
			again := f.do(t, "create-approved", input, true)
			if again.OK || f.posts != count || f.posts > 1 {
				t.Fatal("failed request replayed")
			}
			if (kind == "partial-attempt" || kind == "audit-unavailable") && f.posts != 0 {
				t.Fatal("unreserved/unauditable write")
			}
		})
	}
}

type failingCreateWriter struct{}

func (failingCreateWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestCreateTextSingleClaimConcurrent(t *testing.T) {
	f := newCreateFixture(t)
	in := f.plan(t)
	f.approve(t, in)
	var group sync.WaitGroup
	results := make(chan Response, 12)
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func() { defer group.Done(); results <- f.do(t, "create-approved", in, true) }()
	}
	group.Wait()
	close(results)
	n := 0
	for result := range results {
		if result.OK {
			n++
		}
	}
	if n == 0 || f.posts != 1 {
		t.Fatalf("success=%d posts=%d", n, f.posts)
	}
}

func TestCreateTextStateAndInputBoundary(t *testing.T) {
	for _, kind := range []string{"approval-symlink", "plan-symlink", "state-symlink", "invalid-id", "extra-content-on-apply", "plan-with-apply", "approve-no-id", "invalid-state-mode"} {
		t.Run(kind, func(t *testing.T) {
			f := newCreateFixture(t)
			in := f.plan(t)
			f.approve(t, in)
			cmd := "create-approved"
			apply := true
			switch kind {
			case "invalid-id":
				in.OperationID = "../outside"
			case "extra-content-on-apply":
				text := "evil"
				in.Content = &text
			case "plan-with-apply":
				cmd = "create-text"
				in = Input{Source: "files", Path: "/new.txt", Content: new(string)}
			case "approve-no-id":
				cmd = "approve-create"
				in.OperationID = ""
			case "invalid-state-mode":
				if runtime.GOOS == "windows" {
					t.Skip("NTFS ACL checked by installer")
				}
				os.Chmod(f.r.config.CreateText.StateDir, 0755)
			default:
				target := filepath.Join(f.r.config.CreateText.StateDir, in.OperationID, "approval.json")
				if kind == "plan-symlink" {
					target = filepath.Join(f.r.config.CreateText.StateDir, in.OperationID, "plan.json")
				}
				if kind == "state-symlink" {
					target = f.r.config.CreateText.StateDir
				}
				original := target + "-original"
				if err := os.Rename(target, original); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(original, target); err != nil {
					t.Skip("OS does not permit symlink")
				}
			}
			response := f.do(t, cmd, in, apply)
			if response.OK || f.posts != 0 {
				t.Fatal("unsafe state/input accepted")
			}
		})
	}
}

// Exercise the actual JSON stdin CLI contract, not only direct Runner methods.
func TestCreateTextCLIContract(t *testing.T) {
	f := newCreateFixture(t)
	root := t.TempDir()
	tokenFile := filepath.Join(root, "token")
	if err := os.WriteFile(tokenFile, []byte(f.r.client.token), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := *f.r.config
	cfg.TokenFile = tokenFile
	cfg.AuditLog = filepath.Join(root, "audit.jsonl")
	raw, err := json.Marshal(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(root, "create-config.json")
	if err := os.WriteFile(configFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	call := func(command string, input Input, apply bool) Response {
		t.Helper()
		payload, e := json.Marshal(input)
		if e != nil {
			t.Fatal(e)
		}
		args := []string{"--config", configFile, "--input", "-", command}
		if apply {
			args = append(args, "--apply")
		}
		var out, logs bytes.Buffer
		rc := RunCLI(context.Background(), args, bytes.NewReader(payload), &out, &logs)
		var response Response
		if e = json.Unmarshal(out.Bytes(), &response); e != nil {
			t.Fatal(e)
		}
		if (rc == 0) != response.OK {
			t.Fatalf("exit/response mismatch: %d", rc)
		}
		if bytes.Contains(out.Bytes(), []byte(f.r.client.token)) || bytes.Contains(logs.Bytes(), []byte(f.r.client.token)) {
			t.Fatal("credential exposed")
		}
		return response
	}
	text := "new CLI text\n"
	plan := call("create-text", Input{Source: "files", Path: "/new.txt", Content: &text}, false)
	if !plan.OK || f.posts != 0 {
		t.Fatalf("CLI plan failed: %+v", plan.Error)
	}
	result, ok := plan.Result.(map[string]any)
	if !ok {
		t.Fatal("plan result type")
	}
	digest, ok := result["plan_sha256"].(string)
	if !ok {
		t.Fatal("plan digest missing")
	}
	in := Input{OperationID: plan.OperationID, PlanSHA256: digest}
	assertCreateError(t, call("create-approved", in, true), "create_not_approved")
	if !call("approve-create", in, true).OK {
		t.Fatal("CLI approval failed")
	}
	created := call("create-approved", in, true)
	if !created.OK || f.posts != 1 || f.content != text {
		t.Fatalf("CLI create failed: %+v", created.Error)
	}
	if !call("create-approved", in, true).OK || f.posts != 1 {
		t.Fatal("CLI repeat posted")
	}
	if !call("create-status", in, false).OK {
		t.Fatal("CLI status failed")
	}
}
