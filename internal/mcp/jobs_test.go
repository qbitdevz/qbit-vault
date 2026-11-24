package mcp

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/qbitdevz/qbit-vault/internal/broker"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
)

// script plays the child process of one job: it writes the output the real
// runner would hand over already redacted, and answers how the run ended.
type script func(ctx context.Context, out, errw io.Writer, onStart func()) broker.ExecOutcome

type starter struct {
	fake
	mu       sync.Mutex
	queue    []script
	prepErr  error
	prepared atomic.Int32
	closed   atomic.Int32
}

func (s *starter) PrepareExec(_ context.Context, e broker.Envelope, r broker.ExecRequest) (broker.PreparedExec, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.env, s.exec = e, r
	if s.prepErr != nil {
		return nil, s.prepErr
	}
	s.prepared.Add(1)
	var sc script
	if len(s.queue) > 0 {
		sc, s.queue = s.queue[0], s.queue[1:]
	} else {
		sc = idle(nil)
	}
	return &preparedRun{s: s, run: sc}, nil
}

func (s *starter) enqueue(sc ...script) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue = append(s.queue, sc...)
}

type preparedRun struct {
	s   *starter
	run script
}

func (p *preparedRun) Run(ctx context.Context, out, errw io.Writer, onStart func()) broker.ExecOutcome {
	return p.run(ctx, out, errw, onStart)
}
func (p *preparedRun) Close() { p.s.closed.Add(1) }

// idle runs until release is closed (exit 0) or its context ends (stopped).
func idle(release <-chan struct{}) script {
	return func(ctx context.Context, _, _ io.Writer, onStart func()) broker.ExecOutcome {
		onStart()
		select {
		case <-release:
			return broker.ExecOutcome{Started: true, ExitCode: 0, Duration: time.Millisecond}
		case <-ctx.Done():
			return broker.ExecOutcome{Started: true, ExitCode: 137, Interrupted: true, Duration: time.Millisecond}
		}
	}
}

// steps writes each chunk to stdout when its gate (if any) is closed.
func steps(chunks ...step) script {
	return func(ctx context.Context, out, errw io.Writer, onStart func()) broker.ExecOutcome {
		onStart()
		for _, c := range chunks {
			if c.gate != nil {
				select {
				case <-c.gate:
				case <-ctx.Done():
					return broker.ExecOutcome{Started: true, ExitCode: 137, Interrupted: true}
				}
			}
			w := out
			if c.stderr {
				w = errw
			}
			_, _ = w.Write([]byte(c.text))
		}
		return broker.ExecOutcome{Started: true, ExitCode: 0, Duration: 5 * time.Millisecond}
	}
}

type step struct {
	text   string
	stderr bool
	gate   <-chan struct{}
}

func connectJobs(t *testing.T, b broker.Backend) (*sdk.ClientSession, *Jobs) {
	t.Helper()
	jobs := NewJobs(b)
	t.Cleanup(jobs.Shutdown)
	srv := NewServer(jobs, Options{Session: "claude:sess1234", Cwd: func() (string, error) { return filepath.Abs(".") }, Version: "test"})
	return connectServer(t, srv), jobs
}

func connectServer(t *testing.T, srv *sdk.Server) *sdk.ClientSession {
	t.Helper()
	ctx := context.Background()
	st, ct := sdk.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

var execArgs = map[string]any{"command": "sleep 1", "secrets": []any{map[string]any{"name": "A"}}}

var jobID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func start(t *testing.T, cs *sdk.ClientSession) string {
	t.Helper()
	m, isErr := callJSON(t, cs, "secret_exec_start", execArgs)
	if isErr || m["ok"] != true {
		t.Fatalf("start: %v", m)
	}
	id, _ := m["job"].(string)
	if !jobID.MatchString(id) {
		t.Fatalf("job id %q is not 128 random bits as hex", id)
	}
	return id
}

func status(t *testing.T, cs *sdk.ClientSession, id string, waitMS int) map[string]any {
	t.Helper()
	m, _ := callJSON(t, cs, "secret_exec_status", map[string]any{"job": id, "wait_ms": waitMS})
	return m
}

func refusalOf(m map[string]any) map[string]any {
	r, _ := m["refusal"].(map[string]any)
	return r
}

func TestSevenToolsWithTheirContractDescriptions(t *testing.T) {
	cs, _ := connectJobs(t, &starter{})
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tool := range res.Tools {
		got[tool.Name] = true
		if tool.Description != ToolDescriptions[tool.Name] {
			t.Errorf("%s description drifted", tool.Name)
		}
	}
	for _, want := range []string{"secret_request", "secret_list", "secret_exec", "secret_manage", "secret_exec_start", "secret_exec_status", "secret_exec_stop"} {
		if !got[want] {
			t.Errorf("tools/list has no %s", want)
		}
	}
	if len(got) != 7 {
		t.Errorf("tools = %v, want exactly seven", got)
	}
}

// Rule 1: start returns as soon as the command has started.
func TestStartReturnsBeforeTheCommandEnds(t *testing.T) {
	s := &starter{}
	release := make(chan struct{})
	s.enqueue(idle(release))
	cs, _ := connectJobs(t, s)
	began := time.Now()
	id := start(t, cs)
	if time.Since(began) > 2*time.Second {
		t.Fatal("start waited for the command")
	}
	if m := status(t, cs, id, 0); m["state"] != "running" || m["exit_code"] != nil {
		t.Fatalf("status = %v", m)
	}
	close(release)
	m := status(t, cs, id, 5000)
	if m["state"] != "exited" || m["exit_code"] != float64(0) {
		t.Fatalf("final status = %v", m)
	}
}

// start takes exactly the input of secret_exec, and the backend receives the same request.
func TestStartTakesTheInputOfExec(t *testing.T) {
	s := &starter{}
	cs, _ := connectJobs(t, s)
	m, _ := callJSON(t, cs, "secret_exec_start", map[string]any{
		"command": "make deploy", "secrets": []any{map[string]any{"name": "TOKEN", "from": "A"}}, "timeout_ms": 5000, "shell": "bash", "locale": "es-ES"})
	if m["ok"] != true {
		t.Fatalf("start = %v", m)
	}
	r := s.exec
	if r.Command != "make deploy" || r.TimeoutMS != 5000 || r.Shell != "bash" || len(r.Secrets) != 1 || r.Secrets[0].Name != "TOKEN" || r.Secrets[0].From != "A" {
		t.Fatalf("request = %+v", r)
	}
	if s.env.Op != "exec_start" || s.env.Locale != "es-ES" || s.env.Session != "claude:sess1234" {
		t.Fatalf("envelope = %+v", s.env)
	}
}

// Rule 1: a long poll returns early when the job ends and otherwise within wait_ms.
func TestStatusLongPollReturnsEarlyOnExitAndWithinWaitMS(t *testing.T) {
	s := &starter{}
	release := make(chan struct{})
	s.enqueue(idle(release))
	cs, _ := connectJobs(t, s)
	id := start(t, cs)

	began := time.Now()
	m := status(t, cs, id, 400)
	took := time.Since(began)
	if m["state"] != "running" || took < 350*time.Millisecond || took > 3*time.Second {
		t.Fatalf("state=%v after %v, want running after about 400 ms", m["state"], took)
	}

	time.AfterFunc(150*time.Millisecond, func() { close(release) })
	began = time.Now()
	m = status(t, cs, id, 50000)
	if m["state"] != "exited" || time.Since(began) > 5*time.Second {
		t.Fatalf("state=%v after %v: the poll did not return when the job ended", m["state"], time.Since(began))
	}
}

// Rule 1: output is incremental, nothing is lost or repeated.
func TestStatusReturnsEachOutputOnce(t *testing.T) {
	s := &starter{}
	g1, g2 := make(chan struct{}), make(chan struct{})
	s.enqueue(steps(step{text: "one\n"}, step{text: "oops\n", stderr: true}, step{text: "two\n", gate: g1}, step{text: "three\n", gate: g2}))
	cs, _ := connectJobs(t, s)
	id := start(t, cs)
	time.Sleep(100 * time.Millisecond)

	m := status(t, cs, id, 0)
	if m["stdout"] != "one\n" || m["stderr"] != "oops\n" {
		t.Fatalf("first = %v", m)
	}
	if m := status(t, cs, id, 0); m["stdout"] != "" || m["stderr"] != "" || m["state"] != "running" {
		t.Fatalf("a second call repeated output: %v", m)
	}
	close(g1)
	time.Sleep(100 * time.Millisecond)
	if m := status(t, cs, id, 0); m["stdout"] != "two\n" {
		t.Fatalf("second = %v", m)
	}
	close(g2)
	m = status(t, cs, id, 5000)
	if m["stdout"] != "three\n" || m["state"] != "exited" {
		t.Fatalf("last = %v", m)
	}
}

// Rule 1: the final state of exit, timeout and stop.
func TestFinalStates(t *testing.T) {
	s := &starter{}
	stopped := make(chan struct{})
	s.enqueue(
		func(_ context.Context, _, _ io.Writer, onStart func()) broker.ExecOutcome {
			onStart()
			return broker.ExecOutcome{Started: true, ExitCode: 3, Duration: 7 * time.Millisecond}
		},
		func(_ context.Context, out, _ io.Writer, onStart func()) broker.ExecOutcome {
			onStart()
			_, _ = out.Write([]byte("partial"))
			return broker.ExecOutcome{Started: true, ExitCode: 137, TimedOut: true, Duration: time.Second}
		},
		idle(stopped),
	)
	cs, _ := connectJobs(t, s)

	id := start(t, cs)
	m := status(t, cs, id, 5000)
	if m["state"] != "exited" || m["exit_code"] != float64(3) || m["duration_ms"] == nil {
		t.Fatalf("exit: %v", m)
	}

	id = start(t, cs)
	m = status(t, cs, id, 5000)
	if m["state"] != "timed_out" || m["stdout"] != "partial" {
		t.Fatalf("timeout: %v", m)
	}

	id = start(t, cs)
	m, isErr := callJSON(t, cs, "secret_exec_stop", map[string]any{"job": id})
	if isErr || m["state"] != "stopped" {
		t.Fatalf("stop: %v", m)
	}
}

// Stopping a finished job is a no-op that returns its final state, once.
func TestStopOfAFinishedJobReturnsItsFinalState(t *testing.T) {
	s := &starter{}
	s.enqueue(steps(step{text: "done\n"}))
	cs, _ := connectJobs(t, s)
	id := start(t, cs)
	time.Sleep(100 * time.Millisecond)
	m, isErr := callJSON(t, cs, "secret_exec_stop", map[string]any{"job": id})
	if isErr || m["state"] != "exited" || m["stdout"] != "done\n" || m["exit_code"] != float64(0) {
		t.Fatalf("stop of a finished job: %v", m)
	}
	if again, _ := callJSON(t, cs, "secret_exec_stop", map[string]any{"job": id}); refusalOf(again) == nil {
		t.Fatalf("the final state was reported twice: %v", again)
	}
}

// Rule 7: a status call the client cancels does not kill the job, and its output is not lost.
func TestACancelledStatusCallDoesNotKillTheJob(t *testing.T) {
	s := &starter{}
	g := make(chan struct{})
	s.enqueue(steps(step{text: "before\n"}, step{text: "after\n", gate: g}))
	cs, _ := connectJobs(t, s)
	id := start(t, cs)
	time.Sleep(100 * time.Millisecond)

	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		_, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "secret_exec_status", Arguments: map[string]any{"job": id, "wait_ms": 50000}})
		cancel()
		if err == nil {
			t.Fatal("the long poll ended before the client gave up")
		}
	}
	time.Sleep(100 * time.Millisecond) // let the server see the cancellations
	m := status(t, cs, id, 0)
	if m["state"] != "running" {
		t.Fatalf("a cancelled status call ended the job: %v", m)
	}
	if m["stdout"] != "before\n" {
		t.Fatalf("output lost by the cancelled calls: %v", m)
	}
	close(g)
	if m := status(t, cs, id, 5000); m["stdout"] != "after\n" || m["state"] != "exited" {
		t.Fatalf("job did not survive: %v", m)
	}
}

// Rule 3: at most four jobs run at once per server.
func TestTheFifthRunningJobIsRefused(t *testing.T) {
	s := &starter{}
	cs, _ := connectJobs(t, s)
	var ids []string
	for i := 0; i < MaxRunningJobs; i++ {
		ids = append(ids, start(t, cs))
	}
	m, isErr := callJSON(t, cs, "secret_exec_start", execArgs)
	r := refusalOf(m)
	if !isErr || r == nil || r["retryable"] != true || r["hint"] != refusal.HintJobsBusy {
		t.Fatalf("fifth start = %v", m)
	}
	if s.prepared.Load() != int32(MaxRunningJobs) {
		t.Fatalf("the refused start reached the backend (%d prepared)", s.prepared.Load())
	}
	if m, _ := callJSON(t, cs, "secret_exec_stop", map[string]any{"job": ids[0]}); m["state"] != "stopped" {
		t.Fatalf("stop = %v", m)
	}
	start(t, cs) // a slot is free again
}

// A start that is refused before a process exists keeps no slot, and is the backend's refusal.
func TestARefusedStartTakesNoSlotAndIsTheBackendsRefusal(t *testing.T) {
	s := &starter{prepErr: refusal.New(refusal.GrantRequired, "A")}
	cs, _ := connectJobs(t, s)
	for i := 0; i < MaxRunningJobs+2; i++ {
		m, isErr := callJSON(t, cs, "secret_exec_start", execArgs)
		r := refusalOf(m)
		if !isErr || r == nil || r["type"] != "grant_required" || r["name"] != "A" || r["hint"] != refusal.New(refusal.GrantRequired, "A").Hint {
			t.Fatalf("start = %v", m)
		}
	}
	s.mu.Lock()
	s.prepErr = nil
	s.mu.Unlock()
	start(t, cs)
}

// A command that cannot start is an internal refusal and spends nothing.
func TestACommandThatCannotStartIsRefused(t *testing.T) {
	s := &starter{}
	s.enqueue(func(context.Context, io.Writer, io.Writer, func()) broker.ExecOutcome {
		return broker.ExecOutcome{Started: false, Failed: true}
	})
	cs, _ := connectJobs(t, s)
	m, isErr := callJSON(t, cs, "secret_exec_start", execArgs)
	if r := refusalOf(m); !isErr || r == nil || r["type"] != "internal" {
		t.Fatalf("start = %v", m)
	}
	if s.closed.Load() != 1 {
		t.Fatalf("closed = %d: the prepared exec was not released", s.closed.Load())
	}
	start(t, cs)
}

// Rule 2: an unknown, malformed, finished-and-reported or foreign id is a typed refusal with a fixed hint.
func TestUnknownJobsAreRefused(t *testing.T) {
	s := &starter{}
	s.enqueue(steps(step{text: "x"}))
	jobs := NewJobs(s)
	t.Cleanup(jobs.Shutdown)
	srv := NewServer(jobs, Options{Session: "claude:sess1234", Cwd: func() (string, error) { return filepath.Abs(".") }, Version: "test"})
	cs, other := connectServer(t, srv), connectServer(t, srv)
	id := start(t, cs)
	time.Sleep(100 * time.Millisecond)

	for name, call := range map[string]func() map[string]any{
		"never existed": func() map[string]any { return status(t, cs, strings.Repeat("ab", 16), 0) },
		"other session": func() map[string]any { return status(t, other, id, 0) },
		"stop foreign": func() map[string]any {
			m, _ := callJSON(t, other, "secret_exec_stop", map[string]any{"job": id})
			return m
		},
	} {
		r := refusalOf(call())
		if r == nil || r["type"] != "internal" || r["hint"] != refusal.HintUnknownJob || r["message"] != "no such job" {
			t.Errorf("%s: refusal = %v", name, r)
		}
	}
	// The owner still has it, with the output the intruder could not take.
	if m := status(t, cs, id, 5000); m["state"] != "exited" || m["stdout"] != "x" {
		t.Fatalf("owner = %v", m)
	}
	// Once the final state is reported the job is gone.
	if r := refusalOf(status(t, cs, id, 0)); r == nil || r["hint"] != refusal.HintUnknownJob {
		t.Fatalf("a reported job is still there: %v", r)
	}
	// A malformed id never reaches the registry: the tool boundary names the field.
	for _, bad := range []string{"", "xyz", strings.Repeat("A", 32), strings.Repeat("a", 31)} {
		res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "secret_exec_status", Arguments: map[string]any{"job": bad}})
		if err != nil {
			t.Fatal(err)
		}
		text := ""
		if len(res.Content) == 1 {
			text = res.Content[0].(*sdk.TextContent).Text
		}
		if !res.IsError || !strings.Contains(text, "job") {
			t.Errorf("job %q: IsError=%v %q", bad, res.IsError, text)
		}
	}
}

// The broker keeps its own refusal for a malformed id, for other transports.
func TestTheBrokerRefusesAMalformedJobID(t *testing.T) {
	jobs := NewJobs(&starter{})
	t.Cleanup(jobs.Shutdown)
	env := func(op, extra string) []byte {
		return []byte(`{"contract":"` + broker.Contract + `","op":"` + op + `","v":1,"session":"claude:sess1234","cwd":"` + filepath.ToSlash(t.TempDir()) + `"` + extra + `}`)
	}
	for _, c := range []struct{ op, extra string }{
		{"exec_status", `,"job":"xyz"`}, {"exec_status", `,"job":"` + strings.Repeat("a", 32) + `","wait_ms":50001`},
		{"exec_status", `,"job":"` + strings.Repeat("a", 32) + `","wait_ms":-1`}, {"exec_stop", `,"job":"` + strings.Repeat("a", 32) + `","wait_ms":5`},
		{"exec_stop", ``}, {"exec_start", `,"command":"x"`},
	} {
		var m map[string]any
		_ = json.Unmarshal(broker.Handle(context.Background(), env(c.op, c.extra), jobs, broker.TransportModel), &m)
		r := refusalOf(m)
		if m["ok"] != false || r == nil || r["hint"] != refusal.HintBadRequest {
			t.Errorf("%s %s: %v", c.op, c.extra, m)
		}
	}
}

// The wait is bounded by the wire contract.
func TestWaitMSIsBounded(t *testing.T) {
	cs, _ := connectJobs(t, &starter{})
	id := start(t, cs)
	for _, bad := range []any{-1, 50001, 1.5} {
		res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "secret_exec_status", Arguments: map[string]any{"job": id, "wait_ms": bad}})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Errorf("wait_ms %v was accepted", bad)
		}
	}
}

// Rule 3: unread output and the final state are kept for the retention time, then dropped.
func TestAFinishedJobIsDroppedAfterTheRetention(t *testing.T) {
	old := JobRetention
	JobRetention = 150 * time.Millisecond
	t.Cleanup(func() { JobRetention = old })
	s := &starter{}
	s.enqueue(steps(step{text: "kept\n"}), steps(step{text: "kept\n"}))
	cs, jobs := connectJobs(t, s)
	a, b := start(t, cs), start(t, cs)
	time.Sleep(60 * time.Millisecond)
	if m := status(t, cs, a, 0); m["stdout"] != "kept\n" || m["state"] != "exited" {
		t.Fatalf("before the retention ends: %v", m)
	}
	time.Sleep(500 * time.Millisecond)
	if r := refusalOf(status(t, cs, b, 0)); r == nil || r["hint"] != refusal.HintUnknownJob {
		t.Fatalf("the unread job outlived its retention: %v", r)
	}
	if n := jobs.Held(); n != 0 {
		t.Fatalf("%d jobs still held", n)
	}
}

// A finished job frees its slot at once, whether or not anyone read it.
func TestAFinishedJobFreesItsSlot(t *testing.T) {
	s := &starter{}
	for i := 0; i < MaxRunningJobs; i++ {
		s.enqueue(steps(step{text: "x"}))
	}
	cs, _ := connectJobs(t, s)
	for i := 0; i < MaxRunningJobs; i++ {
		start(t, cs)
	}
	time.Sleep(100 * time.Millisecond)
	start(t, cs)
}

// Rule 2: the server ending ends every job; none outlives it, and no goroutine stays.
func TestShutdownStopsEveryJobAndLeavesNothingRunning(t *testing.T) {
	before := runtime.NumGoroutine()
	s := &starter{}
	ended := make(chan struct{}, 4)
	var wrap = func(sc script) script {
		return func(ctx context.Context, o, e io.Writer, on func()) broker.ExecOutcome {
			out := sc(ctx, o, e, on)
			ended <- struct{}{}
			return out
		}
	}
	for i := 0; i < 3; i++ {
		s.enqueue(wrap(idle(nil)))
	}
	jobs := NewJobs(s)
	srv := NewServer(jobs, Options{Session: "claude:sess1234", Cwd: func() (string, error) { return filepath.Abs(".") }, Version: "test"})
	cs := connectServer(t, srv)
	for i := 0; i < 3; i++ {
		start(t, cs)
	}
	jobs.Shutdown()
	for i := 0; i < 3; i++ {
		select {
		case <-ended:
		default:
			t.Fatalf("Shutdown returned with %d jobs still running", 3-i)
		}
	}
	if s.closed.Load() != 3 {
		t.Fatalf("closed = %d", s.closed.Load())
	}
	m, _ := callJSON(t, cs, "secret_exec_start", execArgs)
	if refusalOf(m) == nil {
		t.Fatalf("a stopped server started a job: %v", m)
	}
	jobs.Shutdown() // idempotent
	_ = cs.Close()
	waitGoroutines(t, before)
}

// A client that goes away takes its jobs with it.
func TestTheEndOfASessionStopsItsJobs(t *testing.T) {
	s := &starter{}
	ended := make(chan struct{}, 1)
	s.enqueue(func(ctx context.Context, o, e io.Writer, on func()) broker.ExecOutcome {
		out := idle(nil)(ctx, o, e, on)
		ended <- struct{}{}
		return out
	})
	cs, _ := connectJobs(t, s)
	start(t, cs)
	_ = cs.Close()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the job outlived its session")
	}
}

// No goroutine stays behind when jobs end, are stopped or are dropped.
func TestNoGoroutineStaysAfterJobsEnd(t *testing.T) {
	before := runtime.NumGoroutine()
	s := &starter{}
	release := make(chan struct{})
	s.enqueue(idle(release), idle(nil), steps(step{text: "x"}))
	cs, jobs := connectJobs(t, s)
	a, b, c := start(t, cs), start(t, cs), start(t, cs)
	close(release)
	status(t, cs, a, 5000)
	callJSON(t, cs, "secret_exec_stop", map[string]any{"job": b})
	status(t, cs, c, 5000)
	if n := jobs.Held(); n != 0 {
		t.Fatalf("%d jobs still held", n)
	}
	_ = cs.Close()
	jobs.Shutdown()
	waitGoroutines(t, before)
}

func waitGoroutines(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		buf := make([]byte, 1<<16)
		t.Fatalf("goroutines: %d before, %d after\n%s", before, n, buf[:runtime.Stack(buf, true)])
	}
}

// Redacted output arrives with its replacement count, per status call.
func TestRedactionsAndTruncationAreReportedPerCall(t *testing.T) {
	s := &starter{}
	g := make(chan struct{})
	s.enqueue(func(ctx context.Context, out, _ io.Writer, on func()) broker.ExecOutcome {
		on()
		cw := out.(interface {
			WriteCounted([]byte, int) (int, error)
		})
		_, _ = cw.WriteCounted([]byte("[REDACTED:A] and [REDACTED:A]\n"), 2)
		<-g
		_, _ = cw.WriteCounted([]byte("[REDACTED:A]\n"), 1)
		big := make([]byte, 3<<20)
		for i := range big {
			big[i] = 'x'
		}
		_, _ = out.Write(big)
		return broker.ExecOutcome{Started: true}
	})
	cs, _ := connectJobs(t, s)
	id := start(t, cs)
	time.Sleep(100 * time.Millisecond)
	if m := status(t, cs, id, 0); m["redactions"] != float64(2) || m["truncated"] != false {
		t.Fatalf("first = %v", m)
	}
	close(g)
	m := status(t, cs, id, 5000)
	if m["redactions"] != float64(1) || m["truncated"] != true {
		t.Fatalf("second: redactions=%v truncated=%v", m["redactions"], m["truncated"])
	}
	if n := len(m["stdout"].(string)); n != 1<<20 {
		t.Fatalf("stdout is %d bytes, want the 1 MiB tail", n)
	}
}

// A multi-byte character split across two status calls is never cut in half.
func TestAnIncompleteCharacterWaitsForTheRestOfIt(t *testing.T) {
	s := &starter{}
	g := make(chan struct{})
	euro := []byte("€") // e2 82 ac
	s.enqueue(func(ctx context.Context, out, _ io.Writer, on func()) broker.ExecOutcome {
		on()
		_, _ = out.Write(append([]byte("a"), euro[:2]...))
		<-g
		_, _ = out.Write(euro[2:])
		return broker.ExecOutcome{Started: true}
	})
	cs, _ := connectJobs(t, s)
	id := start(t, cs)
	time.Sleep(100 * time.Millisecond)
	if m := status(t, cs, id, 0); m["stdout"] != "a" {
		t.Fatalf("first = %q", m["stdout"])
	}
	close(g)
	if m := status(t, cs, id, 5000); m["stdout"] != "€" {
		t.Fatalf("second = %q", m["stdout"])
	}
}

// Issue #65 for the new tools: a long poll and a start report progress with a fixed text.
func TestProgressWhileAStatusCallWaits(t *testing.T) {
	setInterval(t, 40*time.Millisecond)
	s := &starter{}
	cs, got := progressJobsClient(t, s)
	id := start(t, cs)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = cs.CallTool(context.Background(), &sdk.CallToolParams{
			Name: "secret_exec_status", Arguments: map[string]any{"job": id, "wait_ms": 600},
			Meta: sdk.Meta{"progressToken": "p1"}})
	}()
	select {
	case p := <-got:
		if p.Message != "Waiting for the job to produce output or end." {
			t.Fatalf("progress text %q", p.Message)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no progress while the status call waited")
	}
	<-done
}

func progressJobsClient(t *testing.T, b broker.Backend) (*sdk.ClientSession, chan *sdk.ProgressNotificationParams) {
	t.Helper()
	got := make(chan *sdk.ProgressNotificationParams, 64)
	jobs := NewJobs(b)
	t.Cleanup(jobs.Shutdown)
	srv := NewServer(jobs, Options{Session: "claude:sess1234", Cwd: func() (string, error) { return filepath.Abs(".") }, Version: "test"})
	ctx := context.Background()
	st, ct := sdk.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	c := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "1"}, &sdk.ClientOptions{
		ProgressNotificationHandler: func(_ context.Context, r *sdk.ProgressNotificationClientRequest) { got <- r.Params },
	})
	cs, err := c.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs, got
}

// Nothing about a job is written to the server's log or stderr.
func TestJobsWriteNothingToTheLog(t *testing.T) {
	var log strings.Builder
	old := panicLog
	panicLog = &log
	t.Cleanup(func() { panicLog = old })
	s := &starter{}
	s.enqueue(steps(step{text: "TESTSECRET_job_output"}))
	cs, _ := connectJobs(t, s)
	id := start(t, cs)
	status(t, cs, id, 5000)
	callJSON(t, cs, "secret_exec_stop", map[string]any{"job": id})
	if log.Len() != 0 {
		t.Fatalf("log = %q", log.String())
	}
}

// A job tool answers with JSON only: never the command.
func TestStartAnswersOnlyTheJobID(t *testing.T) {
	cs, _ := connectJobs(t, &starter{})
	m, _ := callJSON(t, cs, "secret_exec_start", execArgs)
	raw, _ := json.Marshal(m)
	if len(m) != 2 || m["ok"] != true || strings.Contains(string(raw), "sleep") {
		t.Fatalf("start = %s", raw)
	}
}
