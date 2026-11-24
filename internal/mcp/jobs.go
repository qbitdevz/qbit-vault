package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/qbitdevz/qbit-vault/internal/broker"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
	"github.com/qbitdevz/qbit-vault/internal/runner"
)

// Limits of the job registry (CONTRACT.md § Jobs).
const (
	// MaxRunningJobs is how many jobs run at once in one server; a job that is
	// still being started counts.
	MaxRunningJobs = 4
	// jobOutputCap caps each stream of unread output, keeping the tail, as
	// secret_exec caps its output.
	jobOutputCap = runner.DefaultCaptureLimit
	// stopWait bounds how long secret_exec_stop waits for the tree to end.
	stopWait = 10 * time.Second
	// MaxFinishedJobs is how many ended jobs whose result nobody has read are
	// kept per server; when one more ends, the oldest is dropped and its id
	// answers like any unknown id. It bounds the memory unread output holds
	// (up to 1 MiB per stream per job).
	MaxFinishedJobs = 8
	// shutdownWait bounds how long Shutdown waits for the trees to end.
	shutdownWait = 10 * time.Second
)

// JobRetention is how long an ended job's unread output and final state are
// kept when no status call has returned the final state. A variable for tests.
var JobRetention = 10 * time.Minute

// ownerKey carries the MCP session of a call in its context, so a job is
// visible only to the session that started it.
type ownerKey struct{}

func ownerOf(ctx context.Context) any {
	if ss, ok := ctx.Value(ownerKey{}).(*sdk.ServerSession); ok && ss != nil {
		return ss
	}
	return nil
}

// Jobs is the registry of the commands `secret_exec_start` runs in the
// background, in this process and in memory only: no daemon, no file. It
// wraps the backend that does the real work (grants, dump guard, injection,
// redaction and audit are the backend's exec, reached through
// broker.ExecStarter) and implements broker.Backend and broker.JobBackend
// over it. Shutdown kills every job's process tree; a job never outlives the
// server.
type Jobs struct {
	inner   broker.Backend
	starter broker.ExecStarter

	mu      sync.Mutex
	jobs    map[string]*job
	slots   int    // jobs being started or running
	done    []*job // ended jobs not yet reported, oldest first
	closed  bool
	watched map[*sdk.ServerSession]bool
	base    context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewJobs wraps inner. A backend that is not a broker.ExecStarter refuses
// every start.
func NewJobs(inner broker.Backend) *Jobs {
	r := &Jobs{inner: inner, jobs: map[string]*job{}, watched: map[*sdk.ServerSession]bool{}}
	r.starter, _ = inner.(broker.ExecStarter)
	r.base, r.cancel = context.WithCancel(context.Background())
	return r
}

// job is one background command. Everything under mu is shared with the
// goroutine that runs it.
type job struct {
	id     string
	owner  any
	began  time.Time
	cancel context.CancelFunc
	done   chan struct{} // closed once state is final and the child is gone

	mu         sync.Mutex
	didStart   bool
	state      string
	exit       *int
	dur        time.Duration
	out, errs  stream
	redactions int // replacements in the output not yet reported
	discard    bool
	timer      *time.Timer
}

// stream is the redacted output not yet reported. It only ever holds bytes
// the redactor has already emitted; what it still withholds is in the
// redactor's own carry-over (an ending that may still become a value).
type stream struct {
	buf     []byte
	dropped bool
}

func (s *stream) add(p []byte) {
	s.buf = append(s.buf, p...)
	if len(s.buf) > jobOutputCap {
		n := copy(s.buf, s.buf[len(s.buf)-jobOutputCap:])
		s.buf = s.buf[:n]
		s.dropped = true
	}
}

// take returns what can be reported. While the job runs a trailing partial
// UTF-8 character stays for the next call, so no character is cut between two.
func (s *stream) take(final bool) string {
	b := s.buf
	keep := 0
	if !final {
		keep = incompleteTail(b)
	}
	out := string(b[:len(b)-keep])
	s.buf = append(s.buf[:0], b[len(b)-keep:]...)
	return out
}

// incompleteTail is the length of a trailing, unfinished UTF-8 sequence.
func incompleteTail(b []byte) int {
	for i := 1; i <= utf8.UTFMax-1 && i <= len(b); i++ {
		c := b[len(b)-i]
		if utf8.RuneStart(c) {
			if c >= 0xC0 && !utf8.FullRune(b[len(b)-i:]) {
				return i
			}
			return 0
		}
	}
	return 0
}

// sink is the writer the runner's redactor flushes into: a stream of the job.
type sink struct {
	j *job
	s *stream
}

func (k sink) Write(p []byte) (int, error) { return k.WriteCounted(p, 0) }

func (k sink) WriteCounted(p []byte, replaced int) (int, error) {
	k.j.mu.Lock()
	defer k.j.mu.Unlock()
	k.s.add(p)
	k.j.redactions += replaced
	return len(p), nil
}

func newJobID() string {
	var b [broker.JobIDLen / 2]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("mcp: random source failed")
	}
	return hex.EncodeToString(b[:])
}

var errUnknownJob = refusal.New(refusal.Internal, "").WithMessage("no such job").WithHint(refusal.HintUnknownJob)

// Delegation of everything that is not a job to the wrapped backend.

func (r *Jobs) List(ctx context.Context, e broker.Envelope) (broker.ListResult, error) {
	return r.inner.List(ctx, e)
}
func (r *Jobs) Exec(ctx context.Context, e broker.Envelope, x broker.ExecRequest) (broker.ExecResponse, error) {
	return r.inner.Exec(ctx, e, x)
}
func (r *Jobs) Grant(ctx context.Context, e broker.Envelope, x broker.GrantRequest) (broker.GrantResponse, error) {
	return r.inner.Grant(ctx, e, x)
}
func (r *Jobs) Revoke(ctx context.Context, e broker.Envelope, x broker.RevokeRequest) (broker.RevokeResponse, error) {
	return r.inner.Revoke(ctx, e, x)
}
func (r *Jobs) Request(ctx context.Context, e broker.Envelope, x broker.RequestRequest) (broker.RequestResponse, error) {
	return r.inner.Request(ctx, e, x)
}
func (r *Jobs) Manage(ctx context.Context, e broker.Envelope, x broker.ManageRequest) (broker.ManageResponse, error) {
	return r.inner.Manage(ctx, e, x)
}

// Info is the wrapped backend's, plus the job capability.
func (r *Jobs) Info() broker.Info {
	i := r.inner.Info()
	i.ExecJobs = r.starter != nil
	return i
}

// Refused forwards to the wrapped backend's audit, when it keeps one.
func (r *Jobs) Refused(e broker.Envelope, rf refusal.Refusal) {
	if a, ok := r.inner.(broker.Auditor); ok {
		a.Refused(e, rf)
	}
}

// Held is the number of jobs the registry still holds (tests).
func (r *Jobs) Held() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.jobs)
}

// reserve takes one of the MaxRunningJobs slots.
func (r *Jobs) reserve() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case r.closed:
		return refusal.New(refusal.Internal, "").WithMessage("the server is stopping")
	case r.slots >= MaxRunningJobs:
		return refusal.New(refusal.Internal, "").WithMessage("too many running jobs").WithRetryable(true).WithHint(refusal.HintJobsBusy)
	}
	r.slots++
	return nil
}

func (r *Jobs) unreserve() {
	r.mu.Lock()
	r.slots--
	r.mu.Unlock()
}

// ExecStart decides everything exec decides before a process exists, through
// the wrapped backend, then runs the command in the background and returns
// once it has started.
func (r *Jobs) ExecStart(ctx context.Context, e broker.Envelope, x broker.ExecRequest) (broker.ExecStartResponse, error) {
	if r.starter == nil {
		return broker.ExecStartResponse{}, refusal.New(refusal.Internal, "").WithMessage("invalid request: op").WithHint(refusal.HintBadRequest)
	}
	if err := r.reserve(); err != nil {
		return broker.ExecStartResponse{}, err
	}
	// The slot is the job's from the moment its goroutine runs; until then
	// every way out, a panic included, gives it back.
	reserved := true
	defer func() {
		if reserved {
			r.unreserve()
		}
	}()
	pe, err := r.starter.PrepareExec(ctx, e, x)
	if err != nil {
		return broker.ExecStartResponse{}, err
	}

	runCtx, cancel := context.WithCancel(r.base)
	j := &job{id: newJobID(), owner: ownerOf(ctx), began: time.Now(), cancel: cancel, done: make(chan struct{}), state: broker.JobRunning}
	started := make(chan struct{})

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		cancel()
		pe.Close()
		return broker.ExecStartResponse{}, refusal.New(refusal.Internal, "").WithMessage("the server is stopping")
	}
	r.jobs[j.id] = j
	r.wg.Add(1)
	reserved = false // run's finish gives the slot back
	r.mu.Unlock()
	if ss, ok := j.owner.(*sdk.ServerSession); ok {
		r.watch(ss)
	}
	go r.run(j, pe, runCtx, started)

	select {
	case <-started:
	case <-j.done:
	case <-ctx.Done():
		// The client gave up before the command started: nobody has the id.
		cancel()
		<-j.done
		r.forget(j)
		return broker.ExecStartResponse{}, ctx.Err()
	}
	j.mu.Lock()
	ok := j.didStart
	j.mu.Unlock()
	if !ok {
		<-j.done
		r.forget(j)
		return broker.ExecStartResponse{}, refusal.New(refusal.Internal, "")
	}
	return broker.ExecStartResponse{OK: true, Job: j.id}, nil
}

// run is the goroutine of one job: the wrapped exec's run, its output into
// the job's streams (already redacted), then the final state.
func (r *Jobs) run(j *job, pe broker.PreparedExec, ctx context.Context, started chan struct{}) {
	var out broker.ExecOutcome
	defer r.wg.Done()
	defer func() {
		if recover() != nil {
			fmt.Fprintln(panicLog, broker.PanicLine)
			out = broker.ExecOutcome{Started: true, Interrupted: true}
		}
		pe.Close()
		r.finish(j, out)
	}()
	out = pe.Run(ctx, sink{j, &j.out}, sink{j, &j.errs}, func() {
		j.mu.Lock()
		j.didStart = true
		j.mu.Unlock()
		close(started)
	})
}

// finish records how the job ended, frees its slot and arms its retention.
func (r *Jobs) finish(j *job, out broker.ExecOutcome) {
	j.mu.Lock()
	switch {
	case out.TimedOut:
		j.state = broker.JobTimedOut
	case out.Interrupted:
		j.state = broker.JobStopped
	default:
		j.state = broker.JobExited
	}
	if out.Started {
		code := out.ExitCode
		j.exit = &code
	}
	j.dur = time.Since(j.began)
	discard := j.discard
	j.mu.Unlock()

	var evicted []*job
	r.mu.Lock()
	r.slots--
	if !r.closed && !discard {
		t := time.AfterFunc(JobRetention, func() { r.forget(j) })
		j.mu.Lock()
		j.timer = t
		j.mu.Unlock()
		r.done = append(r.done, j)
		for len(r.done) > MaxFinishedJobs {
			evicted = append(evicted, r.done[0])
			r.done = r.done[1:]
		}
	}
	r.mu.Unlock()
	for _, old := range evicted {
		r.forget(old)
	}
	close(j.done)
	if discard {
		r.forget(j)
	}
}

// forget drops a job and the output it still holds.
func (r *Jobs) forget(j *job) {
	r.mu.Lock()
	delete(r.jobs, j.id)
	for i, d := range r.done {
		if d == j {
			r.done = append(r.done[:i], r.done[i+1:]...)
			break
		}
	}
	r.mu.Unlock()
	j.mu.Lock()
	if j.timer != nil {
		j.timer.Stop()
	}
	clear(j.out.buf)
	clear(j.errs.buf)
	j.out.buf, j.errs.buf = nil, nil
	j.mu.Unlock()
}

func (r *Jobs) lookup(ctx context.Context, id string) (*job, error) {
	r.mu.Lock()
	j := r.jobs[id]
	r.mu.Unlock()
	if j == nil || j.owner != ownerOf(ctx) {
		return nil, errUnknownJob
	}
	return j, nil
}

// ExecStatus long-polls: it returns when the job ends, after WaitMS, or when
// the client gives up (which never touches the job).
func (r *Jobs) ExecStatus(ctx context.Context, _ broker.Envelope, q broker.JobRequest) (broker.ExecStatusResponse, error) {
	j, err := r.lookup(ctx, q.Job)
	if err != nil {
		return broker.ExecStatusResponse{}, err
	}
	if q.WaitMS > 0 {
		t := time.NewTimer(time.Duration(q.WaitMS) * time.Millisecond)
		defer t.Stop()
		select {
		case <-j.done:
		case <-t.C:
		case <-ctx.Done():
		}
	}
	return r.report(ctx, j)
}

// ExecStop kills the job's whole process tree and reports its final state.
func (r *Jobs) ExecStop(ctx context.Context, _ broker.Envelope, q broker.JobRequest) (broker.ExecStatusResponse, error) {
	j, err := r.lookup(ctx, q.Job)
	if err != nil {
		return broker.ExecStatusResponse{}, err
	}
	j.cancel()
	t := time.NewTimer(stopWait)
	defer t.Stop()
	select {
	case <-j.done:
	case <-t.C:
	case <-ctx.Done():
	}
	return r.report(ctx, j)
}

// report answers with the output produced since the previous report. A call
// the client already gave up on takes nothing, so its output stays for the
// next call. The report that carries a final state ends the job.
func (r *Jobs) report(ctx context.Context, j *job) (broker.ExecStatusResponse, error) {
	j.mu.Lock()
	if err := ctx.Err(); err != nil {
		j.mu.Unlock()
		return broker.ExecStatusResponse{}, err
	}
	final := j.state != broker.JobRunning
	res := broker.ExecStatusResponse{OK: true, State: j.state, ExitCode: j.exit, Redactions: j.redactions,
		Truncated: j.out.dropped || j.errs.dropped}
	res.Stdout, res.Stderr = j.out.take(final), j.errs.take(final)
	if final {
		res.DurationMS = j.dur.Milliseconds()
	} else {
		res.DurationMS = time.Since(j.began).Milliseconds()
	}
	j.redactions, j.out.dropped, j.errs.dropped = 0, false, false
	j.mu.Unlock()
	if final {
		r.forget(j)
	}
	return res, nil
}

// watch ends a session's jobs when the session ends.
func (r *Jobs) watch(ss *sdk.ServerSession) {
	r.mu.Lock()
	if r.watched[ss] || r.closed {
		r.mu.Unlock()
		return
	}
	r.watched[ss] = true
	r.mu.Unlock()
	go func() {
		_ = ss.Wait()
		r.mu.Lock()
		delete(r.watched, ss)
		var own []*job
		for _, j := range r.jobs {
			if j.owner == any(ss) {
				own = append(own, j)
			}
		}
		r.mu.Unlock()
		for _, j := range own {
			j.mu.Lock()
			j.discard = true
			j.mu.Unlock()
			j.cancel()
			<-j.done
			r.forget(j)
		}
	}()
}

// Shutdown ends every job: each process tree is killed and the call returns
// once they are gone (bounded). It is what the server runs when it ends, for
// whatever reason, so a job never outlives it and a child never keeps
// injected secrets alive after it. Further starts are refused. Idempotent.
func (r *Jobs) Shutdown() {
	r.mu.Lock()
	r.closed = true
	r.cancel()
	for _, j := range r.jobs {
		j.mu.Lock()
		if j.timer != nil {
			j.timer.Stop()
		}
		j.mu.Unlock()
	}
	r.mu.Unlock()
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	t := time.NewTimer(shutdownWait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	}
	r.mu.Lock()
	all := make([]*job, 0, len(r.jobs))
	for _, j := range r.jobs {
		all = append(all, j)
	}
	r.mu.Unlock()
	for _, j := range all {
		r.forget(j)
	}
}
