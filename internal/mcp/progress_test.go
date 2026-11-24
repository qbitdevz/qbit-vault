package mcp

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/qbitdevz/qbit-vault/internal/broker"
)

// waiting is a backend whose calls wait (for the user, or for work): until
// release is closed or the call's context ends.
type waiting struct {
	fake
	release chan struct{}
	started chan struct{}
	ctxDone atomic.Bool
}

func (w *waiting) wait(ctx context.Context) {
	w.started <- struct{}{}
	select {
	case <-w.release:
	case <-ctx.Done():
		w.ctxDone.Store(true)
	}
}

func (w *waiting) Request(ctx context.Context, e broker.Envelope, r broker.RequestRequest) (broker.RequestResponse, error) {
	w.wait(ctx)
	return broker.RequestResponse{OK: true, Refs: []broker.Ref{{Name: "A", Ref: "secret://A", Layer: "global"}}}, nil
}

func (w *waiting) Manage(ctx context.Context, e broker.Envelope, r broker.ManageRequest) (broker.ManageResponse, error) {
	w.wait(ctx)
	l := r.Layer
	return broker.ManageResponse{OK: true, Applied: true, Action: r.Action, Name: r.Name, Layer: &l}, nil
}

func (w *waiting) List(ctx context.Context, e broker.Envelope) (broker.ListResult, error) {
	w.wait(ctx)
	return w.fake.List(ctx, e)
}

func (w *waiting) Check(ctx context.Context, e broker.Envelope, r broker.CheckRequest) (broker.CheckResponse, error) {
	w.wait(ctx)
	return w.fake.Check(ctx, e, r)
}

func (w *waiting) Exec(ctx context.Context, e broker.Envelope, r broker.ExecRequest) (broker.ExecResponse, error) {
	w.wait(ctx)
	return w.fake.Exec(ctx, e, r)
}

func progressClient(t *testing.T, b broker.Backend, got chan *sdk.ProgressNotificationParams) *sdk.ClientSession {
	t.Helper()
	ctx := context.Background()
	srv := NewServer(b, Options{Session: "claude:sess1234", Cwd: func() (string, error) { return filepath.Abs(".") }, Version: "test"})
	st, ct := sdk.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	c := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "1"}, &sdk.ClientOptions{
		ProgressNotificationHandler: func(_ context.Context, r *sdk.ProgressNotificationClientRequest) {
			got <- r.Params
		},
	})
	cs, err := c.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func setInterval(t *testing.T, d time.Duration) {
	t.Helper()
	old := ProgressInterval
	ProgressInterval = d
	t.Cleanup(func() { ProgressInterval = old })
}

func requestParams(token any) *sdk.CallToolParams {
	p := &sdk.CallToolParams{Name: "secret_request", Arguments: map[string]any{"name": "A", "reason": "create the github release for v1.2.0"}}
	if token != nil {
		p.SetProgressToken(token)
	}
	return p
}

// While a call waits for the user, a client that sent a progress token gets
// notifications/progress, with a growing progress, until the call ends.
func TestProgressWhileTheDialogIsOpen(t *testing.T) {
	setInterval(t, 20*time.Millisecond)
	b := &waiting{release: make(chan struct{}), started: make(chan struct{}, 1)}
	got := make(chan *sdk.ProgressNotificationParams, 100)
	cs := progressClient(t, b, got)
	done := make(chan error, 1)
	go func() { _, err := cs.CallTool(context.Background(), requestParams("tok-1")); done <- err }()
	<-b.started
	var last float64
	for i := 0; i < 2; i++ {
		select {
		case p := <-got:
			if p.ProgressToken != "tok-1" || p.Progress <= last || p.Message == "" {
				t.Fatalf("progress = %+v after %v", p, last)
			}
			last = p.Progress
		case <-time.After(5 * time.Second):
			t.Fatal("no progress notification while the dialog was open")
		}
	}
	close(b.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for len(got) > 0 {
		<-got
	}
	time.Sleep(100 * time.Millisecond)
	if len(got) != 0 {
		t.Fatal("progress kept coming after the call ended")
	}
}

// No token, no notifications; and a call that ends before the first tick
// sends none either.
func TestNoProgressWithoutAToken(t *testing.T) {
	setInterval(t, 20*time.Millisecond)
	b := &waiting{release: make(chan struct{}), started: make(chan struct{}, 1)}
	got := make(chan *sdk.ProgressNotificationParams, 100)
	cs := progressClient(t, b, got)
	done := make(chan error, 1)
	go func() { _, err := cs.CallTool(context.Background(), requestParams(nil)); done <- err }()
	<-b.started
	time.Sleep(150 * time.Millisecond)
	close(b.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("%d progress notifications without a token", len(got))
	}
}

// Issue #65: secret_list and secret_exec can wait for the unlock dialog too.
// They report progress while they wait, with a text that does not claim a
// dialog is open (secret_exec may just be running its command).
func TestProgressWhileListAndExecWait(t *testing.T) {
	setInterval(t, 20*time.Millisecond)
	for tool, c := range map[string]struct {
		args map[string]any
		want string
	}{
		"secret_list":    {map[string]any{}, "Waiting for the vault to be unlocked."},
		"secret_check":   {map[string]any{"names": []any{"A"}}, "Waiting for the vault to be unlocked."},
		"secret_exec":    {map[string]any{"command": "true", "secrets": []any{map[string]any{"name": "A"}}}, "Waiting for the vault to be unlocked or for the command to finish."},
		"secret_request": {map[string]any{"name": "A", "reason": "create the github release for v1.2.0"}, "Waiting for the user to answer the dialog."},
	} {
		b := &waiting{release: make(chan struct{}), started: make(chan struct{}, 1)}
		got := make(chan *sdk.ProgressNotificationParams, 100)
		cs := progressClient(t, b, got)
		p := &sdk.CallToolParams{Name: tool, Arguments: c.args}
		p.SetProgressToken("tok-" + tool)
		done := make(chan error, 1)
		go func() { _, err := cs.CallTool(context.Background(), p); done <- err }()
		<-b.started
		select {
		case n := <-got:
			if n.ProgressToken != "tok-"+tool || n.Message != c.want {
				t.Errorf("%s: progress = %+v, want the message %q", tool, n, c.want)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("%s: no progress while the call waited", tool)
		}
		close(b.release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

// A call that ends before the first tick sends no progress.
func TestNoProgressForAQuickList(t *testing.T) {
	got := make(chan *sdk.ProgressNotificationParams, 10)
	cs := progressClient(t, &fake{}, got)
	p := &sdk.CallToolParams{Name: "secret_list", Arguments: map[string]any{}}
	p.SetProgressToken("tok")
	if _, err := cs.CallTool(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if len(got) != 0 {
		t.Fatal("a quick secret_list sent progress")
	}
}

// A client that cancels ends the backend's context, and the server stops
// sending progress.
func TestCancelReachesTheBackend(t *testing.T) {
	setInterval(t, 20*time.Millisecond)
	b := &waiting{release: make(chan struct{}), started: make(chan struct{}, 1)}
	got := make(chan *sdk.ProgressNotificationParams, 100)
	cs := progressClient(t, b, got)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := cs.CallTool(ctx, requestParams("tok-2")); done <- err }()
	<-b.started
	cancel()
	<-done
	deadline := time.Now().Add(5 * time.Second)
	for !b.ctxDone.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the backend's context did not end when the client cancelled")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
