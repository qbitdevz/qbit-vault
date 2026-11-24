package broker

import (
	"context"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/refusal"
)

// jobFake is a backend that serves the job ops.
type jobFake struct {
	fake
	started ExecRequest
	status  JobRequest
	stopped JobRequest
}

func (j *jobFake) ExecStart(_ context.Context, e Envelope, r ExecRequest) (ExecStartResponse, error) {
	j.calls, j.env, j.started = append(j.calls, "exec_start"), e, r
	return ExecStartResponse{OK: true, Job: jobID}, j.err
}
func (j *jobFake) ExecStatus(_ context.Context, e Envelope, r JobRequest) (ExecStatusResponse, error) {
	j.calls, j.env, j.status = append(j.calls, "exec_status"), e, r
	code := 0
	return ExecStatusResponse{OK: true, State: JobExited, ExitCode: &code}, j.err
}
func (j *jobFake) ExecStop(_ context.Context, e Envelope, r JobRequest) (ExecStatusResponse, error) {
	j.calls, j.env, j.stopped = append(j.calls, "exec_stop"), e, r
	return ExecStatusResponse{OK: true, State: JobStopped}, j.err
}
func (j *jobFake) Info() Info { i := j.fake.Info(); i.ExecJobs = true; return i }

// jobAuditing is a job backend that also keeps an audit log.
type jobAuditing struct {
	jobFake
	refused []refusal.Refusal
	ops     []string
}

func (a *jobAuditing) Refused(e Envelope, rf refusal.Refusal) {
	a.ops, a.refused = append(a.ops, e.Op), append(a.refused, rf)
}

var jobID = strings.Repeat("ab", 16)

// A backend that cannot keep a command running (broker --op) does not serve the job ops.
func TestJobOpsAreUnknownWithoutAJobBackend(t *testing.T) {
	for op, extra := range map[string]string{
		"exec_start":  `"command":"x","secrets":[{"name":"A"}]`,
		"exec_status": `"job":"` + jobID + `"`,
		"exec_stop":   `"job":"` + jobID + `"`,
	} {
		f := &fake{}
		for _, tr := range []Transport{TransportHost, TransportModel} {
			typ, msg := refusalOf(t, call(t, f, tr, env(op, extra)))
			if typ != "internal" || msg != "invalid request: op" {
				t.Errorf("%s: %s %q", op, typ, msg)
			}
		}
		if len(f.calls) != 0 {
			t.Errorf("%s reached the backend", op)
		}
	}
}

func TestExecStartIsExecWithTheSameValidation(t *testing.T) {
	f := &jobFake{}
	m := call(t, f, TransportModel, env("exec_start", `"command":"make","secrets":[{"name":"T","from":"A"}],"timeout_ms":5000,"shell":"sh","locale":"es"`))
	if m["ok"] != true || m["job"] != jobID || len(m) != 2 {
		t.Fatalf("response %v", m)
	}
	if f.started.Command != "make" || f.started.TimeoutMS != 5000 || f.started.Shell != "sh" || f.started.Secrets[0].From != "A" || f.env.Locale != "es" || f.env.Op != "exec_start" {
		t.Fatalf("request %+v env %+v", f.started, f.env)
	}
	// Every case exec refuses, exec_start refuses with the same refusal.
	for _, extra := range []string{
		`"secrets":[{"name":"A"}]`,
		`"command":"  ","secrets":[{"name":"A"}]`,
		`"command":"x","secrets":[]`,
		`"command":"x","secrets":null`,
		`"command":"x","secrets":[{"name":"a"}]`,
		`"command":"x","secrets":[{"name":"A"},{"name":"A"}]`,
		`"command":"x","secrets":[{"name":"A"}],"timeout_ms":999`,
		`"command":"x","secrets":[{"name":"A"}],"timeout_ms":3600001`,
		`"command":"x","secrets":[{"name":"A"}],"shell":"zsh"`,
		`"command":"x","secrets":[{"name":"A"}],"locale":null`,
		`"command":"x","secrets":[{"name":"A"}],"job":"` + jobID + `"`,
	} {
		viaExec := call(t, &fake{}, TransportModel, env("exec", extra))
		viaStart := call(t, &jobFake{}, TransportModel, env("exec_start", extra))
		a, _ := refusalOf(t, viaExec)
		b, _ := refusalOf(t, viaStart)
		if a != b || viaExec["refusal"].(map[string]any)["message"] != viaStart["refusal"].(map[string]any)["message"] ||
			viaExec["refusal"].(map[string]any)["hint"] != viaStart["refusal"].(map[string]any)["hint"] {
			t.Errorf("%s: exec %v, exec_start %v", extra, viaExec["refusal"], viaStart["refusal"])
		}
	}
}

func TestJobRequestValidation(t *testing.T) {
	cases := []struct {
		name, op, extra, msg string
	}{
		{"status ok", "exec_status", `"job":"` + jobID + `","wait_ms":50000`, ""},
		{"status default wait", "exec_status", `"job":"` + jobID + `"`, ""},
		{"stop ok", "exec_stop", `"job":"` + jobID + `"`, ""},
		{"no job", "exec_status", ``, "invalid request: job"},
		{"short job", "exec_status", `"job":"abcd"`, "invalid request: job"},
		{"upper case job", "exec_status", `"job":"` + strings.ToUpper(jobID) + `"`, "invalid request: job"},
		{"non hex job", "exec_stop", `"job":"` + strings.Repeat("zz", 16) + `"`, "invalid request: job"},
		{"job of the wrong type", "exec_stop", `"job":5`, "invalid request: job"},
		{"wait too long", "exec_status", `"job":"` + jobID + `","wait_ms":50001`, "invalid request: wait_ms"},
		{"negative wait", "exec_status", `"job":"` + jobID + `","wait_ms":-1`, "invalid request: wait_ms"},
		{"fractional wait", "exec_status", `"job":"` + jobID + `","wait_ms":1.5`, "invalid request: wait_ms"},
		{"wait of the wrong type", "exec_status", `"job":"` + jobID + `","wait_ms":"5"`, "invalid request: wait_ms"},
		{"stop takes no wait", "exec_stop", `"job":"` + jobID + `","wait_ms":5`, "invalid request: unknown field"},
		{"status takes no locale", "exec_status", `"job":"` + jobID + `","locale":"es"`, "invalid request: unknown field"},
		{"stop takes no command", "exec_stop", `"job":"` + jobID + `","command":"x"`, "invalid request: unknown field"},
	}
	for _, c := range cases {
		f := &jobFake{}
		m := call(t, f, TransportModel, env(c.op, c.extra))
		if c.msg == "" {
			if m["ok"] != true {
				t.Errorf("%s: %v", c.name, m)
			}
			continue
		}
		if typ, msg := refusalOf(t, m); typ != "internal" || msg != c.msg || len(f.calls) != 0 {
			t.Errorf("%s: %s %q (calls %v)", c.name, typ, msg, f.calls)
		}
		if r := m["refusal"].(map[string]any); r["hint"] != refusal.HintBadRequest {
			t.Errorf("%s: hint %v", c.name, r["hint"])
		}
	}
	f := &jobFake{}
	call(t, f, TransportModel, env("exec_status", `"job":"`+jobID+`","wait_ms":1234`))
	if f.status.Job != jobID || f.status.WaitMS != 1234 {
		t.Fatalf("status request %+v", f.status)
	}
	call(t, f, TransportModel, env("exec_stop", `"job":"`+jobID+`"`))
	if f.stopped.Job != jobID {
		t.Fatalf("stop request %+v", f.stopped)
	}
}

// exec_jobs is reported only by a backend that serves the ops; the ops list is the same for everyone.
func TestCapabilitiesReportExecJobsOnlyFromAJobBackend(t *testing.T) {
	plain := call(t, &fake{}, TransportHost, env("capabilities", ""))
	if _, has := plain["exec_jobs"]; has {
		t.Fatalf("plain backend: %v", plain)
	}
	jobs := call(t, &jobFake{}, TransportModel, env("capabilities", ""))
	if jobs["exec_jobs"] != float64(1) || jobs["capabilities"] != "1.1" {
		t.Fatalf("job backend: %v", jobs)
	}
	if len(jobs["ops"].([]any)) != 8 {
		t.Fatalf("ops = %v", jobs["ops"])
	}
}

// A refusal of a job op is audited like every other refusal of a valid envelope.
func TestJobRefusalsAreAudited(t *testing.T) {
	a := &jobAuditing{}
	a.err = refusal.New(refusal.Internal, "").WithMessage("no such job").WithHint(refusal.HintUnknownJob)
	Handle(context.Background(), []byte(env("exec_status", `"job":"`+jobID+`"`)), a, TransportModel)
	Handle(context.Background(), []byte(env("exec_start", `"command":"x","secrets":[{"name":"A"}]`)), a, TransportModel)
	if len(a.refused) != 2 || a.ops[0] != "exec_status" || a.ops[1] != "exec_start" || a.refused[0].Hint != refusal.HintUnknownJob {
		t.Fatalf("reports: ops %v refusals %+v", a.ops, a.refused)
	}
}
