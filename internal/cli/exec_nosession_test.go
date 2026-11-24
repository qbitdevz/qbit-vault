package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
)

// issue #64: exec without --session. Only a project grant can apply; the
// once and session grants belong to a host session.

const (
	wantNoSessionHint = "Without --session only a project grant applies; a once or session grant needs --session <host>:<id>, the id of the session it was granted to. Ask the user for a project grant, or pass --session."
	wantNoSessionMsg  = "GITHUB_TOKEN has no project grant; a once or session grant needs --session <host>:<id>"
)

// noSessionArgs is an exec with no --session at all.
func noSessionArgs(secrets []string, command string, extra ...string) []string {
	return execArgs("", secrets, command, extra...)
}

func TestExecWithoutSessionRunsWithAProjectGrant(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.inRepo()
	w.mustRun("y\n", "grant", "GITHUB_TOKEN", "--scope", "project")
	run := child(t, "leaks", "GITHUB_TOKEN", 0)

	code, out, errs := w.run("", append([]string{"--json"}, noSessionArgs([]string{"GITHUB_TOKEN"}, run)...)...)
	if code != 0 || errs != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
	}
	if strings.Contains(out, xv) || strings.Contains(out, "3456789") && !strings.Contains(out, "REDACTED") {
		t.Fatalf("a value reached the output: %q", out)
	}
	var body struct {
		OK         bool   `json:"ok"`
		Stdout     string `json:"stdout"`
		Redactions int    `json:"redactions"`
	}
	if err := json.Unmarshal([]byte(out), &body); err != nil || !body.OK || body.Redactions == 0 || !strings.Contains(body.Stdout, "[REDACTED:GITHUB_TOKEN]") {
		t.Fatalf("not redacted: %v %+v", err, body)
	}
}

// The audit schema already says "no session" as the session `cli` (the
// commands that take no --session); it cannot be a real id (no colon).
func TestExecWithoutSessionAuditsTheCLISession(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.inRepo()
	w.mustRun("y\n", "grant", "GITHUB_TOKEN", "--scope", "project")
	if code, _, errs := w.run("", noSessionArgs([]string{"GITHUB_TOKEN"}, child(t, "mark", marker(t), 0))...); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	recs := w.auditEvents(audit.EventExec)
	if len(recs) != 2 {
		t.Fatalf("exec records: %+v", recs)
	}
	for _, r := range recs {
		if r.Session != "cli" || r.By != "" {
			t.Fatalf("record %+v: want session cli and no actor", r)
		}
	}
}

func TestExecWithoutSessionRefusesOnceAndSessionGrantsAndKeepsThem(t *testing.T) {
	for _, scope := range []string{"once", "session"} {
		t.Run(scope, func(t *testing.T) {
			w := newExecWorld(t)
			w.setSecret("GITHUB_TOKEN", xv, "--global")
			w.grantTo(sessA, "GITHUB_TOKEN", scope)
			mk := marker(t)
			run := child(t, "mark", mk, 0)

			rf := refusal.New(refusal.GrantRequired, "GITHUB_TOKEN").WithMessage(wantNoSessionMsg).WithHint(wantNoSessionHint)
			w.wantRefusalIs(rf, noSessionArgs([]string{"GITHUB_TOKEN"}, run)...)
			if ran(mk) {
				t.Fatal("the command ran")
			}
			// Nothing was consumed: the same grant still serves its own session.
			if code, _, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, run)...); code != 0 || errs != "" || !ran(mk) {
				t.Fatalf("the %s grant did not survive: code=%d stderr=%q", scope, code, errs)
			}
		})
	}
}

func TestExecWithoutSessionRefusesASecretWithNoGrantWithTheSameHint(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	rf := refusal.New(refusal.GrantRequired, "GITHUB_TOKEN").WithMessage(wantNoSessionMsg).WithHint(wantNoSessionHint)
	w.wantRefusalIs(rf, noSessionArgs([]string{"GITHUB_TOKEN"}, child(t, "mark", marker(t), 0))...)
}

func TestExecWithoutSessionNeverRunsASensitiveSecret(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global", "--sensitive")
	w.grantTo(sessA, "GITHUB_TOKEN", "once")
	mk := marker(t)
	rf := refusal.New(refusal.GrantRequired, "GITHUB_TOKEN").WithMessage(wantNoSessionMsg).WithHint(wantNoSessionHint)
	w.wantRefusalIs(rf, noSessionArgs([]string{"GITHUB_TOKEN"}, child(t, "mark", mk, 0))...)
	if ran(mk) {
		t.Fatal("a sensitive secret ran without a session")
	}
	if code, _, _ := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, child(t, "mark", mk, 0))...); code != 0 || !ran(mk) {
		t.Fatal("the once grant of a sensitive secret was consumed by the refused call")
	}
}

// A project grant that exists but belongs to another repository keeps its
// own explanation; the session hint would mislead.
func TestExecWithoutSessionKeepsTheOtherDirectoryHint(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	w.inRepo()
	w.mustRun("y\n", "grant", "GITHUB_TOKEN", "--scope", "project")
	w.outRepo()
	code, out, _ := w.run("", append([]string{"--json"}, noSessionArgs([]string{"GITHUB_TOKEN"}, "x")...)...)
	if code != 3 || !strings.Contains(out, refusal.HintGrantNotApplying) || strings.Contains(out, "--session") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestExecWithASessionStillHonorsEveryScope(t *testing.T) {
	for _, scope := range []string{"once", "session", "project"} {
		t.Run(scope, func(t *testing.T) {
			w := newExecWorld(t)
			w.setSecret("GITHUB_TOKEN", xv, "--global")
			w.inRepo()
			w.grantTo(sessA, "GITHUB_TOKEN", scope)
			mk := marker(t)
			if code, _, errs := w.run("", execArgs(sessA, []string{"GITHUB_TOKEN"}, child(t, "mark", mk, 0))...); code != 0 || errs != "" || !ran(mk) {
				t.Fatalf("code=%d stderr=%q", code, errs)
			}
			// Another session: only the project grant applies.
			code, _, _ := w.run("", execArgs(sessB, []string{"GITHUB_TOKEN"}, child(t, "mark", mk, 0))...)
			if (scope == "project") != (code == 0) {
				t.Fatalf("session B with a %s grant: code=%d", scope, code)
			}
		})
	}
}

func TestMalformedSessionIsAUsageErrorThatStatesTheFormat(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xv, "--global")
	for _, bad := range []string{"nope", "pi:abc", "PI:abcd", "pi:ab cd"} {
		code, out, errs := w.run("", "--session", bad, "exec", "--secret", "GITHUB_TOKEN", "--", "x")
		want := "error: " + sessionHelp + "\n" + helpHint
		if code != 2 || out != "" || errs != want {
			t.Fatalf("--session %q: code=%d stdout=%q stderr=%q", bad, code, out, errs)
		}
	}
	for _, part := range []string{"<host>:<id>", sessionRE.String(), "host"} {
		if !strings.Contains(sessionHelp, part) {
			t.Errorf("the usage error lacks %q", part)
		}
	}
}

func TestExecHelpStatesTheSessionFormatAndWhereTheIDComesFrom(t *testing.T) {
	_, out, _ := run(t, nil, "exec", "--help")
	for _, part := range []string{"--session <host>:<id>", sessionRE.String(), "project grant", "Without --session", "qbit-vault grants --json"} {
		if !strings.Contains(out, part) {
			t.Errorf("exec --help lacks %q:\n%s", part, out)
		}
	}
}
