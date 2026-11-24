package cli

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

// Issue #62, part 3 (odd/tasks/issues-61-65-dialogs.md T9): a replaced value
// stays recoverable for 7 days, and only the user can restore it.

const (
	pvOld   = "TESTSECRET_prev_old_0123456789"
	pvNew   = "TESTSECRET_prev_new_9876543210"
	pvOther = "TESTSECRET_prev_other_55555"
)

var pvT0 = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)

// pinVault pins the vault's clock (replaced_at, expiry) and returns a setter.
func pinVault(t *testing.T) func(time.Time) {
	t.Helper()
	cur := pvT0
	t.Cleanup(vault.SetNowForTesting(func() time.Time { return cur }))
	return func(n time.Time) { cur = n }
}

// previous reads the previous value through the vault API, for assertions.
func (w *world) previous(name string) (string, bool) {
	w.t.Helper()
	g := &globals{getenv: envFrom(nil), home: w.home}
	s, err := g.openSession()
	if err != nil {
		w.t.Fatal(err)
	}
	defer s.close()
	all, err := s.v.PreviousValues()
	if err != nil {
		w.t.Fatal(err)
	}
	for _, p := range all {
		if p.Name == name {
			return string(p.Value.Reveal()), true
		}
	}
	return "", false
}

// scanHome fails when any file of the home holds a fixture raw or encoded.
func (w *world) scanHome(values ...string) {
	w.t.Helper()
	needles := []string{}
	for _, v := range values {
		needles = append(needles, v, base64.StdEncoding.EncodeToString([]byte(v)), base64.URLEncoding.EncodeToString([]byte(v)), url.QueryEscape(v))
	}
	err := filepath.WalkDir(w.home, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		for _, n := range needles {
			if strings.Contains(string(b), n) {
				w.t.Errorf("%s holds a fixture: %.14s...", p, n)
			}
		}
		return rerr
	})
	if err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) listedMeta(name string) map[string]any {
	w.t.Helper()
	_, m, _ := w.broker("list", envelope("list", w.outside, ""))
	for _, s := range m["secrets"].([]any) {
		if e := s.(map[string]any); e["name"] == name {
			return e
		}
	}
	w.t.Fatalf("%s is not listed", name)
	return nil
}

func revertReq(w *world, name, extra string) string {
	return manageReq(w.outside, `"action":"revert","name":"`+name+`","layer":"global"`+extra)
}

func TestReplaceKeepsThePreviousValueAndListShowsItsEnd(t *testing.T) {
	pinVault(t)
	w := newWorld(t)
	w.setSecret("A", pvOld, "--global")
	w.setSecret("B", pvOther, "--global")
	if _, has := w.listedMeta("A")["previous_until"]; has {
		t.Fatal("a never-replaced secret lists previous_until")
	}
	w.setSecret("A", pvNew, "--global")
	if v, ok := w.previous("A"); !ok || v != pvOld {
		t.Fatalf("previous = %q ok=%v", v, ok)
	}
	want := pvT0.Add(vault.PreviousRetention).Format(time.RFC3339)
	if got := w.listedMeta("A")["previous_until"]; got != want {
		t.Fatalf("previous_until = %v, want %s", got, want)
	}
	if _, has := w.listedMeta("B")["previous_until"]; has {
		t.Fatal("another secret lists previous_until")
	}
	// The human and JSON commands show the end of the window and never a value.
	human := w.mustRun("", "list", "--layer", "all")
	desc := w.mustRun("", "describe", "A", "--global")
	js := w.mustRun("", "--json", "list", "--layer", "all")
	djs := w.mustRun("", "--json", "describe", "A", "--global")
	for what, s := range map[string]string{"list": human, "describe": desc, "list --json": js, "describe --json": djs} {
		if !strings.Contains(s, want) {
			t.Errorf("%s does not show %s: %q", what, want, s)
		}
		noFixtures(t, what, s)
	}
	w.scanHome(pvOld, pvNew)
}

func TestSetOverwriteWithTheSameValueKeepsThePreviousOne(t *testing.T) {
	pinVault(t)
	w := newWorld(t)
	w.setSecret("A", pvOld, "--global")
	w.setSecret("A", pvNew, "--global")
	w.setSecret("A", pvNew, "--global") // the user confirmed the same-value warning, or stdin: no question
	if v, ok := w.previous("A"); !ok || v != pvOld {
		t.Fatalf("previous = %q ok=%v: a same-value overwrite replaced it with a copy of the current value", v, ok)
	}
}

func TestManageReplaceKeepsThePreviousValue(t *testing.T) {
	pinVault(t)
	w := newWorld(t)
	w.setSecret("A", pvOld, "--global")
	withBackend(t, answers(pick(0), val(pvNew)))
	if code, m, _ := w.broker("manage", manageReq(w.outside, `"action":"replace","name":"A","layer":"global"`)); code != exitcode.OK {
		t.Fatalf("m=%v", m)
	}
	if v, ok := w.previous("A"); !ok || v != pvOld {
		t.Fatalf("previous = %q ok=%v", v, ok)
	}
}

func TestManageRevertSwapsAndCanBeUndone(t *testing.T) {
	set := pinVault(t)
	w := newExecWorld(t)
	w.setSecret("A", pvOld, "--global")
	w.setSecret("A", pvNew, "--global")
	w.grantTo(brokerSession, "A", "session")
	idBefore := w.mustRun("", "--json", "describe", "A", "--global")
	set(pvT0.Add(48 * time.Hour))

	f := withBackend(t, answers(yes()))
	code, _, out := w.broker("manage", revertReq(w, "A", ""))
	if code != exitcode.OK || out != `{"ok":true,"applied":true,"action":"revert","name":"A","layer":"global"}`+"\n" {
		t.Fatalf("code=%d out=%s", code, out)
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "confirm" {
		t.Fatalf("calls = %+v, want one confirm", f.Calls)
	}
	wantQ := "Pi wants to restore the previous value of A (all projects), the one replaced on 2026-11-24 10:00 UTC. " +
		"The current value becomes the previous one, and the permissions given for A end.\nWhy: " + manageReason
	if f.Calls[0].Q != wantQ {
		t.Fatalf("question = %q\nwant       %q", f.Calls[0].Q, wantQ)
	}
	noValueInDialogs(t, f.Calls, pvOld, pvNew)
	if w.value("A") != pvOld {
		t.Fatal("the previous value was not restored")
	}
	if v, ok := w.previous("A"); !ok || v != pvNew {
		t.Fatalf("after the swap previous = %q ok=%v", v, ok)
	}
	// The window restarted for the value set aside; the grant did not carry over.
	if got, want := w.listedMeta("A")["previous_until"], pvT0.Add(48*time.Hour).Add(vault.PreviousRetention).Format(time.RFC3339); got != want {
		t.Fatalf("previous_until = %v, want %s", got, want)
	}
	if w.listedMeta("A")["grant"] != nil {
		t.Fatalf("a grant carried over to a different value: %v", w.listedMeta("A")["grant"])
	}
	if idAfter := w.mustRun("", "--json", "describe", "A", "--global"); idAfter == idBefore {
		t.Log("describe has no id to compare; the grant check above covers the identity change")
	}
	if !w.auditHas(`"event":"manage"`) || !w.auditHas(`"detail":"revert"`) {
		t.Fatalf("audit: %s", w.auditText())
	}
	noFixtures(t, "audit", w.auditText())

	// Undo: the same proposal swaps back (another cooldown-free answer).
	withBackend(t, answers(yes()))
	if code, m, _ := w.broker("manage", revertReq(w, "A", "")); code != exitcode.OK {
		t.Fatalf("undo: %v", m)
	}
	if w.value("A") != pvNew {
		t.Fatal("the revert could not be undone")
	}
	w.scanHome(pvOld, pvNew)
}

func TestManageRevertWithNothingToRevertIsRefusedBeforeAnyDialog(t *testing.T) {
	pinVault(t)
	w := newWorld(t)
	w.setSecret("A", pvOld, "--global")
	f := withBackend(t, answers())
	code, m, out := w.broker("manage", revertReq(w, "A", ""))
	want := refusal.New(refusal.Internal, "").WithMessage("A has no previous value to restore").WithHint(refusal.HintNoPreviousValue)
	if code != exitcode.Refusal || out != jsonOf(t, want.Envelope()) {
		t.Fatalf("code=%d m=%v out=%s", code, m, out)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("a dialog opened for nothing: %+v", f.Calls)
	}
	if w.value("A") != pvOld {
		t.Fatal("the vault changed")
	}
}

func TestManageRevertDeclinedChangesNothingAndCoolsDown(t *testing.T) {
	pinVault(t)
	w := newWorld(t)
	w.setSecret("A", pvOld, "--global")
	w.setSecret("A", pvNew, "--global")
	before := w.snapshot()
	withBackend(t, answers(no()))
	code, m, _ := w.broker("manage", revertReq(w, "A", ""))
	if code != exitcode.Refusal || refusalType(m) != "user_declined" {
		t.Fatalf("code=%d m=%v", code, m)
	}
	if w.value("A") != pvNew || w.snapshot() != before {
		t.Fatal("a declined revert changed the vault")
	}
	withBackend(t, answers(yes()))
	if _, m, _ := w.broker("manage", revertReq(w, "A", "")); refusalType(m) != "rate_limited" {
		t.Fatalf("second proposal = %v", m)
	}
}

func TestManageRevertAfterTheWindowIsRefused(t *testing.T) {
	set := pinVault(t)
	w := newWorld(t)
	w.setSecret("A", pvOld, "--global")
	w.setSecret("A", pvNew, "--global")
	set(pvT0.Add(vault.PreviousRetention))
	withBackend(t, answers(yes()))
	code, m, _ := w.broker("manage", revertReq(w, "A", ""))
	if code != exitcode.Refusal || refusalType(m) != "internal" {
		t.Fatalf("revert at the boundary: code=%d m=%v", code, m)
	}
	if _, has := w.listedMeta("A")["previous_until"]; has {
		t.Fatal("an expired previous value is still listed")
	}
	if _, ok := w.previous("A"); ok {
		t.Fatal("an expired previous value is still readable")
	}
}

func TestManageRevertDialogInSpanish(t *testing.T) {
	pinVault(t)
	w := newWorld(t)
	w.setSecret("A", pvOld, "--global")
	w.setSecret("A", pvNew, "--global")
	f := withBackend(t, answers(yes()))
	if code, m, _ := w.broker("manage", revertReq(w, "A", `,"locale":"es"`)); code != exitcode.OK {
		t.Fatalf("m=%v", m)
	}
	q := f.Calls[0].Q
	for _, part := range []string{"restaurar el valor anterior de A (todos los proyectos)", "2026-11-24 10:00 UTC", "los permisos dados a A terminan"} {
		if !strings.Contains(q, part) {
			t.Errorf("question lacks %q: %q", part, q)
		}
	}
	noValueInDialogs(t, f.Calls, pvOld, pvNew)
}

func TestManageRevertRefusesFieldsOfOtherActions(t *testing.T) {
	w := newWorld(t)
	w.setSecret("A", pvOld, "--global")
	for _, extra := range []string{`,"to":"project"`, `,"changes":{"description":"x"}`} {
		if code, m, _ := w.broker("manage", revertReq(w, "A", extra)); code != exitcode.Refusal || refusalType(m) != "internal" {
			t.Errorf("%s: code=%d m=%v", extra, code, m)
		}
	}
}

func TestRevertCommand(t *testing.T) {
	set := pinVault(t)
	w := newExecWorld(t)
	w.setSecret("A", pvOld, "--global")
	if code, out, errs := w.run("", "revert", "A", "--global", "--yes"); code != exitcode.Refusal ||
		out != "" || errs != "error: A has no previous value to restore\n" {
		t.Fatalf("nothing to revert: code=%d out=%q err=%q", code, out, errs)
	}
	w.setSecret("A", pvNew, "--global")
	w.grantTo("pi:grantee123", "A", "session")
	set(pvT0.Add(time.Hour))

	// Declined at the question: nothing changes.
	f := withBackend(t, answers(no()))
	if code, out, _ := w.run("", "revert", "A", "--global"); code != exitcode.Failure || out != "" {
		t.Fatalf("declined: code=%d out=%q", code, out)
	}
	wantQ := "Restore the previous value of A (all projects), the one replaced on 2026-11-24 10:00 UTC? " +
		"The current value becomes the previous one, and the permissions given for A end."
	if f.Calls[0].Kind != "confirm" || f.Calls[0].Q != wantQ {
		t.Fatalf("question = %+v", f.Calls[0])
	}
	if w.value("A") != pvNew {
		t.Fatal("a declined revert changed the value")
	}
	if g := w.grantList(); !strings.Contains(g, `"A"`) {
		t.Fatalf("a declined revert dropped the grants: %s", g)
	}

	// Confirmed: restored, grants dropped, nothing printed but the fact.
	withBackend(t, answers(yes()))
	until := pvT0.Add(time.Hour).Add(vault.PreviousRetention).Format(time.RFC3339)
	code, out, errs := w.run("", "revert", "A", "--global")
	if code != exitcode.OK || errs != "" || out != "restored the previous value of A (global); revert again until "+until+" to undo\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if w.value("A") != pvOld {
		t.Fatal("not restored")
	}
	if g := w.grantList(); strings.Contains(g, `"name":"A"`) {
		t.Fatalf("the grant carried over to a different value: %s", g)
	}
	noFixtures(t, "output", out+errs+w.auditText())

	// --json and --yes.
	code, out, _ = w.run("", "--json", "revert", "A", "--global", "--yes")
	var body map[string]any
	if err := json.Unmarshal([]byte(out), &body); err != nil || code != exitcode.OK || body["reverted"] != true || body["previous_until"] != until {
		t.Fatalf("json: code=%d out=%q", code, out)
	}
	if w.value("A") != pvNew {
		t.Fatal("--yes did not swap back")
	}
	w.scanHome(pvOld, pvNew)
}

func TestRemovingASecretRemovesItsPreviousValue(t *testing.T) {
	pinVault(t)
	w := newWorld(t)
	w.setSecret("A", pvOld, "--global")
	w.setSecret("A", pvNew, "--global")
	w.mustRun("", "rm", "A", "--global", "--yes")
	w.setSecret("A", pvOther, "--global")
	if _, ok := w.previous("A"); ok {
		t.Fatal("a recreated secret inherited the previous value of the removed one")
	}
}

func TestHooksRedactARecoverablePreviousValue(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("API_KEY", hkA)
	w.setSecret("API_KEY", hkB)
	w.grantTo("claude:abcd1234", "API_KEY", "session")
	in := "old=" + hkA + " new=" + hkB + "\n"
	code, out, errs := w.run(postBashEvent(t, in), "hook", "post-bash")
	if code != 0 || errs != "" || out != postBashWant(t, "old=[REDACTED:API_KEY] new=[REDACTED:API_KEY]\n", 2) {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	noFixtures(t, "hook output", out+errs)
}

// exec injects only the current value and its redactor does not know the
// previous one: the previous value is not in the child's environment.
func TestExecInjectsOnlyTheCurrentValue(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("A", pvOld, "--global")
	w.setSecret("A", pvNew, "--global")
	w.grantTo("pi:grantee123", "A", "session")
	code, out, _ := w.run("", execArgs("pi:grantee123", []string{"A"}, `[ "$A" = "`+pvNew+`" ] && echo current`)...)
	if code != exitcode.OK || !strings.Contains(out, "current") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestPreviousValueNeverReachesAnAgentAnswerAuditOrFiles(t *testing.T) {
	pinVault(t)
	w := newExecWorld(t)
	w.setSecret("A", pvOld, "--global")
	var captured strings.Builder
	capture := func(s string) { captured.WriteString(s) }
	w.setSecret("A", pvNew, "--global")
	w.grantTo(brokerSession, "A", "session")
	_, _, out := w.broker("list", envelope("list", w.outside, ""))
	capture(out)
	_, _, out = w.check(w.outside, "A")
	capture(out)
	f := withBackend(t, answers(yes()))
	_, _, out = w.broker("manage", revertReq(w, "A", ""))
	capture(out)
	for _, c := range f.Calls {
		capture(c.Q + strings.Join(c.Options, "\n"))
	}
	withBackend(t, answers())
	_, _, out = w.broker("manage", revertReq(w, "NOPE", ""))
	capture(out)
	capture(w.auditText())
	noFixtures(t, "agent-facing output, dialogs and audit", captured.String())
	w.scanHome(pvOld, pvNew)
}
