package cli

import (
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/prompt/prompttest"
)

// S4 of odd/tasks/actionable-refusals.md: the refusals the broker answers
// carry their fixed hint, and a hint never holds a value.

func refusalHint(m map[string]any) string {
	r, _ := m["refusal"].(map[string]any)
	s, _ := r["hint"].(string)
	return s
}

const (
	hintNoGrant       = "Call secret_request for this name to ask the user for a grant, then retry once."
	hintGrantNotApply = "A grant exists but does not apply here; call secret_request to ask the user for a new one."
	hintUnknown       = "Call secret_list to see the stored names; if it is missing, call secret_request with fields to ask the user to store it."
	hintLocked        = "A QBit Vault tool call such as secret_list opens the unlock dialog; call it again once the user has unlocked."
	hintNoDialog      = "No unlock dialog could be shown; ask the user to run 'qbit-vault unlock' in their terminal, then retry."
)

func TestGrantRequiredHintSaysWhetherAGrantExists(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_hint_a\n", "set", "A", "--global", "--stdin")
	code, m := w.execIn(w.outside)
	if code != exitcode.Refusal || refusalType(m) != "grant_required" || refusalHint(m) != hintNoGrant {
		t.Fatalf("no grant: code=%d m=%v", code, m)
	}

	w = newWorld(t)
	w.approveProjectGrant()
	code, m = w.execIn(w.outside)
	if refusalType(m) != "grant_required" || refusalHint(m) != hintGrantNotApply {
		t.Fatalf("grant for another directory: code=%d m=%v", code, m)
	}
}

func TestUnknownSecretHintOverExec(t *testing.T) {
	w := newWorld(t)
	code, m, out := w.broker("exec", envelope("exec", w.outside, `"command":"x","secrets":[{"name":"NOPE"}]`))
	if code != exitcode.Refusal || refusalType(m) != "unknown_secret" || refusalHint(m) != hintUnknown {
		t.Fatalf("code=%d out=%s", code, out)
	}
}

func TestVaultLockedHints(t *testing.T) {
	w := lockedWorld(t)
	withBackend(t, answers(cancel()))
	_, m, _ := w.broker("list", envelope("list", w.outside, ""))
	if lockedRefusalMessage(t, m); refusalHint(m) != hintLocked {
		t.Errorf("cancelled dialog: hint %q", refusalHint(m))
	}
	withBackend(t, &prompttest.Fake{Unavailable: true})
	_, m, _ = w.broker("list", envelope("list", w.outside, ""))
	if got := lockedRefusalMessage(t, m); got != wantNoDialog || refusalHint(m) != hintNoDialog {
		t.Errorf("no dialog: message %q hint %q", got, refusalHint(m))
	}
}

// Over `exec --json` the refusal is the same envelope, hint included.
func TestExecJSONRefusalCarriesTheHint(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_hint_j\n", "set", "A", "--global", "--stdin")
	_, out, errs := w.run("", append([]string{"--json"}, execArgs(brokerSession, []string{"A"}, "true")...)...)
	if !strings.Contains(out, `"hint":"`+hintNoGrant+`"`) {
		t.Fatalf("out=%q err=%q", out, errs)
	}
	noFixtures(t, "exec --json", out+errs)
}

// Human output of a refusal stays the message only.
func TestHumanRefusalOutputDoesNotPrintTheHint(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_hint_h\n", "set", "A", "--global", "--stdin")
	_, out, errs := w.run("", execArgs(brokerSession, []string{"A"}, "true")...)
	if strings.Contains(out+errs, "secret_request for this name") {
		t.Fatalf("hint printed: out=%q err=%q", out, errs)
	}
}
