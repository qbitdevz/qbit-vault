package cli

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/prompt/prompttest"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
)

// Issue #62, part 3 (odd/tasks/issues-61-65-dialogs.md T8): after a value is
// typed and before it is stored, the user is asked once when it equals the
// value it replaces, the value of another secret in the same layer, or
// another field typed in the same form. Names only, never a value or a length.

const (
	sv        = "TESTSECRET_same_0123456789"
	svOther   = "TESTSECRET_different_987654"
	saveTail  = "That is often a mistake (the wrong field, or something that did not change). Save it anyway?"
	saveTailE = "Suele ser un error (un campo equivocado, o algo que no cambió). ¿Quieres guardarlo de todos modos?"
)

var remainingRE = regexp.MustCompile(`"remaining":"[^"]*"`)

// grantList is the live grants, without the time left, which changes by itself.
func (w *world) grantList() string {
	w.t.Helper()
	return remainingRE.ReplaceAllString(w.grantsState(), `"remaining":""`)
}

// noValueInDialogs fails when a dialog shows a value or its length.
func noValueInDialogs(t *testing.T, calls []prompttest.Call, values ...string) {
	t.Helper()
	for _, c := range calls {
		if c.Kind != "choose" && c.Kind != "confirm" {
			continue
		}
		text := c.Q + "\n" + strings.Join(c.Options, "\n")
		for _, v := range values {
			if strings.Contains(text, v) || strings.Contains(text, strconv.Itoa(len(v))) || strings.Contains(text, v[len("TESTSECRET_"):]) {
				t.Errorf("a dialog shows the value or its length (%d): %q", len(v), text)
			}
		}
	}
}

func sameDialog(t *testing.T, c prompttest.Call, q string) {
	t.Helper()
	if c.Kind != "choose" || c.Q != q {
		t.Fatalf("dialog = %+v, want the question %q", c, q)
	}
	if len(c.Options) != 2 || c.Options[0] != "Save anyway" || c.Options[1] != "Cancel" || c.Default != 1 {
		t.Fatalf("options = %q default %d", c.Options, c.Default)
	}
}

// ---- CLI set ----

func TestSetOverwriteWithTheSameValueAsksFirst(t *testing.T) {
	w := newWorld(t)
	w.setSecret("A", sv, "--global")
	f := withBackend(t, answers(val(sv), pick(0)))
	code, out, errs := w.run("", "set", "A", "--global")
	if code != exitcode.OK || out != "stored A (global)\n" || errs != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 2 || f.Calls[0].Kind != "secret" {
		t.Fatalf("calls = %+v", f.Calls)
	}
	sameDialog(t, f.Calls[1], "The new value of A is the same as the one it replaces.\n"+saveTail)
	noValueInDialogs(t, f.Calls, sv)
	if w.value("A") != sv {
		t.Fatal("not stored after the user said save anyway")
	}
	noFixtures(t, "output and audit", out+errs+w.auditText())
}

func TestSetOverwriteWithTheSameValueDeclinedStoresNothing(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("A", sv, "--global")
	w.grantTo("pi:grantee123", "A", "session")
	before, grantsBefore := w.snapshot(), w.grantList()
	auditBefore := len(w.auditEvents("capture"))
	withBackend(t, answers(val(sv), pick(1)))
	code, out, errs := w.run("", "set", "A", "--global")
	if code != exitcode.Failure || out != "" || errs != msgCancelled {
		t.Fatalf("code=%d out=%q err=%q: a decline is reported like a cancelled capture", code, out, errs)
	}
	if w.snapshot() != before || w.grantList() != grantsBefore {
		t.Fatal("a declined warning changed the vault or the grants")
	}
	if len(w.auditEvents("capture")) != auditBefore {
		t.Fatal("a declined capture was audited as stored")
	}
}

func TestSetNewValueEqualToAnotherSecretInTheLayer(t *testing.T) {
	w := newWorld(t)
	w.setSecret("OTHER_TOKEN", sv, "--global")
	f := withBackend(t, answers(val(sv), pick(0)))
	if code, out, errs := w.run("", "set", "A", "--global"); code != exitcode.OK {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	sameDialog(t, f.Calls[1], "The value of A is the same as the value of OTHER_TOKEN.\n"+saveTail)
	noValueInDialogs(t, f.Calls, sv)
	if w.value("A") != sv {
		t.Fatal("not stored")
	}
	// Declined: nothing is stored for it.
	w.mustRun("", "rm", "A", "--global", "--yes")
	before := w.snapshot()
	withBackend(t, answers(val(sv), pick(1)))
	if code, _, errs := w.run("", "set", "A", "--global"); code != exitcode.Failure || errs != msgCancelled {
		t.Fatalf("declined: code=%d err=%q", code, errs)
	}
	if w.snapshot() != before {
		t.Fatal("a declined warning stored the value")
	}
}

func TestSetWarningNamesEveryMatchInOneDialog(t *testing.T) {
	w := newWorld(t)
	w.setSecret("A", sv, "--global")
	w.setSecret("B_TOKEN", sv, "--global")
	w.setSecret("C_TOKEN", sv, "--global")
	w.setSecret("D_TOKEN", svOther, "--global")
	f := withBackend(t, answers(val(sv), pick(0)))
	if code, _, errs := w.run("", "set", "A", "--global"); code != exitcode.OK {
		t.Fatalf("code=%d err=%q", code, errs)
	}
	if len(f.Calls) != 2 {
		t.Fatalf("%d dialogs, want the value and one warning", len(f.Calls))
	}
	sameDialog(t, f.Calls[1], "The new value of A is the same as the one it replaces.\nThe value of A is the same as the value of B_TOKEN, C_TOKEN.\n"+saveTail)
}

// The layer matters: a project secret and a global one with the same value are
// not a mistake the warning is about.
func TestSetSameValueInAnotherLayerAsksNothing(t *testing.T) {
	w := newWorld(t)
	w.setSecret("G_TOKEN", sv, "--global")
	w.inRepo()
	w.setSecret("P_TOKEN", svOther, "--project")
	f := withBackend(t, answers(val(sv)))
	if code, out, errs := w.run("", "set", "A", "--project"); code != exitcode.OK {
		t.Fatalf("a global match asked about a project value: code=%d out=%q err=%q calls=%+v", code, out, errs, f.Calls)
	}
	f = withBackend(t, answers(val(svOther)))
	if code, out, errs := w.run("", "set", "B_PROJ", "--global"); code != exitcode.OK {
		t.Fatalf("a project match asked about a global value: code=%d out=%q err=%q calls=%+v", code, out, errs, f.Calls)
	}
	if len(f.Calls) != 1 {
		t.Fatalf("calls = %+v", f.Calls)
	}
}

func TestSetWithADifferentValueAsksNothingMore(t *testing.T) {
	w := newWorld(t)
	w.setSecret("A", sv, "--global")
	w.setSecret("B_TOKEN", svOther, "--global")
	f := withBackend(t, answers(val("TESTSECRET_brand_new_value")))
	if code, _, errs := w.run("", "set", "A", "--global"); code != exitcode.OK {
		t.Fatalf("code=%d err=%q", code, errs)
	}
	if len(f.Calls) != 1 {
		t.Fatalf("calls = %+v, want only the value", f.Calls)
	}
}

// The value-issue question keeps working and comes first; the warning is
// about the value that is going to be stored.
func TestSetValueIssueComesBeforeTheSameValueWarning(t *testing.T) {
	w := newWorld(t)
	w.setSecret("A", sv, "--global")
	f := withBackend(t, answers(val(`"`+sv+`"`), pick(0), pick(0)))
	if code, out, errs := w.run("", "set", "A", "--global"); code != exitcode.OK {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 3 || !strings.HasPrefix(f.Calls[1].Q, "The value of A has quotes around it.") {
		t.Fatalf("calls = %+v", f.Calls)
	}
	sameDialog(t, f.Calls[2], "The new value of A is the same as the one it replaces.\n"+saveTail)
	// Kept as typed, the quotes make it a different value: no warning.
	f = withBackend(t, answers(val(`"`+sv+`"`), pick(1)))
	if code, _, errs := w.run("", "set", "A", "--global"); code != exitcode.OK {
		t.Fatalf("code=%d err=%q", code, errs)
	}
	if len(f.Calls) != 2 || w.value("A") != `"`+sv+`"` {
		t.Fatalf("calls = %+v, stored %q", f.Calls, w.value("A"))
	}
}

func TestSetStdinNeverAsksTheSameValueQuestion(t *testing.T) {
	w := newWorld(t)
	w.setSecret("A", sv, "--global")
	w.setSecret("B_TOKEN", sv, "--global") // the same value twice, scripted
	f := withBackend(t, answers())
	if code, out, errs := w.run(sv+"\n", "set", "A", "--stdin", "--global"); code != exitcode.OK || out != "stored A (global)\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("a scripted set opened a dialog: %+v", f.Calls)
	}
}

func TestSetSameValueWarningInSpanish(t *testing.T) {
	w := newWorld(t)
	w.setSecret("A", sv, "--global")
	w.setSecret("B_TOKEN", sv, "--global")
	f := withBackend(t, answers(val(sv), pick(0)))
	code, _, errs := w.runEnv(map[string]string{"QBIT_VAULT_LOCALE": "es"}, "", "set", "A", "--global")
	if code != exitcode.OK {
		t.Fatalf("code=%d err=%q", code, errs)
	}
	c := f.Calls[1]
	want := "El nuevo valor de A es igual al que reemplaza.\nEl valor de A es igual al valor de B_TOKEN.\n" + saveTailE
	if c.Q != want || len(c.Options) != 2 || c.Options[0] != "Guardar de todos modos" || c.Options[1] != "Cancelar" || c.Default != 1 {
		t.Fatalf("dialog = %+v", c)
	}
	noValueInDialogs(t, f.Calls, sv)
}

// ---- secret_request ----

func requestNamed(cwd, name, extra string) string {
	return envelope("request", cwd, `"name":"`+name+`","reason":"`+reqReason+`"`+extra)
}

func TestRequestValueEqualToAnotherSecretAsksTheUser(t *testing.T) {
	w := newWorld(t)
	w.setSecret("OTHER_TOKEN", sv, "--global")
	// What the agent gets for a clean request, to compare with.
	withBackend(t, answers(val(svOther), pick(0)))
	_, _, clean := w.broker("request", requestNamed(w.outside, "CLEAN_ONE", ""))
	auditBefore := len(w.auditRecords())

	f := withBackend(t, answers(val(sv), pick(0), pick(0)))
	code, m, out := w.broker("request", requestNamed(w.outside, "A", ""))
	if code != exitcode.OK || m["ok"] != true {
		t.Fatalf("code=%d out=%s", code, out)
	}
	if len(f.Calls) != 3 || f.Calls[0].Kind != "secret" || f.Calls[2].Kind != "choose" {
		t.Fatalf("calls = %+v", f.Calls)
	}
	sameDialog(t, f.Calls[1], "The value of A is the same as the value of OTHER_TOKEN.\n"+saveTail)
	noValueInDialogs(t, f.Calls, sv)
	if w.value("A") != sv {
		t.Fatal("not stored after save anyway")
	}
	// The agent learns nothing: the answer has the usual shape and no name but its own.
	if strings.Contains(out, "OTHER_TOKEN") || strings.Contains(out, "same") ||
		shape(strings.ReplaceAll(out, "A", "X")) != shape(strings.ReplaceAll(clean, "CLEAN_ONE", "X")) {
		t.Fatalf("the agent's answer differs from a clean request's:\n%s\n%s", out, clean)
	}
	noFixtures(t, "agent answer and audit", out+w.auditText())
	for _, r := range w.auditRecords()[auditBefore:] {
		if slices.Contains(r.Names, "OTHER_TOKEN") {
			t.Fatalf("the audit log names the secret that matched: %+v", r)
		}
	}
}

func TestRequestSameValueDeclinedIsUserDeclinedAndStoresNothing(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("OTHER_TOKEN", sv, "--global")
	w.grantTo(brokerSession, "OTHER_TOKEN", "session")
	before, grantsBefore := w.snapshot(), w.grantList()
	auditBefore := len(w.auditRecords())
	withBackend(t, answers(val(sv), pick(1)))
	code, _, out := w.broker("request", requestNamed(w.outside, "A", ""))
	want := refusal.New(refusal.UserDeclined, "A")
	if code != exitcode.Refusal || out != jsonOf(t, want.Envelope()) {
		t.Fatalf("code=%d out=%s, want the usual user_declined %s", code, out, jsonOf(t, want.Envelope()))
	}
	if w.snapshot() != before || w.grantList() != grantsBefore {
		t.Fatal("a declined warning changed the vault or the grants")
	}
	if strings.Contains(out, "OTHER_TOKEN") {
		t.Fatal("the matched name reached the agent")
	}
	for _, r := range w.auditRecords()[auditBefore:] {
		if slices.Contains(r.Names, "OTHER_TOKEN") {
			t.Fatalf("the audit log names the secret that matched: %+v", r)
		}
	}
	// The cooldown is the one a declined capture always starts, no harsher.
	withBackend(t, answers(val(svOther), pick(0)))
	if _, m, _ := w.broker("request", requestNamed(w.outside, "A", "")); refusalType(m) != "rate_limited" {
		t.Fatalf("second request = %v, want the usual cooldown", m)
	}
	withBackend(t, answers(val(svOther), pick(0)))
	if code, m, _ := w.broker("request", requestNamed(w.outside, "OTHER_NAME", "")); code != exitcode.OK {
		t.Fatalf("another name was cooled down too: %v", m)
	}
}

func TestRequestFormFieldsTypedTwiceAskOnceAndTextFieldsCount(t *testing.T) {
	w := newWorld(t)
	fields := `"fields":[{"name":"DB_HOST","kind":"text"},{"name":"DB_USER","kind":"text"},{"name":"DB_PASSWORD"}]`
	req := func() string {
		return envelope("request", w.outside, fields+`,"reason":"run the shop-api migrations"`)
	}
	// Two text fields and a password typed the same: one dialog for the form.
	f := withBackend(t, answers(val("db.internal"), val("db.internal"), val("db.internal"), pick(0), pick(0)))
	code, m, out := w.broker("request", req())
	if code != exitcode.OK || m["ok"] != true {
		t.Fatalf("code=%d out=%s", code, out)
	}
	if len(f.Calls) != 5 {
		t.Fatalf("calls = %+v", f.Calls)
	}
	sameDialog(t, f.Calls[3], "The value of DB_HOST is the same as the value of DB_USER, DB_PASSWORD.\nThe value of DB_USER is the same as the value of DB_PASSWORD.\n"+saveTail)
	if w.value("DB_HOST") != "db.internal" || w.value("DB_PASSWORD") != "db.internal" {
		t.Fatal("not stored")
	}
}

func TestRequestFormSameValueDeclinedStoresNoField(t *testing.T) {
	w := newWorld(t)
	before := w.snapshot()
	fields := `"fields":[{"name":"LOGIN_EMAIL"},{"name":"LOGIN_PASSWORD"}]`
	withBackend(t, answers(val(sv), val(sv), pick(1)))
	code, m, out := w.broker("request", envelope("request", w.outside, fields+`,"reason":"log in to the staging panel"`))
	if code != exitcode.Refusal || refusalType(m) != "user_declined" {
		t.Fatalf("code=%d out=%s", code, out)
	}
	if w.snapshot() != before {
		t.Fatal("a field of a declined form was stored")
	}
	if strings.Contains(out, "LOGIN_PASSWORD") && !strings.Contains(out, `"name":"LOGIN_EMAIL"`) {
		t.Fatalf("the refusal names the wrong field: %s", out)
	}
}

// A different value in each field asks nothing more, and a stored secret that
// is not typed again is not compared with itself.
func TestRequestFormWithDistinctValuesAsksNothingMore(t *testing.T) {
	w := newWorld(t)
	w.mustRun(sv+"\n", "set", "DB_USER", "--stdin") // stored, not typed
	f := withBackend(t, answers(val("db.internal"), val("TESTSECRET_db_password"), pick(0)))
	code, _, out := w.broker("request", envelope("request", w.outside, dbFields+`,"reason":"run the shop-api migrations"`))
	if code != exitcode.OK || len(f.Calls) != 3 {
		t.Fatalf("code=%d calls=%+v out=%s", code, f.Calls, out)
	}
}

func TestRequestSameValueIsComparedInTheLayerTheValueIsSavedIn(t *testing.T) {
	w := newWorld(t)
	w.setSecret("G_TOKEN", sv, "--global")
	w.inRepo()
	w.setSecret("P_TOKEN", svOther, "--project")
	w.outRepo()
	req := func(name string) string {
		return envelope("request", w.repo, `"name":"`+name+`","reason":"`+reqReason+`","suggested_layer":"project"`)
	}
	// Saved in the project layer, equal to a global secret: not the same layer.
	f := withBackend(t, answers(pick(1), val(sv), pick(0)))
	if code, m, _ := w.broker("request", req("A")); code != exitcode.OK {
		t.Fatalf("m=%v", m)
	}
	if len(f.Calls) != 3 {
		t.Fatalf("a global match asked about a project value: %+v", f.Calls)
	}
	// Equal to a project secret, saved in the project layer: the warning.
	f = withBackend(t, answers(pick(1), val(svOther), pick(0), pick(0)))
	if code, m, _ := w.broker("request", req("B_NEW")); code != exitcode.OK {
		t.Fatalf("m=%v", m)
	}
	if len(f.Calls) != 4 || !strings.HasPrefix(f.Calls[2].Q, "The value of B_NEW is the same as the value of P_TOKEN.") {
		t.Fatalf("calls = %+v", f.Calls)
	}
}

func TestRequestSameValueWarningInSpanish(t *testing.T) {
	w := newWorld(t)
	w.setSecret("OTHER_TOKEN", sv, "--global")
	f := withBackend(t, answers(val(sv), pick(0), pick(0)))
	code, _, out := w.broker("request", requestNamed(w.outside, "A", `,"locale":"es"`))
	if code != exitcode.OK {
		t.Fatalf("code=%d out=%s", code, out)
	}
	c := f.Calls[1]
	if c.Q != "El valor de A es igual al valor de OTHER_TOKEN.\n"+saveTailE || c.Options[0] != "Guardar de todos modos" || c.Options[1] != "Cancelar" {
		t.Fatalf("dialog = %+v", c)
	}
	noValueInDialogs(t, f.Calls, sv)
}

// The value-issue question still comes first in a request and does not hide
// the warning.
func TestRequestValueIssueThenSameValue(t *testing.T) {
	w := newWorld(t)
	w.setSecret("OTHER_TOKEN", sv, "--global")
	f := withBackend(t, answers(val(`'`+sv+`'`), pick(0), pick(0), pick(0)))
	if code, m, _ := w.broker("request", requestNamed(w.outside, "A", "")); code != exitcode.OK {
		t.Fatalf("m=%v", m)
	}
	if len(f.Calls) != 4 || !strings.HasPrefix(f.Calls[1].Q, "The value of A has quotes around it.") || !strings.HasPrefix(f.Calls[2].Q, "The value of A is the same as") {
		t.Fatalf("calls = %+v", f.Calls)
	}
}

// ---- secret_manage replace ----

func TestManageReplaceWithTheSameValueAsksFirst(t *testing.T) {
	w := newWorld(t)
	w.setSecret("A", sv, "--global")
	f := withBackend(t, answers(pick(0), val(sv), pick(0)))
	code, m, out := w.broker("manage", manageReq(w.outside, `"action":"replace","name":"A","layer":"global"`))
	if code != exitcode.OK || m["ok"] != true {
		t.Fatalf("code=%d out=%s", code, out)
	}
	if len(f.Calls) != 3 || f.Calls[0].Kind != "choose" || f.Calls[1].Kind != "secret" {
		t.Fatalf("calls = %+v", f.Calls)
	}
	sameDialog(t, f.Calls[2], "The new value of A is the same as the one it replaces.\n"+saveTail)
	noValueInDialogs(t, f.Calls[2:], sv)
	if w.value("A") != sv {
		t.Fatal("not stored")
	}
	if err := w.execCheck("A", brokerSession); err != nil {
		t.Fatalf("the permission picked in the replace decision was lost: %v", err)
	}
}

func TestManageReplaceSameValueDeclinedKeepsValueAndGrants(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("A", sv, "--global")
	w.setSecret("OTHER_TOKEN", svOther, "--global")
	w.grantTo("pi:grantee123", "A", "session")
	before, grantsBefore := w.snapshot(), w.grantList()
	withBackend(t, answers(pick(0), val(sv), pick(1)))
	code, m, out := w.broker("manage", manageReq(w.outside, `"action":"replace","name":"A","layer":"global"`))
	if code != exitcode.Refusal || out != jsonOf(t, refusal.New(refusal.UserDeclined, "A").Envelope()) {
		t.Fatalf("code=%d m=%v out=%s", code, m, out)
	}
	if w.snapshot() != before || w.grantList() != grantsBefore {
		t.Fatal("a declined warning changed the value or dropped the old grants")
	}
	// Same cooldown as any declined manage.
	withBackend(t, answers(pick(0), val(svOther)))
	if _, m, _ := w.broker("manage", manageReq(w.outside, `"action":"replace","name":"A","layer":"global"`)); refusalType(m) != "rate_limited" {
		t.Fatalf("second replace = %v", m)
	}
}

func TestManageReplaceWithTheValueOfAnotherSecret(t *testing.T) {
	w := newWorld(t)
	w.setSecret("A", svOther, "--global")
	w.setSecret("OTHER_TOKEN", sv, "--global")
	f := withBackend(t, answers(pick(0), val(sv), pick(0)))
	if code, m, _ := w.broker("manage", manageReq(w.outside, `"action":"replace","name":"A","layer":"global"`)); code != exitcode.OK {
		t.Fatalf("m=%v", m)
	}
	sameDialog(t, f.Calls[2], "The value of A is the same as the value of OTHER_TOKEN.\n"+saveTail)
	if w.value("A") != sv {
		t.Fatal("not stored")
	}
}

// A replace with a different value asks nothing more (existing behavior).
func TestManageReplaceWithANewValueAsksNothingMore(t *testing.T) {
	w := newWorld(t)
	w.setSecret("A", sv, "--global")
	f := withBackend(t, answers(pick(0), val("TESTSECRET_brand_new_value")))
	if code, m, _ := w.broker("manage", manageReq(w.outside, `"action":"replace","name":"A","layer":"global"`)); code != exitcode.OK {
		t.Fatalf("m=%v", m)
	}
	if len(f.Calls) != 2 {
		t.Fatalf("calls = %+v", f.Calls)
	}
}

func TestManageReplaceSameValueWarningInSpanish(t *testing.T) {
	w := newWorld(t)
	w.setSecret("A", sv, "--global")
	f := withBackend(t, answers(pick(0), val(sv), pick(0)))
	if code, m, _ := w.broker("manage", manageReq(w.outside, `"action":"replace","name":"A","layer":"global","locale":"es"`)); code != exitcode.OK {
		t.Fatalf("m=%v", m)
	}
	c := f.Calls[2]
	if c.Q != "El nuevo valor de A es igual al que reemplaza.\n"+saveTailE || c.Options[0] != "Guardar de todos modos" {
		t.Fatalf("dialog = %+v", c)
	}
}
