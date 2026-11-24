package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/runner"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

// CONTRACT.md § check, through `broker --op check` against a real vault.

const (
	chkPlain = "TESTSECRET_check_plain_0123"
	chkPad   = " \tTESTSECRET_check_padded\n"
	chkMulti = "TESTSECRET_check_line1\nTESTSECRET_check_line2"
)

// put stores a global secret through the vault API (so a value that `set`
// would trim, or an empty one, can be stored) and grants it to the broker
// session with scope when it is not empty.
func (w *world) put(name, value, scope string) {
	w.t.Helper()
	w.putKind(vault.Global(), name, value, "")
	if scope != "" {
		w.grantTo(brokerSession, name, scope)
	}
}

func (w *world) check(cwd string, names ...string) (int, map[string]any, string) {
	w.t.Helper()
	list, _ := json.Marshal(names)
	return w.broker("check", envelope("check", cwd, `"names":`+string(list)))
}

// resultsOf indexes the results of a successful check by name.
func resultsOf(t *testing.T, m map[string]any) map[string]map[string]any {
	t.Helper()
	if m["ok"] != true {
		t.Fatalf("not a success: %v", m)
	}
	out := map[string]map[string]any{}
	for _, r := range m["results"].([]any) {
		res := r.(map[string]any)
		out[res["name"].(string)] = res
	}
	return out
}

func sameAs(res map[string]any) []string {
	var out []string
	for _, x := range res["same_as"].([]any) {
		out = append(out, x.(string))
	}
	return out
}

func checkWorld(t *testing.T) *world {
	t.Helper()
	return newExecWorld(t)
}

// Rule: each returned field with a representative value and its negative.
func TestCheckDescribesEachProperty(t *testing.T) {
	w := checkWorld(t)
	w.put("PLAIN", chkPlain, "session")
	w.put("PADDED", chkPad, "session")
	w.put("MULTI", chkMulti, "session")
	w.put("PLACEHOLDER", "Change-Me", "session")
	w.put("EMPTY", "", "session")
	w.put("ACCENTED", "contraseña", "session")
	code, m, out := w.check(w.outside, "PLAIN", "PADDED", "MULTI", "PLACEHOLDER", "EMPTY", "ACCENTED")
	if code != exitcode.OK {
		t.Fatalf("code=%d %s", code, out)
	}
	r := resultsOf(t, m)
	want := map[string]map[string]any{
		"PLAIN":       {"layer": "global", "length": float64(len(chkPlain)), "empty": false, "whitespace": false, "multiline": false, "placeholder": false, "looks_like": "text"},
		"PADDED":      {"layer": "global", "length": float64(len(chkPad)), "empty": false, "whitespace": true, "multiline": false, "placeholder": false, "looks_like": "text"},
		"MULTI":       {"layer": "global", "length": float64(len(chkMulti)), "empty": false, "whitespace": false, "multiline": true, "placeholder": false, "looks_like": "text"},
		"PLACEHOLDER": {"layer": "global", "length": float64(9), "empty": false, "whitespace": false, "multiline": false, "placeholder": true, "looks_like": "text"},
		"EMPTY":       {"layer": "global", "length": float64(0), "empty": true, "whitespace": false, "multiline": false, "placeholder": false, "looks_like": "text"},
		"ACCENTED":    {"layer": "global", "length": float64(10), "empty": false, "whitespace": false, "multiline": false, "placeholder": false, "looks_like": "text"},
	}
	for name, fields := range want {
		for k, v := range fields {
			if r[name][k] != v {
				t.Errorf("%s.%s = %v, want %v", name, k, r[name][k], v)
			}
		}
		if len(r[name]) != 9 || len(sameAs(r[name])) != 0 {
			t.Errorf("%s: result = %v", name, r[name])
		}
	}
	// The results come in request order.
	got := []string{}
	for _, x := range m["results"].([]any) {
		got = append(got, x.(map[string]any)["name"].(string))
	}
	if !slices.Equal(got, []string{"PLAIN", "PADDED", "MULTI", "PLACEHOLDER", "EMPTY", "ACCENTED"}) {
		t.Errorf("order = %v", got)
	}
	for _, v := range []string{chkPlain, strings.TrimSpace(chkPad), "contraseña"} {
		if strings.Contains(out, v) {
			t.Errorf("the answer holds a value: %s", out)
		}
	}
}

// Rule: each looks_like class and the fallbacks.
func TestCheckLooksLikeEachClass(t *testing.T) {
	w := checkWorld(t)
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl"
	pem := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----\n"
	values := []struct{ name, value, want string }{
		{"V_EMAIL", "TESTSECRET_ana@example.com", "email"},
		{"V_URL", "postgres://TESTSECRET_user:pw@db.internal:5432/app", "url"},
		{"V_JWT", jwt, "jwt"},
		{"V_PEM", pem, "pem"},
		{"V_UUID", "123e4567-e89b-12d3-a456-426614174000", "uuid"},
		{"V_HEX", "deadbeefcafe0123deadbeefcafe0123", "hex"},
		{"V_BASE64", "dXNlcjpwYXNzd29yZA==", "base64"},
		{"V_NUMBER", "5432", "number"},
		{"V_TEXT", "TESTSECRET_just_a_word", "text"},
		{"V_BADEMAIL", "TESTSECRET_ana@localhost", "text"},
		{"V_HALFPEM", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n", "text"},
		{"V_SPACED", "two words here", "text"},
	}
	var names []string
	for _, v := range values {
		w.put(v.name, v.value, "session")
		names = append(names, v.name)
	}
	code, m, out := w.check(w.outside, names...)
	if code != exitcode.OK {
		t.Fatalf("code=%d %s", code, out)
	}
	r := resultsOf(t, m)
	for _, v := range values {
		if r[v.name]["looks_like"] != v.want {
			t.Errorf("%s looks_like = %v, want %s", v.name, r[v.name]["looks_like"], v.want)
		}
	}
	if strings.Contains(out, "TESTSECRET") || strings.Contains(out, "dXNlcjpw") || strings.Contains(out, "deadbeef") {
		t.Errorf("a value reached the answer: %s", out)
	}
}

// Rule: same_as is symmetric, holds only names of this call and never reaches
// a secret that is not in it.
func TestCheckSameAsIsSymmetricAndOnlyWithinTheCall(t *testing.T) {
	w := checkWorld(t)
	w.put("LOGIN_EMAIL", chkPlain, "session")
	w.put("LOGIN_PASSWORD", chkPlain, "session")
	w.put("LOGIN_HOST", "TESTSECRET_check_other", "session")
	w.put("NOT_IN_THE_CALL", chkPlain, "session")
	w.put("NEAR_MISS", chkPlain+" ", "session")

	_, m, out := w.check(w.outside, "LOGIN_EMAIL", "LOGIN_PASSWORD", "LOGIN_HOST", "NEAR_MISS")
	r := resultsOf(t, m)
	if !slices.Equal(sameAs(r["LOGIN_EMAIL"]), []string{"LOGIN_PASSWORD"}) || !slices.Equal(sameAs(r["LOGIN_PASSWORD"]), []string{"LOGIN_EMAIL"}) {
		t.Errorf("same_as of the pair: %v / %v", r["LOGIN_EMAIL"]["same_as"], r["LOGIN_PASSWORD"]["same_as"])
	}
	if len(sameAs(r["LOGIN_HOST"])) != 0 || len(sameAs(r["NEAR_MISS"])) != 0 {
		t.Errorf("a different value is not the same: %v %v", r["LOGIN_HOST"], r["NEAR_MISS"])
	}
	if strings.Contains(out, "NOT_IN_THE_CALL") {
		t.Errorf("a secret that is not in the call was named: %s", out)
	}
	// Alone, with a name that does not hold the value, or with a third equal one.
	_, m, _ = w.check(w.outside, "LOGIN_EMAIL")
	if len(sameAs(resultsOf(t, m)["LOGIN_EMAIL"])) != 0 {
		t.Error("same_as names a secret outside the call")
	}
	_, m, _ = w.check(w.outside, "LOGIN_EMAIL", "LOGIN_PASSWORD", "NOT_IN_THE_CALL")
	r = resultsOf(t, m)
	if !slices.Equal(sameAs(r["LOGIN_EMAIL"]), []string{"LOGIN_PASSWORD", "NOT_IN_THE_CALL"}) {
		t.Errorf("three equal: %v", r["LOGIN_EMAIL"]["same_as"])
	}
}

// Rule: no grant makes the whole call grant_required, and nothing is said
// about that name or any other of the call.
func TestCheckWithoutAGrantDisclosesNothing(t *testing.T) {
	w := checkWorld(t)
	w.put("GRANTED", chkPlain, "session")
	w.put("NO_GRANT", chkPlain, "")
	for _, names := range [][]string{{"GRANTED", "NO_GRANT"}, {"NO_GRANT", "GRANTED"}, {"NO_GRANT"}} {
		before := len(w.auditEvents("refusal"))
		code, m, out := w.check(w.outside, names...)
		if code != exitcode.Refusal || refusalType(m) != "grant_required" {
			t.Fatalf("%v: code=%d %s", names, code, out)
		}
		r := m["refusal"].(map[string]any)
		if r["name"] != "NO_GRANT" || m["results"] != nil {
			t.Errorf("%v: refusal = %v", names, m)
		}
		for _, leak := range []string{"length", "looks_like", "same_as", "GRANTED\""} {
			if strings.Contains(out, leak) {
				t.Errorf("%v: the refusal says %q: %s", names, leak, out)
			}
		}
		if len(w.auditEvents("refusal"))-before != 1 {
			t.Errorf("%v: the refusal was not audited once", names)
		}
	}
	// The same message and hint exec gives for the same secret.
	_, x, _ := w.broker("exec", envelope("exec", w.outside, `"command":"true","secrets":[{"name":"NO_GRANT"}]`))
	_, c, _ := w.check(w.outside, "NO_GRANT")
	if !reflect.DeepEqual(x["refusal"], c["refusal"]) {
		t.Errorf("exec says %v, check says %v", x["refusal"], c["refusal"])
	}
	// A grant of another session does not apply.
	w.grantTo("pi:another123", "NO_GRANT", "session")
	if code, m, _ := w.check(w.outside, "NO_GRANT"); code != exitcode.Refusal || refusalType(m) != "grant_required" {
		t.Errorf("another session's grant applied: %v", m)
	}
}

// Rule: an unknown name is unknown_secret, even when the others are fine.
func TestCheckUnknownName(t *testing.T) {
	w := checkWorld(t)
	w.put("KNOWN", chkPlain, "session")
	code, m, out := w.check(w.outside, "KNOWN", "NOT_STORED")
	if code != exitcode.Refusal || refusalType(m) != "unknown_secret" || m["refusal"].(map[string]any)["name"] != "NOT_STORED" || strings.Contains(out, "length") {
		t.Fatalf("code=%d %s", code, out)
	}
}

// Rule: a once grant is never spent by a check, and a sensitive secret can be
// checked only while an unused once grant of this session exists.
func TestCheckDoesNotSpendAOnceGrant(t *testing.T) {
	w := checkWorld(t)
	w.put("ONCE_KEY", chkPlain, "once")
	exe := child(t, "leaks", "TOKEN", 0)
	run := `"command":` + jsonString(exe) + `,"secrets":[{"name":"TOKEN","from":"ONCE_KEY"}]`
	for i := 0; i < 3; i++ {
		if code, m, out := w.check(w.outside, "ONCE_KEY"); code != exitcode.OK || m["ok"] != true {
			t.Fatalf("check %d: code=%d %s", i, code, out)
		}
	}
	if code, m, out := w.broker("exec", envelope("exec", w.outside, run)); code != exitcode.OK || m["ok"] != true {
		t.Fatalf("the exec after the checks: code=%d %s", code, out)
	}
	// The grant is now spent by the exec, so the check no longer applies.
	if code, m, _ := w.check(w.outside, "ONCE_KEY"); code != exitcode.Refusal || refusalType(m) != "grant_required" {
		t.Fatalf("a spent once grant allowed a check: %v", m)
	}
}

func TestCheckSensitiveNeedsAnUnusedOnceGrant(t *testing.T) {
	w := checkWorld(t)
	w.setSecret("SENS", chkPlain, "--global", "--sensitive")
	if code, m, _ := w.check(w.outside, "SENS"); code != exitcode.Refusal || refusalType(m) != "grant_required" {
		t.Fatalf("no grant: %v", m)
	}
	w.grantTo("pi:another123", "SENS", "once")
	if code, m, _ := w.check(w.outside, "SENS"); code != exitcode.Refusal || refusalType(m) != "grant_required" {
		t.Fatalf("a once grant of another session: %v", m)
	}
	w.grantTo(brokerSession, "SENS", "once")
	for i := 0; i < 2; i++ {
		code, m, out := w.check(w.outside, "SENS")
		if code != exitcode.OK || resultsOf(t, m)["SENS"]["length"] != float64(len(chkPlain)) {
			t.Fatalf("with an unused once grant, check %d: %s", i, out)
		}
	}
}

// Rule: the project layer comes first and its grant is the one that counts.
func TestCheckResolvesTheProjectLayerFirst(t *testing.T) {
	w := checkWorld(t)
	w.setSecret("DB_PASS", "TESTSECRET_global_value_99", "--global")
	w.inRepo()
	w.setSecret("DB_PASS", "TESTSECRET_project", "--project")
	w.outRepo()
	// Only the global one is granted: from the repository the project secret
	// (not granted) is the one that resolves.
	w.grantTo(brokerSession, "DB_PASS", "session", "--global")
	if code, m, _ := w.check(w.outside, "DB_PASS"); code != exitcode.OK || resultsOf(t, m)["DB_PASS"]["layer"] != "global" {
		t.Fatalf("outside the repository: %v", m)
	}
	if code, m, _ := w.check(w.repo, "DB_PASS"); code != exitcode.Refusal || refusalType(m) != "grant_required" {
		t.Fatalf("in the repository the ungranted project secret resolves: %v", m)
	}
	w.inRepo()
	w.grantTo(brokerSession, "DB_PASS", "session", "--project")
	w.outRepo()
	_, m, _ := w.check(w.repo, "DB_PASS")
	r := resultsOf(t, m)["DB_PASS"]
	if r["layer"] != "project" || r["length"] != float64(len("TESTSECRET_project")) {
		t.Fatalf("project secret = %v", r)
	}
}

// Rule: one audit record per call with the names, never a result field; the
// refusals are audited as exec's are.
func TestCheckAuditRecord(t *testing.T) {
	w := checkWorld(t)
	w.put("AUD_A", chkPlain, "session")
	w.put("AUD_B", chkPlain, "session")
	before := len(w.auditEvents(audit.EventCheck))
	if code, _, out := w.check(w.outside, "AUD_A", "AUD_B"); code != exitcode.OK {
		t.Fatal(out)
	}
	recs := w.auditEvents(audit.EventCheck)
	if len(recs)-before != 1 {
		t.Fatalf("%d check records, want 1", len(recs)-before)
	}
	r := recs[len(recs)-1]
	if !slices.Equal(r.Names, []string{"AUD_A", "AUD_B"}) || r.Session != brokerSession || r.Layer != "global" || r.By != "agent" {
		t.Fatalf("record = %+v", r)
	}
	if r.Command != "" || r.Detail != "" || r.Outcome != "" || r.ExitCode != nil {
		t.Fatalf("a check record carries more than names: %+v", r)
	}
	raw, _ := json.Marshal(r)
	for _, bad := range []string{"length", "same_as", "looks_like", "AUD_A\":"} {
		if strings.Contains(string(raw), bad) {
			t.Errorf("the record carries a result: %s", raw)
		}
	}
	noFixtures(t, "audit log", w.auditText())
	if v := audit.ValidEvent("check"); !v {
		t.Error("check is not an audit event")
	}
	// An unknown name is a refusal record, as for exec.
	n := len(w.auditEvents("refusal"))
	w.check(w.outside, "NOT_STORED")
	if len(w.auditEvents("refusal"))-n != 1 {
		t.Error("the unknown_secret refusal was not audited")
	}
}

// The capability row.
func TestCheckCapabilityRow(t *testing.T) {
	w := checkWorld(t)
	_, m, _ := w.broker("capabilities", envelope("capabilities", w.outside, ""))
	if m["secret_check"] != float64(1) || m["capabilities"] != "1.1" {
		t.Fatalf("capabilities = %v", m)
	}
	if !slices.Contains(toStrings(m["ops"]), "check") {
		t.Fatalf("ops = %v", m["ops"])
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// An unlock dialog may open (as for list), and nothing else does.
func TestCheckOnALockedVaultAsksForTheUnlockOnly(t *testing.T) {
	w := grantedLockedWorld(t)
	f := withBackend(t, answers(val(fxPass)))
	code, m, out := w.broker("check", envelope("check", w.repo, `"names":["A"]`))
	if code != exitcode.OK || resultsOf(t, m)["A"]["length"] != float64(len(fxAgentValue)) {
		t.Fatalf("code=%d %s", code, out)
	}
	if len(f.Calls) != 1 || f.Calls[0].Kind != "passphrase" {
		t.Fatalf("dialogs = %+v, want the unlock dialog only", f.Calls)
	}
	if got := w.auditUnlocks(); len(got) == 0 || !slices.Equal(got[len(got)-1].Names, []string{"A"}) {
		t.Errorf("unlock audit = %+v", got)
	}
	if fmt.Sprintf("%+v", f.Calls) != strings.ReplaceAll(fmt.Sprintf("%+v", f.Calls), fxAgentValue, "") {
		t.Errorf("the dialog transcript holds the value: %+v", f.Calls)
	}
	// Declined: the vault stays locked and nothing is described.
	withBackend(t, answers(cancel()))
	code, m, out = w.broker("check", envelope("check", w.repo, `"names":["A"]`))
	if code != exitcode.Locked || refusalType(m) != "vault_locked" || strings.Contains(out, "length") {
		t.Fatalf("declined unlock: code=%d %s", code, out)
	}
}

// Over MCP: the tool answers the same JSON and an error result for a refusal.
func TestCheckOverMCP(t *testing.T) {
	w := checkWorld(t)
	w.put("MCP_A", chkPlain, "")
	w.put("MCP_B", chkPlain, "")
	w.grantTo(mcpSession, "MCP_A", "session")
	w.grantTo(mcpSession, "MCP_B", "session")
	s := w.startMCP()
	m, isErr := s.call(30, "secret_check", map[string]any{"names": []any{"MCP_A", "MCP_B"}})
	if isErr || m["ok"] != true {
		t.Fatalf("check = %v", m)
	}
	r := resultsOf(t, m)
	if !slices.Equal(sameAs(r["MCP_A"]), []string{"MCP_B"}) || r["MCP_A"]["length"] != float64(len(chkPlain)) {
		t.Fatalf("results = %v", m["results"])
	}
	w.put("MCP_C", chkPlain, "")
	m, isErr = s.call(31, "secret_check", map[string]any{"names": []any{"MCP_A", "MCP_C"}})
	if !isErr || refusalType(m) != "grant_required" || m["refusal"].(map[string]any)["name"] != "MCP_C" {
		t.Fatalf("no grant over MCP: %v", m)
	}
	out, errs := s.finish()
	noFixtures(t, "mcp transcript", out+errs)
}

// Leak battery (docs/TESTING.md § Leak battery): no fixture, raw or encoded,
// in any answer, refusal, audit line or file of the home.
func TestCheckLeakBattery(t *testing.T) {
	w := checkWorld(t)
	w.put("LEAK_A", xv, "session")
	w.put("LEAK_B", xv, "session")
	w.put("LEAK_ONCE", xg, "once")
	w.put("LEAK_NOGRANT", xp, "")
	var captured strings.Builder
	for _, names := range [][]string{{"LEAK_A", "LEAK_B"}, {"LEAK_A", "LEAK_ONCE"}, {"LEAK_NOGRANT"}, {"LEAK_A", "NOT_STORED"}, {"LEAK_A", "LEAK_A"}, {"bad name"}} {
		list, _ := json.Marshal(names)
		for _, op := range []string{"check"} {
			_, out, errs := w.run(envelope(op, w.outside, `"names":`+string(list)), "broker", "--op", op)
			captured.WriteString(out + errs)
		}
	}
	s := w.startMCP()
	for i, names := range [][]any{{"LEAK_A", "LEAK_B"}, {"LEAK_NOGRANT"}} {
		m, _ := s.call(40+i, "secret_check", map[string]any{"names": names})
		b, _ := json.Marshal(m)
		captured.Write(b)
	}
	o, e := s.finish()
	captured.WriteString(o + e)
	captured.WriteString(w.auditText())

	needles := map[string][]string{}
	for _, v := range []string{xv, xg, xp} {
		needles[v] = []string{v, base64.StdEncoding.EncodeToString([]byte(v)), base64.URLEncoding.EncodeToString([]byte(v)), url.QueryEscape(v)}
	}
	scan := func(where string, data []byte) {
		for v, encs := range needles {
			for _, n := range encs {
				if strings.Contains(string(data), n) {
					t.Errorf("%s holds a fixture (%.12s...): %q", where, v, n)
				}
			}
		}
	}
	scan("captured output", []byte(captured.String()))
	if !strings.Contains(captured.String(), `"same_as":["LEAK_B"]`) {
		t.Error("the battery never saw a successful check")
	}
	if err := filepath.WalkDir(w.home, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		scan(filepath.Base(p), b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// THREAT_MODEL R23: what a check discloses is already available to a caller
// with the same grants inside exec, so the dump guard lets the comparison and
// the length through and the answers agree with check's.
func TestCheckDisclosesNothingExecCouldNot(t *testing.T) {
	if !runner.PosixShellAvailable() {
		t.Skip("no POSIX shell")
	}
	w := checkWorld(t)
	w.put("SAME_A", chkPlain, "session")
	w.put("SAME_B", chkPlain, "session")
	w.put("OTHER_C", "TESTSECRET_check_other_value", "session")
	run := func(cmd string) map[string]any {
		t.Helper()
		_, m, _ := w.broker("exec", envelope("exec", w.outside, `"command":`+jsonString(cmd)+`,"shell":"sh","secrets":[{"name":"SAME_A"},{"name":"SAME_B"},{"name":"OTHER_C"}]`))
		if m["ok"] != true {
			t.Fatalf("%q: %v", cmd, m)
		}
		return m
	}
	if m := run(`[ "$SAME_A" = "$SAME_B" ]`); m["exit_code"] != float64(0) {
		t.Errorf("equal pair: %v", m)
	}
	if m := run(`[ "$SAME_A" = "$OTHER_C" ]`); m["exit_code"] == float64(0) {
		t.Errorf("different pair: %v", m)
	}
	m := run(`printf %s ${#SAME_A}`)
	_, c, _ := w.check(w.outside, "SAME_A")
	if m["stdout"] != strconv.Itoa(int(resultsOf(t, c)["SAME_A"]["length"].(float64))) {
		t.Errorf("exec length %v, check length %v", m["stdout"], c["results"])
	}
}
