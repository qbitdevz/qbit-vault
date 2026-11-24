package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

// Issue #62 part 4 (odd/tasks/issues-61-65-dialogs.md T10): the last use of a
// stored record, kept in usage.enc, never in the vault.

const usSession = "pi:usage12345"

func usageWorld(t *testing.T) *world {
	t.Helper()
	w := newExecWorld(t)
	w.setSecret("A", "TESTSECRET_usage_a_0123456789", "--global")
	w.grantTo(usSession, "A", "session")
	w.grantTo(brokerSession, "A", "session")
	return w
}

func (w *world) execA(code int) (int, string, string) {
	w.t.Helper()
	return w.run("", execArgs(usSession, []string{"A"}, child(w.t, "args", "", code))...)
}

func (w *world) usageOf(name string) map[string]any {
	w.t.Helper()
	return w.listedMeta(name)
}

func TestExecRecordsTheLastUse(t *testing.T) {
	at := pinClock(t)
	w := usageWorld(t)
	if m := w.usageOf("A"); m["last_used_at"] != nil || m["last_exit_code"] != nil || m["last_ok_at"] != nil {
		t.Fatalf("a never-used secret lists a use: %v", m)
	}
	at(gt0.Add(time.Hour))
	if code, _, _ := w.execA(0); code != 0 {
		t.Fatalf("exec code=%d", code)
	}
	m := w.usageOf("A")
	want := gt0.Add(time.Hour).Format(time.RFC3339)
	if m["last_used_at"] != want || m["last_ok_at"] != want || m["last_exit_code"] != float64(0) {
		t.Fatalf("after a success: %v", m)
	}
	at(gt0.Add(2 * time.Hour))
	if code, _, _ := w.execA(7); code != 7 {
		t.Fatalf("exec code=%d", code)
	}
	m = w.usageOf("A")
	if m["last_used_at"] != gt0.Add(2*time.Hour).Format(time.RFC3339) || m["last_exit_code"] != float64(7) || m["last_ok_at"] != want {
		t.Fatalf("after a failure: %v (the last success must stay)", m)
	}
}

func TestOnlyAFailedUseLeavesNoLastOK(t *testing.T) {
	w := usageWorld(t)
	w.execA(3)
	m := w.usageOf("A")
	if m["last_exit_code"] != float64(3) || m["last_ok_at"] != nil {
		t.Fatalf("m = %v", m)
	}
}

func TestExecNeverWritesTheVault(t *testing.T) {
	w := usageWorld(t)
	vp, sp := filepath.Join(w.home, "vault.enc"), filepath.Join(w.home, "state.json")
	vb, _ := os.ReadFile(vp)
	sb, _ := os.ReadFile(sp)
	fi, _ := os.Stat(vp)
	snaps := len(w.mustRunList("restore", "--list"))
	for i := 0; i < 2; i++ {
		w.execA(0)
	}
	vb2, _ := os.ReadFile(vp)
	sb2, _ := os.ReadFile(sp)
	fi2, _ := os.Stat(vp)
	if !bytes.Equal(vb, vb2) || !bytes.Equal(sb, sb2) || !fi.ModTime().Equal(fi2.ModTime()) {
		t.Fatal("exec rewrote vault.enc or state.json")
	}
	if len(w.mustRunList("restore", "--list")) != snaps {
		t.Fatal("exec took a snapshot")
	}
	if _, err := os.Stat(filepath.Join(w.home, vault.UsageFile)); err != nil {
		t.Fatalf("exec left no usage file: %v", err)
	}
}

func (w *world) mustRunList(args ...string) []string {
	w.t.Helper()
	return strings.Split(strings.TrimSpace(w.mustRun("", args...)), "\n")
}

// An unwritable usage file changes nothing in exec's output or exit code.
func TestAnUnwritableUsageFileChangesNothingInExec(t *testing.T) {
	good := usageWorld(t)
	bad := usageWorld(t)
	if err := os.Mkdir(filepath.Join(bad.home, vault.UsageFile), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, c := range []int{0, 5} {
		run := child(t, "args", "", c)
		for _, mode := range [][]string{{}, {"--json"}} {
			gc, go_, ge := good.run("", append(append([]string{}, mode...), execArgs(usSession, []string{"A"}, run)...)...)
			bc, bo, be := bad.run("", append(append([]string{}, mode...), execArgs(usSession, []string{"A"}, run)...)...)
			if gc != bc || stripDuration(go_) != stripDuration(bo) || ge != be {
				t.Fatalf("exit %d %v: good=(%d %q %q) bad=(%d %q %q)", c, mode, gc, go_, ge, bc, bo, be)
			}
		}
	}
	if !bad.auditHas(`"detail":"usage not recorded"`) {
		t.Fatalf("the failure is not reported in the audit log: %s", bad.auditText())
	}
	// Through the broker too.
	req := envelope("exec", good.outside, `"command":`+jsonString(child(t, "args", "", 0))+`,"secrets":[{"name":"A"}]`)
	_, gm, _ := good.broker("exec", req)
	_, bm, _ := bad.broker("exec", req)
	if gm["ok"] != true || bm["ok"] != true || gm["exit_code"] != bm["exit_code"] {
		t.Fatalf("broker exec differs: %v vs %v", gm, bm)
	}
}

func stripDuration(s string) string {
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) != nil {
		return s
	}
	delete(m, "duration_ms")
	b, _ := json.Marshal(m)
	return string(b)
}

func TestBrokerExecRecordsTheUse(t *testing.T) {
	w := usageWorld(t)
	req := envelope("exec", w.outside, `"command":`+jsonString(child(t, "args", "", 0))+`,"secrets":[{"name":"A"}]`)
	if code, m, _ := w.broker("exec", req); code != exitcode.OK || m["ok"] != true {
		t.Fatalf("m=%v", m)
	}
	if m := w.usageOf("A"); m["last_ok_at"] == nil {
		t.Fatalf("broker exec recorded nothing: %v", m)
	}
}

func TestAReplacedValueHasNoHistory(t *testing.T) {
	w := usageWorld(t)
	w.execA(0)
	w.setSecret("A", "TESTSECRET_usage_new_9876543210", "--global")
	if m := w.usageOf("A"); m["last_used_at"] != nil {
		t.Fatalf("a replaced value inherited the history: %v", m)
	}
}

func TestDescribeAndListShowTheUse(t *testing.T) {
	at := pinClock(t)
	w := usageWorld(t)
	if out := w.mustRun("", "describe", "A", "--global"); strings.Contains(out, "last used") {
		t.Fatalf("describe of an unused secret: %q", out)
	}
	at(gt0.Add(time.Hour))
	w.execA(2)
	at(gt0.Add(2 * time.Hour))
	w.execA(0)
	out := w.mustRun("", "describe", "A", "--global")
	for _, want := range []string{"  last used:   " + gt0.Add(2*time.Hour).Format(time.RFC3339) + " (exit 0)\n", "  last ok:     " + gt0.Add(2*time.Hour).Format(time.RFC3339) + "\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("describe lacks %q: %q", want, out)
		}
	}
	for _, args := range [][]string{{"--json", "describe", "A", "--global"}, {"--json", "list", "--layer", "all"}} {
		js := w.mustRun("", args...)
		for _, want := range []string{`"last_used_at":"` + gt0.Add(2*time.Hour).Format(time.RFC3339) + `"`, `"last_exit_code":0`, `"last_ok_at"`} {
			if !strings.Contains(js, want) {
				t.Errorf("%v lacks %s: %s", args, want, js)
			}
		}
	}
}

// What the file keeps is a time and a number: never the command, its output,
// the directory or the session.
func TestTheUsageFileKeepsNoCommandOrContext(t *testing.T) {
	w := usageWorld(t)
	run := child(t, "args", "", 0)
	w.run("", execArgs(usSession, []string{"A"}, run, "--cwd", w.outside)...)
	g := &globals{getenv: envFrom(nil), home: w.home}
	s, err := g.openSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	got, err := s.v.Usage()
	if err != nil || len(got) != 1 {
		t.Fatalf("usage = %v %v", got, err)
	}
	for _, u := range got {
		b, _ := json.Marshal(u)
		for _, bad := range []string{run, w.outside, usSession, "args"} {
			if strings.Contains(string(b), bad) {
				t.Fatalf("usage entry %s holds %q", b, bad)
			}
		}
	}
	w.scanHome("TESTSECRET_usage_a_0123456789")
}

func TestDoctorReportsAnUnreadableUsageFileAndPurgeRemovesIt(t *testing.T) {
	w := usageWorld(t)
	w.execA(0)
	if err := os.WriteFile(filepath.Join(w.home, vault.UsageFile), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, _ := w.run("", "doctor")
	if !strings.Contains(out, "usage") || !strings.Contains(out, "usage.enc is unreadable") {
		t.Fatalf("doctor: %s", out)
	}
	if !vaultEntry(vault.UsageFile, false) || !vaultEntry(vault.UsageFile+".tmp.12.ab", false) {
		t.Fatal("uninstall --purge does not know the usage file")
	}
}

// A job records its use when it ends, although its vault key was dropped when
// the child started.
func TestMCPJobRecordsItsUseWhenItEnds(t *testing.T) {
	w := jobWorld(t)
	s := w.startMCP()
	job := s.startJob(10, child(t, "args", "", 3), nil)
	for n := 11; ; n++ {
		if s.jobStatus(n, job, 5000)["state"] != "running" {
			break
		}
	}
	s.finish()
	m := w.listedMeta("A")
	if m["last_exit_code"] != float64(3) || m["last_used_at"] == nil || m["last_ok_at"] != nil {
		t.Fatalf("job use = %v", m)
	}
}
