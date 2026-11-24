package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/perm"
)

// Last use (issue #62 part 4): a local, per-device, encrypted file next to the
// vault. It is not part of vault.enc, so recording a use never writes the vault.

func fileBytes(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRecordingAUseWritesOnlyTheUsageFile(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_a"))
	id := idOf(t, v, "A_KEY")
	vaultBefore, stateBefore := fileBytes(t, filepath.Join(home, vaultFile)), fileBytes(t, filepath.Join(home, stateFile))
	fi, _ := os.Stat(filepath.Join(home, vaultFile))
	backups := len(backupsOf(t, home))

	if err := v.RecordUses([]string{id}, t0, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fileBytes(t, filepath.Join(home, vaultFile)), vaultBefore) || !bytes.Equal(fileBytes(t, filepath.Join(home, stateFile)), stateBefore) {
		t.Fatal("recording a use rewrote the vault or its state")
	}
	if fi2, _ := os.Stat(filepath.Join(home, vaultFile)); !fi2.ModTime().Equal(fi.ModTime()) {
		t.Fatal("vault.enc was touched")
	}
	if len(backupsOf(t, home)) != backups {
		t.Fatal("recording a use took a snapshot")
	}
	if ok, detail := perm.Check(filepath.Join(home, UsageFile)); !ok {
		t.Fatalf("usage file is not owner-only: %s", detail)
	}
	raw := fileBytes(t, filepath.Join(home, UsageFile))
	if bytes.Contains(raw, []byte(id)) || bytes.Contains(raw, []byte("last_used_at")) {
		t.Fatal("the usage file is not encrypted")
	}
}

func TestUsagePerRecord(t *testing.T) {
	v, _ := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_a"))
	mustPut(t, v, Global(), "B_KEY", rec("TESTSECRET_b"))
	a, b := idOf(t, v, "A_KEY"), idOf(t, v, "B_KEY")
	t1, t2, t3 := t0, t0.Add(time.Hour), t0.Add(2*time.Hour)

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(v.RecordUses([]string{a, b}, t1, 0))
	must(v.RecordUses([]string{a}, t2, 3)) // a failed run: the last success stays
	got, err := v.Usage()
	must(err)
	ua, ub := got[a], got[b]
	if ua.LastUsedAt != t2.Format(time.RFC3339) || ua.LastExitCode == nil || *ua.LastExitCode != 3 || ua.LastOKAt != t1.Format(time.RFC3339) {
		t.Fatalf("a = %+v", ua)
	}
	if ub.LastUsedAt != t1.Format(time.RFC3339) || *ub.LastExitCode != 0 || ub.LastOKAt != t1.Format(time.RFC3339) {
		t.Fatalf("b = %+v", ub)
	}
	// Never used successfully: no last_ok_at.
	mustPut(t, v, Global(), "C_KEY", rec("TESTSECRET_c"))
	c := idOf(t, v, "C_KEY")
	must(v.RecordUses([]string{c}, t3, 1))
	got, _ = v.Usage()
	if got[c].LastOKAt != "" || got[c].LastUsedAt == "" {
		t.Fatalf("c = %+v", got[c])
	}
}

func TestAReplacedOrRevertedValueStartsFresh(t *testing.T) {
	pinClock(t, t0)
	v, _ := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_one"))
	if err := v.RecordUses([]string{idOf(t, v, "A_KEY")}, t0, 0); err != nil {
		t.Fatal(err)
	}
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_two"))
	got, _ := v.Usage()
	if _, has := got[idOf(t, v, "A_KEY")]; has {
		t.Fatal("a replaced value inherited the history of the old one")
	}
	_ = v.RecordUses([]string{idOf(t, v, "A_KEY")}, t0, 0)
	if _, err := v.RevertWithGrants(Global(), "A_KEY", &fakeEditor{}); err != nil {
		t.Fatal(err)
	}
	got, _ = v.Usage()
	if _, has := got[idOf(t, v, "A_KEY")]; has {
		t.Fatal("a reverted value inherited history")
	}
}

func TestEntriesOfRecordsThatNoLongerExistAreDroppedOnWrite(t *testing.T) {
	v, _ := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_a"))
	mustPut(t, v, Global(), "B_KEY", rec("TESTSECRET_b"))
	a, b := idOf(t, v, "A_KEY"), idOf(t, v, "B_KEY")
	if err := v.RecordUses([]string{a, b, "0123456789abcdef0123456789abcdef"}, t0, 0); err != nil {
		t.Fatal(err)
	}
	if err := v.Remove(Global(), "A_KEY"); err != nil {
		t.Fatal(err)
	}
	if err := v.RecordUses([]string{b}, t0.Add(time.Minute), 0); err != nil {
		t.Fatal(err)
	}
	got, _ := v.Usage()
	if len(got) != 1 || got[b].LastUsedAt == "" {
		t.Fatalf("usage = %+v: only the live record should remain", got)
	}
}

func TestAnUnreadableUsageFileIsEmptyHistoryNotAnError(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_a"))
	a := idOf(t, v, "A_KEY")
	if err := v.RecordUses([]string{a}, t0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, UsageFile), []byte("not an envelope"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := v.Usage()
	if !errors.Is(err, ErrUsageUnreadable) || len(got) != 0 {
		t.Fatalf("usage = %v err = %v", got, err)
	}
	if err := v.RecordUses([]string{a}, t0, 0); err != nil {
		t.Fatalf("a bad file must be replaced by the next write: %v", err)
	}
	if got, err := v.Usage(); err != nil || got[a].LastUsedAt == "" {
		t.Fatalf("after the rewrite: %v %v", got, err)
	}
	// Deleting it loses only the history.
	if err := os.Remove(filepath.Join(home, UsageFile)); err != nil {
		t.Fatal(err)
	}
	if got, err := v.Usage(); err != nil || len(got) != 0 {
		t.Fatalf("missing file: %v %v", got, err)
	}
}

func TestAnUnwritableUsageFileFailsOnlyTheRecord(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_a"))
	if err := os.Mkdir(filepath.Join(home, UsageFile), 0o700); err != nil { // a directory where the file goes
		t.Fatal(err)
	}
	if err := v.RecordUses([]string{idOf(t, v, "A_KEY")}, t0, 0); err == nil {
		t.Fatal("writing over a directory succeeded")
	}
	if _, err := v.Usage(); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Logf("read over a directory: %v", err)
	}
	// The vault itself is untouched and still works.
	if r, _, err := v.Resolve("A_KEY", t.TempDir()); err != nil || !sameValue(r, "TESTSECRET_a") {
		t.Fatalf("vault: %v", err)
	}
}

func TestRekeyKeepsTheUsageHistoryAndBackupsDoNotHoldIt(t *testing.T) {
	v, home := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_a"))
	a := idOf(t, v, "A_KEY")
	if err := v.RecordUses([]string{a}, t0, 0); err != nil {
		t.Fatal(err)
	}
	mustPut(t, v, Global(), "B_KEY", rec("TESTSECRET_b"))
	for _, id := range backupsOf(t, home) {
		if _, err := os.Stat(filepath.Join(home, "backups", id, UsageFile)); err == nil {
			t.Fatal("a snapshot holds the usage file")
		}
	}
	if err := Rekey(home, testKey(1), testKey(2)); err != nil {
		t.Fatal(err)
	}
	v2, err := Open(home, testKey(2))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := v2.Usage(); err != nil || got[a].LastUsedAt == "" {
		t.Fatalf("history after rekey: %v %v", got, err)
	}
}
