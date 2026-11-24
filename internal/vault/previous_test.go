package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The previous value (issue #62, STORAGE.md § Previous value): one level,
// inside the encrypted body, bounded to PreviousRetention.

func pinClock(t *testing.T, at time.Time) *time.Time {
	t.Helper()
	cur := at
	old := now
	now = func() time.Time { return cur }
	t.Cleanup(func() { now = old })
	return &cur
}

var t0 = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)

func previousOf(t *testing.T, v *Vault, name string) (string, string, bool) {
	t.Helper()
	got, err := v.PreviousValues()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, p := range got {
			p.Value.Wipe()
		}
	}()
	for _, p := range got {
		if p.Name == name {
			b := p.Value.Reveal()
			defer clear(b)
			return string(b), p.ReplacedAt, true
		}
	}
	return "", "", false
}

func plainBody(t *testing.T, v *Vault) string {
	t.Helper()
	pt, _, err := v.st.load()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pt)
	return string(pt)
}

func TestReplacingAValueKeepsTheOldOneWithItsTime(t *testing.T) {
	pinClock(t, t0)
	v, _ := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_one"))
	if _, _, ok := previousOf(t, v, "A_KEY"); ok {
		t.Fatal("a new record has a previous value")
	}
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_two"))
	val, at, ok := previousOf(t, v, "A_KEY")
	if !ok || val != "TESTSECRET_one" || at != t0.Format(time.RFC3339) {
		t.Fatalf("previous = %q at %q ok=%v", val, at, ok)
	}
	r, _, _ := v.Resolve("A_KEY", t.TempDir())
	if !sameValue(r, "TESTSECRET_two") || r.PreviousReplacedAt != at {
		t.Fatalf("current value or marker wrong: %q", r.PreviousReplacedAt)
	}
}

func TestOnlyOneLevelIsKept(t *testing.T) {
	pinClock(t, t0)
	v, _ := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_one"))
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_two"))
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_three"))
	val, _, _ := previousOf(t, v, "A_KEY")
	if val != "TESTSECRET_two" {
		t.Fatalf("previous = %q, want the value just replaced", val)
	}
	if strings.Contains(plainBody(t, v), "TESTSECRET_one") {
		t.Fatal("the older previous value is still in the body")
	}
}

func TestReplacingWithTheSameValueKeepsThePreviousOne(t *testing.T) {
	clk := pinClock(t, t0)
	v, _ := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_one"))
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_two"))
	*clk = t0.Add(time.Hour)
	if _, err := v.ReplaceWithGrants(Global(), "A_KEY", rec("TESTSECRET_two"), &fakeEditor{}); err != nil {
		t.Fatal(err)
	}
	val, at, ok := previousOf(t, v, "A_KEY")
	if !ok || val != "TESTSECRET_one" || at != t0.Format(time.RFC3339) {
		t.Fatalf("previous = %q at %q ok=%v: a same-value replace overwrote it", val, at, ok)
	}
}

func TestMetadataEditsAndRemoveTreatThePreviousValue(t *testing.T) {
	pinClock(t, t0)
	v, _ := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_one"))
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_two"))
	r, _, _ := v.Resolve("A_KEY", t.TempDir())
	r.Description = "changed"
	if _, err := v.EditWithGrants(Global(), "A_KEY", r, &fakeEditor{}); err != nil {
		t.Fatal(err)
	}
	if val, _, ok := previousOf(t, v, "A_KEY"); !ok || val != "TESTSECRET_one" {
		t.Fatal("a metadata edit lost the previous value")
	}
	// An edit that builds its record from scratch cannot drop or forge it.
	scratch := rec("TESTSECRET_two")
	scratch.ID = r.ID
	if err := v.Put(Global(), "A_KEY", scratch); err != nil {
		t.Fatal(err)
	}
	if err := v.Remove(Global(), "A_KEY"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plainBody(t, v), "TESTSECRET_one") {
		t.Fatal("removing the secret left its previous value")
	}
}

func TestPreviousValueExpiresAtTheBoundary(t *testing.T) {
	clk := pinClock(t, t0)
	v, _ := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_one"))
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_two"))
	mustPut(t, v, Global(), "B_KEY", rec("TESTSECRET_other"))

	*clk = t0.Add(PreviousRetention - time.Nanosecond)
	if _, _, ok := previousOf(t, v, "A_KEY"); !ok {
		t.Fatal("expired one tick early")
	}
	*clk = t0.Add(PreviousRetention)
	if _, _, ok := previousOf(t, v, "A_KEY"); ok {
		t.Fatal("still recoverable at the boundary")
	}
	r, _, _ := v.Resolve("A_KEY", t.TempDir())
	if r.PreviousReplacedAt != "" {
		t.Fatal("an expired previous value is still advertised")
	}
	if _, err := v.RevertWithGrants(Global(), "A_KEY", &fakeEditor{}); !errors.Is(err, ErrNoPrevious) {
		t.Fatalf("revert after expiry = %v, want ErrNoPrevious", err)
	}
	// Reading does not write: the bytes are still there until the next write.
	if !strings.Contains(plainBody(t, v), "TESTSECRET_one") {
		t.Fatal("a read rewrote the vault")
	}
	// Any write of any kind drops it for good, even if the clock goes back.
	mustPut(t, v, Global(), "C_KEY", rec("TESTSECRET_c"))
	if strings.Contains(plainBody(t, v), "TESTSECRET_one") {
		t.Fatal("the expired previous value survived a write")
	}
	*clk = t0.Add(time.Hour)
	if _, _, ok := previousOf(t, v, "A_KEY"); ok {
		t.Fatal("an expired previous value came back")
	}
}

func TestExpiryDoesNotRestampTheRecord(t *testing.T) {
	clk := pinClock(t, t0)
	v, _ := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_one"))
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_two"))
	hlc := func() string {
		var w struct {
			Global map[string]struct {
				HLC string `json:"hlc"`
			} `json:"global"`
		}
		if err := json.Unmarshal([]byte(plainBody(t, v)), &w); err != nil {
			t.Fatal(err)
		}
		return w.Global["A_KEY"].HLC
	}
	before := hlc()
	*clk = t0.Add(PreviousRetention + time.Hour)
	mustPut(t, v, Global(), "B_KEY", rec("TESTSECRET_b"))
	if hlc() != before {
		t.Fatal("dropping an expired previous value restamped the record: two devices would conflict")
	}
}

func TestAFarFutureTimestampIsNotKept(t *testing.T) {
	pinClock(t, t0)
	v, _ := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_one"))
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_two"))
	pinClock(t, t0.Add(-30*24*time.Hour)) // the clock of this device went back a month
	if _, _, ok := previousOf(t, v, "A_KEY"); ok {
		t.Fatal("a previous value stamped in the future stays recoverable for longer than the retention")
	}
}

func TestRevertSwapsUndoesAndRestartsTheWindow(t *testing.T) {
	clk := pinClock(t, t0)
	v, _ := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_one"))
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_two"))
	idBefore := idOf(t, v, "A_KEY")

	*clk = t0.Add(24 * time.Hour)
	ed := &fakeEditor{}
	res, err := v.RevertWithGrants(Global(), "A_KEY", ed)
	if err != nil {
		t.Fatal(err)
	}
	r, _, _ := v.Resolve("A_KEY", t.TempDir())
	if !sameValue(r, "TESTSECRET_one") {
		t.Fatal("revert did not restore the previous value")
	}
	if r.ID == idBefore || res.RecordID != r.ID {
		t.Fatal("revert kept the record id: grants would carry over to a different value")
	}
	if len(ed.drops) != 1 || ed.drops[0] != [2]string{"A_KEY", "global"} {
		t.Fatalf("grants dropped = %v", ed.drops)
	}
	val, at, ok := previousOf(t, v, "A_KEY")
	if !ok || val != "TESTSECRET_two" || at != clk.Format(time.RFC3339) {
		t.Fatalf("after revert previous = %q at %q: want the replaced value, window restarted", val, at)
	}

	// Undo within the window: swap back.
	if _, err := v.RevertWithGrants(Global(), "A_KEY", ed); err != nil {
		t.Fatal(err)
	}
	r, _, _ = v.Resolve("A_KEY", t.TempDir())
	if !sameValue(r, "TESTSECRET_two") {
		t.Fatal("the swap could not be undone")
	}
}

func TestRevertRefusals(t *testing.T) {
	pinClock(t, t0)
	v, _ := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_one"))
	if _, err := v.RevertWithGrants(Global(), "A_KEY", &fakeEditor{}); !errors.Is(err, ErrNoPrevious) {
		t.Fatalf("revert of a never-replaced record = %v", err)
	}
	if _, err := v.RevertWithGrants(Global(), "NOPE", &fakeEditor{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revert of a missing record = %v", err)
	}
	if strings.Contains(ErrNoPrevious.Error(), "TESTSECRET") {
		t.Fatal("error text holds a value")
	}
}

func TestImportOverwriteKeepsThePreviousValue(t *testing.T) {
	pinClock(t, t0)
	v, _ := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_one"))
	_, _, err := v.ImportAll([]LayerRecords{{Layer: Global(), Records: []NamedRecord{{Name: "A_KEY", Record: rec("TESTSECRET_two")}}}}, &fakeEditor{})
	if err != nil {
		t.Fatal(err)
	}
	if val, _, ok := previousOf(t, v, "A_KEY"); !ok || val != "TESTSECRET_one" {
		t.Fatalf("import overwrite previous = %q ok=%v", val, ok)
	}
}

// legacyRecord is wireRecord as v1.4.1 decodes it (internal/vault/record.go
// at that tag): no previous field, lenient JSON.
type legacyRecord struct {
	ID          string   `json:"id"`
	Value       string   `json:"value"`
	Kind        string   `json:"kind,omitempty"`
	Description string   `json:"description"`
	Sensitive   bool     `json:"sensitive"`
	Binaries    []string `json:"binaries"`
	Hosts       []string `json:"hosts"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
	HLC         string   `json:"hlc,omitempty"`
}

func TestAnOlderDecoderStillReadsABodyWithAPreviousValue(t *testing.T) {
	pinClock(t, t0)
	v, _ := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_one"))
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_two"))
	var w struct {
		Schema int                     `json:"schema"`
		Global map[string]legacyRecord `json:"global"`
	}
	if err := json.Unmarshal([]byte(plainBody(t, v)), &w); err != nil {
		t.Fatalf("the v1.4.1 body decoder refuses the new body: %v", err)
	}
	if w.Schema != schemaVersion || schemaVersion != 2 {
		t.Fatalf("schema = %d: the previous value must not bump it", w.Schema)
	}
	if w.Global["A_KEY"].Value != "TESTSECRET_two" {
		t.Fatal("the older decoder reads another current value")
	}
}

func TestBackupRestoreAndRekeyKeepThePreviousValue(t *testing.T) {
	pinClock(t, t0)
	v, home := newVault(t)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_one"))
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_two"))
	mustPut(t, v, Global(), "B_KEY", rec("TESTSECRET_b")) // snapshot: A with a previous value
	ids := backupsOf(t, home)
	mustPut(t, v, Global(), "A_KEY", rec("TESTSECRET_three"))

	if err := Restore(home, ids[len(ids)-1], testKey(1)); err != nil {
		t.Fatal(err)
	}
	v2, err := Open(home, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	if val, _, ok := previousOf(t, v2, "A_KEY"); !ok || val != "TESTSECRET_one" {
		t.Fatalf("after restore previous = %q ok=%v", val, ok)
	}
	if err := Rekey(home, testKey(1), testKey(2)); err != nil {
		t.Fatal(err)
	}
	v3, err := Open(home, testKey(2))
	if err != nil {
		t.Fatal(err)
	}
	if val, _, ok := previousOf(t, v3, "A_KEY"); !ok || val != "TESTSECRET_one" {
		t.Fatalf("after rekey previous = %q ok=%v", val, ok)
	}
	// Nothing on disk holds it unencrypted, snapshots included.
	err = filepath.WalkDir(home, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr == nil && bytes.Contains(b, []byte("TESTSECRET_")) {
			t.Errorf("%s holds a fixture in clear", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
