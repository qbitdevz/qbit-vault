package refusal

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
)

// The enum must be exactly the types listed in CONTRACT.md § Refusals.
func TestTypesMatchContract(t *testing.T) {
	data, err := os.ReadFile("../../contracts/secrets-broker/v1/CONTRACT.md")
	if err != nil {
		t.Fatal(err)
	}
	sec := string(data)
	i := strings.Index(sec, "\n## Refusals")
	if i < 0 {
		t.Fatal("CONTRACT.md has no Refusals section")
	}
	sec = sec[i+1:]
	if j := strings.Index(sec[3:], "\n#"); j >= 0 { // the type table ends at the next heading
		sec = sec[:j+3]
	}
	row := regexp.MustCompile("(?m)^\\| `([a-z_]+)` \\|")
	var want []string
	for _, m := range row.FindAllStringSubmatch(sec, -1) {
		if m[1] != "type" { // the table header
			want = append(want, m[1])
		}
	}
	var got []string
	for _, ty := range Types() {
		got = append(got, string(ty))
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("types\n got %v\nwant %v", got, want)
	}
}

func TestExitCodes(t *testing.T) {
	for _, ty := range Types() {
		want := exitcode.Refusal
		switch ty {
		case VaultLocked:
			want = exitcode.Locked
		case VaultCorrupt:
			want = exitcode.Corrupt
		}
		if got := New(ty, "").ExitCode(); got != want {
			t.Errorf("%s: exit %d, want %d", ty, got, want)
		}
	}
}

func TestJSONShape(t *testing.T) {
	b, err := json.Marshal(New(UnknownSecret, "GITHUB_TOKEN").Envelope())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"ok":false,"refusal":{"type":"unknown_secret","name":"GITHUB_TOKEN","message":"GITHUB_TOKEN is not stored","retryable":true,"hint":"Call secret_list to see the stored names; if it is missing, call secret_request with fields to ask the user to store it."}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
	b, _ = json.Marshal(New(InvalidName, "").Envelope())
	want = `{"ok":false,"refusal":{"type":"invalid_name","name":null,"message":"invalid secret name","retryable":false,"hint":"Names match ^[A-Z][A-Z0-9_]{0,63}$ and each appears once."}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
}

func TestOverrides(t *testing.T) {
	r := New(Internal, "").WithMessage("vault is busy").WithRetryable(true)
	if r.Message != "vault is busy" || !r.Retryable || r.Type != Internal || r.Name != nil {
		t.Fatalf("unexpected refusal %+v", r)
	}
	if r.Error() != "vault is busy" {
		t.Fatalf("Error() = %q", r.Error())
	}
}

func TestDefaultsAreFixedStrings(t *testing.T) {
	for _, ty := range Types() {
		r := New(ty, "NAME_X")
		if r.Message == "" || !r.Valid() {
			t.Errorf("%s: empty message or invalid", ty)
		}
		if strings.Contains(New(ty, "").Message, "NAME_X") {
			t.Errorf("%s: nameless message mentions a name", ty)
		}
	}
	if (Refusal{Type: "bogus"}).Valid() {
		t.Fatal("unknown type reported valid")
	}
}

func TestPartialIsOptionalAndOnlyOnRequest(t *testing.T) {
	b, err := json.Marshal(New(Timeout, "").Envelope())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "partial") {
		t.Fatalf("no partial output was attached: %s", b)
	}
	r := New(Timeout, "").WithPartial("out text", "err text")
	b, err = json.Marshal(r.Envelope())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"ok":false,"refusal":{"type":"timeout","name":null,"message":"the command timed out","retryable":true,"partial":{"stdout":"out text","stderr":"err text"},"hint":"Raise timeout_ms or split the command."}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
}

func TestNewDumpRules(t *testing.T) {
	for _, rule := range Rules() {
		r := NewDump(rule, 2)
		if r.Type != DumpCommand || r.Rule != rule || r.Hint == "" || r.Segment == nil || *r.Segment != 2 || r.Retryable {
			t.Errorf("%s: %+v", rule, r)
		}
		if !strings.HasPrefix(r.Message, "the command is refused while secrets are injected: ") || len(r.Message) > 500 {
			t.Errorf("%s: message %q", rule, r.Message)
		}
	}
	if r := NewDump(EnvironmentDump, -1); r.Segment != nil {
		t.Errorf("unknown segment must be omitted: %+v", r)
	}
	if r := NewDump("nope", 0); r != New(DumpCommand, "") {
		t.Errorf("unknown rule must be the plain refusal: %+v", r)
	}
}

// The optional fields are omitted when empty: no rule, no segment on a
// refusal that has none, and no hint when it is cleared.
func TestOptionalFieldsOmitted(t *testing.T) {
	b, _ := json.Marshal(New(GrantRequired, "A").WithHint("").Envelope())
	want := `{"ok":false,"refusal":{"type":"grant_required","name":"A","message":"A has no active grant","retryable":true}}`
	if string(b) != want {
		t.Fatalf("%s", b)
	}
	b, _ = json.Marshal(New(GrantRequired, "A").Envelope())
	if strings.Contains(string(b), `"rule"`) || strings.Contains(string(b), `"segment"`) {
		t.Fatalf("%s", b)
	}
}

// The rules of the contract's table are exactly the ones in code.
func TestRulesMatchContract(t *testing.T) {
	data, err := os.ReadFile("../../contracts/secrets-broker/v1/CONTRACT.md")
	if err != nil {
		t.Fatal(err)
	}
	sec := string(data)
	i := strings.Index(sec, "\n### Optional refusal fields")
	if i < 0 {
		t.Fatal("CONTRACT.md has no optional refusal fields section")
	}
	sec = sec[i+1:]
	if j := strings.Index(sec[3:], "\n#"); j >= 0 {
		sec = sec[:j+3]
	}
	row := regexp.MustCompile("(?m)^[|] `([a-z_]+)` [|] `([^`]+)` [|]")
	var want []string
	for _, m := range row.FindAllStringSubmatch(sec, -1) {
		if m[1] == "rule" {
			continue
		}
		if got := rules[Rule(m[1])].phrase; got != m[2] {
			t.Errorf("%s: phrase %q in code, %q in the contract", m[1], got, m[2])
		}
		want = append(want, m[1])
	}
	var got []string
	for _, r := range Rules() {
		got = append(got, string(r))
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("rules\n got %v\nwant %v", got, want)
	}
}

// S4 of odd/tasks/actionable-refusals.md: every refusal type but dump_command
// (whose hint comes from its rule) carries one fixed hint, built from fixed
// text only.
func TestEveryTypeHasItsFixedHint(t *testing.T) {
	want := map[Type]string{
		GrantRequired:    "Call secret_request for this name to ask the user for a grant, then retry once.",
		UnknownSecret:    "Call secret_list to see the stored names; if it is missing, call secret_request with fields to ask the user to store it.",
		UserDeclined:     "Do not ask again for the same use; continue without it or ask the user in the chat.",
		RateLimited:      "Wait; do not retry the same request.",
		ReasonTooVague:   "Say what the command does and why it needs the secret.",
		InvalidName:      "Names match ^[A-Z][A-Z0-9_]{0,63}$ and each appears once.",
		ScopeNotAllowed:  "Ask for scope once; a sensitive secret allows only a one-time grant.",
		ScopeBinary:      "The user must add the program to the secret's binaries; ask them.",
		NoProject:        "Use the global layer, or run from inside the repository.",
		DumpCommand:      "",
		NotModelCallable: "This is a user-only action; ask the user to run it.",
		VaultLocked:      "A QBit Vault tool call such as secret_list opens the unlock dialog; call it again once the user has unlocked.",
		VaultCorrupt:     "Stop; the user runs 'qbit-vault restore'.",
		Timeout:          "Raise timeout_ms or split the command.",
		ContractMismatch: "Update qbit-vault; the user runs 'qbit-vault sync' and restarts the agent.",
		Internal:         "Report it; the user can run 'qbit-vault doctor'.",
	}
	for _, ty := range Types() {
		w, ok := want[ty]
		if !ok {
			t.Fatalf("no expected hint for %s", ty)
		}
		if got := New(ty, "").Hint; got != w {
			t.Errorf("%s: hint %q, want %q", ty, got, w)
		}
		if got := New(ty, "NAME").Hint; got != w {
			t.Errorf("%s with a name: hint %q, want %q", ty, got, w)
		}
	}
	if New(UnknownSecret, "A").Rule != "" || New(UnknownSecret, "A").Segment != nil {
		t.Fatal("only dump_command carries a rule or a segment")
	}
}

func TestOverrideHintsAreFixedTexts(t *testing.T) {
	r := New(GrantRequired, "A").WithHint(HintGrantNotApplying)
	if r.Hint != "A grant exists but does not apply here; call secret_request to ask the user for a new one." {
		t.Fatalf("hint %q", r.Hint)
	}
	if !strings.Contains(New(VaultLocked, "").WithHint(HintNoUnlockDialog).Hint, "qbit-vault unlock") {
		t.Fatal("the no-dialog hint must send the user to the terminal")
	}
}

func TestHintsAreShortAndValueFree(t *testing.T) {
	for _, ty := range Types() {
		if h := New(ty, "").Hint; len(h) > 300 || strings.Contains(h, "TESTSECRET_") {
			t.Errorf("%s: hint %q", ty, h)
		}
	}
}

// CONTRACT.md lists the hint of every type (and the override hints) in the
// words the code uses.
func TestHintsMatchContract(t *testing.T) {
	data, err := os.ReadFile("../../contracts/secrets-broker/v1/CONTRACT.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	for _, ty := range Types() {
		if h := New(ty, "").Hint; h != "" && !strings.Contains(doc, "| `"+string(ty)+"` | "+h+" |") {
			t.Errorf("CONTRACT.md has no hint row for %s with %q", ty, h)
		}
	}
	for _, h := range []string{HintGrantNotApplying, HintNoUnlockDialog, HintBusy, HintBadRequest, HintCancelled, HintNeedsRepository, HintNeedsSession, HintJobsBusy, HintUnknownJob} {
		if !strings.Contains(doc, "`"+h+"`") {
			t.Errorf("CONTRACT.md does not list the hint %q", h)
		}
	}
}
