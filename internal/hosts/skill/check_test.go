package skill_test

import (
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/hosts/skill"
)

// Issue #62: before proposing a replace the agent runs secret_check on every
// secret the failed call used, tells the user what it shows in plain words,
// and replaces only the secret the evidence points to.
func TestSkillDiagnosesARejectedCredentialWithSecretCheck(t *testing.T) {
	s := string(skill.Content)
	i := strings.Index(s, "## When a service rejects the credential")
	j := strings.Index(s, "## Long commands")
	if i < 0 || j < i {
		t.Fatal("the section about a rejected credential is missing")
	}
	section := s[i:j]
	for _, want := range []string{
		"`secret_check`",
		"every secret the failed call used",
		"identifier fields",
		"an email, a username, a host",
		"returns no value",
		"`looks_like`",
		"`same_as`",
		"`placeholder`",
		"does not spend a `once` grant",
		"in plain words",
		"does not look like an email and holds the same value as",
		"only for the secret the evidence points to",
		"before you propose a `secret_manage` replace",
		"asks the user before saving a value that equals the one it replaces",
		"you are never told which secret matched",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("the rejected-credential section does not say %q", want)
		}
	}
	// The check comes before the replace in the flow.
	if strings.Index(section, "`secret_check`") > strings.Index(section, "`secret_manage`") {
		t.Error("the section proposes a replace before the check")
	}
	// The tool sends the conversation language and has its own place in the
	// rules about printing values.
	if !strings.Contains(s, "`secret_exec_start`, `secret_manage` and `secret_check`") {
		t.Error("the language section does not list secret_check")
	}
	for _, want := range []string{"To check that a value is present or what it looks like, use `secret_check`"} {
		if !strings.Contains(s, want) {
			t.Errorf("rules do not say %q", want)
		}
	}
}
