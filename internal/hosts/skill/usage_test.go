package skill_test

import (
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/hosts/skill"
)

// Issue #62 part 4: the agent reads the last use of a secret as a hint.
func TestSkillReadsTheLastUseAsAHint(t *testing.T) {
	s := string(skill.Content)
	i := strings.Index(s, "## When a service rejects the credential")
	j := strings.Index(s, "## Long commands")
	if i < 0 || j < i {
		t.Fatal("the section about a rejected credential is missing")
	}
	section := s[i:j]
	for _, want := range []string{
		"`last_used_at`",
		"`last_exit_code`",
		"`last_ok_at`",
		"an exit code of 0 is a hint, not proof",
		"never used successfully",
		"before the user's memory",
		"on this device",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("the rejected-credential section does not say %q", want)
		}
	}
}
