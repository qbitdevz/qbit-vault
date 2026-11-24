package skill_test

import (
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/hosts/skill"
)

// Issue #62: a replace keeps the old value for 7 days. When the replace did
// not fix the rejection, the agent proposes revert instead of asking the user
// to remember the old value.
func TestSkillProposesRevertWhenAReplaceDidNotFixTheRejection(t *testing.T) {
	s := string(skill.Content)
	i := strings.Index(s, "## When a service rejects the credential")
	j := strings.Index(s, "## Long commands")
	if i < 0 || j < i {
		t.Fatal("the section about a rejected credential is missing")
	}
	section := s[i:j]
	for _, want := range []string{
		"`previous_until`",
		"`secret_manage` with the action `revert`",
		"instead of asking the user to remember the old value",
		"never shows you either value",
		"The user confirms in a dialog outside the chat",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("the rejected-credential section does not say %q", want)
		}
	}
	if strings.Index(section, "`previous_until`") < strings.Index(section, "propose **one**") {
		t.Error("revert is offered before the replace it undoes")
	}
	if !strings.Contains(s, "or revert it") {
		t.Error("rule 5 does not list revert among the manage actions")
	}
}
