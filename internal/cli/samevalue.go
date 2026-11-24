package cli

import (
	"slices"
	"strings"

	"github.com/qbitdevz/qbit-vault/internal/prompt"
	"github.com/qbitdevz/qbit-vault/internal/prompt/i18n"
	"github.com/qbitdevz/qbit-vault/internal/secret"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

// A value the user just typed repeats another one more often by mistake than
// on purpose: the old value in a replace, a different secret, or another box
// of the same form (a password typed in the user-name field, a replace that
// changed nothing). The user is asked once, after every value of a capture is
// typed and checked for quotes and invisible characters and before anything is
// stored (issue #62, odd/tasks/issues-61-65-dialogs.md T8). The comparison is
// in memory and in constant time; the dialog names secrets, never a value or a
// length, and what the agent that triggered it learns is the usual outcome.

// typedValue is one value typed in a capture, not yet stored.
type typedValue struct {
	name  string
	layer vault.Layer
	value []byte
}

// sameFinding is what one typed value repeats: the value it replaces, and the
// names of other secrets that hold it.
type sameFinding struct {
	name     string
	replaced bool
	others   []string
}

// sameValues compares every typed value with the stored secret it replaces
// (same name and layer), with the other secrets of its layer and with the
// typed values after it. It returns only the values that repeat something.
func (s *session) sameValues(typed []typedValue) ([]sameFinding, error) {
	all, err := s.v.ListAll()
	if err != nil {
		return nil, err
	}
	defer wipeEntries(all)
	vals := make([]secret.Secret, len(typed))
	for i, t := range typed {
		vals[i] = secret.New(t.name, t.value)
	}
	defer func() {
		for _, v := range vals {
			v.Wipe()
		}
	}()
	var out []sameFinding
	for i, t := range typed {
		f := sameFinding{name: t.name}
		for _, e := range all {
			if !sameLayer(e.Layer, t.layer) || !secret.Equal(vals[i], e.Record.Value) {
				continue
			}
			if e.Name == t.name {
				f.replaced = true
			} else {
				f.others = append(f.others, e.Name)
			}
		}
		for j := i + 1; j < len(typed); j++ {
			if secret.Equal(vals[i], vals[j]) && !slices.Contains(f.others, typed[j].name) {
				f.others = append(f.others, typed[j].name)
			}
		}
		if f.replaced || len(f.others) > 0 {
			out = append(out, f)
		}
	}
	return out, nil
}

// confirmSameValues asks once about everything sameValues found. It returns
// nil when there is nothing to ask or the user chose to save anyway, and
// prompt.ErrCancelled when they did not, so a caller treats it exactly like a
// cancelled dialog.
func confirmSameValues(ask prompt.Backend, loc i18n.Locale, found []sameFinding) error {
	if len(found) == 0 {
		return nil
	}
	var lines []string
	for _, f := range found {
		if f.replaced {
			lines = append(lines, loc.T("q.same_replaced", f.name))
		}
		if len(f.others) > 0 {
			lines = append(lines, loc.T("q.same_other", f.name, strings.Join(f.others, ", ")))
		}
	}
	lines = append(lines, loc.T("q.same_save"))
	// Not saving is the preselected answer: this dialog exists to stop a mistake.
	i, err := ask.Choose(strings.Join(lines, "\n"), []string{loc.T("opt.save_anyway"), loc.T("btn.cancel")}, 1)
	if err != nil {
		return err
	}
	if i != 0 {
		return prompt.ErrCancelled
	}
	return nil
}
