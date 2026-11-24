package cli

import (
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
)

// Issue #64: when exec cannot find a name, the person reading the terminal is
// told which layers were searched, in the terms `list` uses for the project.
// The JSON refusal keeps its fixed message and hint: no label, no path.

func TestExecNotFoundNamesTheLayersSearched(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xg, "--global")
	wt := w.mkWorktree("shop-api-feature", false)
	for _, c := range []struct{ name, dir, note string }{
		{"in a repository", w.repo, " (searched: project shop-api, global)"},
		{"in a linked worktree: the main clone's label", wt, " (searched: project shop-api, global)"},
		{"outside any repository", w.outside, " (searched: global; no project applies here)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Chdir(c.dir)
			code, out, errs := w.run("", noSessionArgs([]string{"NOPE_TOKEN"}, "true")...)
			if code != exitcode.Refusal || out != "" || errs != "error: NOPE_TOKEN is not stored"+c.note+"\n" {
				t.Fatalf("human: code=%d out=%q err=%q", code, out, errs)
			}
			code, out, errs = w.run("", append([]string{"--json"}, noSessionArgs([]string{"NOPE_TOKEN"}, "true")...)...)
			want := jsonOf(t, refusal.New(refusal.UnknownSecret, "NOPE_TOKEN").Envelope())
			if code != exitcode.Refusal || out != want || errs != "" || strings.Contains(out, "searched") || strings.Contains(out, "shop-api") {
				t.Fatalf("json: code=%d out=%q err=%q", code, out, errs)
			}
		})
	}
}

// --cwd selects the project that is searched, and the note says which.
func TestExecNotFoundNoteFollowsCwd(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xg, "--global")
	code, _, errs := w.run("", noSessionArgs([]string{"NOPE_TOKEN"}, "true", "--cwd", w.repo)...)
	if code != exitcode.Refusal || errs != "error: NOPE_TOKEN is not stored (searched: project shop-api, global)\n" {
		t.Fatalf("code=%d err=%q", code, errs)
	}
}
