package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
)

// Issue #64: a linked Git worktree shares the project of its main clone, only
// when both name each other (internal/vault/worktree.go). The tests write the
// Git files by hand, as `git worktree add` does, and never run git.

func gitSlash(p string) string { return filepath.ToSlash(p) }

func writeGit(t *testing.T, p, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// mkWorktree links <base>/<name> to w.repo as a real linked worktree.
func (w *world) mkWorktree(name string, relative bool) string {
	w.t.Helper()
	wt := filepath.Join(filepath.Dir(w.repo), name)
	gitdir := filepath.Join(w.repo, ".git", "worktrees", name)
	if err := os.MkdirAll(wt, 0o700); err != nil {
		w.t.Fatal(err)
	}
	writeGit(w.t, filepath.Join(gitdir, "HEAD"), "ref: refs/heads/x\n")
	writeGit(w.t, filepath.Join(gitdir, "commondir"), "../..\n")
	rel := func(from, to string) string {
		r, err := filepath.Rel(from, to)
		if err != nil {
			w.t.Fatal(err)
		}
		return gitSlash(r)
	}
	if relative {
		writeGit(w.t, filepath.Join(gitdir, "gitdir"), rel(gitdir, filepath.Join(wt, ".git"))+"\n")
		writeGit(w.t, filepath.Join(wt, ".git"), "gitdir: "+rel(wt, gitdir)+"\n")
	} else {
		writeGit(w.t, filepath.Join(gitdir, "gitdir"), gitSlash(filepath.Join(wt, ".git"))+"\n")
		writeGit(w.t, filepath.Join(wt, ".git"), "gitdir: "+gitSlash(gitdir)+"\n")
	}
	return wt
}

// notWorktrees are directories whose .git file claims to be a linked worktree
// of w.repo but is not confirmed by it. Each keeps its own project.
func (w *world) notWorktrees() map[string]string {
	w.t.Helper()
	base := filepath.Dir(w.repo)
	out := map[string]string{}

	planted := filepath.Join(base, "planted")
	legit := w.mkWorktree("legit", false)
	_ = legit
	writeGit(w.t, filepath.Join(planted, ".git"), "gitdir: "+gitSlash(filepath.Join(w.repo, ".git", "worktrees", "legit"))+"\n")
	out["a planted .git file the repository does not point back to"] = planted

	elsewhere := filepath.Join(base, "elsewhere")
	w.mkWorktree("elsewhere", false)
	writeGit(w.t, filepath.Join(w.repo, ".git", "worktrees", "elsewhere", "gitdir"), gitSlash(filepath.Join(base, "somewhere-else", ".git"))+"\n")
	out["a back-pointer to another path"] = elsewhere

	gone := w.mkWorktree("gone", false)
	if err := os.Remove(filepath.Join(w.repo, ".git", "worktrees", "gone", "gitdir")); err != nil {
		w.t.Fatal(err)
	}
	out["a missing back-pointer"] = gone

	sub := filepath.Join(base, "sub")
	mod := filepath.Join(w.repo, ".git", "modules", "sub")
	writeGit(w.t, filepath.Join(mod, "gitdir"), gitSlash(filepath.Join(sub, ".git"))+"\n")
	writeGit(w.t, filepath.Join(sub, ".git"), "gitdir: "+gitSlash(mod)+"\n")
	out["a submodule gitdir"] = sub

	orphan := filepath.Join(base, "orphan")
	writeGit(w.t, filepath.Join(orphan, ".git"), "gitdir: "+gitSlash(filepath.Join(base, "removed-main", ".git", "worktrees", "orphan"))+"\n")
	out["a main clone that is gone"] = orphan

	escape := filepath.Join(base, "escape")
	writeGit(w.t, filepath.Join(escape, ".git"), "gitdir: "+strings.Repeat("../", 40)+"nowhere\n")
	out["a relative path that escapes"] = escape
	return out
}

func listNames(t *testing.T, out string) []string {
	t.Helper()
	var b struct {
		Project *struct{ Root, Label string } `json:"project"`
		Secrets []struct {
			Name  string `json:"name"`
			Layer string `json:"layer"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal([]byte(out), &b); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range b.Secrets {
		names = append(names, s.Name+"@"+s.Layer)
	}
	return names
}

// A project secret of the main clone is listed and runnable from a linked
// worktree, with no session and a project grant, and it is redacted.
func TestLinkedWorktreeSharesTheProjectOfItsMainClone(t *testing.T) {
	for name, relative := range map[string]bool{"absolute gitdir": false, "relative gitdir": true} {
		t.Run(name, func(t *testing.T) {
			w := newExecWorld(t)
			w.setSecret("GITHUB_TOKEN", xg, "--global")
			w.inRepo()
			w.setSecret("PROJ_KEY", xp, "--project")
			w.mustRun("y\n", "grant", "GITHUB_TOKEN", "--scope", "project")
			w.mustRun("y\n", "grant", "PROJ_KEY", "--scope", "project")
			wt := w.mkWorktree("shop-api-feature", relative)
			sub := filepath.Join(wt, "pkg", "deep")
			if err := os.MkdirAll(sub, 0o700); err != nil {
				t.Fatal(err)
			}

			for _, dir := range []string{wt, sub} {
				t.Chdir(dir)
				out := w.mustRun("", "--json", "list")
				if got := strings.Join(listNames(t, out), ","); got != "GITHUB_TOKEN@global,PROJ_KEY@project" {
					t.Fatalf("list from %s: %s", filepath.Base(dir), out)
				}
				if !strings.Contains(out, `"project":`+w.projectJSON()) {
					t.Fatalf("the project is not the main clone's: %s", out)
				}
				for _, secret := range []string{"GITHUB_TOKEN", "PROJ_KEY"} {
					code, out, errs := w.run("", append([]string{"--json"}, noSessionArgs([]string{secret}, child(t, "leaks", secret, 0))...)...)
					if code != 0 || errs != "" || !strings.Contains(out, "[REDACTED:"+secret+"]") || strings.Contains(out, xg) || strings.Contains(out, xp) {
						t.Fatalf("exec %s from %s: code=%d out=%q err=%q", secret, filepath.Base(dir), code, out, errs)
					}
				}
			}
			// --cwd keeps its meaning: it selects the project and the child's directory.
			w.outRepo()
			code, out, errs := w.run("", noSessionArgs([]string{"PROJ_KEY"}, child(t, "env", "PROJ_KEY", 0), "--cwd", wt)...)
			if code != 0 || errs != "" || nl(out) != "PROJ_KEY=...000BBBB\n" {
				t.Fatalf("--cwd worktree: code=%d out=%q err=%q", code, out, errs)
			}
		})
	}
}

// A grant approved from the worktree is the main clone's grant and the other
// way round.
func TestProjectGrantFromAWorktreeIsTheMainClonesGrant(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xg, "--global")
	wt := w.mkWorktree("feature", false)
	t.Chdir(wt)
	w.mustRun("y\n", "grant", "GITHUB_TOKEN", "--scope", "project")
	w.inRepo()
	if code, out, errs := w.run("", noSessionArgs([]string{"GITHUB_TOKEN"}, child(t, "mark", marker(t), 0))...); code != 0 {
		t.Fatalf("main clone: code=%d out=%q err=%q", code, out, errs)
	}
}

func TestBrokerFromAWorktreeUsesTheMainClonesProject(t *testing.T) {
	w := newWorld(t)
	w.approveProjectGrant() // global A, granted for w.repo
	wt := w.mkWorktree("feature", true)
	e, out := w.listed(wt, "A")
	if g, _ := e["grant"].(map[string]any); g["scope"] != "project" {
		t.Fatalf("list from the worktree: %s", out)
	}
	if !strings.Contains(out, `"project":{"root":`+jsonString(w.root)) {
		t.Fatalf("project of the listing: %s", out)
	}
	if code, m := w.execIn(wt); code != exitcode.OK || m["ok"] != true {
		t.Fatalf("exec from the worktree: code=%d m=%v", code, m)
	}
}

// A .git file that is not confirmed by the repository it names keeps its own
// project: no secret of the main clone, no grant of it.
func TestUnconfirmedWorktreeLinksKeepTheirOwnProject(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xg, "--global")
	w.inRepo()
	w.setSecret("PROJ_KEY", xp, "--project")
	w.mustRun("y\n", "grant", "GITHUB_TOKEN", "--scope", "project")
	w.mustRun("y\n", "grant", "PROJ_KEY", "--scope", "project")
	for name, dir := range w.notWorktrees() {
		t.Run(name, func(t *testing.T) {
			t.Chdir(dir)
			out := w.mustRun("", "--json", "list")
			if got := strings.Join(listNames(t, out), ","); got != "GITHUB_TOKEN@global" {
				t.Fatalf("list sees the main clone's project: %s", out)
			}
			if strings.Contains(out, w.root) {
				t.Fatalf("list names the main clone: %s", out)
			}
			// No project secret, no project grant of the main clone.
			code, out, _ := w.run("", append([]string{"--json"}, noSessionArgs([]string{"PROJ_KEY"}, "true")...)...)
			if code != exitcode.Refusal || !strings.Contains(out, `"type":"unknown_secret"`) {
				t.Fatalf("PROJ_KEY: code=%d out=%q", code, out)
			}
			code, out, _ = w.run("", append([]string{"--json"}, noSessionArgs([]string{"GITHUB_TOKEN"}, "true")...)...)
			if code != exitcode.Refusal || !strings.Contains(out, `"type":"grant_required"`) {
				t.Fatalf("GITHUB_TOKEN: code=%d out=%q", code, out)
			}
			// The broker agrees (the MCP server uses it).
			_, _, bl := w.broker("list", envelope("list", dir, ""))
			if strings.Contains(bl, w.root) || strings.Contains(bl, "PROJ_KEY") {
				t.Fatalf("broker list sees the main clone's project: %s", bl)
			}
			exe := child(t, "mark", marker(t), 0)
			c, m, _ := w.broker("exec", envelope("exec", dir, `"command":`+jsonString(exe)+`,"secrets":[{"name":"PROJ_KEY","from":"PROJ_KEY"}]`))
			if c != exitcode.Refusal || refusalType(m) != "unknown_secret" {
				t.Fatalf("broker exec: code=%d m=%v", c, m)
			}
		})
	}
}

// What the worktree rule must not change.
func TestProjectResolutionOfPlainRepositoriesIsUnchanged(t *testing.T) {
	w := newExecWorld(t)
	w.setSecret("GITHUB_TOKEN", xg, "--global")
	w.inRepo()
	w.setSecret("PROJ_KEY", xp, "--project")
	w.mustRun("y\n", "grant", "GITHUB_TOKEN", "--scope", "project")
	w.mustRun("y\n", "grant", "PROJ_KEY", "--scope", "project")
	sub := filepath.Join(w.repo, "pkg", "deep")
	nested := filepath.Join(w.repo, "vendor", "lib")
	for _, d := range []string{sub, filepath.Join(nested, ".git")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	other := w.mkRepo("other-repo")
	t.Chdir(other)
	w.setSecret("PROJ_KEY", "TESTSECRET_other_000CCCC", "--project")
	w.outRepo()

	env := child(t, "env", "PROJ_KEY", 0)
	for _, c := range []struct {
		name, dir, want string
		code            int
	}{
		{"repository root", w.repo, "PROJ_KEY=...000BBBB\n", 0},
		{"subdirectory", sub, "PROJ_KEY=...000BBBB\n", 0},
		{"another repository, by --cwd", other, "", exitcode.Refusal}, // its own PROJ_KEY has no grant
		{"nested repository does not inherit the grant", nested, "", exitcode.Refusal},
	} {
		code, out, errs := w.run("", noSessionArgs([]string{"PROJ_KEY"}, env, "--cwd", c.dir)...)
		if code != c.code || (c.code == 0 && (nl(out) != c.want || errs != "")) {
			t.Fatalf("%s: code=%d out=%q err=%q", c.name, code, out, errs)
		}
	}
	// --cwd names the project: from outside any repository the project secret
	// is out of reach, and the global one needs its repository's grant.
	code, _, errs := w.run("", noSessionArgs([]string{"PROJ_KEY"}, env)...)
	if code != exitcode.Refusal || !strings.HasPrefix(errs, "error: PROJ_KEY is not stored") {
		t.Fatalf("outside: code=%d err=%q", code, errs)
	}
}
