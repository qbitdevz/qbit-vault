package vault

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A linked worktree shares the project of its main clone (issue #64). The
// link is a security boundary (project secrets and project grants are keyed
// by the root), so it is followed only when the worktree and the main clone
// name each other. These tests write the Git files by hand, as `git worktree
// add` does, and never run git.

type linkStyle int

const (
	absolute linkStyle = iota
	relative
)

// gitPath writes p the way Git does: forward slashes, also on Windows.
func gitPath(p string) string { return filepath.ToSlash(p) }

// mkMain creates a main working tree with a .git directory.
func mkMain(t *testing.T, base, name string) string {
	t.Helper()
	main := mkDir(t, base, name)
	mkDir(t, main, ".git", "worktrees")
	return main
}

func writeFile(t *testing.T, p, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// mkLinked adds a linked worktree <base>/<name> to main, the way git does:
// <main>/.git/worktrees/<id>/{gitdir,commondir,HEAD} and <wt>/.git.
func mkLinked(t *testing.T, main, base, name string, style linkStyle) (wt, gitdir string) {
	t.Helper()
	wt = mkDir(t, base, name)
	gitdir = filepath.Join(main, ".git", "worktrees", name)
	mkDir(t, gitdir)
	writeFile(t, filepath.Join(gitdir, "HEAD"), "ref: refs/heads/x\n")
	writeFile(t, filepath.Join(gitdir, "commondir"), "../..\n")
	rel := func(from, to string) string {
		r, err := filepath.Rel(from, to)
		if err != nil {
			t.Fatal(err)
		}
		return gitPath(r)
	}
	if style == relative {
		writeFile(t, filepath.Join(gitdir, "gitdir"), rel(gitdir, filepath.Join(wt, ".git"))+"\n")
		writeFile(t, filepath.Join(wt, ".git"), "gitdir: "+rel(wt, gitdir)+"\n")
	} else {
		writeFile(t, filepath.Join(gitdir, "gitdir"), gitPath(filepath.Join(wt, ".git"))+"\n")
		writeFile(t, filepath.Join(wt, ".git"), "gitdir: "+gitPath(gitdir)+"\n")
	}
	return wt, gitdir
}

func TestLinkedWorktreeResolvesToItsMainClone(t *testing.T) {
	for name, style := range map[string]linkStyle{"absolute gitdir": absolute, "relative gitdir": relative} {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			main := mkMain(t, base, "shop-api")
			wt, _ := mkLinked(t, main, base, "shop-api-feature", style)
			sub := mkDir(t, wt, "pkg", "deep")
			want := canonicalPath(t, main)
			for _, cwd := range []string{wt, sub} {
				got, ok, err := ProjectRoot(cwd)
				if err != nil || !ok || got != foldCase(want) {
					t.Fatalf("ProjectRoot(%s) = %q ok=%v err=%v, want the main clone %q", filepath.Base(cwd), got, ok, err, foldCase(want))
				}
				l, err := ProjectLayer(cwd)
				if err != nil || l.Root != foldCase(want) || l.Label != "shop-api" || !l.Project {
					t.Fatalf("ProjectLayer(%s) = %+v err=%v", filepath.Base(cwd), l, err)
				}
			}
			// The main clone itself is unchanged.
			if got, _, _ := ProjectRoot(main); got != foldCase(want) {
				t.Fatalf("main clone root %q", got)
			}
		})
	}
}

// A worktree inside the main clone's tree is still its own .git file first.
func TestLinkedWorktreeInsideTheMainTree(t *testing.T) {
	base := t.TempDir()
	main := mkMain(t, base, "shop-api")
	wt, _ := mkLinked(t, main, filepath.Join(main, ".worktrees"), "feature", absolute)
	got, ok, err := ProjectRoot(mkDir(t, wt, "x"))
	if err != nil || !ok || got != foldCase(canonicalPath(t, main)) {
		t.Fatalf("root %q ok=%v err=%v", got, ok, err)
	}
}

func TestEveryProjectRootConsumerFollowsTheWorktree(t *testing.T) {
	base := t.TempDir()
	main := mkMain(t, base, "shop-api")
	wt, _ := mkLinked(t, main, base, "feature", absolute)
	a, _, _, _ := findRoot(wt)
	b, _, _, _ := findRoot(main)
	if a != b {
		t.Fatalf("findRoot disagrees: %q vs %q", a, b)
	}
}

// Everything below must behave exactly as before: the directory with the
// .git file is its own root.
func TestWorktreeLinkIsNotFollowedWhenItIsNotTwoWay(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, base string) (wt string)
	}{
		{"planted .git file: the repository does not point back", func(t *testing.T, base string) string {
			main := mkMain(t, base, "victim")
			_, gitdir := mkLinked(t, main, base, "legit", absolute)
			planted := mkDir(t, base, "planted")
			writeFile(t, filepath.Join(planted, ".git"), "gitdir: "+gitPath(gitdir)+"\n")
			return planted
		}},
		{"planted .git file naming a worktree entry with no gitdir file", func(t *testing.T, base string) string {
			main := mkMain(t, base, "victim")
			gitdir := mkDir(t, main, ".git", "worktrees", "ghost")
			planted := mkDir(t, base, "planted")
			writeFile(t, filepath.Join(planted, ".git"), "gitdir: "+gitPath(gitdir)+"\n")
			return planted
		}},
		{"back-pointer names another worktree", func(t *testing.T, base string) string {
			main := mkMain(t, base, "main")
			wt, gitdir := mkLinked(t, main, base, "wt", absolute)
			other := mkDir(t, base, "other")
			writeFile(t, filepath.Join(other, ".git"), "gitdir: x\n")
			writeFile(t, filepath.Join(gitdir, "gitdir"), gitPath(filepath.Join(other, ".git"))+"\n")
			return wt
		}},
		{"back-pointer names a path that does not exist", func(t *testing.T, base string) string {
			main := mkMain(t, base, "main")
			wt, gitdir := mkLinked(t, main, base, "wt", absolute)
			writeFile(t, filepath.Join(gitdir, "gitdir"), gitPath(filepath.Join(base, "gone", ".git"))+"\n")
			return wt
		}},
		{"back-pointer is empty", func(t *testing.T, base string) string {
			main := mkMain(t, base, "main")
			wt, gitdir := mkLinked(t, main, base, "wt", absolute)
			writeFile(t, filepath.Join(gitdir, "gitdir"), "\n")
			return wt
		}},
		{"back-pointer is unreadable (a directory)", func(t *testing.T, base string) string {
			main := mkMain(t, base, "main")
			wt, gitdir := mkLinked(t, main, base, "wt", absolute)
			if err := os.Remove(filepath.Join(gitdir, "gitdir")); err != nil {
				t.Fatal(err)
			}
			mkDir(t, gitdir, "gitdir")
			return wt
		}},
		{"back-pointer is missing", func(t *testing.T, base string) string {
			main := mkMain(t, base, "main")
			wt, gitdir := mkLinked(t, main, base, "wt", absolute)
			if err := os.Remove(filepath.Join(gitdir, "gitdir")); err != nil {
				t.Fatal(err)
			}
			return wt
		}},
		{"back-pointer is larger than a path can be", func(t *testing.T, base string) string {
			main := mkMain(t, base, "main")
			wt, gitdir := mkLinked(t, main, base, "wt", absolute)
			writeFile(t, filepath.Join(gitdir, "gitdir"), gitPath(filepath.Join(wt, ".git"))+strings.Repeat("\n ", 4096))
			return wt
		}},
		{"the main clone is gone", func(t *testing.T, base string) string {
			main := mkMain(t, base, "main")
			wt, gitdir := mkLinked(t, main, base, "wt", absolute)
			if err := os.RemoveAll(gitdir); err != nil {
				t.Fatal(err)
			}
			return wt
		}},
		{"the repository is bare (no .git directory to be the main tree)", func(t *testing.T, base string) string {
			bare := mkDir(t, base, "bare.git", "worktrees")
			wt := mkDir(t, base, "wt")
			gitdir := mkDir(t, bare, "worktrees", "wt")
			writeFile(t, filepath.Join(gitdir, "gitdir"), gitPath(filepath.Join(wt, ".git"))+"\n")
			writeFile(t, filepath.Join(wt, ".git"), "gitdir: "+gitPath(gitdir)+"\n")
			return wt
		}},
		{"commondir names another repository", func(t *testing.T, base string) string {
			main := mkMain(t, base, "main")
			other := mkMain(t, base, "other")
			wt, gitdir := mkLinked(t, main, base, "wt", absolute)
			writeFile(t, filepath.Join(gitdir, "commondir"), gitPath(filepath.Join(other, ".git"))+"\n")
			return wt
		}},
		{"a relative path that escapes", func(t *testing.T, base string) string {
			wt := mkDir(t, base, "wt")
			writeFile(t, filepath.Join(wt, ".git"), "gitdir: "+strings.Repeat("../", 40)+"etc/passwd\n")
			return wt
		}},
		{"a relative path to a directory that is not a worktree entry", func(t *testing.T, base string) string {
			main := mkMain(t, base, "main")
			wt := mkDir(t, base, "wt")
			writeFile(t, filepath.Join(wt, ".git"), "gitdir: ../main/.git\n")
			_ = main
			return wt
		}},
		{"a submodule (gitdir under .git/modules)", func(t *testing.T, base string) string {
			super := mkMain(t, base, "super")
			mod := mkDir(t, super, ".git", "modules", "sub")
			sub := mkDir(t, super, "sub")
			writeFile(t, filepath.Join(sub, ".git"), "gitdir: ../.git/modules/sub\n")
			// Even with a back-pointer someone wrote by hand.
			writeFile(t, filepath.Join(mod, "gitdir"), gitPath(filepath.Join(sub, ".git"))+"\n")
			return sub
		}},
		{"a worktree of a submodule", func(t *testing.T, base string) string {
			super := mkMain(t, base, "super")
			mod := mkDir(t, super, ".git", "modules", "sub")
			mkDir(t, mod, "worktrees")
			wt := mkDir(t, base, "wt")
			gitdir := mkDir(t, mod, "worktrees", "wt")
			writeFile(t, filepath.Join(gitdir, "gitdir"), gitPath(filepath.Join(wt, ".git"))+"\n")
			writeFile(t, filepath.Join(gitdir, "commondir"), "../..\n")
			writeFile(t, filepath.Join(wt, ".git"), "gitdir: "+gitPath(gitdir)+"\n")
			return wt
		}},
		{"a submodule directory named .git", func(t *testing.T, base string) string {
			super := mkMain(t, base, "super")
			mod := mkDir(t, super, ".git", "modules", ".git")
			wt := mkDir(t, base, "wt")
			gitdir := mkDir(t, mod, "worktrees", "wt")
			writeFile(t, filepath.Join(gitdir, "gitdir"), gitPath(filepath.Join(wt, ".git"))+"\n")
			writeFile(t, filepath.Join(wt, ".git"), "gitdir: "+gitPath(gitdir)+"\n")
			return wt
		}},
		{"the .git file has a second line", func(t *testing.T, base string) string {
			main := mkMain(t, base, "main")
			wt, gitdir := mkLinked(t, main, base, "wt", absolute)
			writeFile(t, filepath.Join(wt, ".git"), "gitdir: "+gitPath(gitdir)+"\nmore\n")
			return wt
		}},
		{"the .git file has no gitdir prefix", func(t *testing.T, base string) string {
			main := mkMain(t, base, "main")
			wt, gitdir := mkLinked(t, main, base, "wt", absolute)
			writeFile(t, filepath.Join(wt, ".git"), gitPath(gitdir)+"\n")
			return wt
		}},
		{"the .git file is empty", func(t *testing.T, base string) string {
			main := mkMain(t, base, "main")
			wt, _ := mkLinked(t, main, base, "wt", absolute)
			writeFile(t, filepath.Join(wt, ".git"), "")
			return wt
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wt := tc.setup(t, t.TempDir())
			got, ok, err := ProjectRoot(wt)
			if err != nil || !ok || got != foldCase(canonicalPath(t, wt)) {
				t.Fatalf("root %q ok=%v err=%v, want the directory itself %q", got, ok, err, foldCase(canonicalPath(t, wt)))
			}
			l, err := ProjectLayer(mkDir(t, wt, "inner"))
			if err != nil || l.Root != got || l.Label != filepath.Base(canonicalPath(t, wt)) {
				t.Fatalf("layer %+v err=%v", l, err)
			}
		})
	}
}

// A worktree that was moved keeps a stale back-pointer: it is its own root
// until `git worktree repair`.
func TestMovedWorktreeIsNotFollowed(t *testing.T) {
	base := t.TempDir()
	main := mkMain(t, base, "main")
	wt, _ := mkLinked(t, main, base, "wt", absolute)
	moved := filepath.Join(base, "moved")
	if err := os.Rename(wt, moved); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := ProjectRoot(moved); got != foldCase(canonicalPath(t, moved)) {
		t.Fatalf("a moved worktree resolved to %q", got)
	}
}

// Nested repositories keep their own root; the worktree rule adds nothing.
func TestNestedRepositoryIsStillItsOwnProject(t *testing.T) {
	base := t.TempDir()
	main := mkMain(t, base, "main")
	nested := mkRepo(t, main, "vendored", false)
	if got, _, _ := ProjectRoot(mkDir(t, nested, "x")); got != foldCase(canonicalPath(t, nested)) {
		t.Fatalf("nested root %q", got)
	}
}

func TestWorktreeLinkThroughSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	base := t.TempDir()
	main := mkMain(t, base, "main")
	wt, _ := mkLinked(t, main, base, "wt", absolute)
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(wt, alias); err != nil {
		t.Fatal(err)
	}
	// The vault reaches the worktree through a symlink: same answer.
	got, ok, err := ProjectRoot(alias)
	if err != nil || !ok || got != canonicalPath(t, main) {
		t.Fatalf("root %q ok=%v err=%v", got, ok, err)
	}
	// A .git file that is itself a symlink to a real worktree's file is not a
	// worktree: it is refused as a link.
	planted := mkDir(t, base, "planted")
	if err := os.Symlink(filepath.Join(wt, ".git"), filepath.Join(planted, ".git")); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := ProjectRoot(planted); got != canonicalPath(t, planted) {
		t.Fatalf("a symlinked .git file was followed: %q", got)
	}
}
