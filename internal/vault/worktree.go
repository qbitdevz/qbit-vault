package vault

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxGitLinkFile bounds the Git files read to follow a worktree link: a path
// is never this long, and a bigger file is not a Git link.
const maxGitLinkFile = 4096

// linkedMainTree follows dir, a canonical (absolute, symlink-free) directory
// whose .git entry exists, to the main working tree of the repository when dir
// is a linked worktree of it (issue #64). It reports ok only when the link is
// confirmed in both directions by reading the files Git writes, never by
// running git:
//
//   - dir/.git is a regular file `gitdir: <D>` and D is
//     <main>/.git/worktrees/<id>, where <main>/.git is a real directory (not a
//     bare repository, not under .git/modules, so not a submodule);
//   - D/commondir, when present, names <main>/.git again;
//   - D/gitdir names dir/.git back (the same canonical path, case-folded only
//     where the rest of the vault is).
//
// Project secrets and project grants are keyed by the repository root, so a
// planted .git file that names someone else's repository must not claim its
// project: such a file has no back-pointer to it, and any doubt (unreadable or
// oversized file, a path that does not resolve, another layout) is ok == false
// and the caller keeps dir as its own root. root is canonical like findRoot's,
// before case folding.
func linkedMainTree(dir string) (root string, ok bool) {
	gitFile := filepath.Join(dir, ".git")
	target, ok := readGitLink(gitFile, "gitdir: ")
	if !ok {
		return "", false
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(dir, target)
	}
	gitdir, err := filepath.EvalSymlinks(filepath.Clean(target))
	if err != nil {
		return "", false
	}
	if fi, err := os.Stat(gitdir); err != nil || !fi.IsDir() {
		return "", false
	}
	// <main>/.git/worktrees/<id>
	worktrees := filepath.Dir(gitdir)
	common := filepath.Dir(worktrees)
	if foldCase(filepath.Base(worktrees)) != "worktrees" || foldCase(filepath.Base(common)) != ".git" {
		return "", false
	}
	if underModules(common) {
		return "", false // a submodule's repository, whatever it holds
	}
	// The main working tree's .git must be a real directory.
	if fi, err := os.Lstat(common); err != nil || !fi.IsDir() {
		return "", false
	}
	if rel, present, rok := readPointer(filepath.Join(gitdir, "commondir")); present {
		if !rok {
			return "", false
		}
		if !filepath.IsAbs(rel) {
			rel = filepath.Join(gitdir, rel)
		}
		real, err := filepath.EvalSymlinks(filepath.Clean(rel))
		if err != nil || foldCase(real) != foldCase(common) {
			return "", false
		}
	}
	// The back-pointer: the worktree entry must name this very .git file.
	back, present, bok := readPointer(filepath.Join(gitdir, "gitdir"))
	if !present || !bok {
		return "", false
	}
	if !filepath.IsAbs(back) {
		back = filepath.Join(gitdir, back)
	}
	realBack, err := filepath.EvalSymlinks(filepath.Clean(back))
	if err != nil || foldCase(realBack) != foldCase(gitFile) {
		return "", false
	}
	return filepath.Dir(common), true
}

// underModules reports whether p is inside a .git/modules tree.
func underModules(p string) bool {
	parts := strings.Split(filepath.ToSlash(p), "/")
	for i := 1; i < len(parts); i++ {
		if foldCase(parts[i]) == "modules" && foldCase(parts[i-1]) == ".git" {
			return true
		}
	}
	return false
}

// readGitLink reads the single-line regular file p and returns what follows
// prefix. ok is false for a symlink, a directory, a file over maxGitLinkFile,
// a second line, an empty value or a missing prefix.
func readGitLink(p, prefix string) (string, bool) {
	text, present, ok := readSmallLine(p)
	if !present || !ok || !strings.HasPrefix(text, prefix) {
		return "", false
	}
	v := strings.TrimPrefix(text, prefix)
	return v, v != ""
}

// readPointer is readGitLink with no prefix, and also says whether the file
// is there at all (a worktree entry may lack commondir; it may not lack gitdir).
func readPointer(p string) (value string, present, ok bool) {
	v, present, ok := readSmallLine(p)
	return v, present, ok && v != ""
}

// readSmallLine returns the content of a regular file of at most
// maxGitLinkFile bytes, without its trailing line break. present is false when
// nothing exists at p; ok is false when something does but is not such a file
// or has more than one line.
func readSmallLine(p string) (text string, present, ok bool) {
	fi, err := os.Lstat(p)
	if err != nil {
		return "", !os.IsNotExist(err), false
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxGitLinkFile {
		return "", true, false
	}
	f, err := os.Open(p)
	if err != nil {
		return "", true, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxGitLinkFile+1))
	if err != nil || len(b) > maxGitLinkFile {
		return "", true, false
	}
	text = strings.TrimRight(string(b), "\r\n")
	if strings.ContainsAny(text, "\r\n\x00") {
		return "", true, false
	}
	return text, true, true
}
