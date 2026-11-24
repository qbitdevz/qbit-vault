package dumpguard

import "strings"

// Match reports whether cmd must be refused while the secrets named in
// injected are in the child's environment. With nothing injected the guard
// does not apply (R-EXEC-03) and Match is false.
//
// Every segment is tested in up to four forms: as normalized; with input
// redirections (`< file`) folded into plain arguments; and each of those with
// wrappers and the program path resolved, the program lowercased (so
// `/usr/bin/env`, `sudo env`, `command env` and `ENV` all look like `env`).
// A PowerShell encoded command is refused outright: its script is opaque.
func (g *Guard) Match(cmd string, injected []string) (refused bool) {
	_, refused = g.Explain(cmd, injected)
	return refused
}

// Hit says which rule refused a command and where. It holds no text of the
// command or of the pattern.
type Hit struct {
	Class Class
	// Segment is the 0-based index of the top-level pipeline segment that holds
	// the match (a script run by `sh -c` or a $(...) counts as part of its
	// segment), or -1 when it is not known (a here-document body, MatchRaw).
	Segment int
}

// Explain is Match that also returns the first rule to match, in the order
// Match tests: segments, then forms, then patterns.
func (g *Guard) Explain(cmd string, injected []string) (Hit, bool) {
	if len(injected) == 0 {
		return Hit{}, false
	}
	res := g.compiled(injected)
	segs := Segments(cmd)
	pipeline := len(segs)
	if strings.Contains(cmd, "<<") {
		// Here-document bodies are not commands but they reach a program's
		// stdin: test the whole text as one segment too.
		segs = append(segs, rawSegment(strings.NewReplacer("\r", " ", "\n", " ").Replace(cmd)))
	}
	for i, seg := range segs {
		at := seg.top // the top-level segment that holds a nested script or substitution
		if i >= pipeline {
			at = -1
		}
		if h, ok := hitIn(seg, res, at); ok {
			return h, true
		}
	}
	return Hit{}, false
}

// hitIn tests one segment against the compiled patterns.
func hitIn(seg Segment, res []compiledPat, at int) (Hit, bool) {
	if encodedPowerShell(seg.Words) {
		return Hit{EncodedScript, at}, true
	}
	for _, form := range forms(seg) {
		for _, cp := range res {
			if cp.re.MatchString(form) {
				return Hit{cp.class, at}, true
			}
		}
	}
	return Hit{}, false
}

func forms(seg Segment) []string {
	out := []string{seg.Text}
	add := func(s string) {
		for _, have := range out {
			if have == s {
				return
			}
		}
		out = append(out, s)
	}
	variants := [][]string{seg.Words}
	if folded := foldInput(seg.Words); folded != nil {
		variants = append(variants, folded)
		add(strings.Join(folded, " "))
	}
	for _, w := range variants {
		idx, bare, amb := resolveAmbiguity(w)
		if idx < 0 {
			continue
		}
		if amb {
			// Unknown wrapper flags: also test the segment with the wrapper
			// and every prefix of its words removed, at each split point.
			for k := range w {
				add(strings.Join(w[k:], " "))
				add(strings.ToLower(baseName(w[k])) + " " + strings.Join(w[k+1:], " "))
				if j, b := resolve(w[k:]); j >= 0 && !b {
					add(strings.Join(append([]string{strings.ToLower(baseName(w[k+j]))}, w[k+j+1:]...), " "))
				}
			}
		}
		prog := strings.ToLower(baseName(w[idx]))
		if bare {
			add(prog)
			continue
		}
		add(strings.Join(append([]string{prog}, w[idx+1:]...), " "))
	}
	return out
}

// foldInput drops `<` input redirection operators so their target reads as an
// argument; nil when there are none.
func foldInput(w []string) []string {
	var out []string
	changed := false
	for _, a := range w {
		switch {
		case a == "<":
			changed = true
		case strings.HasPrefix(a, "<") && !strings.HasPrefix(a, "<<"):
			changed = true
			out = append(out, a[1:])
		default:
			out = append(out, a)
		}
	}
	if !changed {
		return nil
	}
	return out
}

// rawCleaner drops the characters cmd and pwsh use to escape or quote, so
// `pri^ntenv` and `"env"` read as the dump command they run.
var rawCleaner = strings.NewReplacer("^", "", "`", "", "\"", "", "'", "")

// MatchRaw tests the command as one segment and again in pieces cut at every
// character either shell can use as a separator (& | ; ( ) { } and line
// breaks), ignoring quotes entirely. Callers use it besides Match for shells
// whose grammar Segments does not model (cmd, pwsh): quoting differs from
// POSIX there, so it errs on the side of refusing.
func (g *Guard) MatchRaw(cmd string, injected []string) bool {
	_, refused := g.ExplainRaw(cmd, injected)
	return refused
}

// ExplainRaw is MatchRaw that also returns the first rule to match. Its Segment
// is always -1: the pieces are not pipeline segments.
func (g *Guard) ExplainRaw(cmd string, injected []string) (Hit, bool) {
	if len(injected) == 0 {
		return Hit{}, false
	}
	res := g.compiled(injected)
	clean := rawCleaner.Replace(cmd)
	pieces := strings.FieldsFunc(clean, func(r rune) bool { return strings.ContainsRune("&|;(){}\r\n", r) })
	for _, text := range append([]string{clean}, pieces...) {
		if h, ok := hitIn(rawSegment(text), res, -1); ok {
			return h, true
		}
	}
	return Hit{}, false
}

func rawSegment(cmd string) Segment {
	w := strings.Fields(cmd)
	return Segment{Words: w, Text: strings.Join(w, " ")}
}
