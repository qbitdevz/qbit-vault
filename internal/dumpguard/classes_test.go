package dumpguard

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Every default pattern has a class and the map holds no stale entry.
func TestEveryDefaultPatternHasAClass(t *testing.T) {
	pats, err := parse(defaultYAML)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, p := range pats {
		seen[p.src] = true
		c, ok := defaultClass[p.src]
		if !ok || c == CustomRule || c != p.class {
			t.Errorf("default pattern %q: class %q (in map: %v)", p.src, p.class, ok)
		}
	}
	for src := range defaultClass {
		if !seen[src] {
			t.Errorf("class map has a stale entry %q", src)
		}
	}
}

func TestUserPatternsAreCustomRule(t *testing.T) {
	home := t.TempDir()
	yaml := "format: qbit-vault-dumpguard/1\npatterns:\n  - '^zzdump$'\n  - '^env$'\n"
	if err := os.WriteFile(filepath.Join(home, "dumpguard.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := Load(home)
	if err != nil {
		t.Fatal(err)
	}
	if h, ok := g.Explain("zzdump", []string{"A"}); !ok || h.Class != CustomRule || h.Segment != 0 {
		t.Fatalf("user pattern: %+v %v", h, ok)
	}
	// A user pattern equal to a default is the default: it keeps its class.
	if h, ok := g.Explain("env", []string{"A"}); !ok || h.Class != EnvironmentDump {
		t.Fatalf("duplicate of a default: %+v %v", h, ok)
	}
}

func TestExplainSegments(t *testing.T) {
	g := Default()
	inj := []string{"TOK"}
	tests := []struct {
		cmd     string
		class   Class
		segment int
	}{
		{"env", EnvironmentDump, 0},
		{"true; env", EnvironmentDump, 1},
		{"true | echo $TOK", ValuePrint, 1},
		{`curl -H "Authorization: Bearer $TOK" https://x.invalid | jq .`, NetworkArgument, 0},
		{"true && printenv | cat", EnvironmentDump, 1},
		{`sh -c 'printenv'`, EnvironmentDump, 0}, // nested script: its top-level segment
		{"true; sh -c 'echo ok; printenv'", EnvironmentDump, 1},
		{"true; echo $(printenv)", EnvironmentDump, 1}, // substitution inside segment 1
		{"pwsh -enc AAAA", EncodedScript, 0},
		{"true; pwsh -EncodedCommand AAAA", EncodedScript, 1},
		{"cat <<EOF\n$TOK\nEOF", ValuePrint, -1}, // here-document body: not a pipeline segment
	}
	for _, tt := range tests {
		h, ok := g.Explain(tt.cmd, inj)
		if !ok || h.Class != tt.class || h.Segment != tt.segment {
			t.Errorf("Explain(%q) = %+v %v, want %s segment %d", tt.cmd, h, ok, tt.class, tt.segment)
		}
	}
	if h, ok := g.ExplainRaw("true & env", inj); !ok || h.Class != EnvironmentDump || h.Segment != -1 {
		t.Errorf("ExplainRaw: %+v %v", h, ok)
	}
	if _, ok := g.Explain("env", nil); ok {
		t.Error("nothing injected: the guard does not apply")
	}
}

// Match and Explain decide the same, so the classes add no behavior.
func TestMatchAgreesWithExplain(t *testing.T) {
	g := Default()
	inj := []string{"TOK"}
	cmds := []string{"env", "ls -la", "echo hi", "echo $TOK", "gh pr list", "sh -c 'echo $TOK'", "pwsh -enc AA",
		"cat <<EOF\n$TOK\nEOF", "true; ls | wc -l", "FOO=1 printenv", "sudo env", "python3 -c 'print(1)'"}
	for _, c := range cmds {
		_, ex := g.Explain(c, inj)
		if g.Match(c, inj) != ex {
			t.Errorf("%q: Match and Explain disagree", c)
		}
		_, exr := g.ExplainRaw(c, inj)
		if g.MatchRaw(c, inj) != exr {
			t.Errorf("%q: MatchRaw and ExplainRaw disagree", c)
		}
	}
	if len(slices.Compact(slices.Clone(cmds))) != len(cmds) {
		t.Fatal("duplicate corpus entry")
	}
}
