package broker

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/refusal"
)

// CONTRACT.md § check: the op is served on every transport, validates its
// names like exec does, and answers what the backend decided.
func TestCheckReachesTheBackendWithItsNames(t *testing.T) {
	for _, tr := range []Transport{TransportModel, TransportHost} {
		f := &fake{checkRes: CheckResponse{OK: true, Results: []CheckResult{{Name: "A", Layer: "global", LooksLike: "text", SameAs: []string{}}}}}
		m := call(t, f, tr, env("check", `"names":["A","B_2"],"locale":"es"`))
		if m["ok"] != true || len(f.calls) != 1 || f.calls[0] != "check" {
			t.Fatalf("transport %d: calls=%v m=%v", tr, f.calls, m)
		}
		if strings.Join(f.check.Names, ",") != "A,B_2" || f.env.Locale != "es" || f.env.Op != "check" {
			t.Fatalf("request %+v env %+v", f.check, f.env)
		}
		res := m["results"].([]any)[0].(map[string]any)
		for _, k := range []string{"name", "layer", "length", "empty", "whitespace", "multiline", "placeholder", "looks_like", "same_as"} {
			if _, ok := res[k]; !ok {
				t.Errorf("result has no %q: %v", k, res)
			}
		}
		if len(res) != 9 {
			t.Errorf("result has %d fields, want exactly 9: %v", len(res), res)
		}
		if _, isList := res["same_as"].([]any); !isList {
			t.Errorf("same_as is %T, want a list even when empty", res["same_as"])
		}
	}
}

func TestCheckValidation(t *testing.T) {
	seventeen := make([]string, 17)
	for i := range seventeen {
		seventeen[i] = `"N` + string(rune('A'+i)) + `"`
	}
	cases := []struct {
		name, extra, typ, msg string
	}{
		{"no names", ``, "internal", "invalid request: names"},
		{"names null", `"names":null`, "internal", "invalid request: names"},
		{"names empty", `"names":[]`, "internal", "invalid request: names"},
		{"names not a list", `"names":"A"`, "internal", "invalid request: names"},
		{"names of the wrong type", `"names":[1]`, "internal", "invalid request: names"},
		{"seventeen names", `"names":[` + strings.Join(seventeen, ",") + `]`, "internal", "invalid request: names"},
		{"a repeated name", `"names":["A","A"]`, "internal", "invalid request: names"},
		{"a bad name", `"names":["A","bad name"]`, "invalid_name", "invalid secret name"},
		{"an unknown field", `"names":["A"],"TESTSECRET_x":1`, "internal", "invalid request: unknown field"},
		{"a value field", `"names":["A"],"value":"x"`, "internal", "invalid request: unknown field"},
		{"locale of the wrong type", `"names":["A"],"locale":3`, "internal", "invalid request: locale"},
	}
	for _, c := range cases {
		f := &fake{}
		m := call(t, f, TransportModel, env("check", c.extra))
		typ, msg := refusalOf(t, m)
		if typ != c.typ || (c.typ == "internal" && msg != c.msg) {
			t.Errorf("%s: %s %q", c.name, typ, msg)
		}
		if len(f.calls) != 0 {
			t.Errorf("%s reached the backend", c.name)
		}
	}
	// Sixteen names are the limit and are accepted.
	f := &fake{}
	call(t, f, TransportModel, env("check", `"names":[`+strings.Join(seventeen[:16], ",")+`]`))
	if len(f.calls) != 1 || len(f.check.Names) != 16 {
		t.Fatalf("sixteen names: calls=%v", f.calls)
	}
}

func TestCheckRefusalsAreTypedAndAudited(t *testing.T) {
	a := &auditing{}
	a.err = refusal.New(refusal.GrantRequired, "A")
	m := call(t, a, TransportModel, env("check", `"names":["A"]`))
	if typ, _ := refusalOf(t, m); typ != "grant_required" {
		t.Fatalf("refusal = %v", m)
	}
	if len(a.refused) != 1 || a.envs[0].Op != "check" || a.envs[0].Session != "pi:2f1c00ab" {
		t.Fatalf("audit: envs %+v refusals %+v", a.envs, a.refused)
	}
}

func TestCapabilitiesAdvertiseSecretCheck(t *testing.T) {
	m := call(t, &fake{}, TransportHost, env("capabilities", ""))
	if m["secret_check"] != float64(1) || m["capabilities"] != "1.1" {
		t.Errorf("secret_check=%v capabilities=%v", m["secret_check"], m["capabilities"])
	}
	ops, _ := json.Marshal(m["ops"])
	if !strings.Contains(string(ops), `"check"`) {
		t.Errorf("ops = %s", ops)
	}
}
