package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

var localeCalls = map[string]map[string]any{
	"secret_request": {"name": "GITHUB_TOKEN", "reason": "push the release tag to GitHub"},
	"secret_list":    {},
	"secret_exec":    {"command": "true", "secrets": []any{map[string]any{"name": "A"}}},
	"secret_manage":  {"action": "remove", "name": "A", "layer": "global", "reason": "this key was rotated away"},
}

func withLoc(args map[string]any, v any) map[string]any {
	out := map[string]any{"locale": v}
	for k, x := range args {
		out[k] = x
	}
	return out
}

// The four tools take `locale` and the backend receives it with the envelope.
func TestLocaleReachesTheBackendThroughEveryTool(t *testing.T) {
	for tool, args := range localeCalls {
		f := &fake{}
		cs := connect(t, f)
		callJSON(t, cs, tool, withLoc(args, "es-ES"))
		if f.env.Locale != "es-ES" {
			t.Errorf("%s: backend locale = %q", tool, f.env.Locale)
		}
		f = &fake{}
		cs = connect(t, f)
		callJSON(t, cs, tool, args)
		if f.env.Op == "" || f.env.Locale != "" {
			t.Errorf("%s without locale: op=%q locale=%q", tool, f.env.Op, f.env.Locale)
		}
	}
}

func TestEveryToolAdvertisesLocale(t *testing.T) {
	for tool, s := range toolInputSchemas(t) {
		p, ok := s["properties"].(map[string]any)["locale"].(map[string]any)
		if !ok || p["type"] != "string" {
			t.Errorf("%s has no string `locale` property: %v", tool, p)
			continue
		}
		desc, _ := p["description"].(string)
		if !strings.Contains(desc, "BCP 47") || !strings.Contains(desc, "es-ES") {
			t.Errorf("%s: locale description %q", tool, desc)
		}
		if req, _ := s["required"].([]any); len(req) > 0 {
			for _, r := range req {
				if r == "locale" {
					t.Errorf("%s: locale must stay optional", tool)
				}
			}
		}
	}
}

func TestLocaleOfTheWrongTypeStopsAtTheToolBoundary(t *testing.T) {
	f := &fake{}
	cs := connect(t, f)
	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "secret_list", Arguments: map[string]any{"locale": 5}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || f.env.Op != "" {
		t.Errorf("IsError=%v, backend reached (op %q)", res.IsError, f.env.Op)
	}
}

// The locale is the caller's text: it never appears in what a tool returns.
func TestLocaleIsNeverEchoed(t *testing.T) {
	cs := connect(t, &fake{})
	for tool, args := range localeCalls {
		res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: tool, Arguments: withLoc(args, "TESTSECRET_locale_xx")})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(res)
		if strings.Contains(string(raw), "TESTSECRET_locale") {
			t.Errorf("%s echoes the locale: %s", tool, raw)
		}
	}
}
