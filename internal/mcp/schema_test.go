package mcp

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// boundKeywords are the structural limits a tool input must advertise exactly
// as the wire contract states them. Limits the contract reaches through a
// $ref (secret names, the reason) are left to the broker, whose typed
// refusals (invalid_name, reason_too_vague) carry a hint.
var boundKeywords = []string{"minItems", "maxItems", "minimum", "maximum", "minLength", "maxLength", "pattern", "enum"}

func toolInputSchemas(t *testing.T) map[string]map[string]any {
	t.Helper()
	cs := connect(t, &fake{})
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, tool := range res.Tools {
		raw, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		var s map[string]any
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatal(err)
		}
		out[tool.Name] = s
	}
	return out
}

func wireRequestProperties(t *testing.T, op string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../contracts/secrets-broker/v1/secrets-broker.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Defs map[string]struct {
			AllOf []struct {
				Properties map[string]any `json:"properties"`
			} `json:"allOf"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	def, ok := doc.Defs[op+"Req"]
	if !ok || len(def.AllOf) != 2 {
		t.Fatalf("wire schema has no %sReq with an envelope and a body", op)
	}
	return def.AllOf[1].Properties
}

// Issue #61: tools/list advertised `secrets` as a nullable array of any
// length while the broker refuses null and [].
func TestExecSchemaRequiresOneToSixteenSecrets(t *testing.T) {
	list := toolInputSchemas(t)["secret_exec"]["properties"].(map[string]any)["secrets"].(map[string]any)
	if got := list["type"]; got != "array" {
		t.Errorf("type = %v, want \"array\" (never null)", got)
	}
	if got := list["minItems"]; got != float64(1) {
		t.Errorf("minItems = %v, want 1", got)
	}
	if got := list["maxItems"]; got != float64(16) {
		t.Errorf("maxItems = %v, want 16", got)
	}
}

func TestToolSchemasCarryTheWireContractBounds(t *testing.T) {
	tools := toolInputSchemas(t)
	checked := 0
	for tool, op := range map[string]string{"secret_request": "request", "secret_list": "list", "secret_exec": "exec", "secret_manage": "manage",
		"secret_exec_start": "exec_start", "secret_exec_status": "exec_status", "secret_exec_stop": "exec_stop"} {
		props, _ := tools[tool]["properties"].(map[string]any)
		for name, w := range wireRequestProperties(t, op) {
			if name == "op" {
				continue
			}
			wire := w.(map[string]any)
			got, ok := props[name].(map[string]any)
			if !ok {
				t.Errorf("%s: the wire field %q is not in the tool input", tool, name)
				continue
			}
			for _, k := range boundKeywords {
				if want, has := wire[k]; has {
					checked++
					if !reflect.DeepEqual(got[k], want) {
						t.Errorf("%s.%s %s = %v, the wire contract says %v", tool, name, k, got[k], want)
					}
				}
			}
		}
	}
	if checked < 20 {
		t.Fatalf("only %d bounds compared; the wire schema layout changed", checked)
	}
}

// The broker keeps its own refusal for an empty list; the tool boundary now
// stops it first and names the field.
func TestExecWithoutSecretsStopsAtTheToolBoundary(t *testing.T) {
	f := &fake{}
	cs := connect(t, f)
	for _, list := range []any{nil, []any{}} {
		res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "secret_exec", Arguments: map[string]any{"command": "true", "secrets": list}})
		if err != nil {
			t.Fatal(err)
		}
		text := ""
		if len(res.Content) == 1 {
			text = res.Content[0].(*sdk.TextContent).Text
		}
		if !res.IsError || !strings.Contains(text, "secrets") {
			t.Errorf("secrets=%v: IsError=%v, text %q", list, res.IsError, text)
		}
		if strings.Contains(text, `"refusal"`) {
			t.Errorf("secrets=%v reached the broker: %q", list, text)
		}
	}
	if f.env.Op != "" {
		t.Errorf("the backend was reached (op %q)", f.env.Op)
	}
}

// An optional list may still be sent as null by hosts that render it so.
func TestRequestStillAcceptsANullFieldsList(t *testing.T) {
	cs := connect(t, &fake{})
	m, _ := callJSON(t, cs, "secret_request", map[string]any{"name": "GITHUB_TOKEN", "fields": nil, "reason": "push the release tag to GitHub"})
	if r, _ := m["refusal"].(map[string]any); r == nil || r["type"] != "user_declined" {
		t.Errorf("the call did not reach the backend: %v", m)
	}
}
