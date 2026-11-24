// Package mcp is the stdio MCP server of `qbit-vault mcp` (R-API-01,
// R-API-05, R-API-06): exactly eight tools, secret_request, secret_list,
// secret_exec, secret_manage and secret_check, plus secret_exec_start, secret_exec_status
// and secret_exec_stop for commands that outlast a client's request timeout
// (jobs.go), with the normative descriptions of CONTRACT.md, and the policy
// text as the server instructions. Every call becomes a contract envelope
// handled by internal/broker over the model transport, so validation,
// refusals and the never-a-grant rule are the broker's. No tool returns a
// secret value.
package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/qbitdevz/qbit-vault/internal/broker"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
)

// ToolDescriptions are CONTRACT.md § Model-facing tool definitions, verbatim.
var ToolDescriptions = map[string]string{
	"secret_request":     "Ask the user for permission to use one or several named secrets (e.g. GITHUB_TOKEN, or DB_HOST, DB_USER and DB_PASSWORD together) in later commands. Ask for everything one task needs in a single call: up to 8 fields, each 'secret' (masked) or 'text' (visible, for non-secret values such as a hostname). The user will type or approve them outside the chat. You NEVER receive the values; you receive references and a grant. Give a concrete reason (what command, what for). Do not request secrets you do not need for the current task. If the user declines, do not ask again.",
	"secret_list":        "List the secrets available from this directory (global ones and this project's), and the rules for what you can and cannot do with them. Values are never returned. Call this first when you need a credential.",
	"secret_manage":      "Propose a change to a secret: remove it, edit its metadata, move it between global and this project, replace its value, or revert it to the previous value (only while secret_list shows previous_until for it). The user confirms or declines outside the chat; nothing changes without that. You never see values and you cannot grant access. Give a concrete reason.",
	"secret_check":       "Describe the values of named secrets you could use right now, without seeing them: for each, its length, whether it is empty, padded with white space, multi-line or a placeholder such as change-me, what its shape looks like (email, url, jwt, pem, uuid, hex, base64, number or text), and which of the other names in the same call hold the identical value. Call it when a service rejects a credential, with every secret the failed call used, before you propose to replace one. It returns no value and no part of one. A name without a usable grant is refused as in secret_exec, and a once grant is not spent by a check.",
	"secret_exec_start":  "Start a shell command in the background with named secrets injected as environment variables for that process only, and return a job id as soon as it has started. Use this instead of secret_exec for anything that may take more than about 30 seconds (builds, test suites, deploys, migrations): a host may cancel a tool call that runs longer than its request timeout, 60 seconds in some, and that ends the command. It takes the same input as secret_exec and is refused for the same reasons with the same hints; a once grant is spent when the job starts. Then call secret_exec_status with the job id and wait_ms to read the redacted output and the exit code. At most 4 jobs run at once, and every job ends when this server stops.",
	"secret_exec_status": "Read a job started with secret_exec_start. Waits up to wait_ms (0 to 50000, default 0) and returns early when the job ends, so pass a wait_ms such as 30000 instead of polling in a loop. Returns state (running, exited, timed_out or stopped), exit_code once it ended, duration_ms, and the redacted stdout and stderr the job produced since your previous call for this job: each output is returned once, so keep what you need. A call that returns a finished state is the last one for that job; an unread result is kept for 10 minutes. Secret values are redacted as in secret_exec.",
	"secret_exec_stop":   "Stop a job started with secret_exec_start: its whole process tree is killed. Returns the same fields as secret_exec_status, with the final state and any output you have not read yet. Stopping a job that already ended returns its final state. Use it for a job that is stuck or that you no longer need.",
	"secret_exec":        "Run a shell command with named secrets injected as environment variables for that process only. Output is returned with secret values redacted. Commands that print the environment or a secret are refused; to use only a length, write ${#NAME}. Prefer this over asking the user to paste credentials. A refused command carries a rule and a hint saying why and what to do instead; follow the hint, because an unlocked vault or a grant does not lift a refusal.",
}

// ProgressInterval is how often a call that waits for the user sends
// notifications/progress, when the client gave a progress token. Clients that
// reset their request timeout on progress keep waiting while a dialog is open.
// It is a variable for tests.
var ProgressInterval = 15 * time.Second

// panicLog is where broker.PanicLine goes. It is a seam for tests.
var panicLog io.Writer = os.Stderr

// Options configures the server.
type Options struct {
	// Session is the host session id every envelope carries.
	Session string
	// Cwd returns the working directory of a call (the host's project).
	Cwd func() (string, error)
	// Version is reported as the server version.
	Version string
}

// NewSession returns a fresh session id for a host that did not pass one.
func NewSession() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("mcp: random source failed")
	}
	return "mcp:" + hex.EncodeToString(b[:])
}

type requestIn struct {
	Name           string         `json:"name,omitempty" jsonschema:"one secret name, e.g. GITHUB_TOKEN; or use fields"`
	Fields         []broker.Field `json:"fields,omitempty" jsonschema:"several fields asked in one prompt: name, kind (secret or text), label, description"`
	Reason         string         `json:"reason" jsonschema:"what command needs it and what for, shown to the user verbatim"`
	SuggestedScope string         `json:"suggested_scope,omitempty" jsonschema:"once, session or project; a hint, the user chooses"`
	SuggestedLayer string         `json:"suggested_layer,omitempty" jsonschema:"global or project; a hint, the user chooses"`
	Locale         string         `json:"locale,omitempty" jsonschema:"BCP 47 tag of the conversation language, e.g. es-ES; the dialogs the user sees are shown in it. Always send it."`
}

type listIn struct {
	Locale string `json:"locale,omitempty" jsonschema:"BCP 47 tag of the conversation language, e.g. es-ES; the dialogs the user sees are shown in it. Always send it."`
}

type checkIn struct {
	Names  []string `json:"names" jsonschema:"1 to 16 secret names to describe, e.g. the ones the rejected call used, identifiers such as emails and usernames included"`
	Locale string   `json:"locale,omitempty" jsonschema:"BCP 47 tag of the conversation language, e.g. es-ES; the dialogs the user sees are shown in it. Always send it."`
}

type execIn struct {
	Command   string              `json:"command" jsonschema:"the shell command to run"`
	Secrets   []broker.ExecSecret `json:"secrets" jsonschema:"secrets to inject: name is the variable, from the vault secret (default name)"`
	TimeoutMS int                 `json:"timeout_ms,omitempty" jsonschema:"1000 to 3600000, default 600000"`
	Shell     string              `json:"shell,omitempty" jsonschema:"auto, sh, bash, cmd or pwsh"`
	Locale    string              `json:"locale,omitempty" jsonschema:"BCP 47 tag of the conversation language, e.g. es-ES; the dialogs the user sees are shown in it. Always send it."`
}

// execStartIn is exactly the input of secret_exec.
type execStartIn execIn

type statusIn struct {
	Job    string `json:"job" jsonschema:"the id secret_exec_start returned"`
	WaitMS int    `json:"wait_ms,omitempty" jsonschema:"0 to 50000, default 0: how long to wait for the job to end before answering"`
}

type stopIn struct {
	Job string `json:"job" jsonschema:"the id secret_exec_start returned"`
}

type manageIn struct {
	Action  string                `json:"action" jsonschema:"remove, edit, move, replace or revert"`
	Name    string                `json:"name" jsonschema:"the secret name"`
	Layer   string                `json:"layer" jsonschema:"global or project (the project of this directory)"`
	Reason  string                `json:"reason" jsonschema:"why, shown to the user verbatim"`
	To      string                `json:"to,omitempty" jsonschema:"move only: the other layer"`
	Changes *broker.ManageChanges `json:"changes,omitempty" jsonschema:"edit only: description, binaries, hosts, sensitive"`
	Locale  string                `json:"locale,omitempty" jsonschema:"BCP 47 tag of the conversation language, e.g. es-ES; the dialogs the user sees are shown in it. Always send it."`
}

// NewServer builds the MCP server over a broker backend. The jobs tools run
// in the registry b is, or in a new one around b; whoever creates the
// registry with NewJobs shuts it down (Jobs.Shutdown) when the server ends.
func NewServer(b broker.Backend, o Options) *sdk.Server {
	jobs, ok := b.(*Jobs)
	if !ok {
		jobs = NewJobs(b)
	}
	srv := sdk.NewServer(&sdk.Implementation{Name: "qbit-vault", Version: o.Version}, &sdk.ServerOptions{Instructions: broker.Instructions()})
	add(srv, jobs, o, "secret_request", "request")
	add(srv, jobs, o, "secret_list", "list")
	add(srv, jobs, o, "secret_exec", "exec")
	add(srv, jobs, o, "secret_manage", "manage")
	add(srv, jobs, o, "secret_check", "check")
	add(srv, jobs, o, "secret_exec_start", "exec_start")
	add(srv, jobs, o, "secret_exec_status", "exec_status")
	add(srv, jobs, o, "secret_exec_stop", "exec_stop")
	return srv
}

// execBounds are the wire limits of an exec request, shared by secret_exec and
// secret_exec_start.
func execBounds(p map[string]*jsonschema.Schema) {
	// Required, so never null: the broker refuses null and [].
	p["secrets"].Types, p["secrets"].Type = nil, "array"
	p["secrets"].MinItems, p["secrets"].MaxItems = jsonschema.Ptr(1), jsonschema.Ptr(broker.MaxExecSecrets)
	p["command"].MinLength, p["command"].MaxLength = jsonschema.Ptr(1), jsonschema.Ptr(broker.MaxCommandBytes)
	p["timeout_ms"].Minimum, p["timeout_ms"].Maximum = jsonschema.Ptr(float64(broker.MinTimeoutMS)), jsonschema.Ptr(float64(broker.MaxTimeoutMS))
	p["shell"].Enum = []any{"auto", "sh", "bash", "cmd", "pwsh"}
}

// jobBounds are the wire limits of a job id.
func jobBounds(p map[string]*jsonschema.Schema) {
	p["job"].MinLength, p["job"].MaxLength = jsonschema.Ptr(broker.JobIDLen), jsonschema.Ptr(broker.JobIDLen)
	p["job"].Pattern = "^[0-9a-f]{32}$"
}

func add(srv *sdk.Server, b broker.Backend, o Options, tool, op string) {
	t := &sdk.Tool{Name: tool, Description: ToolDescriptions[tool]}
	switch op {
	case "request":
		t.InputSchema = inputSchema[requestIn](func(p map[string]*jsonschema.Schema) {
			p["fields"].MinItems, p["fields"].MaxItems = jsonschema.Ptr(1), jsonschema.Ptr(broker.MaxFields)
		})
		sdk.AddTool(srv, t, handler[requestIn](b, o, op))
	case "list":
		sdk.AddTool(srv, t, handler[listIn](b, o, op))
	case "check":
		t.InputSchema = inputSchema[checkIn](func(p map[string]*jsonschema.Schema) {
			// Required, so never null: the broker refuses null and [].
			p["names"].Types, p["names"].Type = nil, "array"
			p["names"].MinItems, p["names"].MaxItems = jsonschema.Ptr(1), jsonschema.Ptr(broker.MaxExecSecrets)
		})
		sdk.AddTool(srv, t, handler[checkIn](b, o, op))
	case "exec":
		t.InputSchema = inputSchema[execIn](execBounds)
		sdk.AddTool(srv, t, handler[execIn](b, o, op))
	case "exec_start":
		t.InputSchema = inputSchema[execStartIn](execBounds)
		sdk.AddTool(srv, t, handler[execStartIn](b, o, op))
	case "exec_status":
		t.InputSchema = inputSchema[statusIn](func(p map[string]*jsonschema.Schema) {
			jobBounds(p)
			p["wait_ms"].Minimum, p["wait_ms"].Maximum = jsonschema.Ptr(float64(0)), jsonschema.Ptr(float64(broker.MaxWaitMS))
		})
		sdk.AddTool(srv, t, handler[statusIn](b, o, op))
	case "exec_stop":
		t.InputSchema = inputSchema[stopIn](jobBounds)
		sdk.AddTool(srv, t, handler[stopIn](b, o, op))
	case "manage":
		t.InputSchema = inputSchema[manageIn](func(p map[string]*jsonschema.Schema) {
			p["action"].Enum = []any{"remove", "edit", "move", "replace", "revert"}
		})
		sdk.AddTool(srv, t, handler[manageIn](b, o, op))
	}
}

// inputSchema is the schema the SDK infers for In with the structural limits
// of the wire contract added by bound (issue #61): inference alone leaves a
// list nullable and of any length. Only limits the broker answers with the
// generic invalid-request refusal are added here, so names and reasons still
// reach the broker and get their typed refusals (invalid_name,
// reason_too_vague). A test keeps these equal to the wire schema.
func inputSchema[In any](bound func(props map[string]*jsonschema.Schema)) *jsonschema.Schema {
	s, err := jsonschema.For[In](nil)
	if err != nil {
		panic("mcp: tool input schema: " + err.Error())
	}
	bound(s.Properties)
	return s
}

// handler turns the tool input into an envelope for op and answers with the
// broker's JSON as text, an error result when it is a refusal.
func handler[In any](b broker.Backend, o Options, op string) sdk.ToolHandlerFor[In, any] {
	return func(ctx context.Context, req *sdk.CallToolRequest, in In) (res *sdk.CallToolResult, _ any, _ error) {
		// A panic must not kill the server or print a trace: answer the
		// typed internal refusal, with one fixed line on stderr.
		defer func() {
			if recover() != nil {
				fmt.Fprintln(panicLog, broker.PanicLine)
				out, _ := json.Marshal(refusal.New(refusal.Internal, "").Envelope())
				res = &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: string(out)}}, IsError: true}
			}
		}()
		defer keepAlive(ctx, req, op)()
		if req != nil && req.Session != nil {
			// A job is visible only to the session that started it.
			ctx = context.WithValue(ctx, ownerKey{}, req.Session)
		}
		out := broker.Handle(ctx, envelope(o, op, in), b, broker.TransportModel)
		var ok struct {
			OK bool `json:"ok"`
		}
		_ = json.Unmarshal(out, &ok)
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: string(out)}}, IsError: !ok.OK}, nil, nil
	}
}

// progressText is what a waiting call reports, by op. request and manage
// only ever wait for a dialog. list and exec wait for the unlock dialog of a
// locked vault (issue #65), and exec for its command as well, so their text
// does not claim that a dialog is open.
var progressText = map[string]string{
	"request": "Waiting for the user to answer the dialog.",
	"manage":  "Waiting for the user to answer the dialog.",
	"list":    "Waiting for the vault to be unlocked.",
	"check":   "Waiting for the vault to be unlocked.",
	"exec":    "Waiting for the vault to be unlocked or for the command to finish.",
	// A start waits for the unlock dialog like exec, then only for the command
	// to begin; a status call waits for the job.
	"exec_start":  "Waiting for the vault to be unlocked.",
	"exec_status": "Waiting for the job to produce output or end.",
}

// keepAlive sends a progress notification every ProgressInterval while a
// call is open, if the client sent a progress token; the returned stop ends
// it and waits for it. Without a token it does nothing. The notification
// carries a fixed text, never a name or a value.
func keepAlive(ctx context.Context, req *sdk.CallToolRequest, op string) (stop func()) {
	text := progressText[op]
	if text == "" || req == nil || req.Session == nil || req.Params == nil {
		return func() {}
	}
	token := req.Params.GetProgressToken()
	if token == nil {
		return func() {}
	}
	done, finished := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		tick := time.NewTicker(ProgressInterval)
		defer tick.Stop()
		for n := 1.0; ; n++ {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-tick.C:
				_ = req.Session.NotifyProgress(ctx, &sdk.ProgressNotificationParams{
					ProgressToken: token, Progress: n, Message: text})
			}
		}
	}()
	return func() { close(done); <-finished }
}

// envelope merges the tool input with the contract envelope. A cwd that
// cannot be read is sent empty, which the broker refuses as invalid.
func envelope(o Options, op string, in any) []byte {
	m := map[string]any{}
	if b, err := json.Marshal(in); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	cwd := ""
	if o.Cwd != nil {
		if d, err := o.Cwd(); err == nil {
			cwd = d
		}
	}
	m["contract"], m["op"], m["v"], m["session"], m["cwd"] = broker.Contract, op, 1, o.Session, cwd
	raw, _ := json.Marshal(m)
	return raw
}
