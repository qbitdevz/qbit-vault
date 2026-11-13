// Package refusal defines the typed refusals of the broker contract
// (contracts/secrets-broker/v1/CONTRACT.md § Refusals) and their exit codes.
// Messages are built only from the secret name and fixed strings.
package refusal

import "github.com/qbitdevz/qbit-vault/internal/exitcode"

// Type is a refusal type from the contract.
type Type string

const (
	GrantRequired    Type = "grant_required"
	UnknownSecret    Type = "unknown_secret"
	UserDeclined     Type = "user_declined"
	RateLimited      Type = "rate_limited"
	ReasonTooVague   Type = "reason_too_vague"
	InvalidName      Type = "invalid_name"
	ScopeNotAllowed  Type = "scope_not_allowed"
	ScopeBinary      Type = "scope_binary"
	NoProject        Type = "no_project"
	DumpCommand      Type = "dump_command"
	NotModelCallable Type = "not_model_callable"
	VaultLocked      Type = "vault_locked"
	VaultCorrupt     Type = "vault_corrupt"
	Timeout          Type = "timeout"
	ContractMismatch Type = "contract_mismatch"
	Internal         Type = "internal"
)

type spec struct {
	retryable bool
	message   string // fixed text when there is no name
	named     string // fixed suffix after the name; empty means the message ignores the name
}

// Defaults follow the `retryable` column of the contract table; `internal`
// is "maybe" there and defaults to false.
var specs = map[Type]spec{
	GrantRequired:    {true, "no active grant for this secret", " has no active grant"},
	UnknownSecret:    {true, "unknown secret", " is not stored"},
	UserDeclined:     {false, "the user declined", ""},
	RateLimited:      {false, "too many requests; back off", ""},
	ReasonTooVague:   {true, "the reason is too vague", ""},
	InvalidName:      {false, "invalid secret name", ""},
	ScopeNotAllowed:  {false, "this scope is not allowed for a sensitive secret", ""},
	ScopeBinary:      {false, "the command's binary is not allowed for this secret", ""},
	NoProject:        {false, "not inside a repository", ""},
	DumpCommand:      {false, "the command is refused while secrets are injected", ""},
	NotModelCallable: {false, "this operation is not available to the model", ""},
	VaultLocked:      {true, "vault is locked", ""},
	VaultCorrupt:     {false, "vault is corrupt; run 'qbit-vault restore'", ""},
	Timeout:          {true, "the command timed out", ""},
	ContractMismatch: {false, "unsupported contract version", ""},
	Internal:         {false, "internal error", ""},
}

// hints is the fixed next action of each type (CONTRACT § Refusals). Built
// from fixed text only: no name, no value. dump_command has none here; its
// hint comes from its rule (NewDump).
var hints = map[Type]string{
	GrantRequired:    "Call secret_request for this name to ask the user for a grant, then retry once.",
	UnknownSecret:    "Call secret_list to see the stored names; if it is missing, call secret_request with fields to ask the user to store it.",
	UserDeclined:     "Do not ask again for the same use; continue without it or ask the user in the chat.",
	RateLimited:      "Wait; do not retry the same request.",
	ReasonTooVague:   "Say what the command does and why it needs the secret.",
	InvalidName:      "Names match ^[A-Z][A-Z0-9_]{0,63}$ and each appears once.",
	ScopeNotAllowed:  "Ask for scope once; a sensitive secret allows only a one-time grant.",
	ScopeBinary:      "The user must add the program to the secret's binaries; ask them.",
	NoProject:        "Use the global layer, or run from inside the repository.",
	NotModelCallable: "This is a user-only action; ask the user to run it.",
	VaultLocked:      "A QBit Vault tool call such as secret_list opens the unlock dialog; call it again once the user has unlocked.",
	VaultCorrupt:     "Stop; the user runs 'qbit-vault restore'.",
	Timeout:          "Raise timeout_ms or split the command.",
	ContractMismatch: "Update qbit-vault; the user runs 'qbit-vault sync' and restarts the agent.",
	Internal:         "Report it; the user can run 'qbit-vault doctor'.",
}

// Hints for the cases where the type's own hint would mislead.
const (
	HintGrantNotApplying = "A grant exists but does not apply here; call secret_request to ask the user for a new one."
	HintNoUnlockDialog   = "No unlock dialog could be shown; ask the user to run 'qbit-vault unlock' in their terminal, then retry."
	HintBusy             = "Another qbit-vault command holds the vault; retry in a moment."
	HintBadRequest       = "Fix the request and call again."
	HintCancelled        = "The call was cancelled before the user answered; call again only if the task still needs it."
	HintNeedsRepository  = "Run it inside a repository, or ask for another scope."
)

// order is the contract table order.
var order = []Type{
	GrantRequired, UnknownSecret, UserDeclined, RateLimited, ReasonTooVague,
	InvalidName, ScopeNotAllowed, ScopeBinary, NoProject, DumpCommand,
	NotModelCallable, VaultLocked, VaultCorrupt, Timeout, ContractMismatch, Internal,
}

// Types returns every refusal type in contract order.
func Types() []Type { return append([]Type(nil), order...) }

// Partial is the redacted output a timeout refusal carries (CONTRACT § exec).
type Partial struct {
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

// Refusal is the payload of a typed refusal. Name is nil when the refusal is
// not about one secret.
type Refusal struct {
	Type      Type     `json:"type"`
	Name      *string  `json:"name"`
	Message   string   `json:"message"`
	Retryable bool     `json:"retryable"`
	Partial   *Partial `json:"partial,omitempty"`
	// Rule, Hint and Segment are optional, fixed-text guidance (CONTRACT §
	// Refusals). They never carry a value, the command or a pattern's text.
	Rule    Rule   `json:"rule,omitempty"`
	Hint    string `json:"hint,omitempty"`
	Segment *int   `json:"segment,omitempty"`
}

// Envelope is the wire form: {"ok":false,"refusal":{…}}.
type Envelope struct {
	OK      bool    `json:"ok"`
	Refusal Refusal `json:"refusal"`
}

// New builds a refusal with the fixed message and default retryability of its
// type. An empty name means "no secret"; callers must pass a name that has
// already passed validation, never raw user input.
func New(t Type, name string) Refusal {
	s := specs[t]
	r := Refusal{Type: t, Message: s.message, Retryable: s.retryable, Hint: hints[t]}
	if name != "" {
		n := name
		r.Name = &n
		if s.named != "" {
			r.Message = name + s.named
		}
	}
	return r
}

// Rule is the closed set of reasons a dump_command refusal names.
type Rule string

const (
	EnvironmentDump Rule = "environment_dump"
	ValuePrint      Rule = "value_print"
	ValueEncode     Rule = "value_encode"
	NetworkArgument Rule = "network_argument"
	EncodedScript   Rule = "encoded_script"
	CustomRule      Rule = "custom_rule"
)

type ruleText struct{ phrase, hint string }

var rules = map[Rule]ruleText{
	EnvironmentDump: {"it lists or reads the environment",
		"Run the program that needs the secret and let it read its own environment; to check that a secret is set, use ${#NAME}. Never print the environment."},
	ValuePrint: {"it prints a secret value",
		"Do not print the value; to check that a secret is set, use ${#NAME}."},
	ValueEncode: {"it encodes a secret value",
		"Encoding does not hide a value; pass it to the program that needs it through its environment."},
	NetworkArgument: {"it puts a secret value in a network command's arguments",
		"Use a client that reads the credential from its own environment variable or config (for example gh with GH_TOKEN, or a script that reads os.environ), or a config file the client loads. Filtering the output does not exempt an earlier pipeline segment."},
	EncodedScript: {"its script is encoded and cannot be checked",
		"Pass the script as plain text."},
	CustomRule: {"it matches a rule in your dumpguard.yaml",
		"Ask the user; their dumpguard.yaml rule is not shown."},
}

// Rules returns every dump_command rule.
func Rules() []Rule {
	return []Rule{EnvironmentDump, ValuePrint, ValueEncode, NetworkArgument, EncodedScript, CustomRule}
}

// NewDump builds a dump_command refusal for rule. segment is the 0-based
// index of the pipeline segment that matched, or negative when unknown. An
// unknown rule yields the plain refusal.
func NewDump(rule Rule, segment int) Refusal {
	r := New(DumpCommand, "")
	t, ok := rules[rule]
	if !ok {
		return r
	}
	r.Message += ": " + t.phrase
	r.Rule, r.Hint = rule, t.hint
	if segment >= 0 {
		r.Segment = &segment
	}
	return r
}

// WithMessage returns r with a different fixed message.
func (r Refusal) WithMessage(m string) Refusal { r.Message = m; return r }

// WithHint returns r with a different fixed hint.
func (r Refusal) WithHint(h string) Refusal { r.Hint = h; return r }

// WithPartial returns r carrying the (already redacted) output a timed-out
// command produced before it was killed.
func (r Refusal) WithPartial(stdout, stderr string) Refusal {
	r.Partial = &Partial{Stdout: stdout, Stderr: stderr}
	return r
}

// WithRetryable returns r with an explicit retryable flag.
func (r Refusal) WithRetryable(b bool) Refusal { r.Retryable = b; return r }

// Error implements error. It returns the message only.
func (r Refusal) Error() string { return r.Message }

// Valid reports whether the type is one of the contract types.
func (r Refusal) Valid() bool { _, ok := specs[r.Type]; return ok }

// Envelope returns the JSON wire form of r.
func (r Refusal) Envelope() Envelope { return Envelope{OK: false, Refusal: r} }

// ExitCode maps the refusal to a process exit code (docs/CLI.md § Exit codes).
func (r Refusal) ExitCode() int {
	switch r.Type {
	case VaultLocked:
		return exitcode.Locked
	case VaultCorrupt:
		return exitcode.Corrupt
	default:
		return exitcode.Refusal
	}
}
