package broker

import (
	"context"
	"io"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/refusal"
)

// Envelope is the part every request carries (CONTRACT.md § Envelope).
type Envelope struct {
	Contract string `json:"contract"`
	Op       string `json:"op"`
	V        int    `json:"v"`
	Session  string `json:"session"`
	Cwd      string `json:"cwd"`
	Host     *Host  `json:"host,omitempty"`
	// Locale is the optional BCP 47 tag of the conversation language that
	// request, list, exec, manage and check may carry (CONTRACT.md § Dialog
	// language). It is the caller's raw text: whoever resolves it ignores a
	// tag that names no language, and nothing ever shows, logs or echoes it.
	Locale string `json:"-"`
}

// Host names the calling host, for audit.
type Host struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ExecSecret injects vault secret From (default Name) as variable Name.
type ExecSecret struct {
	Name string `json:"name"`
	From string `json:"from,omitempty"`
}

// ExecRequest is a validated `exec`, defaults applied.
type ExecRequest struct {
	Command   string
	Secrets   []ExecSecret
	TimeoutMS int
	Shell     string
}

// CheckRequest is a validated `check`: one to MaxExecSecrets distinct, valid
// secret names.
type CheckRequest struct {
	Names []string
}

// GrantRequest is a validated `grant`. Layer is "global" or "project".
type GrantRequest struct {
	Name        string
	Layer       string
	Scope       string
	TTLMS       int
	PromptToken string
}

// RevokeRequest is a validated `revoke`: exactly one target is set.
type RevokeRequest struct {
	Name        string
	All         bool
	SessionOnly bool
}

// Field is one box of a `request`.
type Field struct {
	Name        string `json:"name"`
	Kind        string `json:"kind,omitempty"`
	Label       string `json:"label,omitempty"`
	Description string `json:"description,omitempty"`
}

// RequestRequest is a validated `request`; Fields always holds at least one
// entry (a single `name` becomes one secret field). Single reports the
// single-`name` form, whose response also carries `ref` and `layer`.
type RequestRequest struct {
	Fields         []Field
	Single         bool
	Reason         string
	SuggestedScope string
	SuggestedLayer string
}

// ManageChanges are the metadata fields an `edit` may change; nil means
// unchanged.
type ManageChanges struct {
	Description *string   `json:"description,omitempty"`
	Binaries    *[]string `json:"binaries,omitempty"`
	Hosts       *[]string `json:"hosts,omitempty"`
	Sensitive   *bool     `json:"sensitive,omitempty"`
}

// ManageRequest is a validated `manage`.
type ManageRequest struct {
	Action  string
	Name    string
	Layer   string
	Reason  string
	To      string
	Changes *ManageChanges
}

// GrantInfo is a grant as the model sees it.
type GrantInfo struct {
	Scope     string  `json:"scope"`
	ExpiresAt *string `json:"expires_at"`
}

// Project is the repository of the envelope's cwd.
type Project struct {
	Root  string `json:"root"`
	Label string `json:"label"`
}

// SecretMeta is one listed secret: never a value.
type SecretMeta struct {
	Name            string     `json:"name"`
	Layer           string     `json:"layer"`
	OverridesGlobal bool       `json:"overrides_global"`
	Kind            string     `json:"kind"`
	Description     string     `json:"description"`
	Sensitive       bool       `json:"sensitive"`
	Binaries        []string   `json:"binaries"`
	Hosts           []string   `json:"hosts"`
	CreatedAt       string     `json:"created_at"`
	UpdatedAt       string     `json:"updated_at"`
	Grant           *GrantInfo `json:"grant"`
	// GrantNote says why Grant is null although a grant of this secret exists
	// (it does not apply from this directory, or belongs to an earlier value).
	// Optional and additive: absent when there is nothing to say.
	GrantNote string `json:"grant_note,omitempty"`
	// PreviousUntil is when the value this secret replaced stops being
	// recoverable by a revert (RFC 3339). Optional and additive: present only
	// while a previous value exists. It is a time, never the value.
	PreviousUntil string `json:"previous_until,omitempty"`
}

// Notes for SecretMeta.GrantNote. Fixed text: no path, no value.
const (
	NoteOtherDirectory = "a project grant exists for another directory; call secret_request"
	NoteOtherRecord    = "the grant is for an earlier value of this secret; call secret_request"
)

// Cooldown is a name the agent may not ask for again until Until.
type Cooldown struct {
	Name  string `json:"name"`
	Until string `json:"until"`
}

// ListResult is what a backend reports for `list`; the broker adds the
// policy.
type ListResult struct {
	Project   *Project
	Secrets   []SecretMeta
	Cooldowns []Cooldown
	// Unlinked is a synced project layer this repository could link.
	Unlinked *UnlinkedMatch
}

// Policy is the normative block of `list` (R-API-06).
type Policy struct {
	Can       []string   `json:"can"`
	Cannot    []string   `json:"cannot"`
	Layers    []string   `json:"layers"`
	Scopes    []string   `json:"scopes"`
	Cooldowns []Cooldown `json:"cooldowns"`
}

// UnlinkedMatch names a synced project layer this repository could link.
type UnlinkedMatch struct {
	Label string `json:"label"`
}

// ListResponse is the `list` success payload.
type ListResponse struct {
	OK            bool           `json:"ok"`
	Project       *Project       `json:"project"`
	Secrets       []SecretMeta   `json:"secrets"`
	UnlinkedMatch *UnlinkedMatch `json:"unlinked_match"`
	Policy        Policy         `json:"policy"`
}

// ExecResponse is the `exec` success payload.
type ExecResponse struct {
	OK         bool   `json:"ok"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMS int64  `json:"duration_ms"`
	Redactions int    `json:"redactions"`
	Truncated  bool   `json:"truncated"`
}

// CheckResult describes one checked secret (CONTRACT.md § check). Every field
// is a count, a boolean or a word of a closed set, never a value or a part of
// one. SameAs holds the other names of the same call whose value is
// byte-identical (never null).
type CheckResult struct {
	Name        string   `json:"name"`
	Layer       string   `json:"layer"`
	Length      int      `json:"length"`
	Empty       bool     `json:"empty"`
	Whitespace  bool     `json:"whitespace"`
	Multiline   bool     `json:"multiline"`
	Placeholder bool     `json:"placeholder"`
	LooksLike   string   `json:"looks_like"`
	SameAs      []string `json:"same_as"`
}

// CheckResponse is the `check` success payload, one result per requested
// name, in request order.
type CheckResponse struct {
	OK      bool          `json:"ok"`
	Results []CheckResult `json:"results"`
}

// GrantResponse is the `grant` success payload.
type GrantResponse struct {
	OK    bool      `json:"ok"`
	Grant GrantInfo `json:"grant"`
}

// RevokeResponse is the `revoke` success payload.
type RevokeResponse struct {
	OK      bool `json:"ok"`
	Revoked int  `json:"revoked"`
}

// Ref is one handle a `request` returns.
type Ref struct {
	Name  string `json:"name"`
	Ref   string `json:"ref"`
	Layer string `json:"layer"`
}

// RequestResponse is the `request` success payload.
type RequestResponse struct {
	OK    bool      `json:"ok"`
	Refs  []Ref     `json:"refs"`
	Ref   string    `json:"ref,omitempty"`
	Layer string    `json:"layer,omitempty"`
	Grant GrantInfo `json:"grant"`
}

// ManageResponse is the `manage` success payload.
type ManageResponse struct {
	OK      bool    `json:"ok"`
	Applied bool    `json:"applied"`
	Action  string  `json:"action"`
	Name    string  `json:"name"`
	Layer   *string `json:"layer"`
}

// Info is what a backend reports for `capabilities`.
type Info struct {
	Keychain       string
	PromptBackends []string
	Streaming      bool
	// ExecJobs is set by a backend that serves exec_start, exec_status and
	// exec_stop (the MCP server); capabilities then reports `exec_jobs`.
	ExecJobs bool
}

// JobRequest is a validated `exec_status` (WaitMS is the long poll) or
// `exec_stop` (WaitMS is zero): Job is 32 lowercase hex digits.
type JobRequest struct {
	Job    string
	WaitMS int
}

// ExecStartResponse is the `exec_start` success payload.
type ExecStartResponse struct {
	OK  bool   `json:"ok"`
	Job string `json:"job"`
}

// Job states of an ExecStatusResponse.
const (
	JobRunning  = "running"
	JobExited   = "exited"
	JobTimedOut = "timed_out"
	JobStopped  = "stopped"
)

// ExecStatusResponse is the `exec_status` and `exec_stop` success payload.
// Stdout, Stderr, Redactions and Truncated cover the output produced since
// the previous call for the same job. ExitCode is absent while it runs.
type ExecStatusResponse struct {
	OK         bool   `json:"ok"`
	State      string `json:"state"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	Redactions int    `json:"redactions"`
	Truncated  bool   `json:"truncated"`
}

// JobBackend is implemented by a Backend that can keep a command running
// after the call that started it returns: the MCP server, whose process lives
// as long as the host session. `broker --op` is one process per call and
// does not implement it, so it answers these ops as an unknown op.
//
// ExecStart decides everything exec decides before a process exists, with
// the same refusals, and returns once the command has started.
type JobBackend interface {
	ExecStart(ctx context.Context, e Envelope, r ExecRequest) (ExecStartResponse, error)
	ExecStatus(ctx context.Context, e Envelope, r JobRequest) (ExecStatusResponse, error)
	ExecStop(ctx context.Context, e Envelope, r JobRequest) (ExecStatusResponse, error)
}

// ExecOutcome is how a prepared exec ended.
type ExecOutcome struct {
	// Started reports whether the operating system created the child.
	Started  bool
	ExitCode int
	// TimedOut: the command hit its timeout and its tree was killed.
	TimedOut bool
	// Interrupted: the context given to Run ended and its tree was killed.
	Interrupted bool
	// Failed: the run failed for another reason (the command could not
	// start, or its output could not be read).
	Failed   bool
	Duration time.Duration
}

// ExecStarter is implemented by a Backend whose exec can be split into what
// happens before a process exists and the run itself, so a job can decide
// synchronously and run in the background through the same code as exec.
type ExecStarter interface {
	// PrepareExec does everything exec does before the child exists: the
	// vault, the grants (a once grant is claimed), the dump guard, the binary
	// rules and the audit record of the start. Its refusals are exec's. With
	// a nil error the caller must call Close exactly once.
	PrepareExec(ctx context.Context, e Envelope, r ExecRequest) (PreparedExec, error)
}

// PreparedExec is an exec that passed every check.
type PreparedExec interface {
	// Run starts the command and returns when it ends. Everything written to
	// stdout and stderr is already redacted; when a writer implements
	// redact.CountedWriter it also gets the replacement counts. onStart is
	// called once, when the child exists (never, if it cannot start). ctx
	// ends the run: the child's whole process tree is killed.
	Run(ctx context.Context, stdout, stderr io.Writer, onStart func()) ExecOutcome
	// Close wipes the injected values and, if the child never started, gives
	// back the once grants claimed by PrepareExec.
	Close()
}

// Backend implements the operations. Every method gets the validated
// envelope: its Cwd and Session, never the process ones, decide layers and
// grants. An error that is a refusal.Refusal is returned as is; any other
// error becomes `internal` with a fixed message.
type Backend interface {
	List(ctx context.Context, e Envelope) (ListResult, error)
	Exec(ctx context.Context, e Envelope, r ExecRequest) (ExecResponse, error)
	// Check describes the values of secrets the caller could use right now,
	// without consuming a grant and without returning a value.
	Check(ctx context.Context, e Envelope, r CheckRequest) (CheckResponse, error)
	Grant(ctx context.Context, e Envelope, r GrantRequest) (GrantResponse, error)
	Revoke(ctx context.Context, e Envelope, r RevokeRequest) (RevokeResponse, error)
	Request(ctx context.Context, e Envelope, r RequestRequest) (RequestResponse, error)
	Manage(ctx context.Context, e Envelope, r ManageRequest) (ManageResponse, error)
	Info() Info
}

// Auditor is implemented by a Backend that keeps an audit log. Handle calls
// Refused for every refusal of a request whose envelope was valid (so the
// session is known), after the answer is decided and before it is returned.
// A request that fails the envelope check (contract, op, session, cwd) has no
// session to attribute and is not reported. The refusal carries a fixed
// message and at most a validated secret name; the implementation must record
// nothing else (no command, no reason, no field values). It is best effort:
// it cannot change the answer.
type Auditor interface {
	Refused(e Envelope, rf refusal.Refusal)
}
