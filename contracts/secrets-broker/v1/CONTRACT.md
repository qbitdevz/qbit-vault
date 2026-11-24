# Contract: `qbit-vault.secrets-broker/v1`

Status: **draft 1.0.0-draft.2** (draft.2: `request` takes several typed fields; `list` reports `kind` and `unlinked_match`; `capabilities` reports field kinds and sync). Frozen on the first stable release; afterwards only additive changes under the same major, published as capability rows (`capabilities: 1.1`, `1.2`, ...). Consumers MUST refuse envelopes whose `contract` major they do not implement.

This contract defines the only surface through which a host (an agent runtime, its hooks or its extension) talks to the broker. It is transport-independent: the same JSON objects travel over MCP tool calls and over the CLI (`broker --op`, `--json`); the Pi extension (planned, Phase 4) would use the CLI form. The Claude Code hooks do not carry contract traffic.

## Envelope

Every request and response carries:

```json
{ "contract": "qbit-vault.secrets-broker/v1", "op": "request", "v": 1, "session": "pi:2f1c…", "cwd": "/home/me/repo", ... }
```

| Field | Req | Description |
| --- | --- | --- |
| `contract` | yes | Literal `qbit-vault.secrets-broker/v1` |
| `op` | yes | One of `request`, `list`, `exec`, `manage`, `grant`, `revoke`, `capabilities`; the MCP server also serves `exec_start`, `exec_status` and `exec_stop` (§ Jobs) |
| `v` | yes | Operation schema version, integer, currently `1` for all ops |
| `session` | yes | Opaque host session id, `^[a-z0-9-]+:[A-Za-z0-9._-]{4,128}$` (prefix = host: `pi`, `claude`, `codex`, `cli`; the MCP server generates `mcp`) |
| `cwd` | yes | Absolute path of the working directory; used to resolve the repository root for the project layer and the `project` scope. A linked Git worktree resolves to the root of its main clone, when the worktree and the clone name each other |
| `host` | no | `{ "name": "gentle-shell", "version": "3.7.0" }` for audit |

Responses carry `ok: true` with the op's payload, or `ok: false` with a **refusal** (see below). No other error shape exists.

## Layers

Every secret lives in one **layer**: `global`, or `project` (the repository that contains `cwd`). In requests, `layer: "project"` always means *the project of this envelope's `cwd`*; the model never names another repository, so it cannot reach another project's secrets. A name resolves to the project secret when one exists, else to the global one (`STORAGE.md` § Layers). Grants bind to the resolved layer.

## Operations

### `request` — ask for one or several secret handles (model-callable)

Request, one secret:
```json
{ "op": "request", "name": "GITHUB_TOKEN", "reason": "gh release create v1.2.0", "suggested_scope": "once", "suggested_layer": "global" }
```

Request, several fields in one prompt:
```json
{ "op": "request", "reason": "run the shop-api migrations against staging",
  "fields": [ { "name": "DB_HOST", "kind": "text", "label": "Host" },
              { "name": "DB_USER", "kind": "text", "label": "User" },
              { "name": "DB_PASSWORD", "label": "Password", "description": "staging db password" } ],
  "suggested_scope": "once", "suggested_layer": "project" }
```

| Field | Req | Rules |
| --- | --- | --- |
| `name` | one of `name`, `fields` | `^[A-Z][A-Z0-9_]{0,63}$`; shorthand for `fields: [{name}]` |
| `fields[]` | one of `name`, `fields` | 1–8 entries, names unique (a duplicate is `invalid_name`). Each `{name, kind?, label?, description?}`: `kind` `secret` (default; masked) or `text` (visible while typed); `label` ≤ 40 chars shown next to the box (default the name); `description` ≤ 200 chars, stored on a new record. Labels and descriptions are shown escaped, like `reason` |
| `reason` | yes | 8–200 chars, shown verbatim to the user; MUST NOT be empty or generic (`"needed"` is refused with `reason_too_vague` by a minimal heuristic: < 3 words) |
| `suggested_scope` | no | `once` \| `session` \| `project`; a hint only, the user chooses |
| `suggested_layer` | no | `global` \| `project`; a hint only, the user chooses. `project` outside a repository → `no_project` |
| `locale` | no | BCP 47 tag of the conversation language (`es-ES`), see § Dialog language |

Behavior: the broker opens **one user-facing prompt** (host UI or native) for all fields. A field whose name resolves for `cwd` is shown as *already stored* and gets no box; every other field gets a box (masked for `secret`, visible for `text`). The prompt asks the layer once for the new values (when `cwd` is in a repository) and one scope for all fields, offering only scopes every field allows (a `sensitive` one limits all to `once`). It is all-or-nothing: a blank box, a cancel or a timeout stores nothing and grants nothing. On confirmation every new value is stored and every field's record is granted with the chosen scope. The model is not told which fields were already stored. A name in its cooldown makes the whole request `rate_limited` (naming it); a decline starts the cooldown for every name in the request. With sync enabled the broker pulls first (bounded, `REMOTE_SYNC.md` § 7.1), so a secret stored on another machine is found.

Response:
```json
{ "ok": true,
  "refs": [ { "name": "DB_HOST", "ref": "secret://DB_HOST", "layer": "project" },
            { "name": "DB_USER", "ref": "secret://DB_USER", "layer": "project" },
            { "name": "DB_PASSWORD", "ref": "secret://DB_PASSWORD", "layer": "project" } ],
  "grant": { "scope": "session", "expires_at": "2026-10-16T09:12:00Z" } }
```

A single-`name` request also carries `ref` and `layer` of that one field, so draft.1 callers keep working. `layer` is per field because a field already stored keeps its own layer. `expires_at` is `null` for `project`. For `once`, each field's grant is consumed by the next `exec` in the same session that references that name.

### `list` — enumerate handles (model-callable)

Request: `{ "op": "list" }`, with the optional `locale` (§ Dialog language): `{ "op": "list", "locale": "es-ES" }`. A locked vault is unlocked by a dialog, and `locale` is the language of that dialog.

Response:
```json
{ "ok": true,
  "project": { "root": "/home/me/shop-api", "label": "shop-api" },
  "secrets": [
  { "name": "GITHUB_TOKEN", "layer": "global", "overrides_global": false, "kind": "secret",
    "description": "GitHub PAT, repo scope", "sensitive": false,
    "binaries": ["gh", "git"], "hosts": ["api.github.com"],
    "created_at": "…", "updated_at": "…",
    "grant": { "scope": "session", "expires_at": "…" } },
  { "name": "DATABASE_URL", "layer": "project", "overrides_global": true, "…": "…", "grant": null } ],
  "unlinked_match": null,
  "policy": { "…": "see below" } }
```

`grant` is the grant `exec` would accept for this secret from `cwd` and this session (the same check, run without spending a `once` grant): `null` when none applies. A grant that exists but does not apply here is never shown as active. In that case the optional `grant_note` says why and what to do: `a project grant exists for another directory; call secret_request` (a project grant of a global secret covers only the repository it was approved in) or `the grant is for an earlier value of this secret; call secret_request` (the value was replaced). The field is absent when there is nothing to say; clients that do not know it ignore it (added in 1.1.0, additive, issue #42).

Returns the secrets that resolve from `cwd`: every secret of the current project layer, plus every global secret not overridden by it. `project` is `null` outside a repository. Other projects' secrets are never listed. Never values. `unlinked_match` is `{ "label": "shop-api" }` when sync brought a project layer from another device whose origin URL matches this repository but the user has not linked it here (`REMOTE_SYNC.md` § 7.5): the agent may suggest that the user run `qbit-vault link shop-api`; it cannot link it itself. Otherwise `null`.

`policy` tells the agent everything it may and may not do. Its strings are normative (hosts ship them verbatim) and the same text is the MCP server's `instructions`:

```json
{ "can": [
    "List secret names and metadata visible from this directory with secret_list.",
    "Ask the user for one or several secrets (up to 8 fields, each secret or plain text) with a concrete reason using secret_request; the user types them outside the chat.",
    "Run commands with granted secrets using secret_exec or the shell tool; output comes back redacted.",
    "Propose removing, editing, moving (global <-> this project) or replacing a secret using secret_manage; the user confirms or declines." ],
  "cannot": [
    "Read, print, copy or receive any secret value.",
    "Create or widen a grant; only the user grants access.",
    "Apply any change without the user's confirmation.",
    "Reach the secrets of another project.",
    "Print the environment (env, printenv, set, /proc/*/environ, ...) while secrets are injected.",
    "Use a secret with a binary outside its allowlist.",
    "Re-ask for a name the user declined during its cooldown.",
    "Configure sync, pair or revoke devices, or link a project layer; only the user can." ],
  "layers": ["global", "project"],
  "scopes": ["once", "session", "project"],
  "cooldowns": [ { "name": "AWS_SECRET_ACCESS_KEY", "until": "…" } ] }
```

### `exec` — run a command with injected secrets (model-callable)

Request:
```json
{ "op": "exec",
  "command": "gh release create v1.2.0 --notes-file CHANGELOG.md",
  "secrets": [ { "name": "GITHUB_TOKEN" }, { "name": "GH_TOKEN", "from": "GITHUB_TOKEN" } ],
  "timeout_ms": 600000,
  "shell": "auto" }
```

| Field | Req | Rules |
| --- | --- | --- |
| `command` | yes | 1–16 KiB; executed through the platform shell (`/bin/sh -c`, `cmd /c` or `pwsh -c` per `shell`) |
| `secrets[]` | yes | Each `{name, from?}`: inject vault secret `from` (default = `name`) as env var `name`. Max 16. |
| `timeout_ms` | no | 1 s – 1 h, default 600 000 |
| `shell` | no | `auto` \| `sh` \| `bash` \| `cmd` \| `pwsh` |
| `locale` | no | BCP 47 tag of the conversation language (`es-ES`), see § Dialog language |

Behavior (normative, see PRD R-EXEC-*): resolve every `from` for `cwd` to its layer → check grants for that name and layer → dump-guard → binary allowlist → build env (parent env minus any var named like a vault secret, plus injected) → run in own process group with timeout → stream stdout/stderr through the redactor → audit → return. A `once` grant is spent only if the child process is created: a refusal at any earlier step, or a command that cannot start, leaves it usable; a child that starts and exits non-zero spends it. On Windows a bare `bash` or `sh` in `command` never resolves to WSL; with no Git for Windows it is an `internal` refusal with a fixed message.

Response:
```json
{ "ok": true, "exit_code": 0, "stdout": "…redacted…", "stderr": "…redacted…",
  "duration_ms": 1830, "redactions": 2, "truncated": false }
```

`stdout`/`stderr` are capped at 1 MiB each (`truncated: true`, tail kept). Hosts with streaming (Pi) receive chunks over the CLI's `--stream` mode with the same redaction guarantees.

### Jobs — `exec_start`, `exec_status`, `exec_stop` (MCP only, model-callable)

A host may cancel a tool call that runs longer than its request timeout (60 s in some), and that ends the command `exec` was running. A **job** is a command that keeps running after the call that started it returns. Jobs live in the memory of the `qbit-vault mcp` process: no daemon, no job file, nothing on disk. `broker --op` is one process per call and cannot keep a command running, so it does not serve these ops: it answers them as an unknown op (`invalid request: op`), and `capabilities` reports `exec_jobs: 1` only from a backend that serves them (the MCP server).

**`exec_start`** takes exactly the fields of `exec` (same limits, `locale` included) and answers as soon as the command has started:

```json
{ "ok": true, "job": "9f2c4e7a1b8d4c3e8a5f60b7d1e2c3a4" }
```

Everything `exec` decides before a process exists is decided before `exec_start` answers, by the same code, with the same refusal types, messages, hints and audit records: the unlock dialog, grants (a `once` grant is spent when the child is created, exactly as in `exec`, and given back if it cannot start), the dump guard, the binary allowlist, `unknown_secret`, `scope_binary` and the rest. `timeout_ms` bounds the job exactly as it bounds `exec` and ends it as `timed_out`. Two refusals are specific: a fifth job while four run is `internal` (retryable, message `too many running jobs`, hint below), and a start on a server that is stopping is `internal`.

**`exec_status`** takes `job` (32 lowercase hex digits) and `wait_ms` (integer, 0 to 50 000, default 0). It waits up to `wait_ms` and returns early when the job ends: a long poll that stays under the 60 s some hosts allow. Output is **incremental**: `stdout` and `stderr` hold what the job produced since the previous `exec_status` or `exec_stop` call for that job, redacted exactly as in `exec`, so a caller never re-reads or loses output. A call the client cancels takes nothing and never touches the job.

```json
{ "ok": true, "state": "exited", "exit_code": 0, "duration_ms": 183204,
  "stdout": "…redacted…", "stderr": "", "redactions": 1, "truncated": false }
```

| Field | Meaning |
| --- | --- |
| `state` | `running`, `exited` (the process ended by itself), `timed_out` (`timeout_ms` passed, tree killed) or `stopped` (`exec_stop`, or the server ending) |
| `exit_code` | Absent while `running`; otherwise the status the process ended with (after a kill, the operating system's kill status) |
| `duration_ms` | Since the job started; fixed once it ended |
| `stdout`, `stderr` | New redacted output since the previous call; each stream is capped at 1 MiB, tail kept |
| `redactions` | Replacements in the output returned by this call |
| `truncated` | `true` when output was dropped by the cap since the previous call |

**`exec_stop`** takes `job` and kills the job's whole process tree (the same tree kill as a timeout). It answers like `exec_status`, with the final state and the output not read yet. Stopping a job that already ended is a no-op that returns its final state.

Rules (normative):

- **Visibility.** A job is visible only to the MCP session that started it. An id that is unknown, malformed, already reported, stopped, expired or another session's is the same refusal: `internal`, message `no such job`, with the hint below. A malformed id (not 32 lowercase hex digits) is `invalid request: job`.
- **Ids** are 128 random bits from the operating system's random source, shown as 32 hex digits. They name nothing about the command.
- **Limits.** At most 4 jobs run at once per server (a job being started counts). A finished job's unread output and final state are kept for 10 minutes after it ended, or until a call has returned the final state, whichever is first; then they are dropped, and nothing is ever written to disk. At most 8 finished jobs whose result was not read are kept per server: when a ninth ends, the oldest is dropped and its id answers as an unknown id, so read a job's result before starting many more.
- **End of the server.** When the server ends for any reason (the host closed stdin, a signal, a panic), every running job's process tree is killed before the process exits. A job never outlives the server, and a child never keeps injected values alive after it. A tree that left its process group (`setsid`) is out of reach on POSIX, as for `exec`. A server killed outright (SIGKILL, the operating system's out-of-memory killer) cannot do this: on POSIX its jobs' children are not killed and `timeout_ms` does not end them either, because the timer lives in the dead server; on Windows the job object ends the tree with the process.
- **Redaction.** Output is redacted as a stream, with `exec`'s redactor and encodings, before it is buffered for a later call. A value split across two chunks or across two calls appears in neither. The only unredacted bytes the server holds are the redactor's own carry-over: the longest ending of the output so far that is the beginning of a value or of one of its encodings, withheld until it can be told apart from a value. Ordinary output has no such ending and is returned by the next `exec_status` call at once. A value that ends the output cut short (the job was stopped, timed out or exited in the middle of printing it) is not returned in clear: an ending of at least 4 bytes that is the beginning of a value is replaced by its `[REDACTED:NAME]` marker and counted in `redactions`; a shorter overlap is written as it is. The same holds for `exec` and `qbit-vault exec`.
- **Nothing about a job** (command, output, id) is written to logs or stderr. The audit log records the start and the end like `exec`, and `interrupted` for a stopped job.

### `manage` — propose a change to the vault (model-callable, user-confirmed)

The agent proposes; the user decides. Every action opens the user-facing prompt (same channel as `request`) showing the action, name, layer, the change and the reason. Nothing is applied without that confirmation.

Request:
```json
{ "op": "manage", "action": "move", "name": "DATABASE_URL", "layer": "global", "to": "project",
  "reason": "this URL is the shop-api staging db, not a global one" }
```

| Field | Req | Rules |
| --- | --- | --- |
| `action` | yes | `remove` \| `edit` \| `move` \| `replace` |
| `name` | yes | Secret name; must exist in `layer` for `cwd`, else `unknown_secret` |
| `layer` | yes | `global` \| `project` (the project of `cwd`) |
| `reason` | yes | Same rules as `request.reason` |
| `to` | `move` only | The other layer. If the name already exists there, the prompt asks the user whether to overwrite |
| `changes` | `edit` only | Any of `description`, `binaries`, `hosts`, `sensitive`. The prompt shows a before/after diff |
| `locale` | no | BCP 47 tag of the conversation language (`es-ES`), see § Dialog language |

- `remove`: deletes the record and its grants.
- `edit`: metadata only, never the value. Clearing `sensitive` or emptying `binaries` widens access, so the prompt marks it as **widening**.
- `move`: keeps value and metadata, drops the record's grants (R-LAYER-05).
- `replace`: one decision, then the masked capture for the new value. The decision offers `Replace, allow once` (preselected) and, where the record allows it, `Replace, always in this project` (never a session answer), then `Replace, but ask me before each use` and `Don't replace` (a decline). The old grants are dropped; the picked scope, if any, becomes a new prompt-token grant on the new value for this envelope's session, so the agent's next `exec` needs no second permission dialog.

Except for the grant the user picks in a `replace` decision, `manage` never creates a grant. Declines start the same per-name cooldown as `request`.

Response:
```json
{ "ok": true, "applied": true, "action": "move", "name": "DATABASE_URL", "layer": "project" }
```

`layer` is the record's layer after the action (`null` after `remove`).

### `grant` — create or widen a grant (**user-UI only, never model-callable**)

Only the host UI (the planned Pi extension prompt, or the native dialog) may send it, and only as the result of a user interaction. The MCP server does not expose it as a tool. The CLI accepts it only from an interactive TTY or with `--from-prompt-token <t>` issued by the broker's own prompt.

Request: `{ "op": "grant", "name": "GITHUB_TOKEN", "layer": "global", "scope": "session", "ttl_ms": 43200000 }`
Response: `{ "ok": true, "grant": { "scope": "session", "expires_at": "…" } }`

### `revoke` — drop grants (user-callable)

Request: `{ "op": "revoke", "name": "GITHUB_TOKEN" }` or `{ "op": "revoke", "all": true }` or `{ "op": "revoke", "session_only": true }`
Response: `{ "ok": true, "revoked": 2 }`

### `capabilities` — negotiate

Request: `{ "op": "capabilities" }`
Response:
```json
{ "ok": true, "contract": "qbit-vault.secrets-broker/v1", "capabilities": "1.1",
  "ops": ["request","list","exec","manage","grant","revoke","capabilities"],
  "layers": ["global","project"],
  "prompt_backends": ["pi-ui","osascript","powershell","zenity","kdialog","tty"],
  "field_kinds": ["secret","text"], "max_fields": 8,
  "keychain": "secret-service", "streaming": true, "sync": false, "refusal_hints": 1, "dialog_locale": 1 }
```

`refusal_hints: 1` is a capability row (additive, same major): the broker puts a `hint` on every refusal (and a `rule` on `dump_command`), see § Refusals. A host that does not find the row must not depend on those fields. The `capabilities` version string is unchanged.

`exec_jobs: 1` is a capability row (additive, same major, issue #64), present only from a backend that serves the job ops of § Jobs, the MCP server: `exec_start`, `exec_status` and `exec_stop` exist there and nowhere else. The `ops` list is unchanged (it names the ops every transport serves).

`dialog_locale: 1` is a capability row (additive, same major, issue #63): `request`, `list`, `exec` and `manage` accept the optional `locale` field below. A host that does not find the row must not send it (an older broker refuses an unknown field). The `capabilities` version string stays `1.1`.

## Dialog language

`request`, `list`, `exec` and `manage` take an optional `locale`: a string, the BCP 47 tag of the language of the conversation with the user (`es-ES`, `en-GB`). The agent chooses only the language: every dialog is generated by qbit-vault from its own catalogue (English and Spanish today), and no field of a request, `locale` included, can supply dialog text.

- **Resolution.** The request's `locale`, then the environment variable `QBIT_VAULT_LOCALE`, then the system locale (POSIX `LC_ALL`, `LC_MESSAGES`, `LANG`; on Windows the user's first preferred display language), then English. A tag is matched by its primary language subtag, case-insensitive: `es`, `es-AR` and `ES_es.UTF-8` are Spanish.
- **Fallback.** A string that names no shipped language, is malformed or is longer than 35 characters is ignored and the next step decides; it is never refused, shown, logged, audited or echoed. A value that is not a JSON string is the usual `invalid request: locale`.
- **What stays as sent.** Secret names, scopes (`once`, `session`, `project`), layers (`global`, `project`), host names and paths appear unchanged in every language, so what the user approves is what the agent and the audit log name. The agent's `reason` is shown verbatim, never translated; an agent should write it in the language it sends in `locale`.
- **Not dialogs.** Responses, refusals (`message`, `hint`), the audit log and the CLI's plain output stay English; only dialogs the user answers are localized.

## Refusals

A refusal is `{ "ok": false, "refusal": { "type": "<type>", "name": "<secret name or null>", "message": "<human text, no values>", "retryable": true|false } }`, plus the optional fields below.

| `type` | When | `retryable` | Expected host behavior |
| --- | --- | --- | --- |
| `grant_required` | `exec` references a name with no active grant. When a grant exists but does not apply (another directory, or an earlier value) the `message` says so, e.g. `NAME has a project grant for another directory; call secret_request` | yes | Open the grant prompt; retry once |
| `unknown_secret` | `exec` or `manage` references a name that does not resolve from `cwd` (in neither this project nor global) | yes | Model should call `request` |
| `user_declined` | User cancelled the prompt | no (60 s cooldown) | Tell the model the user declined; do not re-ask |
| `rate_limited` | Re-request inside the cooldown | no | Back off |
| `reason_too_vague` | `request.reason` fails the heuristic | yes | Model rephrases with a concrete reason |
| `invalid_name` | Name fails the regex, or appears twice in `fields` | no | Fix the name |
| `scope_not_allowed` | `project`/`session` asked for a `sensitive` secret | no | Offer `once` |
| `scope_binary` | Command's binary not in the secret's `binaries` | no | Tell the user; user may edit the allowlist |
| `no_project` | `layer: "project"` or `suggested_layer: "project"` while `cwd` is not inside a repository | no | Use `global`, or run from the repository |
| `dump_command` | Command matches the dump-guard list. Carries `rule`, `hint` and, when known, `segment` (below) | no | Tell the model which rule stopped it and what to do instead; an unlocked vault and a valid grant never override the guard |
| `not_model_callable` | `grant` arrived over MCP or without a prompt token | no | Log; this is an attack signal |
| `vault_locked` | Keychain unavailable and no cached passphrase | yes | Prompt for passphrase |
| `vault_corrupt` | AEAD tag or envelope check failed | no | Point to `qbit-vault restore` |
| `timeout` | `exec` exceeded `timeout_ms` | yes | Child killed; partial redacted output returned in `partial` |
| `contract_mismatch` | Unsupported `contract` or `v` | no | Upgrade |
| `internal` | Anything else | maybe | Message never contains values |

Messages MUST be built from the secret **name** and fixed strings only.

### Optional refusal fields: `rule`, `hint`, `segment`

A refusal MAY carry these fields; they are omitted when empty, so a refusal without them is unchanged. They are built from fixed strings only (a `hint` may name the secret at most): never a value, the command, an argument, a URL, a path the user typed, or the text of a pattern. `type`, `name`, `retryable` and the exit codes do not depend on them.

- `hint` is present on every refusal type, with the fixed text below (the capability row `refusal_hints`).
- `rule`: why the guard refused (`dump_command` only). One of a closed set, below.
- `hint`: fixed text saying what to do instead, up to 500 characters.
- `segment`: 0-based index of the top-level pipeline segment (split on `|`, `||`, `&&`, `;`, `&` and newlines) that holds the match; a script run by `sh -c` or a `$(...)` counts as part of its segment. Omitted when not known (for example a here-document body, or a command run under `cmd` or `pwsh`). Never the segment's text.

Hints by type (`dump_command` takes its hint from its `rule`, below):

| Type | Hint |
| --- | --- |
| `grant_required` | Call secret_request for this name to ask the user for a grant, then retry once. |
| `unknown_secret` | Call secret_list to see the stored names; if it is missing, call secret_request with fields to ask the user to store it. |
| `user_declined` | Do not ask again for the same use; continue without it or ask the user in the chat. |
| `rate_limited` | Wait; do not retry the same request. |
| `reason_too_vague` | Say what the command does and why it needs the secret. |
| `invalid_name` | Names match ^[A-Z][A-Z0-9_]{0,63}$ and each appears once. |
| `scope_not_allowed` | Ask for scope once; a sensitive secret allows only a one-time grant. |
| `scope_binary` | The user must add the program to the secret's binaries; ask them. |
| `no_project` | Use the global layer, or run from inside the repository. |
| `not_model_callable` | This is a user-only action; ask the user to run it. |
| `vault_locked` | A QBit Vault tool call such as secret_list opens the unlock dialog; call it again once the user has unlocked. |
| `vault_corrupt` | Stop; the user runs 'qbit-vault restore'. |
| `timeout` | Raise timeout_ms or split the command. |
| `contract_mismatch` | Update qbit-vault; the user runs 'qbit-vault sync' and restarts the agent. |
| `internal` | Report it; the user can run 'qbit-vault doctor'. |

Nine cases replace the hint of their type with another fixed text:

- `grant_required` when a grant exists but does not apply here (another directory, or an earlier value): `A grant exists but does not apply here; call secret_request to ask the user for a new one.`
- `vault_locked` when `exec` or `list` could show no unlock dialog (the `message` is the 1.4.0 text that names `qbit-vault unlock`): `No unlock dialog could be shown; ask the user to run 'qbit-vault unlock' in their terminal, then retry.`
- `internal` for a held vault (`vault is busy`): `Another qbit-vault command holds the vault; retry in a moment.`
- `internal` for an invalid request field (`invalid request: <field>`): `Fix the request and call again.`
- `internal` for a call cancelled before the user answered: `The call was cancelled before the user answered; call again only if the task still needs it.`
- `scope_not_allowed` for a project grant outside a repository: `Run it inside a repository, or ask for another scope.`
- `grant_required` from the command line `qbit-vault exec` run without `--session`, when no project grant applies (the `message` is `<NAME> has no project grant; a once or session grant needs --session <host>:<id>`): `Without --session only a project grant applies; a once or session grant needs --session <host>:<id>, the id of the session it was granted to. Ask the user for a project grant, or pass --session.` The broker always has a session, so an MCP or broker call never gets this one.
- `internal` for `exec_start` with four jobs already running (`too many running jobs`, retryable): `Four jobs are already running; wait for one to end with secret_exec_status, or stop one with secret_exec_stop, then start again.`
- `internal` for `exec_status` or `exec_stop` of a job that does not exist for this session (`no such job`): `That job does not exist here: it was never started by this server, its final state was already reported, it was stopped, or its result expired. Start a new one with secret_exec_start.`

For `dump_command` the `message` is `the command is refused while secrets are injected: <phrase>`:

| `rule` | Phrase | Refuses |
| --- | --- | --- |
| `environment_dump` | `it lists or reads the environment` | `env`, `printenv`, `set`, `export -p`, `declare`/`typeset` listings, `compgen`, `/proc/*/environ`, PowerShell `env:` listings, `[Environment]::GetEnvironmentVariables`, interpreter scripts that read the environment |
| `value_print` | `it prints a secret value` | `echo`, `printf` or `Write-Output` of `$NAME`, `$env:NAME` or `%NAME%`; here-strings of the value |
| `value_encode` | `it encodes a secret value` | `base64`, `xxd`, `od` or `hexdump` of the value |
| `network_argument` | `it puts a secret value in a network command's arguments` | `curl`, `wget`, `http`, `nc`, `ncat` or `socat` with the value in an argument, wherever the segment sits in a pipeline |
| `encoded_script` | `its script is encoded and cannot be checked` | PowerShell `-EncodedCommand` and its prefixes |
| `custom_rule` | `it matches a rule in your dumpguard.yaml` | A pattern from the user's `dumpguard.yaml`; its text is never shown |

The set is closed within a major version. Filtering the output (`| jq`, `| grep`) is not an exemption: the command is refused before any process starts, whatever follows the matching segment. The `dumpguard.yaml` format is unchanged; the rule of each default pattern is fixed in code and every user pattern is `custom_rule`.

Every refusal answered to a request with a valid envelope, over the host or the model transport, is appended to the audit log as a `refusal` record: the `type`, the `name` when there is one, and the envelope's `session`. The record never holds the command, the reason or a value.

## Model-facing tool definitions (normative text)

These descriptions are shipped verbatim to every host so models see the same contract.

**`secret_request`** — "Ask the user for permission to use one or several named secrets (e.g. GITHUB_TOKEN, or DB_HOST, DB_USER and DB_PASSWORD together) in later commands. Ask for everything one task needs in a single call: up to 8 fields, each 'secret' (masked) or 'text' (visible, for non-secret values such as a hostname). The user will type or approve them outside the chat. You NEVER receive the values; you receive references and a grant. Give a concrete reason (what command, what for). Do not request secrets you do not need for the current task. If the user declines, do not ask again."

**`secret_list`** — "List the secrets available from this directory (global ones and this project's), and the rules for what you can and cannot do with them. Values are never returned. Call this first when you need a credential."

**`secret_manage`** — "Propose a change to a secret: remove it, edit its metadata, move it between global and this project, or replace its value. The user confirms or declines outside the chat; nothing changes without that. You never see values and you cannot grant access. Give a concrete reason."

**`secret_exec_start`** — "Start a shell command in the background with named secrets injected as environment variables for that process only, and return a job id as soon as it has started. Use this instead of secret_exec for anything that may take more than about 30 seconds (builds, test suites, deploys, migrations): a host may cancel a tool call that runs longer than its request timeout, 60 seconds in some, and that ends the command. It takes the same input as secret_exec and is refused for the same reasons with the same hints; a once grant is spent when the job starts. Then call secret_exec_status with the job id and wait_ms to read the redacted output and the exit code. At most 4 jobs run at once, and every job ends when this server stops."

**`secret_exec_status`** — "Read a job started with secret_exec_start. Waits up to wait_ms (0 to 50000, default 0) and returns early when the job ends, so pass a wait_ms such as 30000 instead of polling in a loop. Returns state (running, exited, timed_out or stopped), exit_code once it ended, duration_ms, and the redacted stdout and stderr the job produced since your previous call for this job: each output is returned once, so keep what you need. A call that returns a finished state is the last one for that job; an unread result is kept for 10 minutes. Secret values are redacted as in secret_exec."

**`secret_exec_stop`** — "Stop a job started with secret_exec_start: its whole process tree is killed. Returns the same fields as secret_exec_status, with the final state and any output you have not read yet. Stopping a job that already ended returns its final state. Use it for a job that is stuck or that you no longer need."

**`secret_exec`** — "Run a shell command with named secrets injected as environment variables for that process only. Output is returned with secret values redacted. Commands that print the environment or a secret are refused; to use only a length, write ${#NAME}. Prefer this over asking the user to paste credentials. A refused command carries a rule and a hint saying why and what to do instead; follow the hint, because an unlocked vault or a grant does not lift a refusal."

## Conformance

A host adapter is conformant when it passes the conformance harness (`internal/conformance` and `TestContractConformance` in `internal/cli`, see `docs/TESTING.md`): every op, every refusal, the no-value invariant on every byte returned, and the `grant`-over-MCP rejection.
