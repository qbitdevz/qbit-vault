package skill_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/filemerge"
	"github.com/qbitdevz/qbit-vault/internal/hosts"
	"github.com/qbitdevz/qbit-vault/internal/hosts/claude"
	"github.com/qbitdevz/qbit-vault/internal/hosts/codex"
	"github.com/qbitdevz/qbit-vault/internal/hosts/pi"
	"github.com/qbitdevz/qbit-vault/internal/hosts/skill"
	"github.com/qbitdevz/qbit-vault/internal/mcp"
	"github.com/qbitdevz/qbit-vault/internal/refusal"
	"github.com/qbitdevz/qbit-vault/internal/secret"
	"github.com/qbitdevz/qbit-vault/internal/vault"
)

// skillHost is a host whose only step is the skill at path.
type skillHost struct {
	name string
	path func(hosts.Env) (string, error)
}

func (h skillHost) Name() string                 { return h.name }
func (h skillHost) Detect(hosts.Env) bool        { return true }
func (h skillHost) Steps(hosts.Env) []hosts.Step { return []hosts.Step{skill.Step(h.name, h.path)} }

func newEnv(t *testing.T) hosts.Env {
	t.Helper()
	base := t.TempDir()
	home := filepath.Join(base, "vault-home")
	if _, err := vault.Init(home, vault.NewID(), secret.New("k", bytes.Repeat([]byte{7}, 32))); err != nil {
		t.Fatal(err)
	}
	return hosts.Env{VaultHome: home, UserHome: filepath.Join(base, "user")}
}

func mustApply(t *testing.T, env hosts.Env, a ...hosts.Adapter) []hosts.Result {
	t.Helper()
	res := hosts.Apply(env, a)
	for _, r := range res {
		if err := r.Err(); err != nil {
			t.Fatalf("apply %s: %v", r.Host, err)
		}
	}
	return res
}

func TestPathsAreTheSkillLocationsOfEachAgent(t *testing.T) {
	env := hosts.Env{UserHome: filepath.FromSlash("/home/ana")}
	c, _ := skill.ClaudePath(env)
	a, _ := skill.AgentsPath(env)
	if c != filepath.FromSlash("/home/ana/.claude/skills/qbit-vault/SKILL.md") || a != filepath.FromSlash("/home/ana/.agents/skills/qbit-vault/SKILL.md") {
		t.Fatalf("paths = %s, %s", c, a)
	}
	if _, err := skill.ClaudePath(hosts.Env{}); err == nil {
		t.Fatal("no user home must be an error")
	}
}

func TestContentIsAValidSkillThatNamesEveryTool(t *testing.T) {
	s := string(skill.Content)
	if !strings.HasPrefix(s, "---\nname: qbit-vault\ndescription: ") || !strings.Contains(s, skill.Marker) {
		t.Fatalf("frontmatter or marker missing:\n%.200s", s)
	}
	desc := strings.SplitN(strings.SplitN(s, "description: ", 2)[1], "\n", 2)[0]
	if len(desc) == 0 || len(desc) > 1024 {
		t.Fatalf("description is %d bytes, want 1..1024", len(desc))
	}
	// A renamed or added tool must show up in the skill in the same change.
	for tool := range mcp.ToolDescriptions {
		if !strings.Contains(s, "`"+tool+"`") {
			t.Errorf("skill does not mention %s", tool)
		}
	}
	// So must every refusal type, each with its own row: a new type in
	// internal/refusal needs its instruction here in the same change.
	for _, r := range refusal.Types() {
		if !strings.Contains(s, "| `"+string(r)+"` |") {
			t.Errorf("skill has no row in \"Refusals and what to do\" for refusal %s", r)
		}
	}
	if bytes.Contains(skill.Content, []byte("TESTSECRET_")) {
		t.Fatal("skill holds a fixture value")
	}
}

func TestApplyInstallsTheSkillOnceAndThenWritesNothing(t *testing.T) {
	env := newEnv(t)
	h := skillHost{"claude-code", skill.ClaudePath}
	res := mustApply(t, env, h)
	if !res[0].Changed() {
		t.Fatal("first apply did not write")
	}
	p, _ := skill.ClaudePath(env)
	if b, err := os.ReadFile(p); err != nil || !bytes.Equal(b, skill.Content) {
		t.Fatalf("installed skill differs: %v", err)
	}
	if res := mustApply(t, env, h); res[0].Changed() {
		t.Fatal("second apply wrote again")
	}
	st, _ := vault.ReadHosts(env.VaultHome)
	if checks := hosts.Verify(env, h, st["claude-code"]); checks[0].Err != nil {
		t.Fatalf("verify = %v", checks[0].Err)
	}
}

func TestAStaleSkillIsDriftAndApplyUpdatesIt(t *testing.T) {
	env := newEnv(t)
	h := skillHost{"claude-code", skill.ClaudePath}
	mustApply(t, env, h)
	p, _ := skill.ClaudePath(env)
	old := strings.Replace(string(skill.Content), "# qbit-vault", "# qbit-vault (older text)", 1)
	if err := os.WriteFile(p, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	st, _ := vault.ReadHosts(env.VaultHome)
	if checks := hosts.Verify(env, h, st["claude-code"]); !errors.Is(checks[0].Err, hosts.ErrDrift) {
		t.Fatalf("verify = %v, want drift", checks[0].Err)
	}
	if res := mustApply(t, env, h); !res[0].Changed() {
		t.Fatal("apply did not update the stale skill")
	}
	if b, _ := os.ReadFile(p); !bytes.Equal(b, skill.Content) {
		t.Fatal("skill not updated")
	}
}

// A skill of the same name the user wrote wins: registration succeeds without
// touching it, doctor accepts it, and uninstall leaves it.
func TestTheUsersOwnSkillOfTheSameNameIsLeftAlone(t *testing.T) {
	env := newEnv(t)
	h := skillHost{"claude-code", skill.ClaudePath}
	p, _ := skill.ClaudePath(env)
	const mine = "---\nname: qbit-vault\n---\nmine\n"
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(mine), 0o600); err != nil {
		t.Fatal(err)
	}
	res := mustApply(t, env, h)
	if res[0].Changed() {
		t.Fatal("the user's skill was rewritten")
	}
	st, _ := vault.ReadHosts(env.VaultHome)
	if checks := hosts.Verify(env, h, st["claude-code"]); checks[0].Err != nil {
		t.Fatalf("verify = %v, want ok", checks[0].Err)
	}
	if steps, err := hosts.RevertHost(env, h); err != nil || steps[0].Outcome != filemerge.Unchanged {
		t.Fatalf("revert = %+v, %v", steps, err)
	}
	if b, _ := os.ReadFile(p); string(b) != mine {
		t.Fatalf("user's skill changed: %q", b)
	}
}

func TestASharedSkillStaysUntilTheLastHostIsRemoved(t *testing.T) {
	env := newEnv(t)
	codex := skillHost{"codex", skill.AgentsPath}
	pi := skillHost{"pi", skill.AgentsPath}
	mustApply(t, env, codex, pi)
	p, _ := skill.AgentsPath(env)

	if steps, err := hosts.RevertHost(env, codex); err != nil || steps[0].Outcome != filemerge.Unchanged {
		t.Fatalf("revert codex = %+v, %v", steps, err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("the skill pi still uses was removed")
	}
	if steps, err := hosts.RevertHost(env, pi); err != nil || steps[0].Outcome != filemerge.Deleted {
		t.Fatalf("revert pi = %+v, %v", steps, err)
	}
	if _, err := os.Stat(filepath.Dir(p)); !os.IsNotExist(err) {
		t.Fatal("the skill directory was kept")
	}
}

func TestTheAdaptersInstallTheSkillWhereEachAgentReadsIt(t *testing.T) {
	env := newEnv(t)
	exe, _ := filepath.Abs(filepath.FromSlash("/opt/qbit/bin/qbit-vault"))
	noEnv := func(string) string { return "" }
	res := mustApply(t, env, claude.NewWithExe(exe), codex.NewWithExe(exe), pi.NewWithExe(exe).WithGetenv(noEnv))
	var changed []bool
	for _, r := range res {
		changed = append(changed, r.Steps[len(r.Steps)-1].Changed)
	}
	// Claude writes its own copy, Codex creates the shared one, Pi finds it current.
	if changed[0] != true || changed[1] != true || changed[2] != false {
		t.Fatalf("skill step changed per host = %v, want [true true false]", changed)
	}
	for _, p := range []func(hosts.Env) (string, error){skill.ClaudePath, skill.AgentsPath} {
		path, _ := p(env)
		if b, err := os.ReadFile(path); err != nil || !bytes.Equal(b, skill.Content) {
			t.Fatalf("%s: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(env.UserHome, ".pi", "agent", "skills")); !os.IsNotExist(err) {
		t.Fatal("pi got a second copy that would collide with ~/.agents/skills")
	}
}

// S7 of odd/tasks/output-guard.md: the model reads the two messages of the
// output and write guard and must know what to do about each.
func TestSkillExplainsTheWithheldOutputAndTheWriteBlock(t *testing.T) {
	s := string(skill.Content)
	for _, want := range []string{
		"output withheld: qbit-vault could not check it for secrets",
		"qbit-vault could not check this edit for secrets",
		"This edit would write the value of the stored secret",
		"`qbit-vault unlock`",
		"`secret_exec`",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("skill does not mention %q", want)
		}
	}
}

// S4 of odd/tasks/unlock-zero-friction.md: for a locked vault the model calls
// a tool, which opens the unlock dialog; the terminal command is only the
// fallback when no dialog could be shown, and the model never asks the user to
// type a command for something a tool can do.
func TestSkillUnlocksThroughTheToolsAndKeepsTheTerminalAsTheFallback(t *testing.T) {
	s := string(skill.Content)
	for _, want := range []string{
		"With `vault locked`, call a QBit Vault tool (for example `secret_list`): it opens the unlock dialog for the user",
		"With `vault locked`, call a QBit Vault tool (for example `secret_list`), which opens the unlock dialog, then write again.",
		"`secret_list` and `secret_exec` ask the same way",
		"no unlock dialog could be shown",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("skill does not say %q", want)
		}
	}
	for _, stale := range []string{
		"tell the user to run `qbit-vault unlock`",
		"never ask: when one answers this",
		"call `secret_request` for the name (it unlocks",
	} {
		if strings.Contains(s, stale) {
			t.Errorf("skill still says %q", stale)
		}
	}
	// Every mention of the terminal command is the documented fallback.
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "qbit-vault unlock") && !strings.Contains(line, "no unlock dialog could be shown") &&
			!strings.Contains(line, "no dialog is possible") {
			t.Errorf("a line sends the user to the terminal outside the fallback: %.120s", line)
		}
	}
}

// S5 of odd/tasks/actionable-refusals.md: the model reads every dump_command
// rule with what to do, and is told that neither an unlocked vault nor a grant
// lifts the guard and that filtering the output is not an exemption.
func TestSkillExplainsEveryDumpCommandRuleAndTheHint(t *testing.T) {
	s := string(skill.Content)
	for _, r := range refusal.Rules() {
		if !strings.Contains(s, "`"+string(r)+"`") {
			t.Errorf("skill does not mention the dump_command rule %s", r)
		}
	}
	for _, want := range []string{
		"`rule`",
		"`hint`",
		"An unlocked vault and a valid grant never override the dump guard",
		"Filtering the output (`| jq`, `| grep`) does not exempt an earlier pipeline segment",
		"${#NAME}",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("skill does not say %q", want)
		}
	}
	if strings.Contains(s, "The command would print a secret or the environment. Rewrite it so it does not.") {
		t.Error("skill still has the generic dump_command row")
	}
}

// Issue #63: the agent sends the conversation language with every call that
// can open a dialog, and writes its reason in the same language; it never
// writes dialog text, and identifiers stay as they are.
func TestSkillAsksForTheConversationLanguage(t *testing.T) {
	s := string(skill.Content)
	for _, want := range []string{
		"## Dialog language",
		"Always send `locale`",
		"`secret_request`, `secret_list`, `secret_exec`, `secret_exec_start` and `secret_manage`",
		"BCP 47",
		"`es-ES`",
		"write the `reason` in that same language",
		"never translated",
		"Secret names",
		"qbit-vault writes every dialog itself",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("skill does not say %q", want)
		}
	}
}

// Issue #64: the skill states the real limit and the supported route for a
// long command, and does not send the agent to a detached-job detour.
func TestSkillStatesTheLimitAndTheRouteForLongCommands(t *testing.T) {
	s := string(skill.Content)
	for _, want := range []string{
		"## Long commands",
		"the host's own request timeout",
		"`timeout_ms` only bounds the command",
		"Do not start a job with `setsid`, `nohup` or `&`",
		"`qbit-vault exec --secret NAME -- <command>`",
		"Pass no `--session`",
		"only a project grant applies",
		"linked Git worktrees",
		"`secret_request`",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("skill does not say %q", want)
		}
	}
	// Mentioned only to forbid it: never as a recipe.
	for _, bad := range []string{"setsid nohup", "nohup qbit-vault", "setsid qbit-vault"} {
		if strings.Contains(s, bad) {
			t.Errorf("skill recommends %q", bad)
		}
	}
}

// Issue #64: the long-command routes name the job tools, in order: a short
// command through secret_exec, anything past about 30 seconds through a job,
// and the host's background job through the CLI as the fallback.
func TestSkillRoutesLongCommandsThroughJobs(t *testing.T) {
	s := string(skill.Content)
	long := s[strings.Index(s, "## Long commands"):]
	long = long[:strings.Index(long[len("## Long commands"):], "\n## ")+len("## Long commands")]
	routes := []string{
		"1. A command that finishes well within 30 seconds: `secret_exec`.",
		"2. Anything that may pass about 30 seconds",
		"3. The MCP tools are not available",
	}
	last := -1
	for _, r := range routes {
		i := strings.Index(long, r)
		if i < 0 || i < last {
			t.Fatalf("route %q is missing or out of order in:\n%s", r, long)
		}
		last = i
	}
	for _, want := range []string{
		"`secret_exec_start`", "`secret_exec_status`", "`secret_exec_stop`",
		"`wait_ms`", "at most 50000", "`job`", "`running`, `exited`, `timed_out` or `stopped`", "`exit_code`",
		"Each output is returned once", "At most 4 jobs run at once", "every job ends when the MCP server stops",
		"a once grant is spent then", "kills the whole process tree",
	} {
		if !strings.Contains(long, want) {
			t.Errorf("the long commands section does not say %q", want)
		}
	}
	// The job refusals have their own instructions in the table.
	for _, want := range []string{"`too many running jobs` is retryable", "`no such job` means start a new one"} {
		if !strings.Contains(s, want) {
			t.Errorf("skill does not say %q", want)
		}
	}
}

// Verifier findings F2 and F4: the skill tells the true lag and the cap on unread results.
func TestSkillStatesTheLagAndTheUnreadJobCap(t *testing.T) {
	s := string(skill.Content)
	for _, want := range []string{
		"only the end of a line that could be the start of a secret value is held back",
		"at most 8 finished jobs you have not read",
		"read a job's result before starting many more",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("skill does not say %q", want)
		}
	}
}
