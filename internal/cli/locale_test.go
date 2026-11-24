package cli

import (
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/exitcode"
	"github.com/qbitdevz/qbit-vault/internal/prompt/i18n"
)

// Issue #63: a dialog is shown in the language the agent sends; names, scopes,
// layers and the agent's own reason are never translated.

const (
	reasonEs = "publicar la versión 1.2.0 en GitHub"
	reqEs    = `"name":"A","reason":"` + reasonEs + `"`
)

func reqEsFor(cwd, extra string) string {
	return envelope("request", cwd, reqEs+extra)
}

func TestRequestDialogsInSpanish(t *testing.T) {
	w := newWorld(t)
	f := withBackend(t, answers(val("TESTSECRET_es_value"), pick(0)))
	code, m, out := w.broker("request", reqEsFor(w.outside, `,"locale":"es-AR"`))
	if code != exitcode.OK || m["ok"] != true {
		t.Fatalf("code=%d out=%s", code, out)
	}
	if len(f.Calls) != 2 {
		t.Fatalf("calls=%+v", f.Calls)
	}
	// The capture dialog gets the agent's reason as sent; its own texts come from the backend.
	if r := f.Calls[0].Request; r.Name != "A" || r.Reason != reasonEs || r.Host != "pi" {
		t.Errorf("capture request=%+v", r)
	}
	q := f.Calls[1]
	wantQ := "Pi quiere usar A (todos los proyectos).\nMotivo: " + reasonEs
	if q.Q != wantQ {
		t.Errorf("question=%q, want %q", q.Q, wantQ)
	}
	// A global secret outside a repository can only be allowed once.
	if len(q.Options) != 2 || q.Options[0] != "Una vez (once): solo el siguiente comando" || q.Options[1] != "No permitir" {
		t.Errorf("options=%q", q.Options)
	}
	// What was approved is the same grant an English call makes.
	g := w.mustRun("", "--json", "--session", brokerSession, "grants")
	if !strings.Contains(g, `"name":"A"`) || !strings.Contains(g, `"scope":"once"`) {
		t.Errorf("grants=%s", g)
	}
	// The locale is neither audited nor echoed.
	for _, text := range []string{w.auditText(), out} {
		if strings.Contains(text, "es-AR") || strings.Contains(text, "locale") {
			t.Errorf("the locale leaked: %s", text)
		}
	}
}

func TestProjectScopeOptionKeepsItsEnglishToken(t *testing.T) {
	w := newWorld(t)
	f := withBackend(t, answers(pick(1), val("TESTSECRET_ps"), pick(1)))
	code, m, out := w.broker("request", envelope("request", w.repo, reqEs+`,"suggested_layer":"project","locale":"es-ES"`))
	if code != exitcode.OK || m["grant"].(map[string]any)["scope"] != "project" {
		t.Fatalf("code=%d out=%s", code, out)
	}
	o := f.Calls[len(f.Calls)-1].Options
	if len(o) != 3 || o[1] != "Siempre (project): en este proyecto, hasta que lo revoques" || o[2] != "No permitir" {
		t.Errorf("options=%q", o)
	}
}

func TestLayerAndFormQuestionsInSpanish(t *testing.T) {
	w := newWorld(t)
	f := withBackend(t, answers(pick(1), val("TESTSECRET_p1"), val("TESTSECRET_p2"), pick(0)))
	code, m, out := w.broker("request", envelope("request", w.repo, `"fields":[{"name":"DB_USER","kind":"text"},{"name":"DB_PASS"}],"reason":"`+reasonEs+`","suggested_layer":"project","locale":"es"`))
	if code != exitcode.OK || m["ok"] != true {
		t.Fatalf("code=%d out=%s", code, out)
	}
	if c := f.Calls[0]; c.Kind != "choose" || c.Q != "¿Dónde se debe guardar DB_USER, DB_PASS?" || len(c.Options) != 2 || c.Options[0] != "Todos los proyectos" || c.Options[1] != "Solo este proyecto (shop-api)" {
		t.Errorf("layer question=%+v", c)
	}
	last := f.Calls[len(f.Calls)-1]
	if !strings.HasPrefix(last.Q, "Pi quiere usar DB_USER (proyecto shop-api), DB_PASS (proyecto shop-api).\nMotivo: ") {
		t.Errorf("scope question=%q", last.Q)
	}
	// A second request: one field already stored.
	f = withBackend(t, answers(pick(1), val("TESTSECRET_p3"), pick(0)))
	w.broker("request", envelope("request", w.repo, `"fields":[{"name":"DB_USER","kind":"text"},{"name":"DB_TOKEN"}],"reason":"`+reasonEs+`","suggested_layer":"project","locale":"es"`))
	if q := f.Calls[len(f.Calls)-1].Q; !strings.Contains(q, "DB_USER (proyecto shop-api, ya guardado)") {
		t.Errorf("already saved item: %q", q)
	}
}

func TestPastedValueReviewInSpanish(t *testing.T) {
	w := newWorld(t)
	f := withBackend(t, answers(val(`"TESTSECRET_quoted"`), pick(0), pick(0)))
	code, _, out := w.broker("request", reqEsFor(w.outside, `,"locale":"es"`))
	if code != exitcode.OK {
		t.Fatalf("code=%d out=%s", code, out)
	}
	r := f.Calls[1]
	if r.Kind != "choose" || r.Q != "El valor de A tiene comillas alrededor. La mayoría de las claves y tokens no incluyen nada de eso, y los caracteres adicionales rompen los inicios de sesión. ¿Cuál se debe guardar?" {
		t.Errorf("review question=%+v", r)
	}
	if len(r.Options) != 3 || r.Options[0] != "Sin los caracteres adicionales (recomendado)" || r.Options[1] != "Conservarlo tal como se escribió" || r.Options[2] != "Cancelar" {
		t.Errorf("review options=%q", r.Options)
	}
	if w.value("A") != "TESTSECRET_quoted" {
		t.Error("the first choice must still mean 'without them'")
	}
}

func TestManageDialogsInSpanish(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_m\n", "set", "A", "--stdin", "--sensitive", "--binaries", "gh", "--description", "vieja")
	body := func(extra string) string {
		return manageReq(w.outside, extra+`,"locale":"es"`)
	}
	f := withBackend(t, answers(yes()))
	w.broker("manage", body(`"action":"edit","name":"A","layer":"global","changes":{"sensitive":false,"binaries":[]}`))
	q := f.Calls[0].Q
	for _, want := range []string{"Pi quiere editar A (todos los proyectos): ", "sensitive: true -> false (amplía el acceso)", "binaries: gh -> cualquiera (amplía el acceso)", "Motivo: " + manageReason} {
		if !strings.Contains(q, want) {
			t.Errorf("edit question lacks %q: %q", want, q)
		}
	}
	f = withBackend(t, answers(yes()))
	w.broker("manage", body(`"action":"remove","name":"A","layer":"global"`))
	if q := f.Calls[0].Q; q != "Pi quiere eliminar A (todos los proyectos).\nMotivo: "+manageReason || f.Calls[0].Kind != "confirm" {
		t.Errorf("remove question=%q", q)
	}

	w.mustRun("TESTSECRET_m2\n", "set", "B", "--stdin")
	w.inRepo()
	w.mustRun("TESTSECRET_m3\n", "set", "B", "--stdin", "--project")
	f = withBackend(t, answers(yes()))
	w.broker("manage", manageReq(w.repo, `"action":"move","name":"B","layer":"global","to":"project","locale":"es"`))
	if q := f.Calls[0].Q; q != "Pi quiere mover B de todos los proyectos a proyecto shop-api (sobrescribiendo el secreto B que ya existe allí).\nMotivo: "+manageReason {
		t.Errorf("move question=%q", q)
	}
	w.outRepo()

	w.mustRun("TESTSECRET_m4\n", "set", "C", "--stdin")
	f = withBackend(t, answers(pick(0), val("TESTSECRET_new_c")))
	w.broker("manage", manageReq(w.outside, `"action":"replace","name":"C","layer":"global","locale":"es"`))
	c := f.Calls[0]
	if c.Kind != "choose" || c.Q != "Pi quiere reemplazar el valor de C (todos los proyectos).\nMotivo: "+manageReason {
		t.Errorf("replace question=%+v", c)
	}
	wantOpts := []string{"Reemplazar y permitir una vez (once)", "Reemplazar y permitir siempre en este proyecto (project)", "Reemplazar, pero preguntarme antes de cada uso", "No reemplazar"}
	if strings.Join(c.Options, "|") != strings.Join(wantOpts, "|") {
		// outside a repository the project scope is not offered
		wantOpts = append(wantOpts[:1:1], wantOpts[2:]...)
		if strings.Join(c.Options, "|") != strings.Join(wantOpts, "|") {
			t.Errorf("replace options=%q", c.Options)
		}
	}
	if r := f.Calls[1].Request; r.Reason != manageReason || r.Existing != true {
		t.Errorf("replace capture=%+v", r)
	}
}

// The unlock dialog that list and exec open follows the call's locale.
func TestUnlockDialogOfListAndExecInSpanish(t *testing.T) {
	const (
		wantNone  = "Pi necesita la bóveda. Desbloquéala para continuar."
		wantNamed = "Pi quiere usar A. Desbloquea la bóveda para continuar."
	)
	w := grantedLockedWorld(t)

	f := withBackend(t, answers(val(fxPass)))
	if code, m, out := w.broker("list", envelope("list", w.repo, `"locale":"es-ES"`)); code != exitcode.OK || m["ok"] != true {
		t.Fatalf("list: code=%d out=%s", code, out)
	}
	if p := f.Calls[0].Passphrase; len(f.Calls) != 1 || p.Reason != wantNone || p.ID != "vault" || p.Heading != "Vault passphrase" {
		t.Errorf("list unlock=%+v", f.Calls)
	}

	f = withBackend(t, answers(val(fxPass)))
	exe := child(t, "leaks", "TOKEN", 0)
	code, m, out := w.broker("exec", envelope("exec", w.repo, `"command":`+jsonString(exe)+`,"secrets":[{"name":"TOKEN","from":"A"}],"locale":"es"`))
	if code != exitcode.OK || m["ok"] != true {
		t.Fatalf("exec: code=%d out=%s", code, out)
	}
	if len(f.Calls) != 1 || f.Calls[0].Passphrase.Reason != wantNamed {
		t.Errorf("exec unlock=%+v", f.Calls)
	}

	// The layer, when the caller says it, stays the English token.
	f = withBackend(t, answers(val(fxPass), pick(0)))
	w.broker("request", reqEsFor(w.outside, `,"suggested_layer":"global","locale":"es"`))
	if got := f.Calls[0].Passphrase.Reason; got != "Pi quiere usar A (global). Desbloquea la bóveda para continuar." {
		t.Errorf("layer in the reason: %q", got)
	}

	// Without a locale it is the English text, as before.
	f = withBackend(t, answers(val(fxPass)))
	w.broker("list", envelope("list", w.repo, ""))
	if got := f.Calls[0].Passphrase.Reason; got != unlockReasonNo {
		t.Errorf("no locale: %q", got)
	}
	// The audit record of the unlock is English whatever the dialog said.
	for _, r := range w.auditUnlocks() {
		if r.Detail != "Pi" {
			t.Errorf("unlock record %+v", r)
		}
	}
}

func TestLocaleResolutionOfAgentCalls(t *testing.T) {
	w := newWorld(t)
	ask := func(env map[string]string, locale string) string {
		t.Helper()
		f := withBackend(t, answers(val("TESTSECRET_r"), pick(0)))
		extra := ""
		if locale != "" {
			extra = `,"locale":"` + locale + `"`
		}
		stdinOverride = strings.NewReader(reqEsFor(w.outside, extra))
		t.Cleanup(func() { stdinOverride = nil })
		var out, errb strings.Builder
		execute([]string{"--home", w.home, "broker", "--op", "request"}, &out, &errb, envFrom(env))
		if len(f.Calls) < 2 {
			t.Fatalf("calls=%+v out=%s", f.Calls, out.String())
		}
		w.mustRun("", "revoke", "--all")
		w.mustRun("", "rm", "A", "--yes")
		return f.Calls[1].Q
	}
	es, en := "Pi quiere usar", "Pi wants to use"
	tests := []struct {
		name   string
		env    map[string]string
		locale string
		want   string
	}{
		{"nothing is English", nil, "", en},
		{"the request wins over the env", map[string]string{i18n.EnvLocale: "en"}, "es", es},
		{"an English request wins over a Spanish env", map[string]string{i18n.EnvLocale: "es"}, "en-GB", en},
		{"the env when the request has none", map[string]string{i18n.EnvLocale: "es"}, "", es},
		{"an unknown request falls to the env", map[string]string{i18n.EnvLocale: "es"}, "fr-FR", es},
		{"a malformed request falls to the env", map[string]string{i18n.EnvLocale: "es"}, "e s!", es},
		{"the POSIX variables when the request has none", map[string]string{"LC_ALL": "es_ES.UTF-8"}, "", es},
		{"LANG", map[string]string{"LANG": "es_MX.UTF-8"}, "", es},
		{"an unknown tag everywhere is English", map[string]string{i18n.EnvLocale: "klingon", "LANG": "C"}, "zz", en},
	}
	for _, tt := range tests {
		if got := ask(tt.env, tt.locale); !strings.HasPrefix(got, tt.want) {
			t.Errorf("%s: question %q does not start with %q", tt.name, got, tt.want)
		}
	}
}

// What a tag looks like never reaches the dialog, the audit log or an error.
func TestAnOddLocaleIsNeverShown(t *testing.T) {
	w := newWorld(t)
	for _, loc := range []string{"TESTSECRET_loc", "es\\u0000x", strings.Repeat("e", 300), "<b>es</b>"} {
		f := withBackend(t, answers(val("TESTSECRET_o"), pick(0)))
		code, _, out := w.broker("request", reqEsFor(w.outside, `,"locale":"`+loc+`"`))
		if code != exitcode.OK {
			t.Fatalf("%.12s: code=%d out=%s", loc, code, out)
		}
		raw := out + w.auditText()
		for _, c := range f.Calls {
			raw += c.Q + strings.Join(c.Options, "|") + c.Request.Reason + c.Request.Name
		}
		if strings.Contains(raw, "<b>") || strings.Contains(raw, "TESTSECRET_loc") || strings.Contains(raw, "eeeeeeee") {
			t.Errorf("%.12s: the tag was echoed", loc)
		}
		if !strings.Contains(f.Calls[1].Q, "Pi wants to use") {
			t.Errorf("%.12s: fell back to %q", loc, f.Calls[1].Q)
		}
		w.mustRun("", "revoke", "--all")
		w.mustRun("", "rm", "A", "--yes")
	}
}

// The commands a person types follow QBIT_VAULT_LOCALE, then the system.
func TestCLIConfirmationsFollowTheEnvironment(t *testing.T) {
	w := newWorld(t)
	w.mustRun("TESTSECRET_c\n", "set", "A", "--stdin")
	env := map[string]string{i18n.EnvLocale: "es"}
	f := withBackend(t, answers(no()))
	if code, _, _ := run(t, env, "--home", w.home, "rm", "A"); code == exitcode.OK {
		t.Fatal("a declined rm succeeded")
	}
	if q := f.Calls[0].Q; q != "¿Eliminar A (todos los proyectos)?" {
		t.Errorf("rm question=%q", q)
	}
	f = withBackend(t, answers(no()))
	run(t, nil, "--home", w.home, "rm", "A")
	if q := f.Calls[0].Q; q != "Remove A (all projects)?" {
		t.Errorf("English rm question=%q", q)
	}
	// The machine's language is the next step.
	old := i18n.OSLocale
	i18n.OSLocale = func() string { return "es-ES" }
	t.Cleanup(func() { i18n.OSLocale = old })
	f = withBackend(t, answers(no()))
	run(t, nil, "--home", w.home, "rm", "A")
	if q := f.Calls[0].Q; q != "¿Eliminar A (todos los proyectos)?" {
		t.Errorf("system locale question=%q", q)
	}
	// ...and the environment variable still beats it.
	f = withBackend(t, answers(no()))
	run(t, map[string]string{i18n.EnvLocale: "en"}, "--home", w.home, "rm", "A")
	if q := f.Calls[0].Q; q != "Remove A (all projects)?" {
		t.Errorf("env over system question=%q", q)
	}
	// set asks its capture and scope questions in Spanish, too.
	f = withBackend(t, answers(val("TESTSECRET_s"), pick(0)))
	run(t, env, "--home", w.home, "--session", brokerSession, "set", "S", "--grant", "once")
	if len(f.Calls) != 2 || f.Calls[0].Request.Reason != "entrada manual" || f.Calls[1].Q != "¿Permitir que los agentes usen S (todos los proyectos) ahora mismo?" {
		t.Errorf("set calls=%+v", f.Calls)
	}
	if o := f.Calls[1].Options; len(o) != 3 || o[0] != "Una vez (once): solo el siguiente comando" || o[1] != "Sesión (session): hasta que el agente se reinicie (máx. 12h)" || o[2] != "Guardar sin permitir todavía" {
		t.Errorf("set options=%q", o)
	}
}

// The English names of the remote dialogs are the catalogue's.
func TestRemoteDialogNamesAreTheCatalogueEnglish(t *testing.T) {
	for id, want := range map[string]string{"name.invite": nameInvite, "name.recovery": nameRecovery, "name.last_four": nameLastFour,
		"name.pairing": namePairing, "name.label": nameLabel, "name.confirm_code": nameConfirm} {
		if got := i18n.En.T(id); got != want {
			t.Errorf("%s = %q, the constant is %q", id, got, want)
		}
	}
}
