package prompt

import (
	"strings"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/prompt/i18n"
)

// A request in Spanish: the texts qbit-vault adds are Spanish; the secret
// name, the project, the host and the agent's reason stay as sent.
var reqEs = SecretRequest{
	Name: "GITHUB_TOKEN", Reason: "ejecutar el release de <shop> & co", Host: "claude-code",
	Session: "claude-code:sess-aaaa", Project: "shop-api",
}

func mustContain(t *testing.T, what, s string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(s, w) {
			t.Errorf("%s lacks %q:\n%s", what, w, s)
		}
	}
}

func mustNotContain(t *testing.T, what, s string, bad ...string) {
	t.Helper()
	for _, w := range bad {
		if strings.Contains(s, w) {
			t.Errorf("%s holds %q:\n%s", what, w, s)
		}
	}
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

func TestSecretDialogInSpanish(t *testing.T) {
	d := secretDialog(i18n.Es, reqEs)
	if d.heading != "Solicitud de secreto" || d.okLabel != "Guardar" || d.cancelLabel != "Cancelar" || d.title != "QBit Vault" {
		t.Errorf("heading/buttons/title: %q %q %q %q", d.heading, d.okLabel, d.cancelLabel, d.title)
	}
	mustContain(t, "text", d.text,
		"Quién:", "Claude Code (sesión sess-aaa)", "Secreto:", "GITHUB_TOKEN", "Motivo:", "ejecutar el release de <shop> & co",
		"Se guarda en:", "proyecto shop-api", "Valor:", "nuevo", "Pega o escribe el valor. El agente nunca lo ve:")
	mustNotContain(t, "text", d.text, "Who:", "Why:", "Saved in:", "Save")
	if d := secretDialog(i18n.Es, SecretRequest{Name: "A", Reason: "r", Existing: true, Visible: true}); !strings.Contains(d.text, "reemplaza el valor guardado") || !strings.Contains(d.text, "se muestra mientras escribes") || !strings.Contains(d.text, "todos los proyectos") {
		t.Errorf("existing visible: %q", d.text)
	}
	// A capture of several fields.
	d = secretDialog(i18n.Es, SecretRequest{Name: "A", Reason: "r", Field: 2, Fields: 3, Label: "Clave", Description: "la de producción", Stored: []string{"B", "C"}})
	mustContain(t, "multi-field text", d.text, "Campo:", "2 de 3 (Clave)", "Descripción:", "la de producción", "Ya guardados:", "B, C (no se vuelven a pedir)")
}

func TestHeadingDialogInSpanish(t *testing.T) {
	d := secretDialog(i18n.Es, SecretRequest{Heading: "Código de confirmación", Reason: "escribe el código"})
	if d.heading != "Código de confirmación" || d.text != "escribe el código" || d.okLabel != "Continuar" || d.cancelLabel != "Cancelar" {
		t.Errorf("%+v", d)
	}
}

func TestFormDialogInSpanish(t *testing.T) {
	d := formDialog(i18n.Es, formReqs)
	if d.heading != "Solicitud de secreto" || d.okLabel != "Guardar" || d.cancelLabel != "Cancelar" {
		t.Errorf("%q %q %q", d.heading, d.okLabel, d.cancelLabel)
	}
	if d.fields[0].label != "Host (se muestra mientras escribes)" || d.fields[1].label != "Password (oculto)" {
		t.Errorf("labels: %q, %q", d.fields[0].label, d.fields[1].label)
	}
	mustContain(t, "text", d.text, "Completa cada campo. El agente nunca ve lo que escribes:", "DB_HOST, DB_PASSWORD", "proyecto shop-api")
	mustNotContain(t, "text", d.text, "Valor:") // no Value line in a form
}

func TestChooseAndConfirmInSpanish(t *testing.T) {
	perm := []string{"Una vez (once): solo el siguiente comando", "No permitir"}
	d := chooseDialog(i18n.Es, "Claude Code quiere usar GITHUB_TOKEN (proyecto shop-api).\nMotivo: x", perm, 1)
	if d.heading != "Solicitud de permiso" || d.okLabel != "Continuar" || d.cancelLabel != "Cancelar" || d.def != 1 {
		t.Errorf("permission: %+v", d)
	}
	if d := chooseDialog(i18n.Es, "¿Dónde se debe guardar A?", []string{"Todos los proyectos", "Solo este proyecto (shop)"}, 0); d.heading != "" {
		t.Errorf("a layer question is not a permission request: %q", d.heading)
	}
	// The markers of one language do not decide in the other.
	if chooseDialog(i18n.En, "q", []string{"No permitir"}, 0).heading != "" {
		t.Error("a Spanish option made an English permission heading")
	}
	if chooseDialog(i18n.Es, "q", []string{"Don't allow"}, 0).heading != "" {
		t.Error("an English option made a Spanish permission heading")
	}
	c := confirmDialog(i18n.Es, "¿Eliminar A (todos los proyectos)?")
	if c.heading != "Confirmar" || c.okLabel != "Confirmar" || c.cancelLabel != "Rechazar" || !c.removal() {
		t.Errorf("confirm: %+v removal=%v", c, c.removal())
	}
	if confirmDialog(i18n.Es, "¿Usar los secretos del proyecto shop en /x?").removal() {
		t.Error("a link question is not a removal")
	}
	if !confirmDialog(i18n.Es, "¿Borrar el archivo?").removal() || !confirmDialog(i18n.En, "Delete it?").removal() {
		t.Error("delete is a removal in both languages")
	}
}

func TestPassphraseAndShowInSpanish(t *testing.T) {
	v := passphraseDialog(i18n.Es, VaultPassphrase, false)
	if v.heading != "Frase de contraseña de la bóveda" || v.text != "Frase de contraseña de la bóveda:" || v.okLabel != "Continuar" {
		t.Errorf("vault: %q %q", v.heading, v.text)
	}
	if a := passphraseDialog(i18n.Es, VaultPassphrase.Twice(), true); a.text != "Escribe la frase de contraseña de nuevo:" {
		t.Errorf("again: %q", a.text)
	}
	if e := passphraseDialog(i18n.Es, ExportPassphrase, true); e.text != "Escribe de nuevo la frase de contraseña de exportación:" {
		t.Errorf("export again: %q", e.text)
	}
	if i := passphraseDialog(i18n.Es, ImportPassphrase, false); i.heading != "Frase de contraseña de exportación" || i.text != "Frase de contraseña del archivo de exportación:" {
		t.Errorf("import: %q %q", i.heading, i.text)
	}
	r := VaultPassphrase
	r.Reason = "Claude Code quiere usar A. Desbloquea la bóveda para continuar."
	if d := passphraseDialog(i18n.Es, r, false); !strings.HasPrefix(d.text, r.Reason+"\n\n") {
		t.Errorf("reason: %q", d.text)
	}
	if d := retryDialog(i18n.Es, VaultPassphrase); !strings.HasPrefix(d.text, "Las frases de contraseña no coinciden. Inténtalo de nuevo.\n\n") {
		t.Errorf("retry: %q", d.text)
	}
	// A passphrase of the caller's own keeps its text and gets the catalogue's second question.
	custom := PassphraseRequest{Label: "Mi frase", Confirm: true}
	if d := passphraseDialog(i18n.Es, custom, true); d.text != "Escribe la frase de contraseña de nuevo:" {
		t.Errorf("custom again: %q", d.text)
	}
	s := showDialog(i18n.Es, "Clave de recuperación", "Anótala.\n\nQVR1-X")
	if s.okLabel != "Hecho" || s.cancelLabel != "Cancelar" || s.heading != "Clave de recuperación" {
		t.Errorf("show: %+v", s)
	}
}

func TestRequesterInSpanish(t *testing.T) {
	tests := []struct{ host, session, want string }{
		{"", "", "un agente"}, {"mcp", "", "tu agente"}, {"cli", "cli:x", "tú (qbit-vault)"},
		{"claude-code", "claude-code:abcdefghij", "Claude Code (sesión abcdefgh)"}, {"codex", "", "Codex"}, {"pi", "pi:s-1234", "Pi (sesión s-1234)"},
		{"my-host", "", "my-host"},
	}
	for _, tt := range tests {
		if got := RequesterIn(i18n.Es, tt.host, tt.session); got != tt.want {
			t.Errorf("RequesterIn(es, %q, %q) = %q, want %q", tt.host, tt.session, got, tt.want)
		}
	}
	// The audit text is English whatever the dialog language.
	if got := Requester("cli", ""); got != "you (qbit-vault)" {
		t.Errorf("Requester = %q", got)
	}
}

// Spanish text goes through every helper: accents, inverted marks and
// markup-looking text arrive intact, in a script that stays ASCII.
func TestSpanishThroughEveryBackend(t *testing.T) {
	const q = "¿Eliminar A (todos los proyectos)?\n¡Atención! año <b>ñ</b> & \"co\""
	cd := confirmDialog(i18n.Es, q)
	sd := secretDialog(i18n.Es, reqEs)
	ch := chooseDialog(i18n.Es, "¿Dónde?", []string{"Todos los proyectos", "Solo este proyecto (shop)"}, 0)

	for _, d := range []dialog{sd, cd, ch, formDialog(i18n.Es, formReqs), showDialog(i18n.Es, "Clave", "Anótala.\n\nQVR1-X")} {
		var script string
		if d.kind == dialogForm {
			script = string(powershellTool{}.buildForm("powershell.exe", d).Stdin)
		} else {
			script = string(powershellTool{}.build("powershell.exe", d).Stdin)
		}
		for _, b := range []byte(script) {
			if b >= 0x80 || (b < 0x20 && b != '\n' && b != '\r' && b != '\t') {
				t.Fatalf("byte %#x in a Spanish PowerShell script", b)
			}
		}
		mustContain(t, "PowerShell script", script, "$okLabel = Dec "+psString(d.okLabel), "$cancelLabel = Dec "+psString(d.cancelLabel))
	}
	ps := string(powershellTool{}.build("powershell.exe", cd).Stdin)
	mustContain(t, "confirm script", ps, psString(cd.text), psString("Confirmar"), psString("Rechazar"))

	// osascript: the buttons are the Spanish ones, the text keeps ¿ ¡ and accents.
	osa := string(osascriptTool{}.build("osascript", cd).Stdin)
	mustContain(t, "osascript", osa, `buttons {"Rechazar", "Confirmar"} default button "Rechazar" cancel button "Rechazar" with icon caution`, "¿Eliminar A", "¡Atención!", "año")
	mustNotContain(t, "osascript", osa, `"Decline"`, `"Confirm"`)
	if o := string(osascriptTool{}.build("osascript", sd).Stdin); !strings.Contains(o, `buttons {"Cancelar", "Guardar"} default button "Guardar" cancel button "Cancelar"`) {
		t.Errorf("osascript secret buttons: %s", o)
	}

	// kdialog: the confirmation list offers the Spanish choices, in the same order.
	kd := kdialogTool{}.build("kdialog", cd).Args
	if !contains(kd, "Rechazar") || !contains(kd, "Confirmar") || contains(kd, "Decline") || contains(kd, "Confirm") {
		t.Fatalf("kdialog confirm list: %q", kd)
	}
	i, j := indexOf(kd, "Rechazar"), indexOf(kd, "Confirmar")
	if kd[i-1] != "1" || kd[i+1] != "on" || kd[j-1] != "2" || kd[j+1] != "off" {
		t.Errorf("kdialog list order: %q", kd)
	}
	// A Confirmar answer confirms, a Rechazar answer declines.
	if (kdialogTool{}).classify(cd, result{Exit: 0, Stdout: []byte("2\n")}) != statusOK || (kdialogTool{}).classify(cd, result{Exit: 0, Stdout: []byte("1\n")}) != statusNo {
		t.Error("kdialog classify")
	}

	// zenity: the buttons.
	zn := zenityTool{}.build("zenity", cd).Args
	if !contains(zn, "--ok-label=Confirmar") || !contains(zn, "--cancel-label=Rechazar") {
		t.Errorf("zenity confirm buttons: %q", zn)
	}
	zs := zenityTool{}.build("zenity", sd).Args
	if !contains(zs, "--ok-label=Guardar") || !contains(zs, "--cancel-label=Cancelar") {
		t.Errorf("zenity secret buttons: %q", zs)
	}
}

func TestRevealToggleInSpanish(t *testing.T) {
	s := psScript(secretDialog(i18n.Es, reqEs))
	mustContain(t, "secret script", s,
		"$tShow = Dec "+psString("Mostrar"), "$tHide = Dec "+psString("Ocultar"),
		"$tShowValue = Dec "+psString("Mostrar valor"), "$tHideValue = Dec "+psString("Ocultar valor"))
	mustNotContain(t, "secret script", s, "'Show'", "'Hide'", "Show value")
	// The longer labels get a wider button; the box gives up the same width.
	mustContain(t, "secret script", s, "Size(76, 26)", "$box.Width = $w - 82")
	mustNotContain(t, "secret script", s, "Size(60, 26)", "$w - 66")
	mustContain(t, "English script", psScript(secretDialog(i18n.En, reqEs)), "Size(60, 26)", "$box.Width = $w - 66")
	f := psFormScript(formDialog(i18n.Es, formReqs))
	mustContain(t, "form script", f, "$tShow = Dec "+psString("Mostrar"))
	// A visible field has no toggle, so no label either.
	mustNotContain(t, "visible script", psScript(secretDialog(i18n.Es, SecretRequest{Name: "A", Reason: "r", Visible: true})), "$tShow")
}

func TestTerminalBackendInSpanish(t *testing.T) {
	b, term := backendOf("TESTSECRET_x")
	if _, err := BindLocale(b, i18n.Es).Secret(reqEs); err != nil {
		t.Fatal(err)
	}
	out := term.out.String()
	mustContain(t, "terminal secret", out, "QBit Vault: solicitud de secreto", "Quién:", "Motivo:", "ejecutar el release de <shop> & co", "Valor (oculto): ")
	mustNotContain(t, "terminal secret", out, "Who:", "(hidden)")

	b, term = backendOf("TESTSECRET_x")
	if _, err := BindLocale(b, i18n.Es).Secret(SecretRequest{Name: "A", Visible: true, Heading: "Código", Reason: "escribe el código"}); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "terminal heading", term.out.String(), "QBit Vault: Código", "Respuesta (se muestra mientras escribes): ")

	b, term = backendOf("x", "9", "2")
	if i, err := BindLocale(b, i18n.Es).Choose("¿Cuál?", []string{"a", "b"}, 0); err != nil || i != 1 {
		t.Fatalf("choose = %d, %v", i, err)
	}
	mustContain(t, "terminal choice", term.out.String(), "Opción [1]: ", "Escribe un número del 1 al 2, o pulsa Intro para elegir la opción predeterminada.")

	// A yes is a yes in Spanish too; in English only y and yes.
	for _, tt := range []struct {
		loc    i18n.Locale
		answer string
		want   bool
	}{{i18n.Es, "s", true}, {i18n.Es, "Sí", true}, {i18n.Es, "si", true}, {i18n.Es, "y", true}, {i18n.Es, "n", false}, {i18n.Es, "", false}, {i18n.Es, "no", false},
		{i18n.En, "y", true}, {i18n.En, "yes", true}, {i18n.En, "s", false}, {i18n.En, "sí", false}} {
		b, _ = backendOf(tt.answer)
		got, err := BindLocale(b, tt.loc).Confirm("¿Seguro?")
		if err != nil || got != tt.want {
			t.Errorf("%s %q: %v, %v", tt.loc, tt.answer, got, err)
		}
	}
	b, term = backendOf("n")
	_, _ = BindLocale(b, i18n.Es).Confirm("¿Seguro?")
	mustContain(t, "terminal confirm", term.out.String(), "¿Seguro? [s/N] ")

	// Passphrase mismatch in Spanish.
	b, term = backendOf("aaa", "bbb", "ccc", "ccc")
	if _, err := BindLocale(b, i18n.Es).Passphrase(VaultPassphrase.Twice()); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "terminal passphrase", term.out.String(), "Frase de contraseña de la bóveda: ", "Escribe la frase de contraseña de nuevo: ", "Las frases de contraseña no coinciden.")

	// Show.
	b, term = backendOf("")
	if err := BindLocale(b, i18n.Es).(Shower).Show("Clave de recuperación", "Anótala.\n\nQVR1-X"); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "terminal show", term.out.String(), "QBit Vault: Clave de recuperación", "Pulsa Intro al terminar. ")
}

func TestNativeBackendDrivesTheLocale(t *testing.T) {
	f := &fakeRun{res: []result{ok("1")}}
	b := BindLocale(nativeOf(zenityTool{}, f), i18n.Es)
	if _, err := b.Choose("¿Qué?", []string{"No permitir", "a"}, 0); err != nil {
		t.Fatal(err)
	}
	args := f.cmds[0].Args
	if !contains(args, "--ok-label=Continuar") || !contains(args, "--cancel-label=Cancelar") || !strings.Contains(strings.Join(args, "\n"), "Solicitud de permiso") {
		t.Errorf("zenity args: %q", args)
	}
	// BindLocale does not change the backend it was given.
	f2 := &fakeRun{res: []result{ok("1")}}
	orig := nativeOf(zenityTool{}, f2)
	_ = BindLocale(orig, i18n.Es)
	if _, err := orig.Choose("q", []string{"a", "b"}, 0); err != nil || !contains(f2.cmds[0].Args, "--ok-label=Continue") {
		t.Errorf("the unbound backend must stay English: %q, %v", f2.cmds[0].Args, err)
	}
	// Show falls back to the terminal for kdialog, in the same language.
	term := &memTerm{lines: []string{""}}
	n := nativeOf(kdialogTool{}, &fakeRun{}).(*native)
	n.open = func() (Terminal, error) { return term, nil }
	if err := BindLocale(n, i18n.Es).(Shower).Show("Clave", "x"); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "kdialog show fallback", term.out.String(), "Pulsa Intro al terminar. ")
}

func TestHeaderInEnglishIsTheOldText(t *testing.T) {
	want := "QBit Vault: secret request\n  Who:      Claude Code (session sess-aaa)\n  Secret:   GITHUB_TOKEN\n  Why:      run the release\n  Saved in: project shop-api\n  Value:    new\n"
	if got := Header(req); got != want {
		t.Errorf("Header:\n%q\nwant\n%q", got, want)
	}
	if HeaderIn(i18n.Es, req) == want {
		t.Error("HeaderIn(es) is English")
	}
}

// Every option an agent question offers is recognised as a permission in its
// language, so the dialog gets its heading (and the warning icon of a removal
// follows the same words); a drifting translation fails here.
func TestPermissionAndRemovalMarkersCoverTheQuestions(t *testing.T) {
	for _, loc := range []i18n.Locale{i18n.En, i18n.Es} {
		for _, id := range []string{"opt.deny", "opt.save_only", "opt.replace_once", "opt.replace_ask", "opt.dont_replace"} {
			if !isPermission(loc, []string{loc.T(id)}) {
				t.Errorf("%s: %q (%q) is not recognised as a permission option", loc, id, loc.T(id))
			}
		}
		for _, id := range []string{"scope.once", "scope.project", "opt.layer_all", "opt.without", "opt.as_typed"} {
			if isPermission(loc, []string{loc.T(id, "x")}) {
				t.Errorf("%s: %q is taken for a permission option", loc, id)
			}
		}
		for _, q := range []string{loc.T("q.remove", "A", "x"), loc.T("q.delete_dotenv"), loc.T("q.manage", "Pi", loc.T("what.remove", "A", "x"), "r")} {
			if !confirmDialog(loc, q).removal() {
				t.Errorf("%s: %q is not recognised as a removal", loc, q)
			}
		}
		for _, q := range []string{loc.T("q.link", "p", "/x"), loc.T("q.update", "1", "2"), loc.T("q.restore", "b"), loc.T("q.manage", "Pi", loc.T("what.replace", "A", "x"), "r"), loc.T("q.overwrite", "A", "x")} {
			if confirmDialog(loc, q).removal() {
				t.Errorf("%s: %q is taken for a removal", loc, q)
			}
		}
	}
}
