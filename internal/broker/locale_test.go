package broker

import (
	"encoding/json"
	"strings"
	"testing"
)

// Each op that can open a dialog takes an optional locale.
var localeOps = map[string]string{
	"request": `"name":"A","reason":"run the db migration now"`,
	"list":    ``,
	"exec":    `"command":"x","secrets":[{"name":"A"}]`,
	"manage":  `"action":"remove","name":"A","layer":"global","reason":"three word reason"`,
	"check":   `"names":["A"]`,
}

func withLocale(extra, locale string) string {
	loc := `"locale":` + locale
	if extra == "" {
		return loc
	}
	return extra + "," + loc
}

func TestLocaleReachesTheBackendOfEveryDialogOp(t *testing.T) {
	for op, extra := range localeOps {
		f := &fake{}
		call(t, f, TransportModel, env(op, withLocale(extra, `"es-ES"`)))
		if len(f.calls) != 1 || f.env.Locale != "es-ES" {
			t.Errorf("%s: calls=%v locale=%q", op, f.calls, f.env.Locale)
		}
		// Absent means empty: the backend falls back on its own.
		f = &fake{}
		call(t, f, TransportModel, env(op, extra))
		if len(f.calls) != 1 || f.env.Locale != "" {
			t.Errorf("%s without locale: calls=%v locale=%q", op, f.calls, f.env.Locale)
		}
	}
}

func TestLocaleWithAnyStringIsAccepted(t *testing.T) {
	// An unknown, malformed or overlong tag is the backend's to ignore: the
	// broker neither refuses nor echoes it.
	long, _ := json.Marshal(strings.Repeat("x", 5000))
	for _, loc := range []string{`"fr-FR"`, `""`, `"not a locale!"`, `"TESTSECRET_locale"`, `"es\u0000"`, string(long)} {
		f := &fake{}
		out := Handle(t.Context(), []byte(env("exec", withLocale(localeOps["exec"], loc))), f, TransportModel)
		if len(f.calls) != 1 {
			t.Errorf("%.20s: not handled: %s", loc, out)
		}
		if strings.Contains(string(out), "TESTSECRET_") || strings.Contains(string(out), "not a locale") {
			t.Errorf("response echoes the locale: %s", out)
		}
	}
}

func TestLocaleOfTheWrongTypeIsRefused(t *testing.T) {
	for op, extra := range localeOps {
		for _, bad := range []string{`1`, `true`, `null`, `["es"]`, `{"a":1}`, `1.5`} {
			f := &fake{}
			typ, msg := refusalOf(t, call(t, f, TransportModel, env(op, withLocale(extra, bad))))
			if typ != "internal" || msg != "invalid request: locale" || len(f.calls) != 0 {
				t.Errorf("%s locale=%s: %s %q calls=%v", op, bad, typ, msg, f.calls)
			}
		}
	}
	// The hint is the usual one for a bad request.
	m := call(t, &fake{}, TransportModel, env("list", `"locale":3`))
	if m["refusal"].(map[string]any)["hint"] == nil {
		t.Errorf("no hint: %v", m)
	}
}

func TestLocaleIsNotAFieldOfTheOtherOps(t *testing.T) {
	for op, extra := range map[string]string{
		"grant":        `"name":"A","layer":"global","scope":"once","prompt_token":"0123456789abcdef"`,
		"revoke":       `"all":true`,
		"capabilities": ``,
	} {
		typ, msg := refusalOf(t, call(t, &fake{}, TransportHost, env(op, withLocale(extra, `"es"`))))
		if typ != "internal" || msg != "invalid request: unknown field" {
			t.Errorf("%s: %s %q", op, typ, msg)
		}
	}
}

func TestCapabilitiesAdvertiseDialogLocale(t *testing.T) {
	m := call(t, &fake{}, TransportHost, env("capabilities", ""))
	if m["dialog_locale"] != float64(1) || m["capabilities"] != "1.1" {
		t.Errorf("dialog_locale=%v capabilities=%v", m["dialog_locale"], m["capabilities"])
	}
}
