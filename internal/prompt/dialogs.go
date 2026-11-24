package prompt

import (
	"fmt"
	"strings"

	"github.com/qbitdevz/qbit-vault/internal/prompt/i18n"
)

// dialogTitle is the window title of every native dialog; the heading inside
// says what it is. It is the product name, the same in every language.
const dialogTitle = "QBit Vault"

// secretDialog is the capture dialog: the request as headerRows lays it out.
func secretDialog(loc i18n.Locale, req SecretRequest) dialog {
	if req.Heading != "" {
		return dialog{kind: dialogSecret, title: dialogTitle, heading: escape(req.Heading), text: escape(req.Reason), visible: req.Visible, okLabel: loc.T("btn.continue"), cancelLabel: loc.T("btn.cancel"), loc: loc}
	}
	rows := headerRows(loc, req, true)
	input := loc.T("input.hidden")
	if req.Visible {
		input = loc.T("input.visible")
	}
	return dialog{
		kind:        dialogSecret,
		title:       dialogTitle,
		heading:     loc.T("heading.request"),
		rows:        rows,
		tail:        input,
		text:        rowsText(rows) + "\n" + input,
		visible:     req.Visible,
		okLabel:     loc.T("btn.save"),
		cancelLabel: loc.T("btn.cancel"),
		loc:         loc,
	}
}

// passphraseDialog asks one entry of a passphrase: the first, or the second
// when again.
func passphraseDialog(loc i18n.Locale, req PassphraseRequest, again bool) dialog {
	heading, label, second := req.texts(loc)
	text := label + ":"
	if again {
		text = second + ":"
	} else if req.Reason != "" {
		text = escapeLines(req.Reason) + "\n\n" + text
	}
	return dialog{kind: dialogSecret, title: dialogTitle, heading: heading, text: text, okLabel: loc.T("btn.continue"), cancelLabel: loc.T("btn.cancel"), loc: loc}
}

// chooseDialog is a question with options. A question about letting an agent
// use a secret is a permission request; any other has no heading, the
// question says it all.
func chooseDialog(loc i18n.Locale, q string, options []string, def int) dialog {
	opts := make([]string, len(options))
	for i, o := range options {
		opts[i] = escape(o)
	}
	heading := ""
	if isPermission(loc, options) {
		heading = loc.T("heading.permission")
	}
	return dialog{kind: dialogChoose, title: dialogTitle, heading: heading, text: escapeLines(q), options: opts, def: def, okLabel: loc.T("btn.continue"), cancelLabel: loc.T("btn.cancel"), loc: loc}
}

// isPermission reports whether the options answer a permission question: one
// of them refuses or defers the permission.
func isPermission(loc i18n.Locale, options []string) bool {
	prefix, a, b := loc.T("mark.perm_prefix"), loc.T("mark.perm_a"), loc.T("mark.perm_b")
	for _, o := range options {
		l := strings.ToLower(o)
		if strings.HasPrefix(l, prefix) || strings.Contains(l, a) || strings.Contains(l, b) {
			return true
		}
	}
	return false
}

func confirmDialog(loc i18n.Locale, q string) dialog {
	return dialog{kind: dialogConfirm, title: dialogTitle, heading: loc.T("heading.confirm"), text: escapeLines(q), okLabel: loc.T("btn.confirm"), cancelLabel: loc.T("btn.decline"), loc: loc}
}

// noDash keeps a row of text from reading as an option to helpers that take
// rows as positional arguments.
func noDash(s string) string {
	if strings.HasPrefix(s, "-") {
		return " " + s
	}
	return s
}

// numbered is "N) text", how osascript lists show and return an option.
func numbered(i int, o string) string { return fmt.Sprintf("%d) %s", i+1, o) }

// plain is the text of a dialog for the helpers that have no heading of their
// own: the heading, a blank line and the text.
func (d dialog) plain() string {
	if d.heading == "" {
		return d.text
	}
	return d.heading + "\n\n" + d.text
}

// removal reports whether a confirmation is about taking something away: the
// one dialog that wears a warning icon.
func (d dialog) removal() bool {
	l := strings.ToLower(d.text)
	return d.kind == dialogConfirm && (strings.Contains(l, d.loc.T("mark.removal_a")) || strings.Contains(l, d.loc.T("mark.removal_b")))
}

// buttons are the labels of the accept and cancel buttons.
func (d dialog) buttons() (ok, cancel string) {
	ok, cancel = d.okLabel, d.cancelLabel
	if ok == "" {
		ok = d.loc.T("btn.ok")
		if d.kind == dialogConfirm {
			ok = d.loc.T("btn.confirm")
		}
	}
	if cancel == "" {
		cancel = d.loc.T("btn.cancel")
		if d.kind == dialogConfirm {
			cancel = d.loc.T("btn.decline")
		}
	}
	return ok, cancel
}

// retryDialog is the first entry of a passphrase asked again after a mismatch.
func retryDialog(loc i18n.Locale, req PassphraseRequest) dialog {
	d := passphraseDialog(loc, req, false)
	d.text = loc.T("pass.mismatch_retry") + "\n\n" + d.text
	return d
}
