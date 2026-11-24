package prompt

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/qbitdevz/qbit-vault/internal/prompt/i18n"
)

// Shower is a backend that can show text the user must read and keep, such
// as a recovery key or a pairing confirmation code (REMOTE_SYNC.md § 4).
// Show waits until the user acknowledges it; closing the dialog or Ctrl-C is
// ErrCancelled. The text never reaches a helper's argv (any local user can
// read a command line), stdout or stderr: a helper that takes its text only
// as arguments (kdialog) leaves it to the terminal.
type Shower interface {
	Show(title, text string) error
}

const dialogShow dialogKind = 101

// showDialog escapes every line of text and keeps the line breaks.
func showDialog(loc i18n.Locale, title, text string) dialog {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = escape(l)
	}
	return dialog{kind: dialogShow, title: dialogTitle, heading: escape(title), text: strings.Join(lines, "\n"), okLabel: loc.T("btn.done"), cancelLabel: loc.T("btn.cancel"), loc: loc}
}

// Show implements Shower.
func (n *native) Show(title, text string) error {
	d := showDialog(n.loc, title, text)
	var c command
	switch n.t.(type) {
	case zenityTool:
		ok, cancel := d.buttons()
		c = command{Path: n.path, Args: []string{"--text-info", "--title=" + d.title, "--width=480", "--height=280", "--ok-label=" + ok, "--cancel-label=" + cancel}, Stdin: []byte(d.plain())}
	case osascriptTool, powershellTool:
		c = n.t.build(n.path, d)
	default:
		// The helper takes its text only as arguments, which any local user
		// can read: the terminal shows it.
		return BindLocale(Bind(base(n.ctx), New(n.open, Timeout(n.timeout))), n.loc).(Shower).Show(title, text)
	}
	_, st, err := n.askWith(c, d)
	if err != nil {
		return err
	}
	if st != statusOK {
		return ErrCancelled
	}
	return nil
}

// Show implements Shower on the controlling terminal.
func (b *tty) Show(title, text string) error {
	d := showDialog(b.loc, title, text)
	return b.with(func(ctx context.Context, t Terminal) error {
		_, _ = fmt.Fprintf(t, "\n%s: %s\n\n%s\n\n%s", dialogTitle, d.heading, d.text, b.loc.T("tty.press_enter"))
		if _, err := t.ReadLine(ctx); err != nil {
			return readErr(err)
		}
		_, _ = io.WriteString(t, "\n")
		return nil
	})
}

// splitShown separates the explanation from the code in a shown text: the
// code is the last paragraph (after the last blank line); a text with one
// paragraph is all code.
func splitShown(text string) (intro, code string) {
	text = strings.TrimRight(text, "\n")
	i := strings.LastIndex(text, "\n\n")
	if i < 0 {
		return "", text
	}
	return strings.TrimRight(text[:i], "\n"), strings.TrimLeft(text[i:], "\n")
}
