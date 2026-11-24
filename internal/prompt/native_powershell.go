package prompt

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/qbitdevz/qbit-vault/internal/prompt/i18n"
)

// powershellTool shows a WinForms dialog (L4). The script goes to
// powershell.exe on stdin; the request text is in it only as base64 data
// that the script decodes, so no character of it can end a literal or start
// a command. Exit codes: 0 answered, 2 cancelled, anything else a failure.
type powershellTool struct{}

func (powershellTool) name() string    { return "powershell" }
func (powershellTool) program() string { return "powershell.exe" }

// psExitCancel is the exit code of a dialog the user closed or declined.
const psExitCancel = 2

func (powershellTool) classify(_ dialog, r result) status {
	switch r.Exit {
	case 0:
		return statusOK
	case psExitCancel:
		return statusCancel
	}
	return statusFail
}

func (powershellTool) build(path string, d dialog) command {
	return psCommand(path, psScript(d))
}

// psCommand runs script, read from stdin, in a single-threaded apartment.
func psCommand(path, script string) command {
	return command{
		Path:  path,
		Args:  []string{"-NoProfile", "-NonInteractive", "-STA", "-Command", "-"},
		Stdin: []byte(script),
	}
}

// Every statement of the script sits on one line: powershell.exe reads
// "-Command -" from stdin line by line and silently drops what follows a
// statement that spans lines (a for loop with a body on its own lines).

// psString is a PowerShell single-quoted literal for s: its base64, which has
// no quote, backslash, dollar, backtick, newline or non-ASCII character. The
// script turns it back into text with Dec.
func psString(s string) string {
	return "'" + base64.StdEncoding.EncodeToString([]byte(s)) + "'"
}

// psBodyMarker separates the data lines of a script from its fixed body.
const psBodyMarker = "# ---- body ----"

// psPrelude is the data half of the script: everything that comes from the
// request, as variables.
func psPrelude(d dialog) string {
	okLabel, cancelLabel := d.buttons()
	opts := make([]string, len(d.options))
	for i, o := range d.options {
		opts[i] = "(Dec " + psString(o) + ")"
	}
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\n")
	b.WriteString("function Dec($s) { [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($s)) }\n")
	fmt.Fprintf(&b, "$title = Dec %s\n", psString(d.title))
	fmt.Fprintf(&b, "$heading = Dec %s\n", psString(d.heading))
	switch {
	case d.kind == dialogShow:
		intro, code := splitShown(d.text)
		fmt.Fprintf(&b, "$text = Dec %s\n", psString(intro))
		fmt.Fprintf(&b, "$code = Dec %s\n", psString(code))
	case len(d.rows) > 0:
		// The request lines go in a grid, the question under it.
		fmt.Fprintf(&b, "$text = Dec %s\n", psString(d.tail))
	default:
		fmt.Fprintf(&b, "$text = Dec %s\n", psString(d.text))
	}
	cells := make([]string, 0, 2*len(d.rows))
	for _, r := range d.rows {
		cells = append(cells, "(Dec "+psString(r.label+":")+")", "(Dec "+psString(r.value)+")")
	}
	fmt.Fprintf(&b, "$rows = @(%s)\n", strings.Join(cells, ", "))
	fmt.Fprintf(&b, "$confirm = $%t\n", d.kind == dialogConfirm)
	fmt.Fprintf(&b, "$okLabel = Dec %s\n", psString(okLabel))
	fmt.Fprintf(&b, "$cancelLabel = Dec %s\n", psString(cancelLabel))
	fmt.Fprintf(&b, "$opts = @(%s)\n", strings.Join(opts, ", "))
	fmt.Fprintf(&b, "$def = %d\n", d.def)
	fmt.Fprintf(&b, "$hide = $%t\n", !d.visible)
	return b.String()
}

func psScript(d dialog) string {
	var b strings.Builder
	b.WriteString(psPrelude(d))
	b.WriteString(psBodyMarker + "\n")
	b.WriteString(psFormTop)
	accept := "$ok"
	switch d.kind {
	case dialogSecret:
		if d.visible {
			b.WriteString(psSecretInput + "$p.Controls.Add($tb)\n")
		} else {
			b.WriteString(psEye(d.loc) + psSecretInput + "AddInput $tb 520 $hide\n")
		}
		b.WriteString("$first = $tb\n")
	case dialogChoose:
		b.WriteString(psChooseInput)
	case dialogShow:
		b.WriteString(psShowText)
	case dialogConfirm:
		accept = "$no" // Enter declines
	}
	b.WriteString(psButtons)
	fmt.Fprintf(&b, "$f.AcceptButton = %s\n", accept)
	if d.kind == dialogSecret {
		b.WriteString("$f.Add_Shown({ $this.Activate(); $tb.Focus() | Out-Null })\n")
	} else {
		b.WriteString("$f.Add_Shown({ $this.Activate() })\n")
	}
	b.WriteString(psShow)
	switch d.kind {
	case dialogSecret:
		b.WriteString(psSecretOutput)
	case dialogChoose:
		b.WriteString(psChooseOutput)
	}
	b.WriteString("exit 0\n")
	return b.String()
}

// The dialog is TopMost so it cannot hide behind the agent's window; labels
// do not treat & as an accelerator, so a name with & is shown as written.
// Colors are the design system's (design/system.md): deep background, frost
// text, blue-glow heading, qubit-blue primary button, line borders.
const psFormTop = `Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
function Col($h) { [System.Drawing.ColorTranslator]::FromHtml($h) }
$f = New-Object System.Windows.Forms.Form
$f.Text = $title
$f.TopMost = $true
$f.StartPosition = 'CenterScreen'
$f.FormBorderStyle = 'FixedDialog'
$f.MinimizeBox = $true
$f.MaximizeBox = $false
$f.AutoSize = $true
$f.AutoSizeMode = 'GrowAndShrink'
$f.BackColor = Col '#07121B'
$f.ForeColor = Col '#C7D9DE'
$f.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$first = $null
$global:wasMin = $false
$f.Add_Resize({ if ($this.WindowState -eq [System.Windows.Forms.FormWindowState]::Minimized) { $global:wasMin = $true } elseif ($global:wasMin) { $global:wasMin = $false; $this.TopMost = $true; $this.Activate(); if ($null -ne $first) { $first.Focus() | Out-Null } } })
$p = New-Object System.Windows.Forms.FlowLayoutPanel
$p.FlowDirection = 'TopDown'
$p.WrapContents = $false
$p.AutoSize = $true
$p.Padding = New-Object System.Windows.Forms.Padding(20, 16, 20, 16)
$h = New-Object System.Windows.Forms.Label
$h.UseMnemonic = $false
$h.AutoSize = $true
$h.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 12)
$h.ForeColor = Col '#7FD0EC'
$h.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 10)
$h.Text = $heading
if ($heading.Length -gt 0) { $p.Controls.Add($h) }
$g = New-Object System.Windows.Forms.TableLayoutPanel
$g.AutoSize = $true
$g.ColumnCount = 2
$g.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 12)
for ($i = 0; $i -lt $rows.Count; $i += 2) { $a = New-Object System.Windows.Forms.Label; $a.UseMnemonic = $false; $a.AutoSize = $true; $a.ForeColor = Col '#8FA7B2'; $a.Margin = New-Object System.Windows.Forms.Padding(0, 3, 18, 3); $a.Text = $rows[$i]; $v = New-Object System.Windows.Forms.Label; $v.UseMnemonic = $false; $v.AutoSize = $true; $v.MaximumSize = New-Object System.Drawing.Size(420, 0); $v.Margin = New-Object System.Windows.Forms.Padding(0, 3, 0, 3); $v.Text = $rows[$i + 1]; $g.Controls.Add($a, 0, [int]($i / 2)); $g.Controls.Add($v, 1, [int]($i / 2)) }
if ($rows.Count -gt 0) { $p.Controls.Add($g) }
$l = New-Object System.Windows.Forms.Label
$l.UseMnemonic = $false
$l.AutoSize = $true
$l.MaximumSize = New-Object System.Drawing.Size(520, 0)
$l.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 12)
$l.Text = $text
$p.Controls.Add($l)
`

const psSecretInput = `$tb = New-Object System.Windows.Forms.TextBox
$tb.UseSystemPasswordChar = $hide
$tb.Width = 520
$tb.BorderStyle = 'FixedSingle'
$tb.BackColor = Col '#000204'
$tb.ForeColor = Col '#C7D9DE'
$tb.Font = New-Object System.Drawing.Font('Consolas', 11)
$tb.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 12)
$tb.MaxLength = 70000
`

// The minimize box (S4): a minimized dialog stays in the taskbar, and when it
// is restored it comes back in front (TopMost) with the input focused. The
// prompt timeout is the Go side's and still ends it. The handler only acts on
// a restore, not on the first show.

// psEye (S5) defines AddInput: a masked input gets a toggle button to its
// right that shows the typed value while it is switched on; a visible one is
// added as it was. The button is a normal tab stop (Space toggles it), is not
// the AcceptButton, never takes the initial focus, starts off (masked), and
// has an accessible name that follows its state. It only flips
// UseSystemPasswordChar on the box: the value goes nowhere else. The labels
// come from the catalogue, as base64 data like every other text of the script.
const psEyeCode = `$eyes = @()
function AddInput($box, $w, $masked) { if (-not $masked) { $box.Width = $w; $p.Controls.Add($box); return }; $c = New-Object System.Windows.Forms.CheckBox; $c.Appearance = 'Button'; $c.FlatStyle = 'Flat'; $c.FlatAppearance.BorderColor = Col '#16303D'; $c.FlatAppearance.CheckedBackColor = Col '#16303D'; $c.AutoSize = $false; $c.Size = New-Object System.Drawing.Size(60, 26); $c.TextAlign = 'MiddleCenter'; $c.Margin = New-Object System.Windows.Forms.Padding(0); $c.BackColor = Col '#07121B'; $c.ForeColor = Col '#C7D9DE'; $c.UseMnemonic = $false; $c.Text = $tShow; $c.AccessibleName = $tShowValue; $c.Checked = $false; $c.Add_CheckedChanged({ $box.UseSystemPasswordChar = -not $this.Checked; if ($this.Checked) { $this.Text = $tHide; $this.AccessibleName = $tHideValue } else { $this.Text = $tShow; $this.AccessibleName = $tShowValue } }.GetNewClosure()); $box.Width = $w - 66; $m = $box.Margin; $box.Margin = New-Object System.Windows.Forms.Padding(0, 0, 6, 0); $row = New-Object System.Windows.Forms.FlowLayoutPanel; $row.FlowDirection = 'LeftToRight'; $row.WrapContents = $false; $row.AutoSize = $true; $row.Margin = $m; $row.Controls.Add($box); $row.Controls.Add($c); $p.Controls.Add($row); $global:eyes += $c }
`

// psShowText puts the code of a show dialog (a recovery key, a pairing code)
// in a read-only text box so it can be selected and copied rather than typed
// by hand; the explanation stays in the label above it. The box is as tall as
// the wrapped code measures, so no part of it is cut off; past 320 px it
// scrolls.
const psShowText = `if ($text.Length -eq 0) { $p.Controls.Remove($l) }
$sel = New-Object System.Windows.Forms.TextBox
$sel.Multiline = $true
$sel.ReadOnly = $true
$sel.WordWrap = $true
$sel.ScrollBars = 'None'
$sel.Width = 520
$sel.BorderStyle = 'FixedSingle'
$sel.BackColor = Col '#000204'
$sel.ForeColor = Col '#C7D9DE'
$sel.Font = New-Object System.Drawing.Font('Consolas', 11)
$sel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 12)
$sel.Text = $code.Replace([string][char]10, [System.Environment]::NewLine)
$mw = New-Object System.Drawing.Size(496, 100000)
$mf = [System.Windows.Forms.TextFormatFlags]::WordBreak -bor [System.Windows.Forms.TextFormatFlags]::NoPadding
$mh = [System.Windows.Forms.TextRenderer]::MeasureText($sel.Text, $sel.Font, $mw, $mf).Height
$sel.Height = [Math]::Min(320, $mh + 24)
if ($mh + 24 -gt 320) { $sel.ScrollBars = 'Vertical' }
$sel.SelectionStart = 0
$p.Controls.Add($sel)
`

const psChooseInput = `$radios = @()
for ($i = 0; $i -lt $opts.Count; $i++) { $r = New-Object System.Windows.Forms.RadioButton; $r.UseMnemonic = $false; $r.AutoSize = $true; $r.MaximumSize = New-Object System.Drawing.Size(520, 0); $r.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 6); $r.Text = $opts[$i]; $r.Checked = ($i -eq $def); $p.Controls.Add($r); $radios += $r }
`

const psButtons = `$bp = New-Object System.Windows.Forms.FlowLayoutPanel
$bp.FlowDirection = 'LeftToRight'
$bp.AutoSize = $true
$bp.Anchor = 'Right'
$bp.Margin = New-Object System.Windows.Forms.Padding(0, 6, 0, 0)
$ok = New-Object System.Windows.Forms.Button
$ok.Text = $okLabel
$ok.AutoSize = $true
$ok.MinimumSize = New-Object System.Drawing.Size(104, 34)
$ok.FlatStyle = 'Flat'
$ok.FlatAppearance.BorderSize = 0
$ok.BackColor = Col '#2E9BE0'
$ok.ForeColor = Col '#FFFFFF'
$ok.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 10)
$ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
$no = New-Object System.Windows.Forms.Button
$no.Text = $cancelLabel
$no.AutoSize = $true
$no.MinimumSize = New-Object System.Drawing.Size(104, 34)
$no.FlatStyle = 'Flat'
$no.FlatAppearance.BorderColor = Col '#16303D'
$no.BackColor = Col '#07121B'
$no.ForeColor = Col '#C7D9DE'
$no.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$bp.Controls.Add($ok)
$bp.Controls.Add($no)
$p.Controls.Add($bp)
$f.Controls.Add($p)
$f.CancelButton = $no
if ($confirm) { $no.FlatAppearance.BorderSize = 0; $no.BackColor = Col '#2E9BE0'; $no.ForeColor = Col '#FFFFFF'; $no.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 10); $ok.FlatAppearance.BorderSize = 1; $ok.FlatAppearance.BorderColor = Col '#16303D'; $ok.BackColor = Col '#07121B'; $ok.ForeColor = Col '#C7D9DE'; $ok.Font = $f.Font }
`

const psShow = `if ($f.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { exit 2 }
`

// The value leaves as UTF-8 bytes on the process's stdout, the private pipe
// to the broker; Console.Out would apply the console code page.
const psSecretOutput = `$bytes = [System.Text.Encoding]::UTF8.GetBytes($tb.Text)
$out = [System.Console]::OpenStandardOutput()
$out.Write($bytes, 0, $bytes.Length)
$out.Flush()
`

const psChooseOutput = `for ($i = 0; $i -lt $radios.Count; $i++) { if ($radios[$i].Checked) { [System.Console]::Out.Write([string]($i + 1)) } }
`

// psEye is the toggle code with its four labels in loc, set as variables
// first: base64 data decoded by the script, so a label of any language
// travels as ASCII.
func psEye(loc i18n.Locale) string {
	var b strings.Builder
	fmt.Fprintf(&b, "$tShow = Dec %s\n", psString(loc.T("eye.show")))
	fmt.Fprintf(&b, "$tHide = Dec %s\n", psString(loc.T("eye.hide")))
	fmt.Fprintf(&b, "$tShowValue = Dec %s\n", psString(loc.T("eye.show_value")))
	fmt.Fprintf(&b, "$tHideValue = Dec %s\n", psString(loc.T("eye.hide_value")))
	// The button is as wide as its longest label needs: the box gives up the
	// same width, so the row keeps the width of the input it replaces.
	w := 60
	if n, err := strconv.Atoi(loc.T("eye.width")); err == nil && n >= 60 && n <= 120 {
		w = n
	}
	code := strings.Replace(psEyeCode, "Size(60, 26)", fmt.Sprintf("Size(%d, 26)", w), 1)
	code = strings.Replace(code, "$box.Width = $w - 66", fmt.Sprintf("$box.Width = $w - %d", w+6), 1)
	return b.String() + code
}
