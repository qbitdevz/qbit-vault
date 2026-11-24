package prompt

import (
	"strings"
	"testing"
)

// S4 and S5 (odd/tasks/issues-61-65-dialogs.md): the PowerShell dialog can be
// minimized and has a reveal toggle next to every masked input. The scripts
// are checked as text; the real form is probed by hand (docs/TESTING.md).

func psScripts() map[string]string {
	return map[string]string{
		"secret":     psScript(secretDialog(req)),
		"passphrase": psScript(passphraseDialog(PassphraseRequest{Label: "Passphrase"}, false)),
		"choose":     psScript(chooseDialog("q", []string{"a", "b"}, 0)),
		"confirm":    psScript(confirmDialog("q")),
		"show":       psScript(showDialog("t", "intro\n\ncode")),
		"form":       psFormScript(formDialog(formReqs)),
	}
}

func TestEveryPowerShellDialogCanBeMinimized(t *testing.T) {
	for name, s := range psScripts() {
		t.Run(name, func(t *testing.T) {
			if strings.Contains(s, "MinimizeBox = $false") || !strings.Contains(s, "$f.MinimizeBox = $true\n") {
				t.Error("minimize box is not enabled")
			}
			if strings.Contains(s, "ShowInTaskbar = $false") {
				t.Error("dialog left the taskbar")
			}
			// Restored: back in front, TopMost again, focus on the input.
			for _, must := range []string{"$f.Add_Resize(", "FormWindowState]::Minimized", "$this.TopMost = $true", "$this.Activate()", "$first.Focus()"} {
				if !strings.Contains(s, must) {
					t.Errorf("restore handler lacks %q", must)
				}
			}
		})
	}
}

func TestRevealToggleForMaskedSecretInput(t *testing.T) {
	for _, name := range []string{"secret", "passphrase"} {
		s := psScripts()[name]
		for _, must := range []string{"$hide = $true\n", "AddInput $tb 520 $hide", "System.Windows.Forms.CheckBox", "AccessibleName = 'Show value'", "UseSystemPasswordChar = -not $this.Checked", "$c.Checked = $false"} {
			if !strings.Contains(s, must) {
				t.Errorf("%s: script lacks %q", name, must)
			}
		}
	}
}

func TestNoRevealToggleForVisibleInput(t *testing.T) {
	s := psScript(secretDialog(textReq))
	for _, bad := range []string{"CheckBox", "AddInput", "AccessibleName", "$eyes"} {
		if strings.Contains(s, bad) {
			t.Errorf("visible field has toggle code %q", bad)
		}
	}
	if !strings.Contains(s, "$hide = $false\n") || !strings.Contains(s, "$tb.UseSystemPasswordChar = $hide") || !strings.Contains(s, "$p.Controls.Add($tb)") {
		t.Error("visible field behavior changed")
	}
	// Dialogs without an input have no toggle either.
	for _, name := range []string{"choose", "confirm", "show"} {
		if strings.Contains(psScripts()[name], "CheckBox") {
			t.Errorf("%s has a toggle", name)
		}
	}
}

func TestRevealToggleInForm(t *testing.T) {
	s := psFormScript(formDialog(formReqs))
	for _, must := range []string{"$hides = @($false, $true)", "AddInput $tb 480 $hides[$i]", "System.Windows.Forms.CheckBox", "AccessibleName = 'Show value'", "UseSystemPasswordChar = -not $this.Checked"} {
		if !strings.Contains(s, must) {
			t.Errorf("form script lacks %q", must)
		}
	}
	// The visible field takes the plain branch of AddInput.
	if !strings.Contains(s, "if (-not $masked) {") {
		t.Error("AddInput has no plain branch for visible fields")
	}
	allVisible := psFormScript(formDialog([]SecretRequest{formReqs[0], formReqs[0]}))
	if strings.Contains(allVisible, "CheckBox") {
		t.Error("a form of visible fields has a toggle")
	}
}

func TestRevealToggleIsMaskedByDefaultAndKeepsFocusAndEnter(t *testing.T) {
	for name, s := range map[string]string{"secret": psScripts()["secret"], "form": psScripts()["form"]} {
		if strings.Contains(s, "$c.Checked = $true") || strings.Contains(s, "UseSystemPasswordChar = $false") {
			t.Errorf("%s: unmasked by default", name)
		}
		if strings.Contains(s, "TabStop = $false") {
			t.Errorf("%s: toggle is not reachable by keyboard", name)
		}
		if !strings.Contains(s, "$f.AcceptButton = $ok\n") {
			t.Errorf("%s: Enter no longer accepts", name)
		}
		if strings.Contains(s, "$c.Focus()") || strings.Contains(s, "$eyes[0].Focus") {
			t.Errorf("%s: toggle takes the focus", name)
		}
	}
	if !strings.Contains(psScripts()["secret"], "$first = $tb\n") || !strings.Contains(psScripts()["secret"], "$tb.Focus()") {
		t.Error("secret dialog does not focus the input")
	}
	if !strings.Contains(psScripts()["form"], "$first = $boxes[0]\n") || !strings.Contains(psScripts()["form"], "$boxes[0].Focus()") {
		t.Error("form does not focus the first input")
	}
}

// The toggle changes nothing about where the value goes.
func TestRevealToggleLeavesTheValuePathAndExitCodesAlone(t *testing.T) {
	s := psScripts()["secret"]
	if strings.Count(s, "OpenStandardOutput") != 1 || !strings.Contains(s, "GetBytes($tb.Text)") || strings.Count(s, "[System.Console]") != 1 {
		t.Error("value no longer leaves only through the one stdout write")
	}
	if !strings.Contains(s, "-ne [System.Windows.Forms.DialogResult]::OK) { exit 2 }") || !strings.HasSuffix(s, "exit 0\n") {
		t.Error("cancel/answer exit codes changed")
	}
	if (powershellTool{}).classify(dialog{}, result{Exit: 2}) != statusCancel || (powershellTool{}).classify(dialog{}, result{Exit: 0}) != statusOK {
		t.Error("classify changed")
	}
	f := psScripts()["form"]
	if strings.Count(f, "OpenStandardOutput") != 1 || !strings.Contains(f, "foreach ($b in $boxes)") {
		t.Error("form output path changed")
	}
	// Nothing in the toggle code writes anything out.
	eye := psEye[:strings.Index(psEye, "\n")+1]
	_ = eye
	if strings.Contains(psEye, "Console") || strings.Contains(psEye, "Write(") || strings.Contains(psEye, "Out-File") {
		t.Error("toggle code writes output")
	}
}
