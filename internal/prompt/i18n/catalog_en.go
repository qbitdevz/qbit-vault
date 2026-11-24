package i18n

// en is the English catalogue. Its texts are the ones qbit-vault always
// showed: every other language is a translation of an entry here, with the
// same indexed arguments.
var en = map[string]string{}

func init() {
	add(en, map[string]string{
		// Buttons.
		"btn.save":     "Save",
		"btn.cancel":   "Cancel",
		"btn.continue": "Continue",
		"btn.confirm":  "Confirm",
		"btn.decline":  "Decline",
		"btn.done":     "Done",
		"btn.ok":       "OK",

		// Headings inside a dialog.
		"heading.request":    "Secret request",
		"heading.permission": "Permission request",
		"heading.confirm":    "Confirm",

		// The request lines of a capture: label, then value.
		"row.who":           "Who",
		"row.secret":        "Secret",
		"row.why":           "Why",
		"row.saved_in":      "Saved in",
		"row.about":         "About",
		"row.already_saved": "Already saved",
		"row.field":         "Field",
		"row.value":         "Value",
		"val.all_projects":  "all projects",
		"val.project":       "project %[1]s",
		"val.not_asked":     "%[1]s (not asked again)",
		"val.field_of":      "%[1]d of %[2]d (%[3]s)",
		"val.new":           "new",
		"val.replaces":      "replaces the saved value",

		// What the user is asked to type.
		"input.hidden":  "Paste or type the value. The agent never sees it:",
		"input.visible": "Type the value (shown while you type):",
		"input.form":    "Fill in each field. The agent never sees what you enter:",
		"field.hidden":  " (hidden)",
		"field.shown":   " (shown while you type)",

		// Who is asking.
		"who.agent":      "an agent",
		"who.your_agent": "your agent",
		"who.cli":        "you (qbit-vault)",
		"who.session":    "%[1]s (session %[2]s)",

		// The reveal toggle of the Windows dialog.
		"eye.show":       "Show",
		"eye.hide":       "Hide",
		"eye.show_value": "Show value",
		"eye.hide_value": "Hide value",
		"eye.width":      "60",

		// Passphrase dialogs.
		"pass.again":          "Type the passphrase again",
		"pass.mismatch":       "Passphrases do not match.",
		"pass.mismatch_retry": "Passphrases do not match. Try again.",
		"pass.vault.heading":  "Vault passphrase",
		"pass.vault.label":    "Vault passphrase",
		"pass.vault.again":    "Type the passphrase again",
		"pass.export.heading": "Export passphrase",
		"pass.export.label":   "Export passphrase (protects this backup file)",
		"pass.export.again":   "Type the export passphrase again",
		"pass.import.heading": "Export passphrase",
		"pass.import.label":   "Passphrase of the export file",

		// The terminal backend.
		"tty.request_title": "QBit Vault: secret request",
		"tty.value":         "Value",
		"tty.answer":        "Answer",
		"tty.hidden":        "%[1]s (hidden): ",
		"tty.shown":         "%[1]s (shown while you type): ",
		"tty.choice":        "Choice [%[1]d]: ",
		"tty.choice_retry":  "Type a number from 1 to %[1]d, or press Enter for the default.",
		"tty.yes_no":        " [y/N] ",
		"tty.yes_words":     "y,yes",
		"tty.press_enter":   "Press Enter when done. ",

		// Words that tell what kind of question an answer list belongs to:
		// the permission heading and the warning icon follow from them.
		"mark.perm_prefix": "don't ",
		"mark.perm_a":      "allow",
		"mark.perm_b":      "ask me before",
		"mark.removal_a":   "remove",
		"mark.removal_b":   "delete",
	})
}

func add(dst, src map[string]string) {
	for k, v := range src {
		dst[k] = v
	}
}
