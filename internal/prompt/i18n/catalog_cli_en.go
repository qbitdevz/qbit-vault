package i18n

// The texts of the dialogs the command code asks (internal/cli): permission
// questions, confirmations, the reasons qbit-vault itself gives. English is
// the source; the arguments (secret names, layers, scopes, hosts, paths) are
// the same in every language.
func init() {
	add(en, map[string]string{
		// Scopes. The option explains the scope; the scope word itself is the
		// token the audit log uses.
		"scope.once":    "Once: only the next command",
		"scope.session": "Session: until the agent restarts (max %[1]s)",
		"scope.project": "Always: in this project, until you revoke it",
		"opt.deny":      "Don't allow",
		"opt.save_only": "Save it, don't allow yet",

		// Permission questions.
		"q.allow":            "%[1]s wants to use %[2]s.\nWhy: %[3]s",
		"q.allow_saved":      "%[1]s (%[2]s, already saved)",
		"q.allow_now":        "Allow agents to use %[1]s (%[2]s) right away?",
		"q.grant":            "Grant %[1]s (%[2]s) to %[3]s, scope %[4]s?",
		"grant.this_project": "this project",

		// Where a secret lives.
		"q.where_saved":     "Where should %[1]s be saved?",
		"q.where_live":      "Where should %[1]s live?",
		"q.where_these":     "Where should these secrets live?",
		"opt.layer_project": "Only this project (%[1]s)",
		"opt.layer_all":     "All projects",

		// Changes an agent proposes (manage).
		"q.manage":            "%[1]s wants to %[2]s.\nWhy: %[3]s",
		"what.move":           "move %[1]s from %[2]s to %[3]s",
		"what.move_over":      " (overwriting the %[1]s already there)",
		"what.edit":           "edit %[1]s (%[2]s): %[3]s",
		"what.replace":        "replace the value of %[1]s (%[2]s)",
		"what.remove":         "remove %[1]s (%[2]s)",
		"diff.widening":       " (widening)",
		"diff.any":            "any",
		"opt.replace_once":    "Replace, allow once",
		"opt.replace_project": "Replace, always in this project",
		"opt.replace_ask":     "Replace, but ask me before each use",
		"opt.dont_replace":    "Don't replace",

		// A pasted value that looks wrong.
		"q.value_issue":  "The value of %[1]s %[2]s. Most keys and tokens don't, and extra characters break logins. Which one should be saved?",
		"problem.both":   "has quotes around it and invisible characters in it",
		"problem.quotes": "has quotes around it",
		"problem.hidden": "has invisible characters in it",
		"opt.without":    "Without them (recommended)",
		"opt.as_typed":   "Keep it as typed",

		// A typed value that repeats another one (names only, never a value).
		"q.same_replaced": "The new value of %[1]s is the same as the one it replaces.",
		"q.same_other":    "The value of %[1]s is the same as the value of %[2]s.",
		"q.same_save":     "That is often a mistake (the wrong field, or something that did not change). Save it anyway?",
		"opt.save_anyway": "Save anyway",

		// Unlocking the vault for an agent.
		"unlock.none":  "%[1]s needs the vault. Unlock it to continue.",
		"unlock.wants": "%[1]s wants to use %[2]s. Unlock the vault to continue.",
		"unlock.more":  "%[1]s and %[2]d more",

		// Confirmations of the user's own commands.
		"q.import":          "Import %[1]s from %[2]s into %[3]s? Existing secrets with these names are replaced.",
		"word.env":          "the environment",
		"word.dotenv":       "the dotenv file",
		"q.delete_dotenv":   "Delete the dotenv file now that its values are in the vault?",
		"q.import_one":      "Import %[1]d secret from the export?",
		"q.import_many":     "Import %[1]d secrets from the export?",
		"q.import_replaces": " These replace existing ones: %[1]s",
		"q.link":            "Use the secrets of project %[1]s in %[2]s?",
		"q.overwrite":       "%[1]s already exists in %[2]s; overwrite?",
		"q.remove":          "Remove %[1]s (%[2]s)?",
		"q.restore":         "Restore the vault from %[1]s? The current vault is backed up first.",
		"q.update":          "Update QBit Vault %[1]s to %[2]s?",
		"q.uninstall":       "Revert the qbit-vault registrations in %[1]s? The vault stays.",
		"reason.purge":      "Type '%[1]s' to revert %[2]d host registration(s) and permanently delete the vault at %[3]s and its key in the OS keychain",
		"name.confirmation": "confirmation",
		"reason.manual":     "manual entry",

		// Sync.
		"word.the_server":      "the server",
		"word.never":           "never",
		"reason.register":      "Register this vault on %[1]s",
		"q.sync":               "Sync this vault to %[1]s? Secrets are encrypted on this device before upload; the server can never read them.",
		"q.join":               "Join the synced vault on %[1]s?",
		"q.join_local_one":     " %[1]d local secret will be added to the synced vault on %[2]s.",
		"q.join_local_many":    " %[1]d local secrets will be added to the synced vault on %[2]s.",
		"q.stop_sync":          "Stop syncing this vault on %[1]s? The local vault and key stay.",
		"q.rekey":              "Rotate the master key of your vault on %[1]s? Every device switches to the new key, and the recovery key is replaced.",
		"q.replace_recovery":   "Replace the recovery key for your vault on %[1]s? The old recovery key stops working.",
		"q.revoke_device":      "Revoke device %[1]s (last sync %[2]s) on %[3]s? It will lose access to the synced vault; the account key and the recovery key will be replaced.",
		"q.history":            "Restore the vault to server version %[1]d (written by %[2]s, %[3]s)? Records that differ are replaced; the current state stays in the local backups.",
		"q.conflict_keep":      "Resolve the sync conflict of %[1]s (%[2]s): keep the current version and discard the kept one?",
		"q.conflict_swap":      "Resolve the sync conflict of %[1]s (%[2]s): swap in the kept version? The current one becomes the kept one.",
		"name.invite":          "invite code",
		"name.recovery":        "recovery key",
		"name.last_four":       "recovery key, last four characters",
		"name.pairing":         "pairing code",
		"name.label":           "device label",
		"name.confirm_code":    "confirmation code",
		"reason.recover":       "Recover the vault on %[1]s",
		"reason.approve":       "Approve a new device on %[1]s",
		"reason.check_key":     "Check that you saved the recovery key",
		"reason.confirm_code":  "Type the confirmation code shown on the device that approved this one",
		"reason.add_device":    "Add this device to your vault on %[1]s? It will be able to read every secret. Name it, or leave this empty for %[2]q.",
		"heading.confirm_code": "Confirmation code",
		"show.recovery_title":  "Recovery key",
		"show.recovery_text":   "Write this recovery key down and keep it offline. It is the only way to open your vault on a new machine if you lose access to every device.",
		"show.confirm_text":    "Type this code on the new device.",
	})
}
