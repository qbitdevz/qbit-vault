package cli

import "github.com/qbitdevz/qbit-vault/internal/prompt/i18n"

// The tests pin the English texts: the language of the machine that runs them
// must never change what a dialog says. Tests that want another language ask
// for it through the request's `locale` or QBIT_VAULT_LOCALE.
func init() { i18n.OSLocale = func() string { return "" } }
