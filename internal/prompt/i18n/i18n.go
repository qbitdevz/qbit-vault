// Package i18n is the catalogue of every text qbit-vault puts in a dialog,
// in the languages it ships (docs/CLI.md § Dialog language, issue #63).
//
// The agent picks only the language; it never supplies dialog text. A locale
// tag taken from a request, the environment or the system is matched by its
// primary language subtag against the languages below, and anything that does
// not match (unknown, malformed, too long) is dropped silently and never
// shown, logged or echoed. Identifiers (secret names, scopes, layers, host
// names, paths) are not part of the catalogue: callers pass them as
// arguments and they appear unchanged in every language.
package i18n

import (
	"fmt"
	"strings"
)

// Locale is a language the catalogue has. The zero value reads English.
type Locale string

// The languages with a catalogue. To add one: a catalog_xx.go with every id of
// catalog_en.go (a test checks that), an entry in catalogs and in Match.
const (
	En Locale = "en"
	Es Locale = "es"
)

// EnvLocale is the environment variable that sets the dialog language for
// every command, below a locale the request carries and above the system's.
const EnvLocale = "QBIT_VAULT_LOCALE"

// MaxTagLen is the longest tag taken into account (the BCP 47 bound).
const MaxTagLen = 35

var catalogs = map[Locale]map[string]string{En: en, Es: es}

// OSLocale reads the locale of the system's user (Windows: the first preferred
// display language). It is a variable so a test never depends on the machine's language.
var OSLocale = systemLocale

// Match reports the language of tag, by its primary subtag and ignoring case:
// "es", "es-AR" and "ES_es.UTF-8" are Spanish. A tag that is too long, holds a
// character a locale never holds, or names no language qbit-vault has gives
// false.
func Match(tag string) (Locale, bool) {
	if tag == "" || len(tag) > MaxTagLen {
		return "", false
	}
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '@':
		default:
			return "", false
		}
	}
	primary := tag
	if i := strings.IndexAny(primary, "-_.@"); i >= 0 {
		primary = primary[:i]
	}
	if len(primary) < 2 || len(primary) > 3 {
		return "", false
	}
	switch strings.ToLower(primary) {
	case "en":
		return En, true
	case "es":
		return Es, true
	}
	return "", false
}

// posixVars are the variables the system locale is read from, in order: the
// first one that is set is the one POSIX uses.
var posixVars = []string{"LC_ALL", "LC_MESSAGES", "LANG"}

// Resolve picks the language of a dialog: the request's tag, then
// QBIT_VAULT_LOCALE, then the system locale, then English. A step whose tag
// does not match a language is skipped without a trace. getenv may be nil.
func Resolve(requested string, getenv func(string) string) Locale {
	if l, ok := Match(requested); ok {
		return l
	}
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	if l, ok := Match(getenv(EnvLocale)); ok {
		return l
	}
	for _, v := range posixVars {
		if tag := getenv(v); tag != "" {
			if l, ok := Match(tag); ok {
				return l
			}
			break
		}
	}
	if OSLocale != nil {
		if l, ok := Match(OSLocale()); ok {
			return l
		}
	}
	return En
}

// T is the text of id in l, with args applied by fmt (ids with arguments use
// indexed verbs, so a translation may reorder them). A language without id
// reads English; an id nobody has is shown as itself, which a test prevents.
func (l Locale) T(id string, args ...any) string {
	s, ok := catalogs[l][id]
	if !ok {
		if s, ok = catalogs[En][id]; !ok {
			return id
		}
	}
	if len(args) == 0 {
		return s
	}
	return fmt.Sprintf(s, args...)
}
