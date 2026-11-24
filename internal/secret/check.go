package secret

import (
	"bytes"
	"crypto/subtle"
	"regexp"
	"unicode"
	"unicode/utf8"
)

// The `looks_like` words of the contract's `check` op (CONTRACT.md § check):
// a closed set, a guess from the shape of the value only.
const (
	LooksEmail  = "email"
	LooksURL    = "url"
	LooksJWT    = "jwt"
	LooksPEM    = "pem"
	LooksUUID   = "uuid"
	LooksHex    = "hex"
	LooksBase64 = "base64"
	LooksNumber = "number"
	LooksText   = "text"
)

// LooksLikeSet is the closed set of Shape.LooksLike, in the order the rules
// are tried (the first that matches wins; text is the fallback).
var LooksLikeSet = []string{LooksEmail, LooksURL, LooksJWT, LooksPEM, LooksUUID, LooksHex, LooksBase64, LooksNumber, LooksText}

// Placeholders is the one list of values `check` calls a placeholder: the
// value, trimmed and lowercased, is exactly one of these. It is short on
// purpose: a longer list would call real values placeholders.
var Placeholders = []string{"change-me", "changeme", "todo", "xxx", "your-api-key", "example", "password", "secret", "none", "null", "test"}

// Shape is what `check` may say about a value: counts and booleans and one
// word of a closed set. It holds no text of the value, no hash and nothing a
// reader could rebuild or test the value from.
type Shape struct {
	// Length is the number of characters (Unicode code points).
	Length int
	// Empty: the value has no characters at all.
	Empty bool
	// Whitespace: it starts or ends with a white-space character, a trailing
	// newline included.
	Whitespace bool
	// Multiline: a line break (LF or CR) remains after leading and trailing
	// white space is removed.
	Multiline bool
	// Placeholder: trimmed and lowercased it is one of Placeholders.
	Placeholder bool
	// LooksLike is one of LooksLikeSet.
	LooksLike string
}

var (
	reEmail  = regexp.MustCompile("^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)+$")
	reURL    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]*://[^\s/?#]+`)
	reJWT    = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$`)
	rePEM    = regexp.MustCompile(`^-----BEGIN ([A-Z0-9 ]+)-----`)
	reUUID   = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
	reHex    = regexp.MustCompile(`^[0-9A-Fa-f]+$`)
	reB64Std = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	reNumber = regexp.MustCompile(`^[+-]?[0-9]+(\.[0-9]+)?$`)
)

// minHexLen and minBase64Len keep short words from being called encodings.
const (
	minHexLen    = 16
	minBase64Len = 16
)

// Inspect describes the shape of the value of s. It works on the stored bytes
// in place and keeps no copy of them.
func Inspect(s Secret) Shape {
	var b []byte
	if s.p != nil {
		b = s.p.b
	}
	sh := Shape{Length: utf8.RuneCount(b), Empty: len(b) == 0, LooksLike: LooksText}
	if sh.Empty {
		return sh
	}
	if r, _ := utf8.DecodeRune(b); unicode.IsSpace(r) {
		sh.Whitespace = true
	}
	if r, _ := utf8.DecodeLastRune(b); unicode.IsSpace(r) {
		sh.Whitespace = true
	}
	t := bytes.TrimFunc(b, unicode.IsSpace)
	sh.Multiline = bytes.ContainsAny(t, "\n\r")
	sh.Placeholder = isPlaceholder(t)
	sh.LooksLike = looksLike(t)
	return sh
}

func isPlaceholder(t []byte) bool {
	low := bytes.ToLower(t)
	defer clear(low)
	for _, p := range Placeholders {
		if string(low) == p {
			return true
		}
	}
	return false
}

// looksLike applies the rules in order to the trimmed value (CONTRACT.md §
// check). Only a PEM block may hold white space inside.
func looksLike(t []byte) string {
	if len(t) == 0 {
		return LooksText
	}
	if isPEM(t) {
		return LooksPEM
	}
	if bytes.IndexFunc(t, unicode.IsSpace) >= 0 {
		return LooksText
	}
	switch {
	case reJWT.Match(t):
		return LooksJWT
	case reUUID.Match(t):
		return LooksUUID
	case reURL.Match(t):
		return LooksURL
	case reEmail.Match(t):
		return LooksEmail
	case reNumber.Match(t):
		return LooksNumber
	case len(t) >= minHexLen && len(t)%2 == 0 && reHex.Match(t):
		return LooksHex
	case isBase64(t):
		return LooksBase64
	}
	return LooksText
}

// isPEM: a `-----BEGIN LABEL-----` header and the matching
// `-----END LABEL-----` footer at the end.
func isPEM(t []byte) bool {
	m := rePEM.FindSubmatch(t)
	if m == nil {
		return false
	}
	return bytes.HasSuffix(t, []byte("-----END "+string(m[1])+"-----"))
}

// isBase64: at least minBase64Len characters of the standard alphabet (the
// URL-safe `-` and `_` are not recognized: they are as common in names and
// passwords as in encodings), padded with up to two `=` to a multiple of four
// or unpadded with a length that is not one more than a multiple of four, and
// at least one digit, `=`, `+` or `/`, so that a long word is not taken for an
// encoding.
func isBase64(t []byte) bool {
	if len(t) < minBase64Len || bytes.IndexAny(t, "0123456789=+/") < 0 || !reB64Std.Match(t) {
		return false
	}
	if t[len(t)-1] == '=' {
		return len(t)%4 == 0
	}
	return len(t)%4 != 1
}

// Equal reports whether a and b hold the same bytes, in constant time for
// values of the same length. A zero Secret is the empty value.
func Equal(a, b Secret) bool {
	var x, y []byte
	if a.p != nil {
		x = a.p.b
	}
	if b.p != nil {
		y = b.p.b
	}
	return subtle.ConstantTimeCompare(x, y) == 1
}
