package secret

import (
	"strings"
	"testing"
)

func val(s string) Secret { return New("X", []byte(s)) }

// Every field of Inspect, each with a representative value and its negative.
func TestInspectProperties(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  Shape
	}{
		{"plain word", "hunter2x", Shape{Length: 8, LooksLike: LooksText}},
		{"empty", "", Shape{Length: 0, Empty: true, LooksLike: LooksText}},
		{"length counts characters not bytes", "contraseña", Shape{Length: 10, LooksLike: LooksText}},
		{"leading space", " abc", Shape{Length: 4, Whitespace: true, LooksLike: LooksText}},
		{"trailing space", "abc ", Shape{Length: 4, Whitespace: true, LooksLike: LooksText}},
		{"trailing newline", "abc\n", Shape{Length: 4, Whitespace: true, LooksLike: LooksText}},
		{"trailing CRLF", "abc\r\n", Shape{Length: 5, Whitespace: true, LooksLike: LooksText}},
		{"leading tab", "\tabc", Shape{Length: 4, Whitespace: true, LooksLike: LooksText}},
		{"only spaces is not empty", "   ", Shape{Length: 3, Whitespace: true, LooksLike: LooksText}},
		{"inner space is not padding", "a b", Shape{Length: 3, LooksLike: LooksText}},
		{"two lines", "line one\nline two", Shape{Length: 17, Multiline: true, LooksLike: LooksText}},
		{"CR line break", "a\rb", Shape{Length: 3, Multiline: true, LooksLike: LooksText}},
		{"a trailing newline alone is not multiline", "abc\n", Shape{Length: 4, Whitespace: true, LooksLike: LooksText}},
		{"placeholder change-me", "change-me", Shape{Length: 9, Placeholder: true, LooksLike: LooksText}},
		{"placeholder is case-insensitive", "ChangeMe", Shape{Length: 8, Placeholder: true, LooksLike: LooksText}},
		{"placeholder is trimmed", "  TODO\n", Shape{Length: 7, Whitespace: true, Placeholder: true, LooksLike: LooksText}},
		{"placeholder xxx", "xxx", Shape{Length: 3, Placeholder: true, LooksLike: LooksText}},
		{"near placeholder is not one", "change-me-now", Shape{Length: 13, LooksLike: LooksText}},
		{"placeholder password", "PASSWORD", Shape{Length: 8, Placeholder: true, LooksLike: LooksText}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Inspect(val(c.value)); got.Length != c.want.Length || got.Empty != c.want.Empty ||
				got.Whitespace != c.want.Whitespace || got.Multiline != c.want.Multiline ||
				got.Placeholder != c.want.Placeholder || got.LooksLike != c.want.LooksLike {
				t.Fatalf("Inspect = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestEveryPlaceholderOfTheListIsOne(t *testing.T) {
	want := []string{"change-me", "changeme", "todo", "xxx", "your-api-key", "example", "password", "secret", "none", "null", "test"}
	if strings.Join(Placeholders, ",") != strings.Join(want, ",") {
		t.Fatalf("Placeholders = %v", Placeholders)
	}
	for _, p := range Placeholders {
		if !Inspect(val(p)).Placeholder || !Inspect(val(strings.ToUpper(p))).Placeholder {
			t.Errorf("%q is not a placeholder", p)
		}
	}
}

// One class per row, with values that belong to it and values that must fall
// to another class: the rules are documented in CONTRACT.md § check.
func TestLooksLike(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl"
	pem := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----\n"
	cases := []struct{ name, value, want string }{
		{"email", "ana@example.com", LooksEmail},
		{"email with plus and subdomain", "ana+x@mail.example.co.uk", LooksEmail},
		{"email padded is still an email", " ana@example.com\n", LooksEmail},
		{"email without domain dot", "ana@localhost", LooksText},
		{"two at signs", "a@b@example.com", LooksText},
		{"email with a space", "ana @example.com", LooksText},
		{"user name is text", "ana.garcia", LooksText},
		{"https url", "https://api.example.com/v1", LooksURL},
		{"url with embedded credentials is just url", "postgres://user:pa55@db.internal:5432/app", LooksURL},
		{"url with user only is url not email", "https://ana@example.com", LooksURL},
		{"scheme without host", "https://", LooksText},
		{"url with a space", "https://example.com/a b", LooksText},
		{"host only is text", "api.example.com", LooksText},
		{"jwt", jwt, LooksJWT},
		{"jwt with empty signature", "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.", LooksJWT},
		{"two segments are not a jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0", LooksText},
		{"jwt segments must start like json", "abc.def.ghi", LooksText},
		{"pem", pem, LooksPEM},
		{"pem padded", "\n" + pem + "\n", LooksPEM},
		{"pem without its footer is text", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n", LooksText},
		{"pem with another footer is text", "-----BEGIN PRIVATE KEY-----\nAA\n-----END PUBLIC KEY-----", LooksText},
		{"uuid", "123e4567-e89b-12d3-a456-426614174000", LooksUUID},
		{"uuid uppercase", "123E4567-E89B-12D3-A456-426614174000", LooksUUID},
		{"uuid with spaces for dashes", "123e4567 e89b 12d3 a456 426614174000", LooksText},
		{"integer", "123456", LooksNumber},
		{"signed decimal", "-12.50", LooksNumber},
		{"number with a letter", "12a45", LooksText},
		{"hex of 16 digits", "deadbeefcafe0123", LooksHex},
		{"hex uppercase 32", "DEADBEEFCAFE0123DEADBEEFCAFE0123", LooksHex},
		{"hex odd length is not hex", "deadbeefcafe012", LooksText},
		{"short hex is text", "cafe", LooksText},
		{"digits only wins over hex", "0123456789012345", LooksNumber},
		{"base64 padded", "dXNlcjpwYXNzd29yZA==", LooksBase64},
		{"base64 unpadded", "Zm9vYmFyYmF6cXV4MQ", LooksBase64},
		{"base64 unpadded of the impossible length", "Zm9vYmFyYmF6cXV4M", LooksText},
		{"the url-safe alphabet is text", "Zm9vLWJhci1iYXotcXV4_1", LooksText},
		{"a name with underscores and digits is text", "TESTSECRET_check_plain_0123", LooksText},
		{"long words are not base64", "correcthorsebatterystaple", LooksText},
		{"base64 too short", "dXNlcg==", LooksText},
		{"base64 with a space", "dXNlcjpw YXNzd29yZA==", LooksText},
		{"empty", "", LooksText},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Inspect(val(c.value)).LooksLike; got != c.want {
				t.Fatalf("LooksLike = %q, want %q", got, c.want)
			}
		})
	}
}

func TestLooksLikeIsAClosedSet(t *testing.T) {
	want := "email,url,jwt,pem,uuid,hex,base64,number,text"
	if got := strings.Join(LooksLikeSet, ","); got != want {
		t.Fatalf("LooksLikeSet = %s", got)
	}
}

func TestEqual(t *testing.T) {
	if !Equal(val("same value"), val("same value")) {
		t.Fatal("identical values differ")
	}
	for _, other := range []string{"same valuE", "same value ", "same", ""} {
		if Equal(val("same value"), val(other)) {
			t.Fatalf("%q equals the value", other)
		}
	}
	if !Equal(Secret{}, val("")) || Equal(Secret{}, val("a")) {
		t.Fatal("the zero Secret is the empty value")
	}
}

// Inspect says nothing that could rebuild the value: the Shape holds no text.
func TestShapeRendersNoValue(t *testing.T) {
	v := "TESTSECRET_shape_0123456789"
	got := Inspect(val(v))
	for _, s := range []string{got.LooksLike} {
		if strings.Contains(s, "TESTSECRET") {
			t.Fatal("the shape carries text of the value")
		}
	}
}
