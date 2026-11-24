package redact

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

type collect struct{ bytes.Buffer }

// F1: a value cut short by the end of the stream is never written in clear
// once at least 4 bytes of it are there.
func TestACutValueIsRedactedAtTheFinalFlush(t *testing.T) {
	forms := map[string]string{
		"raw": fixture,
		"b64": base64.RawStdEncoding.EncodeToString([]byte(fixture)),
	}
	for name, form := range forms {
		for n := 4; n < len(form); n++ {
			r := mustNew(t, sec("API_KEY", fixture))
			var c collect
			w := r.Writer(&c)
			_, _ = w.Write([]byte("p:" + form[:n]))
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if got := c.String(); got != "p:"+token || w.Count() != 1 {
				t.Fatalf("%s cut at %d: output %q count %d", name, n, got, w.Count())
			}
		}
		// 1 to 3 bytes stay as written.
		for n := 1; n < 4; n++ {
			r := mustNew(t, sec("API_KEY", fixture))
			var c collect
			w := r.Writer(&c)
			_, _ = w.Write([]byte("p:" + form[:n]))
			_ = w.Close()
			if c.String() != "p:"+form[:n] || w.Count() != 0 {
				t.Fatalf("%s cut at %d: output %q", name, n, c.String())
			}
		}
	}
	r := mustNew(t, sec("API_KEY", fixture))
	var c collect
	w := r.Writer(&c)
	_, _ = w.Write([]byte("an ordinary line ending in text"))
	_ = w.Close()
	if c.String() != "an ordinary line ending in text" || w.Count() != 0 {
		t.Fatalf("unrelated output changed: %q", c.String())
	}
}

// The cut is also redacted in whole-buffer redaction, and a complete value is
// still a single replacement.
func TestBytesRedactsACutTail(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	out, n := r.Bytes([]byte("x " + fixture[:20]))
	if string(out) != "x "+token || n != 1 {
		t.Fatalf("%q %d", out, n)
	}
	out, n = r.Bytes([]byte(fixture + fixture[:9]))
	if string(out) != token+token || n != 2 {
		t.Fatalf("%q %d", out, n)
	}
}

// F2: ordinary output is released at once; only a suffix that could still
// become a value is held.
func TestOrdinaryOutputIsReleasedAtOnce(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	var c collect
	w := r.Writer(&c)
	_, _ = w.Write([]byte("one line only\n"))
	if c.String() != "one line only\n" {
		t.Fatalf("released %q", c.String())
	}
}

func TestOnlyThePartialValueIsHeldBack(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	var c collect
	w := r.Writer(&c)
	_, _ = w.Write([]byte("line\n" + fixture[:10]))
	if c.String() != "line\n" {
		t.Fatalf("released %q", c.String())
	}
	_, _ = w.Write([]byte(fixture[10:] + " tail\n"))
	if c.String() != "line\n"+token+" tail\n" {
		t.Fatalf("released %q", c.String())
	}
	_ = w.Close()
	if w.Count() != 1 {
		t.Fatalf("count %d", w.Count())
	}
}

// A partial that turns out not to be a value is released with the next write.
func TestAFalseStartIsReleasedLater(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	var c collect
	w := r.Writer(&c)
	_, _ = w.Write([]byte("a TESTSECRET_redact_ "))
	_, _ = w.Write([]byte("b"))
	if c.String() != "a TESTSECRET_redact_ b" {
		t.Fatalf("released %q", c.String())
	}
}

// Many patterns and a multi-line value, split at every offset, one byte at a
// time and in two halves: the value never appears and the text is intact.
func TestManyPatternsAndAMultiLineValueSplitAnywhere(t *testing.T) {
	pem := "-----BEGIN KEY-----\nTESTSECRET_line_one_0123456789abcdef\nTESTSECRET_line_two_0123456789abcdef\n-----END KEY-----"
	r := mustNew(t, sec("PEM_KEY", pem), sec("API_KEY", fixture), sec("OTHER", fixtureB))
	text := "start\n" + pem + "\nmid " + fixture + " " + base64.StdEncoding.EncodeToString([]byte(fixtureB)) + "\nend\n"
	want, _ := r.Bytes([]byte(text))
	for _, step := range []int{1, 3, 7, 64} {
		var c collect
		w := r.Writer(&c)
		for i := 0; i < len(text); i += step {
			_, _ = w.Write([]byte(text[i:min(i+step, len(text))]))
			if strings.Contains(c.String(), "TESTSECRET_") {
				t.Fatalf("step %d: value in the output so far", step)
			}
		}
		_ = w.Close()
		if c.String() != string(want) {
			t.Fatalf("step %d: output differs", step)
		}
	}
	for cut := 1; cut < len(text); cut++ {
		var c collect
		w := r.Writer(&c)
		_, _ = w.Write([]byte(text[:cut]))
		_, _ = w.Write([]byte(text[cut:]))
		_ = w.Close()
		if c.String() != string(want) {
			t.Fatalf("split at %d differs", cut)
		}
	}
}
