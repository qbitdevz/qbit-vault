package redact

import (
	"bytes"
	"strings"
	"testing"
)

// countingSink records what a StreamWriter hands over with its replacement
// counts, as a job does.
type countingSink struct {
	buf    bytes.Buffer
	counts []int
	plain  int
}

func (c *countingSink) Write(p []byte) (int, error) { c.plain++; return c.buf.Write(p) }
func (c *countingSink) WriteCounted(p []byte, n int) (int, error) {
	c.counts = append(c.counts, n)
	return c.buf.Write(p)
}

// A destination that implements CountedWriter gets the replacements of each
// hand-over, and they add up to Count, whatever the chunking.
func TestCountedWriterReceivesTheReplacementsOfEachWrite(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	sink := &countingSink{}
	w := r.Writer(sink)
	text := "a " + fixture + " b " + fixture + " c " + fixture + "\n"
	for i := 0; i < len(text); i += 7 {
		if _, err := w.Write([]byte(text[i:min(i+7, len(text))])); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	sum := 0
	for _, n := range sink.counts {
		sum += n
	}
	if sum != 3 || sum != w.Count() || sink.plain != 0 {
		t.Fatalf("counts %v (sum %d), Count %d, plain writes %d", sink.counts, sum, w.Count(), sink.plain)
	}
	if strings.Contains(sink.buf.String(), "TESTSECRET_") || strings.Count(sink.buf.String(), token) != 3 {
		t.Fatal("output is not redacted")
	}
}

// A plain destination is written as before.
func TestAPlainDestinationStillGetsWrite(t *testing.T) {
	r := mustNew(t, sec("API_KEY", fixture))
	var b bytes.Buffer
	w := r.Writer(&b)
	_, _ = w.Write([]byte("x " + fixture))
	_ = w.Close()
	if b.String() != "x "+token {
		t.Fatalf("output %q", b.String())
	}
}
