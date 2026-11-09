package pipeexcerpt_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/provin-line/oss/internal/excerpt"
	"github.com/provin-line/oss/pipeline/internal/pipeexcerpt"
)

// Both limits are ones package excerpt takes, and a whole text has room for
// more than one named value.
func TestLimits(t *testing.T) {
	if pipeexcerpt.ValueLimit < excerpt.MinLimit {
		t.Errorf("ValueLimit %d is under excerpt.MinLimit %d", pipeexcerpt.ValueLimit, excerpt.MinLimit)
	}
	if pipeexcerpt.TextLimit < 2*pipeexcerpt.ValueLimit {
		t.Errorf("TextLimit %d has no room for two values of ValueLimit %d", pipeexcerpt.TextLimit, pipeexcerpt.ValueLimit)
	}
}

var long = strings.Repeat("a\n\xff", 10<<10)

// Text holds a text within TextLimit bytes of UTF-8, whatever its size, and
// leaves one that fits as it is.
func TestText(t *testing.T) {
	if got := pipeexcerpt.Text(long); len(got) > pipeexcerpt.TextLimit || !utf8.ValidString(got) || !strings.HasSuffix(got, " bytes)") {
		t.Errorf("Text: %d bytes (UTF-8: %v): %.60q", len(got), utf8.ValidString(got), got)
	}
	if got := pipeexcerpt.Text("short"); got != "short" {
		t.Errorf("Text(short) = %q", got)
	}
}

// Value is a value quoted within ValueLimit bytes, as one line.
func TestValue(t *testing.T) {
	got := pipeexcerpt.Value(long)
	if len(got) > pipeexcerpt.ValueLimit || strings.ContainsAny(got, "\n\r") || !utf8.ValidString(got) || !strings.HasPrefix(got, `"`) {
		t.Errorf("Value: %d bytes: %.60q", len(got), got)
	}
	if got := pipeexcerpt.Value("sha256:ab"); got != `"sha256:ab"` {
		t.Errorf("Value(short) = %s", got)
	}
}

type panickingError struct{}

func (panickingError) Error() string { panic("boom") }

type nilPointerError struct{ text string }

func (e *nilPointerError) Error() string { return e.text }

// verboseError writes far more under %+v than its Error text.
type verboseError struct{}

func (verboseError) Error() string { return "short" }

func (verboseError) Format(s fmt.State, verb rune) {
	if s.Flag('+') {
		_, _ = s.Write([]byte(long))
		return
	}
	_, _ = s.Write([]byte("short"))
}

// ErrorText is the text %v writes for an error, within TextLimit bytes of
// UTF-8: also for an error that is a nil pointer, whose Error method panics,
// or which writes more under %+v; nil is "<nil>".
func TestErrorText(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "<nil>"},
		{"nil pointer", (*nilPointerError)(nil), "<nil>"},
		{"panicking Error method", panickingError{}, fmt.Sprint(panickingError{})},
		{"verbose under %+v", verboseError{}, "short"},
		{"short", errors.New("no such head"), "no such head"},
	} {
		got := func() (s string) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: ErrorText panicked: %v", c.name, r)
				}
			}()
			return pipeexcerpt.ErrorText(c.err)
		}()
		if got != c.want {
			t.Errorf("%s: ErrorText = %q, want %q", c.name, got, c.want)
		}
	}
	if got := pipeexcerpt.ErrorText(errors.New(long)); len(got) > pipeexcerpt.TextLimit || !utf8.ValidString(got) {
		t.Errorf("ErrorText of a long error: %d bytes", len(got))
	}
}
