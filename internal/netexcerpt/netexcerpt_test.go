package netexcerpt_test

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/provin-line/oss/internal/excerpt"
	"github.com/provin-line/oss/internal/netexcerpt"
)

// Both limits are ones package excerpt takes, and a whole text has room for
// more than one named value.
func TestLimits(t *testing.T) {
	if netexcerpt.ValueLimit < excerpt.MinLimit {
		t.Errorf("ValueLimit %d is under excerpt.MinLimit %d", netexcerpt.ValueLimit, excerpt.MinLimit)
	}
	if netexcerpt.TextLimit < 2*netexcerpt.ValueLimit {
		t.Errorf("TextLimit %d has no room for two values of ValueLimit %d", netexcerpt.TextLimit, netexcerpt.ValueLimit)
	}
}

// A value the network names, and an error, are written quoted within their
// limit, as one line: a line break or a byte that is not UTF-8 is escaped.
func TestValueTextAndErrorText(t *testing.T) {
	long := strings.Repeat("a\n\xff", 10<<10)
	for _, c := range []struct {
		name  string
		got   string
		limit int
	}{
		{"ValueText", netexcerpt.ValueText(long), netexcerpt.ValueLimit},
		{"ErrorText", netexcerpt.ErrorText(errors.New(long)), netexcerpt.TextLimit},
	} {
		if len(c.got) > c.limit || strings.ContainsAny(c.got, "\n\r") || !utf8.ValidString(c.got) {
			t.Errorf("%s: %d bytes (limit %d): %.60q", c.name, len(c.got), c.limit, c.got)
		}
		if !strings.HasPrefix(c.got, `"`) || !strings.HasSuffix(c.got, " bytes)") {
			t.Errorf("%s: %.60q is not a quoted head with its length", c.name, c.got)
		}
	}
	if got := netexcerpt.ValueText("did:example:a"); got != `"did:example:a"` {
		t.Errorf("ValueText of a short value = %s", got)
	}
	if got := netexcerpt.ErrorText(errors.New("no such head")); got != `"no such head"` {
		t.Errorf("ErrorText of a short error = %s", got)
	}
	if got := netexcerpt.ErrorText(nil); got != "<nil>" {
		t.Errorf("ErrorText(nil) = %s", got)
	}
}

type panickingError struct{}

func (panickingError) Error() string { panic("boom") }

type nilPointerError struct{ text string }

func (e *nilPointerError) Error() string { return e.text }

// selfPanickingError panics with itself, a value fmt cannot write either.
type selfPanickingError struct{}

func (e selfPanickingError) Error() string { panic(e) }

// formattingError writes under %v another text than its Error text.
type formattingError struct{}

func (formattingError) Error() string                 { return "plain" }
func (formattingError) Format(s fmt.State, verb rune) { _, _ = s.Write([]byte("formatted")) }

// ErrorText quotes the text excerpt.ErrorText takes for an error: its Error
// text first, whatever fmt writes for it; what fmt writes when Error panics,
// such as "<nil>" for a nil pointer; a fixed text when fmt panics too. It does
// not panic itself.
func TestErrorTextOfAnyError(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"formats itself", formattingError{}, `"plain"`},
		{"panicking Error method", panickingError{}, strconv.Quote(fmt.Sprint(panickingError{}))},
		{"nil pointer", (*nilPointerError)(nil), `"<nil>"`},
		{"panics with a value fmt cannot write", selfPanickingError{}, `"%!v(PANIC=Error method of netexcerpt_test.selfPanickingError)"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			var got string
			done := false
			func() {
				defer func() {
					r := recover()
					if !done {
						t.Fatalf("ErrorText panicked: %T", r)
					}
				}()
				got = netexcerpt.ErrorText(c.err)
				done = true
			}()
			if got != c.want {
				t.Errorf("ErrorText = %s, want %s", got, c.want)
			}
		})
	}
}
