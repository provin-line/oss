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

// ErrorText writes an error as %v does when its Error method panics or its
// value is a nil pointer, instead of panicking itself.
func TestErrorTextOfAnErrorThatPanics(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
	}{
		{"panicking Error method", panickingError{}},
		{"nil pointer", (*nilPointerError)(nil)},
	} {
		got := func() (s string) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: ErrorText panicked: %v", c.name, r)
				}
			}()
			return netexcerpt.ErrorText(c.err)
		}()
		if want := strconv.Quote(fmt.Sprint(c.err)); got != want {
			t.Errorf("%s: ErrorText = %s, want %s", c.name, got, want)
		}
	}
}
