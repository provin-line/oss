package excerpt_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/provin-line/oss/internal/excerpt"
)

type nilPointerError struct{ text string }

func (e *nilPointerError) Error() string { return e.text }

// valueError has a value receiver, so calling Error through a nil pointer to
// it panics.
type valueError struct{}

func (valueError) Error() string { return "value" }

type panickingError struct{ value any }

func (e panickingError) Error() string { panic(e.value) }

// selfPanickingError panics with itself, a value fmt cannot write either.
type selfPanickingError struct{}

func (e selfPanickingError) Error() string { panic(e) }

// onceError panics the first time its Error is called, and returns after.
type onceError struct{ called *bool }

func (e onceError) Error() string {
	if !*e.called {
		*e.called = true
		panic("first")
	}
	return "second"
}

// formattingError writes under %v another text than its Error text.
type formattingError struct{}

func (formattingError) Error() string                 { return "plain" }
func (formattingError) Format(s fmt.State, verb rune) { _, _ = s.Write([]byte("formatted")) }

// OfError and the error it returns do not panic for an error that is a nil
// pointer or whose Error method panics, whatever it panics with; the text is
// within the limit, and errors.Is and errors.As find the error.
func TestOfError_AnErrorWhoseTextPanics(t *testing.T) {
	const limit = 64
	for _, c := range []struct {
		name string
		err  error
		want string // "" when only the bound is checked
	}{
		{"nil pointer", (*nilPointerError)(nil), "<nil>"},
		{"nil pointer to a value receiver", (*valueError)(nil), "<nil>"},
		{"panics", panickingError{"boom"}, "%!v(PANIC=Error method: boom)"},
		{"panics with a long value", panickingError{strings.Repeat("a\xff", 1000)}, ""},
		{"panics with a value fmt cannot write", selfPanickingError{}, "%!v(PANIC=Error method of excerpt_test.selfPanickingError)"},
		{"panics with nil", panickingError{nil}, cut(fmt.Sprint(panickingError{nil}), limit)},
		{"panics the first time", onceError{new(bool)}, "second"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var got error
			var text string
			returns(t, func() {
				got = excerpt.OfError(c.err, limit)
				text = got.Error()
			})
			if got == nil {
				t.Fatal("OfError returned nil")
			}
			if len(text) > limit || !utf8.ValidString(text) {
				t.Errorf("text: %d bytes (UTF-8: %v): %q", len(text), utf8.ValidString(text), text)
			}
			if c.want != "" && text != c.want {
				t.Errorf("text = %q, want %q", text, c.want)
			}
			if !errors.Is(got, c.err) {
				t.Error("errors.Is does not find the error")
			}
		})
	}
	var target *nilPointerError
	if !errors.As(excerpt.OfError((*nilPointerError)(nil), limit), &target) {
		t.Error("errors.As does not find the nil pointer")
	}
	if got := fmt.Sprint(excerpt.OfError(selfPanickingError{}, limit)); len(got) > limit {
		t.Errorf("%%v of the error OfError returns: %d bytes", len(got))
	}
}

// returns fails t when f panics, whatever with: it tells by whether f
// returned, since under GODEBUG=panicnil=1 recover returns nil for panic(nil).
func returns(t *testing.T, f func()) {
	t.Helper()
	done := false
	defer func() {
		r := recover()
		if !done {
			t.Fatalf("panicked: %T", r)
		}
	}()
	f()
	done = true
}

func cut(s string, limit int) string {
	t, _ := excerpt.Of(s, limit)
	return t
}

// OfError returns err itself when its Error method returns a text that fits,
// whatever fmt writes for it: also for a nil pointer, and for an error that
// writes another text under %v.
func TestOfError_TheErrorTextComesFirst(t *testing.T) {
	for name, err := range map[string]error{
		"formats itself":                  formattingError{},
		"nil pointer whose Error returns": (*safeNilError)(nil),
	} {
		if got := excerpt.OfError(err, 64); got != err {
			t.Errorf("%s: OfError = %v, not the error itself", name, got)
		}
	}
}

type safeNilError struct{}

func (e *safeNilError) Error() string {
	if e == nil {
		return "nil, and says so"
	}
	return "set"
}

// ErrorText is "<nil>" for nil, an error's Error text when Error returns
// (whatever fmt writes for it), and otherwise what OfError cuts; it does not
// panic, and the text is whole.
func TestErrorText(t *testing.T) {
	long := strings.Repeat("a\xff", 1000)
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "<nil>"},
		{"short", errors.New("short"), "short"},
		{"long, not UTF-8", errors.New(long), long},
		{"formats itself", formattingError{}, "plain"},
		{"nil pointer whose Error returns", (*safeNilError)(nil), "nil, and says so"},
		{"nil pointer", (*nilPointerError)(nil), "<nil>"},
		{"nil pointer to a value receiver", (*valueError)(nil), "<nil>"},
		{"panics", panickingError{"boom"}, "%!v(PANIC=Error method: boom)"},
		{"panics with nil", panickingError{nil}, fmt.Sprint(panickingError{nil})},
		{"panics with a value fmt cannot write", selfPanickingError{}, "%!v(PANIC=Error method of excerpt_test.selfPanickingError)"},
		{"panics the first time", onceError{new(bool)}, "second"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var got string
			returns(t, func() { got = excerpt.ErrorText(c.err) })
			if got != c.want {
				t.Errorf("ErrorText = %.80q, want %.80q", got, c.want)
			}
		})
	}
}

// underPanicNil is set in the environment of the test binary run again under
// GODEBUG=panicnil=1.
const underPanicNil = "EXCERPT_TEST_UNDER_PANICNIL"

// The tests of an error whose text panics hold also where recover returns nil
// for panic(nil) (GODEBUG=panicnil=1): the test binary runs them again so,
// and checks first that the setting is in effect.
func TestErrorTextUnderPanicNil(t *testing.T) {
	if os.Getenv(underPanicNil) != "" {
		var r any
		func() {
			defer func() { r = recover() }()
			panic(nil)
		}()
		if r != nil {
			t.Fatalf("recover() = %T: GODEBUG=panicnil=1 is not in effect", r)
		}
		return
	}
	tests := []string{"TestErrorTextUnderPanicNil", "TestOfError_AnErrorWhoseTextPanics", "TestErrorText"}
	cmd := exec.Command(os.Args[0], "-test.run=^("+strings.Join(tests, "|")+")$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "GODEBUG=panicnil=1", underPanicNil+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("under GODEBUG=panicnil=1: %v\n%s", err, out)
	}
	for _, name := range tests {
		if !strings.Contains(string(out), "--- PASS: "+name+" ") {
			t.Errorf("under GODEBUG=panicnil=1, %s did not pass:\n%s", name, out)
		}
	}
}
