// Package excerpt writes text within a byte bound, for quoting what this
// module took from its input (a JSON literal, a member name, a path) in the
// text of an error, so the size of that text does not follow the input's: the
// text whole when it fits, or else its head and its length, "… (N bytes)".
// The limit is each caller's; how a text is cut and how its length is written
// are this package's, and so is how the text of an error is taken
// (ErrorText), so that a panic of the error's methods does not leave the
// function that takes it.
//
// The promises of the functions that take a limit, for every text and every
// limit from MinLimit:
//   - what it writes is at most limit bytes, the length it adds included;
//   - it is valid UTF-8, whether the text given was or not, so nothing it
//     writes ends in part of a character: Of replaces each run of bytes that
//     is not UTF-8 by one U+FFFD before anything else (a text written as it
//     is has no escape to name a byte with), and Quoted writes each such
//     byte as \xNN, as strconv.Quote does, so the byte stays named;
//   - a head is cut where a character starts;
//   - N is the length in bytes of the text given, not of what is written,
//     so a text whose replacements or escapes make it too long is cut and
//     says the length it had.
//
// A limit under MinLimit is its caller's error, and every function that takes
// a limit panics on it, whatever the text: MinLimit is what the longest length
// it writes takes, so a limit from MinLimit never panics, whatever the input.
package excerpt

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MinLimit is the least limit the functions that take one accept: the two
// quotes of a quoted head and the longest length, "… (N bytes)" with N of 19
// digits.
const MinLimit = len(`""… (`) + len("9223372036854775807") + len(" bytes)")

// Of is s within limit bytes: whole when it fits, or else its head and its
// length, "… (N bytes)"; and whether it was cut.
func Of(s string, limit int) (string, bool) {
	check(limit)
	t := strings.ToValidUTF8(s, "\uFFFD")
	if len(t) <= limit {
		return t, false
	}
	tail := length(s)
	n := limit - len(tail)
	for !utf8.RuneStart(t[n]) {
		n--
	}
	return t[:n] + tail, true
}

// Quoted is s as a quoted Go string (strconv.Quote) within limit bytes, for
// naming what is quoted: whole when its quoted form fits, or else its head
// quoted and its length after the quotes, "head"… (N bytes), escapes
// counted in the limit. A byte that is not UTF-8 is written as \xNN, as
// strconv.Quote writes it, and the head unquotes to the first bytes of s.
func Quoted(s string, limit int) string {
	check(limit)
	if len(s)+2 <= limit {
		if q := strconv.Quote(s); len(q) <= limit {
			return q
		}
	}
	tail := length(s)
	room := limit - len(tail) - 2
	b := []byte{'"'}
	for i := 0; i < len(s); {
		_, size := utf8.DecodeRuneInString(s[i:])
		q := strconv.Quote(s[i : i+size])
		q = q[1 : len(q)-1]
		if len(b)-1+len(q) > room {
			break
		}
		b = append(b, q...)
		i += size
	}
	return string(append(b, '"')) + tail
}

// OfError is err within limit bytes: err itself when its Error method returns
// a text that Of leaves as it is (nil for nil), or else an error whose text is
// Of the text ErrorText takes for err (cut, made UTF-8, or taken where Error
// panicked) and which wraps err, so errors.Is and errors.As find what err
// does. Returning err itself takes Error to return the same text each time it
// is called. Only its text is bounded: the error it wraps is whole, and a tool
// that writes the wrapped errors out writes them whole.
func OfError(err error, limit int) error {
	out, _ := OfErrorChanged(err, limit)
	return out
}

// OfErrorChanged is OfError(err, limit), and whether it returns a new error
// in place of err: false when it returns err itself (nil and false for nil),
// true when it returns a new error that wraps err, whose text is Of the text
// ErrorText takes for err (cut, made UTF-8, or taken where Error panicked). A
// caller tells which by the bool rather than by comparing the errors, which
// panics when err's value is one == cannot compare (it holds a slice, a map
// or a func, also inside an interface field). Returning err itself takes Error
// to return the same text each time it is called.
func OfErrorChanged(err error, limit int) (error, bool) {
	check(limit)
	if err == nil {
		return nil, false
	}
	s, own := errorText(err)
	text, _ := Of(s, limit)
	if own && text == s {
		return err, false
	}
	return &cutError{text: text, err: err}, true
}

// ErrorText is the text of err that this package cuts, taken so that a panic
// of err's methods does not leave it:
//   - "<nil>" for nil;
//   - err's Error text when Error returns, a nil pointer's too;
//   - when Error panics, what fmt.Sprint writes for err, which calls err's
//     methods again (such as "<nil>" for a nil pointer, or the panic);
//   - when that panics too, "%!v(PANIC=Error method of T)", T being err's
//     type as %T writes it.
//
// The text is whole, of any length and maybe not UTF-8, for Of or Quoted to
// cut. It does not return while err's methods do not: they loop, end the
// goroutine, or end the program with a fatal error such as a stack overflow.
func ErrorText(err error) string {
	text, _ := errorText(err)
	return text
}

// errorText is ErrorText's text for err, and whether it is what err's Error
// method returned.
func errorText(err error) (text string, own bool) {
	if err == nil {
		return "<nil>", false
	}
	if text, ok := returned(err.Error); ok {
		return text, true
	}
	if text, ok := returned(func() string { return fmt.Sprint(err) }); ok {
		return text, false
	}
	return fmt.Sprintf("%%!v(PANIC=Error method of %T)", err), false
}

// returned is f's text and true when f returns, or else "" and false: a panic
// of f, whatever its value (nil too), stops here.
func returned(f func() string) (text string, ok bool) {
	defer func() { _ = recover() }()
	return f(), true
}

type cutError struct {
	text string
	err  error
}

func (e *cutError) Error() string { return e.text }
func (e *cutError) Unwrap() error { return e.err }

func length(s string) string { return fmt.Sprintf("… (%d bytes)", len(s)) }

func check(limit int) {
	if limit < MinLimit {
		panic(fmt.Sprintf("excerpt: limit %d is under MinLimit (%d)", limit, MinLimit))
	}
}
