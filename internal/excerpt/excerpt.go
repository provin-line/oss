// Package excerpt writes text within a byte bound, for quoting what this
// module took from its input (a JSON literal, a member name, a path) in the
// text of an error, so the size of that text does not follow the input's: the
// text whole when it fits, or else its head and its length, "… (N bytes)".
// The limit is each caller's; how a text is cut and how its length is written
// are this package's.
//
// Its promises, for every text and every limit from MinLimit:
//   - what it writes is at most limit bytes, the length it adds included;
//   - it is valid UTF-8: each run of bytes that is not is replaced by one
//     U+FFFD before anything else, so nothing it writes ends in part of a
//     character, whether the text given was UTF-8 or not;
//   - a head is cut where a character starts;
//   - N is the length in bytes of the text given, not of what is written,
//     so a text whose replacements make it too long is cut and says the
//     length it had.
//
// A limit under MinLimit is its caller's error, and every function panics on
// it, whatever the text: MinLimit is what the longest length it writes takes,
// so a limit from MinLimit never panics, whatever the input.
package excerpt

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MinLimit is the least limit the functions take: the two quotes of a quoted
// head and the longest length, "… (N bytes)" with N of 19 digits.
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
// counted in the limit.
func Quoted(s string, limit int) string {
	check(limit)
	t := strings.ToValidUTF8(s, "\uFFFD")
	if len(t)+2 <= limit {
		if q := strconv.Quote(t); len(q) <= limit {
			return q
		}
	}
	tail := length(s)
	room := limit - len(tail) - 2
	b := []byte{'"'}
	for _, r := range t {
		q := strconv.Quote(string(r))
		q = q[1 : len(q)-1]
		if len(b)-1+len(q) > room {
			break
		}
		b = append(b, q...)
	}
	return string(append(b, '"')) + tail
}

// OfError is err within limit bytes: err itself when Of leaves its text as it
// is (nil for nil), or else an error whose text is Of its text (cut, or made
// UTF-8) and which wraps err, so errors.Is and errors.As find what err does.
// Only its text is bounded: the error it wraps is whole, and a tool that
// writes the wrapped errors out writes them whole.
func OfError(err error, limit int) error {
	check(limit)
	if err == nil {
		return nil
	}
	s := err.Error()
	text, _ := Of(s, limit)
	if text == s {
		return err
	}
	return &cutError{text: text, err: err}
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
