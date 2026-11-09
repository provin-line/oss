// Package pipeexcerpt holds how much of others' text the pipeline writes,
// and how: the limits its packages give package excerpt when they write text
// taken from an event, a credential, a peer's answer or a push into an error a
// caller or an observer receives, a record they keep (a reject, a decision's
// reason), an answer to a push, or a log line. How a text is cut is package
// excerpt's.
//
// A whole text or a field the pipeline writes (an error's message, a reject's
// detail or issuer, a decision's reason, an answer's text) takes at most
// TextLimit bytes (Text). A value named inside a sentence the pipeline writes
// (an output hash, an issuer) is written with Value, quoted within
// ValueLimit bytes, so a long one does not push the rest of the sentence out.
// An error in a log line is written with ErrorText and passed as a string:
// the log's handler quotes it. A sentence the pipeline builds around an
// error (a result's error, a reject's detail, a decision's reason) takes the
// error's text with excerpt.ErrorText, and the whole is held to TextLimit
// where it is written.
//
// The values are the network's (internal/netexcerpt) because the texts are
// of the same kinds; each side owns its own.
package pipeexcerpt

import "github.com/provin-line/oss/internal/excerpt"

const (
	// ValueLimit is the most bytes a value the pipeline names takes, its
	// quotes and the length excerpt adds included.
	ValueLimit = 128
	// TextLimit is the most bytes a text or a field the pipeline writes from
	// others' input takes, the length excerpt adds included.
	TextLimit = 1024
)

// Text is s as the pipeline writes it: whole when it is UTF-8 within
// TextLimit bytes, or else its head and its length, "… (N bytes)" (package
// excerpt), with what is not UTF-8 replaced.
func Text(s string) string {
	t, _ := excerpt.Of(s, TextLimit)
	return t
}

// Value is s as a sentence the pipeline writes names it: quoted, within
// ValueLimit bytes, escapes counted.
func Value(s string) string {
	return excerpt.Quoted(s, ValueLimit)
}

// ErrorText is err as a log line of the pipeline names it: the text
// excerpt.ErrorText takes for it (its Error text, a nil pointer's too; what
// fmt writes when Error panics, such as "<nil>" for a nil pointer; a fixed
// text when fmt panics too; "<nil>" for nil), held as Text holds a text. It
// is a string, so the log's handler writes it as it is and not under a verb
// an error may format itself for.
func ErrorText(err error) string {
	return Text(excerpt.ErrorText(err))
}
