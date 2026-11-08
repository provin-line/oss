// Package netexcerpt holds how much of others' text the network writes, and
// how: the limits the network's packages give package excerpt when they write
// text taken from a request, a peer's answer, a stored artifact or a lookup
// into an error a caller receives, a record they keep or serve, or a log line,
// and the form a value or an error takes inside a sentence the network writes.
// How a text is cut is package excerpt's.
//
// A value named inside a sentence the network writes (a hash, a key, a DID,
// an endpoint) is written with ValueText, and an error with ErrorText; each
// is formatted with %s. Both quote the text and count its escapes in the
// limit (which %q of a text cut with excerpt.Of would not), so a line break of
// the input stays out of the line. A whole text (the message of an error, one
// notation) takes at most TextLimit bytes.
package netexcerpt

import (
	"fmt"

	"github.com/provin-line/oss/internal/excerpt"
)

const (
	// ValueLimit is the most bytes a value the network names takes, its
	// quotes and the length excerpt adds included.
	ValueLimit = 128
	// TextLimit is the most bytes a whole text the network writes from
	// others' input takes, the length excerpt adds included.
	TextLimit = 1024
)

// ValueText is s as a sentence the network writes names it: quoted, within
// ValueLimit bytes.
func ValueText(s string) string {
	return excerpt.Quoted(s, ValueLimit)
}

// ErrorText is err as a sentence the network writes names it: the text %v
// writes for it (its Error text, or what fmt writes when Error panics or err
// is a nil pointer), quoted, within TextLimit bytes; "<nil>" for nil.
func ErrorText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return excerpt.Quoted(fmt.Sprint(err), TextLimit)
}
