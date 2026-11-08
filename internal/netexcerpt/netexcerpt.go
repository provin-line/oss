// Package netexcerpt holds how much of others' text the network writes: the
// limits the network's packages give package excerpt when they write text
// taken from a request, a peer's answer, a stored artifact or a lookup into an
// error a caller receives, a record they keep or serve, or a log line. How a
// text is cut is package excerpt's.
//
// A value named inside a sentence the network writes (a hash, a key, a DID,
// an endpoint) takes at most ValueLimit bytes. In a log line it is written
// with excerpt.Quoted and formatted with %s: Quoted counts its escapes in the
// limit, which %q of a value cut with excerpt.Of would not, and leaves no line
// break of the input in the line. A whole text (the message of an error, one
// notation, an error inside a log line) takes at most TextLimit bytes.
package netexcerpt

const (
	// ValueLimit is the most bytes a value the network names takes, its
	// quotes and the length excerpt adds included.
	ValueLimit = 128
	// TextLimit is the most bytes a whole text the network writes from
	// others' input takes, the length excerpt adds included.
	TextLimit = 1024
)
