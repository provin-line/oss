package canon

// Error is the type of the errors this package reports by value. This
// package's functions wrap them with the detail of each failure; match them
// with errors.Is.
//
// Compare an error with a sentinel by errors.Is alone: that an error is an
// Error under errors.As, or equal to a sentinel under ==, is not promised.
type Error string

func (e Error) Error() string { return string(e) }

// quotedLimit is the most bytes an error of this package writes of one value
// it quotes from its input (a literal, a member name, a path), and
// decodeErrorLimit the most it writes of the error of the typed decode
// StrictDecoder runs, which encoding/json and a type's own decoding write
// from the input. The values are cut as package excerpt cuts them.
const (
	quotedLimit      = 128
	decodeErrorLimit = 1024
)
