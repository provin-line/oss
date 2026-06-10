package canon

import "fmt"

// DuplicateKeyError reports a duplicate object key encountered during strict
// decoding, with the path to the offending object for diagnostics.
type DuplicateKeyError struct {
	Key  string
	Path []string
}

func (e *DuplicateKeyError) Error() string {
	return fmt.Sprintf("duplicate JSON key %q at %v", e.Key, e.Path)
}

// StrictDecoder is the only JSON decode path permitted on protocol
// boundaries. It enforces, in order:
//
//  1. duplicate-key rejection (RFC 8785 §3.2.5) — returns *DuplicateKeyError
//  2. trailing-data rejection — a document must be exactly one JSON value
//  3. numeric precision preservation — numbers decode as json.Number so
//     integers above 2^53 survive round-trips
//
// Direct encoding/json decoding on a protocol path requires a
// `decoder-hygiene-exempt` comment and is checked by CI.
type StrictDecoder struct {
	data []byte
	used bool
}

// NewStrictDecoder returns a single-shot decoder over data.
func NewStrictDecoder(data []byte) *StrictDecoder { panic("not implemented") }

// Decode decodes the document into v under the strict rules. A second call
// returns io.EOF.
func (d *StrictDecoder) Decode(v any) error { panic("not implemented") }
