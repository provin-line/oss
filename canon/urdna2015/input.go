package urdna2015

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/provin-line/oss/internal/excerpt"
)

// requireNodeObjects fails unless every element of a node-array position
// (the top-level array, an @graph value) is a JSON object — expansion drops
// scalar entries in those positions silently, so [{…}, "rider"] would
// canonicalize as [{…}].
func requireNodeObjects(list []any, where func() string) error {
	for i, e := range list {
		if _, ok := e.(map[string]any); !ok {
			return fmt.Errorf("urdna2015: element %d of %s is %T, want a JSON object — expansion drops scalar node-array entries silently (an unsigned rider)", i, where(), e)
		}
	}
	return nil
}

// jsonPath is the location of a value in the input, one segment a level: an
// array element's index (index ≥ 0), or an object member's key (index −1).
// The walk pushes and pops one shared stack and spells it only into an error,
// so walking a document costs no more than its size, however deep or wide.
type jsonPath []pathSegment

type pathSegment struct {
	key   string
	index int
}

// pathQuoteLimit bounds the path a refusal quotes: a path is as long as the
// keys and the depth of the document that holds it.
const pathQuoteLimit = 256

// quoted is the path quoted for a refusal, within pathQuoteLimit bytes: whole
// when it fits, or else its head and its length.
func (p *jsonPath) quoted() string { return excerpt.Quoted(p.String(), pathQuoteLimit) }

func (p *jsonPath) String() string {
	var b strings.Builder
	for _, s := range *p {
		b.WriteByte('/')
		if s.index >= 0 {
			b.WriteString(strconv.Itoa(s.index))
		} else {
			b.WriteString(s.key)
		}
	}
	return b.String()
}

// rejectSilentDrops walks the raw input and fails on every value expansion
// would discard or mutate without an error: a number, which json-gold carries
// through float64, cutting an integer above 2^53 (encode one as a string on
// the RDFC path); null, which expansion drops (JSON-LD's null-equals-omission;
// omit the member instead); a non-object @graph entry; and a member named ""
// outside a context, which JSON-LD gives no meaning. path is the
// JSON-pointer-ish location of v, for the error; inContext is whether v is in
// a context (a member named @context is always one, as JSON-LD gives @context
// no alias).
func rejectSilentDrops(v any, path *jsonPath, inContext bool) error {
	switch t := v.(type) {
	case map[string]any:
		if _, ok := t[""]; ok && !inContext {
			return fmt.Errorf("urdna2015: a member named \"\" at %s: JSON-LD gives the empty name no meaning, so the RDFC path does not read it", path.quoted())
		}
		for _, k := range sortedKeys(t) {
			e := t[k]
			*path = append(*path, pathSegment{key: k, index: -1})
			if k == "@graph" {
				if list, ok := e.([]any); ok {
					if err := requireNodeObjects(list, path.quoted); err != nil {
						return err
					}
				}
			}
			if err := rejectSilentDrops(e, path, inContext || k == "@context"); err != nil {
				return err
			}
			*path = (*path)[:len(*path)-1]
		}
	case []any:
		for i, e := range t {
			*path = append(*path, pathSegment{index: i})
			if err := rejectSilentDrops(e, path, inContext); err != nil {
				return err
			}
			*path = (*path)[:len(*path)-1]
		}
	case string, bool:
		// The value types the RDFC path canonicalizes losslessly.
	case nil:
		return fmt.Errorf("urdna2015: refusing null at %s: JSON-LD expansion drops null members and null array entries silently (an unsigned rider) — omit the member instead", path.quoted())
	default:
		// json.Number, float64, and every other scalar type land here.
		return fmt.Errorf("urdna2015: refusing value of type %T at %s: JSON numbers are rejected on the RDFC path (integers above 2^53 are silently truncated in JSON-LD processing) — encode numeric values as strings", v, path.quoted())
	}
	return nil
}

// valueQuoteLimit bounds a key or value a refusal quotes, its quotes, escapes
// and length included. excerpt takes no limit under excerpt.MinLimit; at 64,
// a key or value too long to quote whole leaves 64 - excerpt.MinLimit = 31
// bytes or more for its head as quoted, whatever its length (an escape that
// does not fit is left out, and an escaped byte takes more than one), so a
// refusal still says which one it names.
const valueQuoteLimit = 64

// valueQuoteLimit is at least excerpt.MinLimit: the constant expression would
// not compile otherwise.
const _ = uint(valueQuoteLimit - excerpt.MinLimit)

// bounded is s quoted for a refusal, as excerpt quotes it within
// valueQuoteLimit: whole when its quoted form fits, or else its head and its
// length, valid UTF-8; so an error never carries a whole literal.
func bounded(s string) string { return excerpt.Quoted(s, valueQuoteLimit) }
