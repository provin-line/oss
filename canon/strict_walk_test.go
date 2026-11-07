package canon_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/provin-line/oss/canon"
)

// A duplicate key reports the path to the object that holds it, through every
// object member and array index above it, whatever siblings came before.
func TestStrictDecoder_DuplicateKeyReportsItsPath(t *testing.T) {
	for _, c := range []struct {
		doc  string
		path []string
	}{
		{`{"a":1,"a":2}`, []string{}},
		{`{"a":[{"x":1},{"b":1,"b":2}]}`, []string{"a", "1"}},
		{`{"a":{"p":[1,[2,{"q":3}]]},"c":[{"q":1},{"d":{"e":1,"e":2}}]}`, []string{"c", "1", "d"}},
		{`[[0,1,2],[[{"k":0}],{"m":[{}],"n":{"k":1,"k":2}}]]`, []string{"1", "1", "n"}},
	} {
		var v any
		err := canon.NewStrictDecoder([]byte(c.doc)).Decode(&v)
		var dup *canon.DuplicateKeyError
		if !errors.As(err, &dup) {
			t.Errorf("Decode(%s): want DuplicateKeyError, got %v", c.doc, err)
			continue
		}
		if !slices.Equal(dup.Path, c.path) {
			t.Errorf("Decode(%s): Path = %q, want %q", c.doc, dup.Path, c.path)
		}
	}
}

// nestedMixed opens depth arrays and objects, alternating by the bits of
// pattern, around a zero.
func nestedMixed(depth int, pattern uint64) []byte {
	var open, close bytes.Buffer
	for i := range depth {
		if pattern>>(i%64)&1 == 0 {
			open.WriteString("[")
			close.WriteString("]")
		} else {
			open.WriteString(`{"k":`)
			close.WriteString("}")
		}
	}
	closing := close.Bytes()
	slices.Reverse(closing)
	return append(append(open.Bytes(), '0'), closing...)
}

// The decoder takes a document nested exactly as deep as encoding/json
// decodes, in arrays, objects or both, and refuses one level more.
func TestStrictDecoder_NestingAsDeepAsEncodingJSON(t *testing.T) {
	for _, depth := range []int{9999, 10000, 10001, 10002} {
		for _, pattern := range []uint64{0, ^uint64(0), 0x5555555555555555, 0x0f0f0f0f0f0f0f0f, 0x123456789abcdef} {
			doc := nestedMixed(depth, pattern)
			var v any
			err := canon.NewStrictDecoder(doc).Decode(&v)
			if want := json.Valid(doc); (err == nil) != want {
				t.Errorf("Decode(depth %d, pattern %x): err = %v, encoding/json accepts it: %t", depth, pattern, err, want)
			}
		}
	}
}

// A document nested far deeper than any decoder takes is refused, in time
// and stack bounded by the depth limit rather than by the document: walking
// a megabyte of "[" one level per call would exhaust the goroutine stack,
// which no recover catches.
func TestStrictDecoder_RefusesAMegabyteOfNesting(t *testing.T) {
	for _, doc := range [][]byte{
		bytes.Repeat([]byte("["), 1<<20),
		bytes.Repeat([]byte(`{"k":`), 1<<18),
	} {
		var v any
		if err := canon.NewStrictDecoder(doc).Decode(&v); err == nil {
			t.Errorf("Decode(%.10s… × %d bytes) accepted it", doc, len(doc))
		}
	}
}

// Past the depth limit the walk stops: a duplicate key after the too-deep
// part is never reached, so the document is refused for its depth.
func TestStrictDecoder_StopsAtTheDepthLimit(t *testing.T) {
	doc := []byte(`[` + string(nestedMixed(10001, 0)) + `,{"a":1,"a":2}]`)
	var v any
	err := canon.NewStrictDecoder(doc).Decode(&v)
	var dup *canon.DuplicateKeyError
	if err == nil || errors.As(err, &dup) {
		t.Errorf("Decode: err = %v, want a refusal for depth", err)
	}
}

// appendFullDepth is a nesting depth at which a path grown from nil by one
// append per level has no spare capacity, so an append per sibling there
// would copy the whole path each time.
func appendFullDepth(near int) int {
	var p []string
	full := 0
	for len(p) < near {
		p = append(p, "")
		if len(p) == cap(p) {
			full = len(p)
		}
	}
	return full
}

// nestedSiblings is levels nested arrays whose innermost holds siblings zeros.
func nestedSiblings(levels, siblings int) []byte {
	var b bytes.Buffer
	b.WriteString(strings.Repeat("[", levels))
	for i := range siblings {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('0')
	}
	b.WriteString(strings.Repeat("]", levels))
	return b.Bytes()
}

func bytesAllocatedByDecode(t *testing.T, doc []byte) uint64 {
	t.Helper()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var v any
	if err := canon.NewStrictDecoder(doc).Decode(&v); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// The walk keeps one path for the whole document: siblings deep in a document
// cost what they cost near its root, so the work is linear in the document,
// not in its depth times its width.
func TestStrictDecoder_SiblingsCostTheSameAtAnyDepth(t *testing.T) {
	const siblings = 4096
	levels := appendFullDepth(4096) + 1
	deep := bytesAllocatedByDecode(t, nestedSiblings(levels, siblings))
	shallow := bytesAllocatedByDecode(t, nestedSiblings(1, siblings))
	// The deep document has levels-1 more arrays, each a few hundred bytes to
	// walk and decode; nothing is paid again per sibling.
	if budget := uint64(levels) * 1024; deep > shallow+budget {
		t.Errorf("%d siblings at depth %d allocate %d bytes, at depth 1 %d: more than %d bytes per level",
			siblings, levels, deep, shallow, budget/uint64(levels))
	}
}

// The cost of a document grows with its length, not with its depth times its
// width: the MB/s at depth 1 and deep down are the same, and stay flat as the
// siblings grow.
func BenchmarkStrictDecoder_DeepSiblings(b *testing.B) {
	for _, levels := range []int{1, appendFullDepth(8192) + 1} {
		for _, siblings := range []int{1 << 10, 1 << 13, 1 << 16} {
			doc := nestedSiblings(levels, siblings)
			b.Run(fmt.Sprintf("depth%d/siblings%d", levels, siblings), func(b *testing.B) {
				b.SetBytes(int64(len(doc)))
				for b.Loop() {
					var v any
					if err := canon.NewStrictDecoder(doc).Decode(&v); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
