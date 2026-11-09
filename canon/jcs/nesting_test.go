package jcs_test

import (
	"strings"
	"testing"

	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/internal/jsondepth"
)

func deepArrays(depth int) any {
	var v any = "x"
	for i := range depth {
		if i%2 == 0 {
			v = []any{v}
		} else {
			v = map[string]any{"k": v}
		}
	}
	return v
}

// Both canonicalizations write a value nested as deep as encoding/json
// decodes, jsondepth.Max objects and arrays alternating, and refuse one
// deeper, however it was built, before the serializer enters the level past
// the bound: two million deep, it would exhaust the goroutine stack, a fatal
// error. (Hash and HashRFC8785 write through them.)
func TestCanonicalize_RefusesNestingPastTheBound(t *testing.T) {
	for name, canonicalize := range map[string]func(any) ([]byte, error){"RFC 8785": jcs.CanonicalizeRFC8785, "legacy": jcs.Canonicalize} {
		out, err := canonicalize(deepArrays(jsondepth.Max))
		if err != nil || len(out) < 2*jsondepth.Max {
			t.Fatalf("%s, %d deep: %d bytes, %v", name, jsondepth.Max, len(out), err)
		}
		objects := func(depth int) any {
			var v any = "x"
			for range depth {
				v = map[string]any{"k": v}
			}
			return v
		}
		if _, err := canonicalize(objects(jsondepth.Max + 1)); err == nil || !strings.Contains(err.Error(), "nested deeper than") {
			t.Errorf("%s, %d objects deep: %v, want the nesting refused", name, jsondepth.Max+1, err)
		}
		for _, depth := range []int{jsondepth.Max + 1, 2000000} {
			if _, err := canonicalize(deepArrays(depth)); err == nil || !strings.Contains(err.Error(), "nested deeper than") {
				t.Errorf("%s, %d deep: %v, want the nesting refused", name, depth, err)
			}
		}
	}
}
