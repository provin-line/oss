package jsondepth_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/provin-line/oss/internal/jsondepth"
)

// nested is depth objects and arrays, alternating, around a string.
func nested(depth int) any {
	var v any = "leaf"
	for i := range depth {
		if i%2 == 0 {
			v = map[string]any{"k": v}
		} else {
			v = []any{v}
		}
	}
	return v
}

// Max is as deep as encoding/json decodes: a document of Max arrays decodes,
// one of Max+1 does not, so no document decoded by it passes the bound.
func TestMax_IsAsDeepAsEncodingJSONDecodes(t *testing.T) {
	var v any
	if err := json.Unmarshal([]byte(strings.Repeat("[", jsondepth.Max)+strings.Repeat("]", jsondepth.Max)), &v); err != nil {
		t.Errorf("%d arrays: %v", jsondepth.Max, err)
	}
	if err := json.Unmarshal([]byte(strings.Repeat("[", jsondepth.Max+1)+strings.Repeat("]", jsondepth.Max+1)), &v); err == nil {
		t.Errorf("%d arrays decoded; Max is no longer as deep as encoding/json decodes", jsondepth.Max+1)
	}
}

// A value is within the bound when it nests at most Max objects and arrays
// deep; a scalar nests none.
func TestWithin_CountsObjectsAndArrays(t *testing.T) {
	for name, tc := range map[string]struct {
		v    any
		want bool
	}{
		"a scalar":                         {"x", true},
		"Max deep":                         {nested(jsondepth.Max), true},
		"Max+1 deep":                       {nested(jsondepth.Max + 1), false},
		"Max deep beside a shallow member": {map[string]any{"a": "x", "b": nested(jsondepth.Max - 1)}, true},
		"Max+1 deep in a list's last item": {[]any{"x", "y", nested(jsondepth.Max)}, false},
	} {
		if got := jsondepth.Within(tc.v); got != tc.want {
			t.Errorf("%s: Within = %v, want %v", name, got, tc.want)
		}
	}
}

// Within keeps its own stack: a value far deeper than a recursive walk could
// enter, built in Go, is reported past the bound rather than exhausting the
// goroutine stack.
func TestWithin_IsSafeAtAnyDepth(t *testing.T) {
	if jsondepth.Within(nested(500000)) {
		t.Error("500,000 deep: within the bound")
	}
}
