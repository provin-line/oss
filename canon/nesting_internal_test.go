package canon

import (
	"errors"
	"strings"
	"testing"

	"github.com/provin-line/oss/internal/jsondepth"
)

// deepArrays is depth arrays and objects, alternating, around a string, built
// in Go: far deeper than any decoder here reads.
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

// AdmitSafeNumbers admits a value nested as deep as encoding/json decodes,
// jsondepth.Max objects and arrays, and refuses one deeper, however it was
// built, before its walk enters the level past the bound: two million deep,
// the walk would exhaust the goroutine stack, a fatal error.
func TestAdmitSafeNumbers_RefusesNestingPastTheBound(t *testing.T) {
	if err := AdmitSafeNumbers(deepArrays(jsondepth.Max)); err != nil {
		t.Fatalf("%d deep: %v", jsondepth.Max, err)
	}
	objects := func(depth int) any {
		var v any = "x"
		for range depth {
			v = map[string]any{"k": v}
		}
		return v
	}
	if err := AdmitSafeNumbers(objects(jsondepth.Max + 1)); err == nil || !strings.Contains(err.Error(), "nested deeper than") {
		t.Errorf("%d objects deep: %v, want the nesting refused", jsondepth.Max+1, err)
	}
	for _, depth := range []int{jsondepth.Max + 1, 2000000} {
		err := AdmitSafeNumbers(deepArrays(depth))
		var unsafe *UnsafeNumberError
		if err == nil || errors.As(err, &unsafe) || !strings.Contains(err.Error(), "nested deeper than") {
			t.Errorf("%d deep: %v, want the nesting refused", depth, err)
		}
	}
}
