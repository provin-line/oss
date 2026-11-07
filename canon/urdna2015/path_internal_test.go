package urdna2015

import (
	"runtime"
	"strings"
	"testing"
)

// deep nests n objects and arrays, alternately, around a string.
func deep(n int) any {
	var v any = "leaf"
	for i := range n {
		if i%2 == 0 {
			v = map[string]any{"https://example.org/p": v}
		} else {
			v = []any{v}
		}
	}
	return v
}

// The walk spells the path to a value only into an error: walking a document
// nested 10 000 deep costs at most 256 bytes a level, and refusing one spells
// the whole path.
func TestRejectSilentDrops_SpellsThePathOnlyOnError(t *testing.T) {
	const depth = 10000
	ok := deep(depth)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if err := rejectSilentDrops(ok, new(jsonPath)); err != nil {
		t.Fatalf("valid document: %v", err)
	}
	runtime.ReadMemStats(&after)
	if got := after.TotalAlloc - before.TotalAlloc; got > 256*depth {
		t.Errorf("walking %d levels allocated %d bytes, want at most %d", depth, got, 256*depth)
	}

	var refused any = nil
	for range depth {
		refused = map[string]any{"k": refused}
	}
	err := rejectSilentDrops(refused, new(jsonPath))
	if err == nil {
		t.Fatal("null 10000 deep: want error")
	}
	if want := strings.Repeat("/k", depth); !strings.Contains(err.Error(), want) {
		t.Errorf("error does not spell the path to the null:\n%.200s", err)
	}
}

// The path is spelled as before: "/"-separated keys and indexes.
func TestRejectSilentDrops_SpellsThePath(t *testing.T) {
	doc := map[string]any{"a": []any{"x", map[string]any{"b": nil}}}
	err := rejectSilentDrops(doc, new(jsonPath))
	if err == nil || !strings.Contains(err.Error(), `"/a/1/b"`) {
		t.Errorf("err = %v, want the path \"/a/1/b\"", err)
	}
	graph := map[string]any{"@graph": []any{map[string]any{}, "rider"}}
	err = rejectSilentDrops(graph, new(jsonPath))
	if err == nil || !strings.Contains(err.Error(), "element 1 of /@graph") {
		t.Errorf("err = %v, want element 1 of /@graph", err)
	}
}

// A container wide at any depth costs no more per value than a narrow one:
// d single-member objects around an array of 64 strings, for every d up to
// 2048, cost at most 256 bytes a value.
func TestRejectSilentDrops_CostsTheSameAtEveryDepth(t *testing.T) {
	leaves := make([]any, 64)
	for i := range leaves {
		leaves[i] = "x"
	}
	for d := 1; d <= 2048; d++ {
		var v any = leaves
		for range d {
			v = map[string]any{"a": v}
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		if err := rejectSilentDrops(v, new(jsonPath)); err != nil {
			t.Fatal(err)
		}
		runtime.ReadMemStats(&after)
		values := uint64(d + 1 + len(leaves))
		if got := after.TotalAlloc - before.TotalAlloc; got > 256*values {
			t.Fatalf("depth %d: %d bytes for %d values (%d a value), want at most 256 a value", d, got, values, got/values)
		}
	}
}
