// Package jsondepth holds how deep this module reads a JSON value: the
// deepest nesting of objects and arrays, Max. It is the number encoding/json
// decodes to, so a value decoded by encoding/json or canon.StrictDecoder never
// passes it; a value built in Go can be deeper.
//
// A walk of a decoded value that recurses once or more per level refuses a
// value deeper than Max before it enters the level past it, as a goroutine
// stack exhausted is a fatal error no recover catches. A walk that counts its
// own depth (a path, a depth argument) compares it with Max; one that cannot,
// such as a library's, is preceded by Within. The refusal's error is each
// package's own.
package jsondepth

// Max is the deepest nesting of objects and arrays this module reads: 10,000,
// as deep as encoding/json decodes (its maxNestingDepth).
const Max = 10000

// Within reports whether v, a value as encoding/json decodes into an any
// (objects as map[string]any, arrays as []any), nests at most Max objects and
// arrays deep. A scalar nests none. It keeps its own stack rather than
// recursing, so it is safe at any depth.
func Within(v any) bool {
	type item struct {
		v     any
		depth int
	}
	stack := []item{{v, 1}}
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch t := it.v.(type) {
		case map[string]any:
			if it.depth > Max {
				return false
			}
			for _, x := range t {
				stack = append(stack, item{x, it.depth + 1})
			}
		case []any:
			if it.depth > Max {
				return false
			}
			for _, x := range t {
				stack = append(stack, item{x, it.depth + 1})
			}
		}
	}
	return true
}
