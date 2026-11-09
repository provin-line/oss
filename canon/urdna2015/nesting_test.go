package urdna2015

import (
	"errors"
	"fmt"
	"testing"
)

// nestedNodes is a node holding a node through urn:p, depth objects deep.
func nestedNodes(depth int) map[string]any {
	node := map[string]any{"@id": "urn:leaf", "urn:q": "v"}
	for i := 1; i < depth; i++ {
		node = map[string]any{"@id": fmt.Sprintf("urn:d:%d", i), "urn:p": node}
	}
	return node
}

// A document nested as deep as encoding/json and canon.StrictDecoder decode,
// 10,000 objects and arrays, is accepted; one deeper, however it was built,
// is refused with an error wrapping ErrTooComplex, before any walk of
// Canonicalize recurses into it. 30,000 is one well past the bound.
func TestCanonicalize_RefusesNestingPastTheBound(t *testing.T) {
	c := NewCanonicalizer(nil)
	if _, err := c.Canonicalize(nestedNodes(10000)); err != nil {
		t.Fatalf("10,000 deep: %v", err)
	}
	for _, depth := range []int{10001, 30000} {
		if _, err := c.Canonicalize(nestedNodes(depth)); !errors.Is(err, ErrTooComplex) {
			t.Errorf("%d deep: %v, want ErrTooComplex", depth, err)
		}
	}
	if _, err := c.Canonicalize([]any{nestedNodes(10000)}); !errors.Is(err, ErrTooComplex) {
		t.Errorf("10,000 deep inside an array: %v, want ErrTooComplex", err)
	}
}
