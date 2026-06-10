// Package canon owns the deterministic byte representation of JSON signing
// scopes ("canonicalization") and the strict decoder that protects them.
//
// Two peers computing different canonical bytes for the same logical document
// is a partition trap: verification fails — or silently diverges — with no
// obvious error, including against non-Go implementations. Every rule in this
// package exists to prevent that failure mode.
package canon

// Canonicalizer produces the canonical byte representation of a JSON value.
// Implementations are identified by Name, which is the exact identifier
// recorded in wire fields (cryptosuite, source_root_canonical) — renaming an
// implementation is a protocol change, not a refactor.
type Canonicalizer interface {
	// Name returns the wire identifier of this canonicalization.
	Name() string
	// Canonicalize returns the canonical bytes for v. Implementations must be
	// deterministic across processes, platforms, and library versions.
	Canonicalize(v any) ([]byte, error)
}
