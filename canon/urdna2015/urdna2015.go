// Package urdna2015 implements RDF Dataset Normalization (URDNA2015) for the
// eddsa-rdfc-2022 cryptosuite (Phase 2, MAY).
//
// JSON-LD contexts are resolved exclusively from an in-process allowlist of
// embedded documents — never the network. Known limitation to preserve in
// docs: @json literal integers above 2^53 are truncated by the underlying
// JSON-LD machinery; encode large integers as strings when this cryptosuite
// is in play.
package urdna2015

// Name is the wire identifier of this canonicalization.
const Name = "urdna2015"

// Canonicalizer normalizes JSON-LD documents to canonical N-Quads bytes using
// an offline document loader.
type Canonicalizer struct {
	contexts map[string][]byte
}

// NewCanonicalizer returns a Canonicalizer whose loader serves exactly the
// given context documents (IRI → bytes) and fails on any other IRI. The map
// is defensively copied.
func NewCanonicalizer(contexts map[string][]byte) *Canonicalizer { panic("not implemented") }

// Name implements canon.Canonicalizer.
func (c *Canonicalizer) Name() string { return Name }

// Canonicalize implements canon.Canonicalizer.
func (c *Canonicalizer) Canonicalize(v any) ([]byte, error) { panic("not implemented") }
