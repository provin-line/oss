// Package jcs implements RFC 8785 (JSON Canonicalization Scheme) — the
// Phase 1 (MUST) canonicalization for dplaax signing scopes.
//
// Byte-for-byte RFC 8785 conformance is the contract, including the corners
// Go's encoder gets wrong by default: U+2028/U+2029 must appear as raw UTF-8
// (not \u-escaped), and numeric precision must survive via json.Number.
package jcs

// Name is the wire identifier of this canonicalization.
const Name = "jcs"

// Canonicalize returns the RFC 8785 canonical bytes for v.
func Canonicalize(v any) ([]byte, error) { panic("not implemented") }

// Hash returns "sha256:<hex>" over the canonical bytes of v — the standard
// content address for VC bodies and chain links.
func Hash(v any) (string, error) { panic("not implemented") }

// Canonicalizer adapts this package to the canon.Canonicalizer interface.
type Canonicalizer struct{}

// Name implements canon.Canonicalizer.
func (Canonicalizer) Name() string { return Name }

// Canonicalize implements canon.Canonicalizer.
func (Canonicalizer) Canonicalize(v any) ([]byte, error) { return Canonicalize(v) }
