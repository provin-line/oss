// Package merkle implements RFC 6962 Merkle tree commitments for
// source_root: a compact, order-independent commitment to the set of source
// VCs an Origin Source derived its output from.
//
// Conventions: 0x00/0x01 domain-separation prefixes (second-preimage
// defense), content-hash-sorted leaves (set semantics), odd-leaf promotion
// (never duplication), multibase+multihash encoding.
package merkle

// SourceRoot computes the source_root commitment over the canonicalized wire
// bytes of the source VCs: content-hash sort → RFC 6962 leaf/internal hashing
// → multibase+multihash encoding ("f1220" + 64 hex).
func SourceRoot(canonicalSourceBytes [][]byte) string { panic("not implemented") }

// LeafNodeHash returns SHA-256(0x00 ‖ b) — the RFC 6962 leaf hash.
func LeafNodeHash(b []byte) [32]byte { panic("not implemented") }

// InternalNodeHash returns SHA-256(0x01 ‖ left ‖ right).
func InternalNodeHash(left, right [32]byte) [32]byte { panic("not implemented") }

// ContentHash returns SHA-256(b) — the leaf sort key.
func ContentHash(b []byte) [32]byte { panic("not implemented") }

// Decode parses a source_root string back to the 32-byte root. Accepts the
// "f" (base16) and "b" (base32) multibase prefixes and validates the
// multihash header (0x12 0x20).
func Decode(sourceRoot string) ([32]byte, error) { panic("not implemented") }
