# packages/merkle — RFC 6962 Merkle Commitments

Merkle tree construction for `source_root`: a compact, order-independent commitment
to the set of source VCs an Origin Source derived its output from.

## Conventions

- RFC 6962 domain separation: leaf hash = `SHA-256(0x00 ‖ leaf)`, internal node =
  `SHA-256(0x01 ‖ left ‖ right)` — prevents the second-preimage attack
  (CVE-2012-2459 class).
- Leaves are sorted by content hash before tree construction (set semantics — the
  commitment is independent of source arrival order).
- Odd leaves are **promoted**, not duplicated.
- Encoding: multibase + multihash (`f1220<64 hex>`); decoder accepts `f` (base16)
  and `b` (base32) prefixes.
- Leaf bytes are produced by the canonicalizer named in the credential's
  `source_root_canonical` field (see `packages/vc`); this package never chooses
  the canonicalization itself.
