# canon — Signing-Scope Canonicalization

Deterministic byte representations of JSON signing scopes, plus the strict decoder
that protects them. One responsibility, multiple cryptosuite-specific algorithms.

## Why this package exists

Two peers computing **different canonical bytes for the same logical document** is a
*partition trap*: verification fails (or worse, diverges) with no obvious error. Every
rule in this package exists to prevent that failure mode, including against
non-Go implementations (Java / Rust / JS).

## Subpackages

| Path | Algorithm |
|---|---|
| `canon/jcs` | RFC 8785 JSON Canonicalization Scheme (Phase 1 cryptosuite, MUST) |
| `canon/urdna2015` | RDF Dataset Normalization for `eddsa-rdfc-2022` (Phase 2, MAY) |

## Hard rules

- **StrictDecoder is the only JSON decode path on protocol boundaries**: rejects
  duplicate keys (RFC 8785 §3.2.5), rejects trailing data, preserves numeric
  precision via `json.Number` (integers > 2^53 must not collapse to float64).
  `make lint` enforces this via `scripts/check-decoder-hygiene.sh`; exemptions
  require a `decoder-hygiene-exempt` comment.
- JCS output must match RFC 8785 byte-for-byte — including the U+2028/U+2029
  raw-UTF-8 requirement that Go's encoder violates by default.
- URDNA2015 uses an **offline document loader only**: JSON-LD contexts come from an
  in-process allowlist (embedded bytes), never the network.
- Known limitation to preserve in docs: the JSON-LD path truncates `@json` literal
  integers above 2^53; large integers must be encoded as strings when the RDF
  cryptosuite is in play.
