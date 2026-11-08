# canon — Signing-Scope Canonicalization

Deterministic byte representations of JSON signing scopes, plus the strict decoder
that protects them. One responsibility, multiple cryptosuite-specific algorithms.

## Why this package exists

Two peers computing **different canonical bytes for the same logical document** is a
*partition trap*: verification fails (or worse, diverges) with no obvious error. Every
rule in this package exists to prevent that failure mode, including against
non-Go implementations (Java / Rust / JS).

## Subpackages

| Path | Algorithm | Status |
| --- | --- | --- |
| `canon/jcs` | RFC 8785 JSON Canonicalization Scheme (Phase 1 cryptosuite, MUST) | implemented |
| `canon/urdna2015` | RDF Dataset Canonicalization (URDNA2015) for `eddsa-rdfc-2022` (Phase 2, MAY) | implemented — wraps `piprate/json-gold` behind an offline context allowlist (never the network) and fails closed on everything JSON-LD processing would silently drop from the signing scope: undefined terms, relative `@id`/`@type` values, and numeric members (2^53 truncation). Bounds the work of building the dataset (json-gold's node map compares the values one node's property gathers) and the length of the canonical form (1 MiB plus 32 bytes per byte of the document), and labels blank nodes within a work bound (RDFC-1.0 §4.4.3): a dataset too complex to build, to write or to label is refused with `urdna2015.ErrTooComplex`. Refuses a document some value of which the canonical form would not hold: its values are counted in the document, in its expanded form and in the dataset, and must agree. A context that sets `@base` is refused, and so are a node's property that holds one RDF term twice (write a node once and refer to it by its `@id`), a language tag not of ASCII letters, digits and hyphens, and the RDF collection vocabulary written out (`rdf:first`, `rdf:rest`, `rdf:nil`; write a list with `@list`). One property of one node holds at most about 1,460 distinct values; a document with more is refused with `ErrTooComplex` both when a proof is created and when one is verified. `vc` registers the suite at init, so proofs that use it are verified by default; an issuer uses it only when it chooses it. Refuses an IRI or literal the canonical N-Quads cannot write one-to-one, or would write differently from RDFC-1.0 (Appendix A). Anchored to the official W3C vc-di-eddsa test vector |

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
