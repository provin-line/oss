package vc

import "context"

// SourceRootCanonical identifiers name the canonical JSON specification used
// to compute source-root leaves. They are the dPLaaX specification's
// canonical-JSON registry names — shared across wire profiles (the dplaas
// profile uses the same identifiers), distinct from this repository's
// internal canonicalizer package names. They enter the LifecycleRegistry
// like cryptosuites: lifecycle phases apply, zero/no-op values fail closed.
const (
	// SourceRootCanonicalJCS — JCS (RFC 8785) canonicalization (Phase 1, MUST
	// for emitters).
	SourceRootCanonicalJCS = "jcs-rfc8785"
)

// OriginCommitment is the optional audit commitment a chain-origin
// (FirstDrop) credential may carry under the audit-reachable conformance
// class.
//
// It is an audit attribute of the FirstDrop, NOT a parent link: the chain
// stays strictly linear (Paper 01 §4.8 — the base credential schema carries
// no upstream-reference fields; this commitment is wire-profile vocabulary
// declared via the dplaax JSON-LD context, riding the open signed body).
// Whether an Origin Source emits it is a deployment decision
// (config-driven); deployment profiles — e.g. a regulatory domain — may
// require the audit-reachable class.
//
// What it proves and what it does not: the commitment binds the issuer to
// the claimed source set at issuance time (tamper-evident after the fact —
// a verifier re-fetches the source credentials and recomputes the root). It
// does NOT prove completeness: an issuer can omit inputs from the claim.
// Omission detection is an audit-layer reconciliation (claimed commitments
// vs the counterparties' ingress VC stores), not a cryptographic check.
//
// Emitters construct values through NewOriginCommitment — hand-assembly
// risks diverging from the verifier's recomputation.
type OriginCommitment struct {
	// DerivedFrom is the unique set of issuer DIDs of the Pipeline-conformant
	// source credentials consumed by the aggregation, carried sorted
	// lexicographically ascending: JCS canonicalizes object keys, not array
	// order, so a pinned order keeps the signed body byte-deterministic for
	// equal sets. Empty is legal and meaningful — external ingestion with no
	// conformant upstream; a signed claim of "zero conformant sources" is
	// itself audit-valuable. External-world lookups (DB / API / file reads
	// inside the Origin Source) are deliberately excluded — this is an
	// audit-reachability claim over conformant signing entities only.
	DerivedFrom []string
	// SourceRoot is the multihash-encoded (typically "f1220<64 hex>") RFC
	// 6962 Merkle root over the consumed source credentials: leaves are
	// SHA-256(0x00 || canon(VC)) sorted by content hash ascending, internal
	// nodes SHA-256(0x01 || left || right), odd leaves promoted (never
	// duplicated). The empty set commits to SHA-256 of the empty string
	// (RFC 6962 §2.1). The multihash/multibase form — not this repository's
	// "sha256:<hex>" content addresses — is pinned by the dPLaaX Origin
	// Source specification for cross-profile compatibility; verifiers
	// dispatch on the multihash prefix.
	SourceRoot string
	// SourceRootCanonical names the canonical JSON spec the leaves were
	// computed with (e.g. SourceRootCanonicalJCS). Verifiers dispatch on it;
	// unknown identifiers fail closed.
	SourceRootCanonical string
}

// NewOriginCommitment derives a commitment from the consumed source
// credentials: DerivedFrom as the unique issuer set (sorted), SourceRoot via
// ComputeSourceRoot. The single construction path keeps emit and verify
// from diverging. Errors on an unknown canonical or duplicate sources
// (emit-time misuse fails loud, before signing).
func NewOriginCommitment(sources []*PipelinePassCredential, canonical string) (*OriginCommitment, error) {
	panic("not implemented")
}

// ComputeSourceRoot computes the source-root commitment over the consumed
// source credentials using the named canonicalization. Emitters reach it
// through NewOriginCommitment; auditors call it to recompute and compare
// against a credential's claimed commitment. Errors on an unknown canonical
// or duplicate source credentials.
func ComputeSourceRoot(sources []*PipelinePassCredential, canonical string) (string, error) {
	panic("not implemented")
}

// VerifyOriginCommitment is the on-demand audit check for the
// audit-reachable class — deliberately OUTSIDE the three normative axes and
// the per-event verification path. Callers gather the claimed source
// credentials asynchronously (VC resolver, counterparties' stores).
//
// Verdict semantics (judgment outcomes ride the ConfidenceState; the error
// return is reserved for caller misuse and environmental failures):
//   - recomputed root differs from the claimed SourceRoot, or the unique
//     issuer set of sources differs from DerivedFrom (the equality
//     property) → failed
//   - source set incomplete (claimed leaves not yet resolvable) →
//     indeterminate; may resolve later
//   - unknown SourceRootCanonical → failed (fail closed)
//   - cred carries no origin commitment, or is chain-preserving → error
//     (misuse: there is nothing to verify)
func (v *Verifier) VerifyOriginCommitment(ctx context.Context, cred *PipelinePassCredential, sources []*PipelinePassCredential) (ConfidenceState, error) {
	panic("not implemented")
}
