package vc

import "context"

// SourceRootCanonical identifiers name the canonical JSON specification used
// to compute source-root leaves. Registered like cryptosuites: lifecycle
// phases apply, zero/no-op values fail closed.
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
// no upstream-reference fields; this commitment is a namespaced wire-profile
// extension riding the open signed body). Whether an Origin Source emits it
// is a deployment decision (config-driven); deployment profiles — e.g. a
// regulatory domain — may require the audit-reachable class.
//
// What it proves and what it does not: the commitment binds the issuer to
// the claimed source set at issuance time (tamper-evident after the fact —
// a verifier re-fetches the source credentials and recomputes the root). It
// does NOT prove completeness: an issuer can omit inputs from the claim.
// Omission detection is an audit-layer reconciliation (claimed commitments
// vs the counterparties' ingress VC stores), not a cryptographic check.
type OriginCommitment struct {
	// DerivedFrom is the unique set of issuer DIDs of the Pipeline-conformant
	// source credentials consumed by the aggregation. Empty for external
	// ingestion (no conformant upstream). External-world lookups (DB / API /
	// file reads inside the Origin Source) are deliberately excluded — this
	// is an audit-reachability claim over conformant signing entities only.
	DerivedFrom []string
	// SourceRoot is the multihash-encoded (typically "f1220<64 hex>") RFC
	// 6962 Merkle root over the consumed source credentials: leaves are
	// SHA-256(0x00 || canon(VC)) sorted by content hash ascending, internal
	// nodes SHA-256(0x01 || left || right), odd leaves promoted (never
	// duplicated).
	SourceRoot string
	// SourceRootCanonical names the canonical JSON spec the leaves were
	// computed with (e.g. SourceRootCanonicalJCS). Verifiers dispatch on it;
	// unknown identifiers fail closed.
	SourceRootCanonical string
}

// ComputeSourceRoot computes the source-root commitment over the consumed
// source credentials using the named canonicalization. Emitters call it at
// issuance; auditors call it to recompute and compare against a credential's
// claimed commitment.
func ComputeSourceRoot(sources []*PipelinePassCredential, canonical string) (string, error) {
	panic("not implemented")
}

// VerifyOriginCommitment is the on-demand audit check for the
// audit-reachable class — deliberately OUTSIDE the three normative axes and
// the per-event verification path. Callers gather the claimed source
// credentials asynchronously (VC resolver, counterparties' stores); until
// the full set is available the verdict is indeterminate.
//
// It checks: the recomputed source root equals cred's claimed SourceRoot
// (byte-equal), and the unique issuer set of sources equals DerivedFrom
// (the equality property). Established mismatch → failed; incomplete source
// set → indeterminate.
func (v *Verifier) VerifyOriginCommitment(ctx context.Context, cred *PipelinePassCredential, sources []*PipelinePassCredential) (ConfidenceState, error) {
	panic("not implemented")
}
