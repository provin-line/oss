package vc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

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
//
// sources must be the credentials AS RECEIVED (signed wire form): leaves
// hash the full wire document including proof, so a commitment computed
// over pre-signing in-memory credentials will never verify against the
// counterparties' stores.
func NewOriginCommitment(sources []*PipelinePassCredential, canonical string) (*OriginCommitment, error) {
	root, err := ComputeSourceRoot(sources, canonical)
	if err != nil {
		return nil, err
	}
	return &OriginCommitment{
		DerivedFrom:         uniqueIssuers(sources),
		SourceRoot:          root,
		SourceRootCanonical: canonical,
	}, nil
}

// ComputeSourceRoot computes the source-root commitment over the consumed
// source credentials using the named canonicalization. Emitters reach it
// through NewOriginCommitment; auditors call it to recompute and compare
// against a credential's claimed commitment. Errors on an unknown canonical
// or duplicate source credentials.
func ComputeSourceRoot(sources []*PipelinePassCredential, canonical string) (string, error) {
	if canonical != SourceRootCanonicalJCS {
		return "", fmt.Errorf("vc: unknown source_root_canonical %q", canonical)
	}
	type leaf struct {
		content [sha256.Size]byte // SHA-256(canon(VC)) — the sort key
		hash    [sha256.Size]byte // SHA-256(0x00 || canon(VC)) — the tree leaf
	}
	leaves := make([]leaf, len(sources))
	seen := make(map[[sha256.Size]byte]bool, len(sources))
	for i, s := range sources {
		wire, err := s.MarshalJSON()
		if err != nil {
			return "", fmt.Errorf("vc: canonicalizing source %d: %w", i, err)
		}
		content := sha256.Sum256(wire)
		if seen[content] {
			return "", fmt.Errorf("vc: duplicate source credential (content hash %x)", content[:8])
		}
		seen[content] = true
		leaves[i] = leaf{content: content, hash: sha256.Sum256(append([]byte{0x00}, wire...))}
	}
	sort.Slice(leaves, func(i, j int) bool {
		return bytes.Compare(leaves[i].content[:], leaves[j].content[:]) < 0
	})
	hashes := make([][sha256.Size]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = l.hash
	}
	root := merkleTreeHash(hashes)
	// Multihash sha2-256 (0x12, length 0x20), multibase lowercase hex ("f").
	return "f1220" + hex.EncodeToString(root[:]), nil
}

// merkleTreeHash is RFC 6962 §2.1 MTH over pre-hashed leaves: the left
// subtree spans the largest power of two smaller than n, so odd leaves are
// promoted, never duplicated. MTH of the empty list is SHA-256 of the empty
// string.
func merkleTreeHash(leaves [][sha256.Size]byte) [sha256.Size]byte {
	switch len(leaves) {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return leaves[0]
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	left := merkleTreeHash(leaves[:k])
	right := merkleTreeHash(leaves[k:])
	buf := make([]byte, 0, 1+2*sha256.Size)
	buf = append(buf, 0x01)
	buf = append(buf, left[:]...)
	buf = append(buf, right[:]...)
	return sha256.Sum256(buf)
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
//
// Incompleteness is detectable at issuer granularity only (DerivedFrom is
// an issuer set): a missing credential whose issuer is already covered by
// another provided source surfaces as failed, not indeterminate — the
// commitment grammar cannot distinguish the two.
func (v *Verifier) VerifyOriginCommitment(ctx context.Context, cred *PipelinePassCredential, sources []*PipelinePassCredential) (ConfidenceState, error) {
	claimed := cred.Origin()
	if claimed == nil {
		return ConfidenceFailed, errors.New("vc: credential carries no origin commitment")
	}
	if cred.PreviousCredential() != "" {
		return ConfidenceFailed, errors.New("vc: chain-preserving credential cannot carry an origin commitment")
	}
	if claimed.SourceRootCanonical != SourceRootCanonicalJCS {
		return ConfidenceFailed, nil // unknown canonicalization fails closed
	}

	claimedSet := make(map[string]bool, len(claimed.DerivedFrom))
	for _, d := range claimed.DerivedFrom {
		claimedSet[d] = true
	}
	if len(claimedSet) != len(claimed.DerivedFrom) {
		// DerivedFrom is defined as a unique set: a duplicate-carrying claim
		// is malformed and fails closed (never "resolves later").
		return ConfidenceFailed, nil
	}
	providedIssuers := uniqueIssuers(sources)
	for _, p := range providedIssuers {
		if !claimedSet[p] {
			return ConfidenceFailed, nil // source outside the claimed set
		}
	}
	if len(providedIssuers) < len(claimedSet) {
		return ConfidenceIndeterminate, nil // claimed issuers not yet resolved
	}

	recomputed, err := ComputeSourceRoot(sources, claimed.SourceRootCanonical)
	if err != nil {
		return ConfidenceFailed, err // duplicates in the gathered set: caller data problem
	}
	if recomputed != claimed.SourceRoot {
		return ConfidenceFailed, nil
	}
	return ConfidenceVerified, nil
}

// uniqueIssuers returns the deduplicated, lexicographically sorted issuer
// DIDs of the given credentials — the DerivedFrom grammar.
func uniqueIssuers(sources []*PipelinePassCredential) []string {
	set := make(map[string]bool, len(sources))
	for _, s := range sources {
		set[s.Issuer()] = true
	}
	out := make([]string, 0, len(set))
	for issuer := range set {
		out = append(out, issuer)
	}
	sort.Strings(out)
	return out
}
