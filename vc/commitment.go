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
// internal canonicalizer package names. The profile pins a single suite today
// (SourceRootCanonicalJCS): ComputeSourceRoot accepts only it and fails closed
// otherwise. A registration surface and lifecycle phases — as cryptosuites have
// via RegisterCryptosuite — would be added here only if a second source-root
// suite is ever introduced.
const (
	// SourceRootCanonicalJCS — JCS (RFC 8785) canonicalization (Phase 1, MUST
	// for emitters).
	SourceRootCanonicalJCS = "jcs-rfc8785"
)

// SourceCommitment is the optional audit commitment any credential may
// carry under the audit-reachable conformance class: a commitment over the
// FULL set of Pipeline-conformant source credentials the boundary consumed.
// It is orthogonal to previousCredential — chain-origin (FirstDrop) and
// chain-preserving credentials alike may carry it. On a chain-preserving
// credential the committed set includes the triggering predecessor
// (all-consumed semantics), so DerivedFrom necessarily contains the
// predecessor's issuer and the set is never empty there.
//
// It is an audit attribute, NOT a parent link: the chain stays strictly
// linear (Paper 01 §4.8 — the base credential schema carries no
// upstream-reference fields; this commitment is wire-profile vocabulary
// declared via the dplaax JSON-LD context, riding the open signed body).
// Whether a boundary emits it is a deployment decision (config-driven);
// deployment profiles — e.g. a regulatory domain — may require the
// audit-reachable class.
//
// What it proves and what it does not: the commitment binds the issuer to
// the claimed source set at issuance time (tamper-evident after the fact —
// a verifier re-fetches the source credentials and recomputes the root). It
// does NOT prove completeness: an issuer can omit inputs from the claim.
// Omission detection is an audit-layer reconciliation (claimed commitments
// vs the counterparties' ingress VC stores), not a cryptographic check.
//
// Emitters construct values through NewSourceCommitment — hand-assembly
// risks diverging from the verifier's recomputation.
type SourceCommitment struct {
	// DerivedFrom is the unique set of issuer DIDs of the Pipeline-conformant
	// source credentials consumed by the boundary, carried sorted
	// lexicographically ascending: JCS canonicalizes object keys, not array
	// order, so a pinned order keeps the signed body byte-deterministic for
	// equal sets. Empty is legal and meaningful on a chain origin — external
	// ingestion with no conformant upstream; a signed claim of "zero
	// conformant sources" is itself audit-valuable. On a chain-preserving
	// credential the set is never empty: all-consumed semantics include the
	// triggering predecessor's issuer. External-world lookups (DB / API /
	// file reads inside the boundary) are deliberately excluded — this is an
	// audit-reachability claim over conformant signing entities only.
	DerivedFrom []string
	// SourceRoot is the multihash-encoded (typically "f1220<64 hex>") RFC
	// 6962 Merkle root over the consumed source credentials: leaves are
	// SHA-256(0x00 || canon(VC)) sorted by content hash ascending, internal
	// nodes SHA-256(0x01 || left || right), odd leaves promoted (never
	// duplicated). The empty set commits to SHA-256 of the empty string
	// (RFC 6962 §2.1). The multihash/multibase form — not this repository's
	// "sha256:<hex>" content addresses — is pinned by the dPLaaX
	// specification for cross-profile compatibility; verifiers dispatch on
	// the multihash prefix.
	SourceRoot string
	// SourceRootCanonical names the canonical JSON spec the leaves were
	// computed with (e.g. SourceRootCanonicalJCS). Verifiers dispatch on it;
	// unknown identifiers fail closed.
	SourceRootCanonical string
}

// NewSourceCommitment derives a commitment from the consumed source
// credentials: DerivedFrom as the unique issuer set (sorted), SourceRoot via
// ComputeSourceRoot. The single construction path keeps emit and verify
// from diverging. Errors on an unknown canonical or duplicate sources
// (emit-time misuse fails loud, before signing).
//
// sources must be the credentials AS RECEIVED (signed wire form): leaves
// hash the full wire document including proof, so a commitment computed
// over pre-signing in-memory credentials will never verify against the
// counterparties' stores.
func NewSourceCommitment(sources []*PipelinePassCredential, canonical string) (*SourceCommitment, error) {
	root, err := ComputeSourceRoot(sources, canonical)
	if err != nil {
		return nil, err
	}
	return &SourceCommitment{
		DerivedFrom:         uniqueIssuers(sources),
		SourceRoot:          root,
		SourceRootCanonical: canonical,
	}, nil
}

// ComputeSourceRoot computes the source-root commitment over the consumed
// source credentials using the named canonicalization. Emitters reach it
// through NewSourceCommitment; auditors call it to recompute and compare
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
		if s == nil {
			// Fail closed: a nil element would panic on MarshalJSON/Issuer.
			return "", fmt.Errorf("vc: nil source credential at index %d", i)
		}
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

// VerifySourceCommitment is the on-demand audit check for the
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
//   - chain-preserving credential none of whose gathered sources hashes to
//     previousCredential, once the claimed issuer set is fully resolved →
//     failed (all-consumed semantics: the triggering predecessor is part of
//     the consumed set, and the verifier holds its content hash)
//   - cred carries no source commitment → error (misuse: there is nothing
//     to verify)
//
// Incompleteness is detectable at issuer granularity only (DerivedFrom is
// an issuer set): a missing credential whose issuer is already covered by
// another provided source surfaces as failed, not indeterminate — the
// commitment grammar cannot distinguish the two.
func (v *Verifier) VerifySourceCommitment(ctx context.Context, cred *PipelinePassCredential, sources []*PipelinePassCredential) (ConfidenceState, error) {
	// Misuse guards, checked before any traversal (uniqueIssuers dereferences
	// each source): nil inputs are caller wiring errors — a gather loop with
	// unfilled slots — and must surface as errors, never panics. Mirrors the
	// construction-side hardening in ComputeSourceRoot (17k).
	if cred == nil {
		return ConfidenceFailed, errors.New("vc: nil credential")
	}
	for i, s := range sources {
		if s == nil {
			return ConfidenceFailed, fmt.Errorf("vc: nil source credential at index %d", i)
		}
	}
	claimed := cred.SourceCommitment()
	if claimed == nil {
		return ConfidenceFailed, errors.New("vc: credential carries no source commitment")
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

	// All-consumed semantics: a chain-preserving credential's commitment
	// covers the full consumed set, the triggering predecessor included. The
	// claimed set is fully resolved at this point, so a missing predecessor
	// is an omission, not a not-yet-gathered source.
	if prev := cred.PreviousCredential(); prev != "" {
		found := false
		for _, s := range sources {
			h, err := s.Hash()
			if err != nil {
				return ConfidenceFailed, fmt.Errorf("vc: hashing gathered source: %w", err)
			}
			if h == prev {
				found = true
				break
			}
		}
		if !found {
			return ConfidenceFailed, nil // predecessor omitted from the commitment
		}
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
