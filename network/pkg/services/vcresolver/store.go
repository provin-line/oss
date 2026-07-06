// Package vcresolver stores VCs submitted by pipeline runtimes and resolves
// previousCredential chains across registry boundaries. This file defines
// the storage contracts; the in-memory PoC implementations and the batch
// resolver land with the service.
//
// Audit-reachable deployments (source commitments — see
// pipeline/source) require a DURABLE Store implementation:
// retrospective audits resolve claimed source credentials long after
// issuance, which an in-memory store cannot honor. How an auditor LOCATES a
// claimed source set is deliberately outside the wire profile — the
// commitment carries the Merkle root and the issuer DID set, not content
// addresses; acquisition goes through the issuers' stores and the
// counterparties' ingress VC stores (the obligation in
// pipeline/contract.IngressVCStore). An enumeration surface for that audit
// query lands with the service API, not with this storage contract.
package vcresolver

import (
	"errors"

	"github.com/provin-line/oss/vc"
)

// ErrNotFound is returned for misses. Handlers map it with errors.Is.
var ErrNotFound = errors.New("vcresolver: not found")

// Store holds resolved VCs keyed by their content address
// ("sha256:<hex>" over the JCS-canonical body).
type Store interface {
	Put(hash string, cred *vc.PipelinePassCredential) error
	Get(hash string) (*vc.PipelinePassCredential, error)
	// ListHashes returns EXACTLY min(remaining, limit) held content
	// addresses in lexicographic order, strictly after fromExclusive (""
	// starts at the beginning) — the enumeration primitive the service's
	// forward index (and any future export/GC path) builds on. The
	// full-page rule is contract, not convenience: the index build infers
	// "store exhausted" from a short page, so an implementation returning
	// fewer entries than remain would build a silently incomplete index —
	// a recall answering a false "no descendants". Listing names what is
	// held; it reads no credential bodies.
	ListHashes(fromExclusive string, limit int) ([]string, error)
}

// UnresolvedEntry is one queued chain hole: a previousCredential hash we do
// not hold, plus the upstream endpoint to fetch it from.
type UnresolvedEntry struct {
	// Hash is the previousCredential content address ("sha256:<hex>") not held.
	Hash string
	// UpstreamEndpoint is the caller-supplied hint for where the predecessor can
	// be fetched. Empty means none was supplied — the batch resolver derives the
	// endpoint from ReferrerIssuer instead.
	UpstreamEndpoint string
	// ReferrerIssuer is the issuer DID of the credential that referenced this
	// hole. With no UpstreamEndpoint hint, the batch resolver derives the fetch
	// endpoint from this DID's #vc-resolver service endpoint — so an empty-hint
	// entry stays resolvable after the referrer credential is gone.
	ReferrerIssuer string
	// RetryCount is the batch resolver's bounded-retry counter.
	RetryCount int
	// AssemblyDepth is this hole's distance from the nearest directly-received
	// credential (a directly-received credential is depth 0, so a real hole — the
	// predecessor of some stored credential at depth d — is always >= 1). The batch
	// resolver enforces a configured max-depth against it to bound assembly of an
	// adversarial unbounded chain. Pool.Add keeps the minimum when the same hole is
	// reached from multiple heads (the shortest path wins).
	AssemblyDepth int
}

// Pool queues unresolved entries for the batch resolver. Ordering is
// newest-first (recent chain holes are the most likely to be resolvable).
//
// Add is an idempotent upsert keyed by Hash: re-adding a queued hole does not
// duplicate it, but fills an empty UpstreamEndpoint / ReferrerIssuer from the new
// entry and never clobbers a non-empty hint with an empty one — so a hole first
// queued with no hint is repaired when a better-informed referrer arrives.
type Pool interface {
	Add(e UnresolvedEntry) error
	ListNewest(n int) ([]UnresolvedEntry, error)
	Remove(hash string) error
	IncrementRetry(hash string) error
	Len() int
}
