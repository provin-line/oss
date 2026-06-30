// Package provenance defines the process-facing interfaces over the VC
// machinery in vc — shared signing/verification mechanics carrying no
// process semantics. Every process type that signs or verifies uses
// these; the DID/VC-backed implementation lives in vcdid/.
//
// Signing capabilities are split by chain behaviour, mirroring
// vc.Builder's explicit method split: a process is constructed with
// exactly the capability matching its declared contract.ChainBehavior,
// so the type system enforces that a Chained Process cannot issue a
// FirstDrop and a Source Process cannot carry a predecessor. Signers
// are stateless with respect to the chain: the predecessor is handed
// per call by the layer that verified it — the chain link names the
// event's input credential, never the process's previously issued one,
// so hidden last-credential state is both unnecessary and incorrect.
// The two operations carry distinct method names (mirroring
// vc.Builder's BuildChainPreserving / BuildFirstDrop) so one provider
// value can implement both capabilities — same-named methods with
// different parameter lists would make that impossible in Go.
package provenance

import (
	"context"

	"github.com/provin-line/oss/vc"
)

// ChainedSigner signs one processed event for a Chained Process: the
// issued credential carries previousCredential = the predecessor's
// content hash. The predecessor is the event's verified input
// credential, supplied per call. For deployments in the audit-reachable
// conformance class (config-driven), the signer also attaches the
// source commitment over the consumed conformant set — for a stateless
// 1:1 process that set is exactly {predecessor} (all-consumed
// semantics).
type ChainedSigner interface {
	SignChainPreserving(ctx context.Context, payload []byte, inputHash, outputHash string, predecessor *vc.PipelinePassCredential) (*vc.PipelinePassCredential, error)
}

// SourceSigner signs one processed event for a Source Process — the issued
// credential is a FirstDrop, a fresh chain origin with no previousCredential.
// The protocol has exactly one Source Process type; ingest (N=0) and aggregation
// (N pooled inputs) are mechanics, not distinct types, so both signing paths live
// on this one capability (split by chain behaviour, mirroring vc.Builder):
//
//   - SignFirstDrop serves external ingestion (N=0): a single external input, so
//     InputHash is present (== OutputHash for verbatim ingestion); no source
//     commitment.
//   - SignAggregateFirstDrop serves audit-reachable aggregation (N pooled inputs):
//     no single input (InputHash structurally absent — the method takes none), and
//     a source commitment over the consumed set.
//
// A consumer that exercises only one path should depend on a narrower,
// consumer-defined interface, so it cannot call the path it never uses.
type SourceSigner interface {
	SignFirstDrop(ctx context.Context, payload []byte, inputHash, outputHash string) (*vc.PipelinePassCredential, error)
	// SignAggregateFirstDrop signs an aggregate FirstDrop over a consumed set of
	// Pipeline-conformant source credentials (transformationClaim provin:aggregate).
	// It takes no inputHash (an aggregate has no single input) and is always
	// commitment-bearing: it commits to the full set, the sources AS RECEIVED
	// (signed wire form). previousCredential stays absent — the commitment is an
	// audit attribute, not a parent link. The chain stays strictly linear.
	SignAggregateFirstDrop(ctx context.Context, payload []byte, outputHash string, sources []*vc.PipelinePassCredential) (*vc.PipelinePassCredential, error)
}

// Verifier verifies one credential and returns the confidence verdict
// (weakest-link composition over the normative axes).
type Verifier interface {
	Verify(ctx context.Context, cred *vc.PipelinePassCredential) (*vc.VerifyResult, error)
}

// ChainVerifier verifies a full credential chain from its head — the engine of the
// async chain-audit runner (slice-17h), which assembles each consumed head's chain
// from the local store and records a verdict out of band. (Real-time full ingress
// verification was retired in slice-17j; chains are no longer walked synchronously on
// the consume path.) Chain retrieval — walking previousCredential by content address —
// is the implementation's concern; the verification semantics are vc.Verifier.VerifyChain's.
type ChainVerifier interface {
	VerifyChain(ctx context.Context, head *vc.PipelinePassCredential) (*vc.VerifyResult, error)
}
