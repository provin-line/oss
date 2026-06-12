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

// SourceSigner signs one processed event for a Source Process: the
// issued credential is a FirstDrop — a fresh chain origin with no
// previousCredential. External ingestion (N=0) is fully served by this
// signature. The consumed-set path that an audit-reachable aggregation
// (N pooled inputs) needs for its source commitment is deliberately
// absent: it gates with the aggregate runtime.
type SourceSigner interface {
	SignFirstDrop(ctx context.Context, payload []byte, inputHash, outputHash string) (*vc.PipelinePassCredential, error)
}

// Verifier verifies one credential and returns the confidence verdict
// (weakest-link composition over the normative axes).
type Verifier interface {
	Verify(ctx context.Context, cred *vc.PipelinePassCredential) (*vc.VerifyResult, error)
}

// ChainVerifier verifies a full credential chain from its head, for
// processes declaring contract.VerificationFull (sinks, observation
// tooling). Chain retrieval — walking previousCredential by content
// address, typically against the network's VC resolver — is the
// implementation's concern; the verification semantics are
// vc.Verifier.VerifyChain's.
type ChainVerifier interface {
	VerifyChain(ctx context.Context, head *vc.PipelinePassCredential) (*vc.VerifyResult, error)
}
