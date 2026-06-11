// Package provenance defines the component-facing interfaces over the VC
// machinery in vc — shared signing/verification mechanics carrying no
// component semantics. Every component type that signs or verifies uses
// these; the DID/VC-backed implementation lives in vcdid/.
package provenance

import (
	"context"

	"github.com/provin-line/oss/vc"
)

// Provider signs one processed event into a PipelinePassCredential. It owns
// the per-process chain state (previousCredential linking) and, for
// boundaries deployed in the audit-reachable conformance class
// (config-driven), the source commitment.
//
// KNOWN CONTRACT GAP (open question, morning gate): this signature offers
// no path for the event's predecessor credential, which chain-preserving
// issuance requires (previousCredential = hash of the input VC, per event —
// not the last credential this process issued). The signature follows the
// README pin verbatim and will be revised at the gate; do not paper over
// the gap with hidden state.
type Provider interface {
	Sign(ctx context.Context, payload []byte, inputHash, outputHash string) (*vc.PipelinePassCredential, error)
}

// Verifier verifies one credential and returns the confidence verdict
// (weakest-link composition over the normative axes).
type Verifier interface {
	Verify(ctx context.Context, cred *vc.PipelinePassCredential) (*vc.VerifyResult, error)
}
