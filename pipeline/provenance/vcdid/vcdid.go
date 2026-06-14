// Package vcdid is the DID/VC-backed implementation of the provenance signing
// capabilities: it adapts vc.Builder (Ed25519 Data Integrity signing behind a
// crypto.Signer) to the process-facing provenance.SourceSigner and
// provenance.ChainedSigner interfaces.
//
// One Signer value carries a single issuing process's static credential
// identity — its Process DID, signing key reference, and the constant subject
// metadata (pipeline / process ids, transformation claim, optional schema) —
// and implements BOTH capabilities; the runtime hands a process the interface
// matching its declared contract.ChainBehavior. Per-event inputs (payload
// hashes, the verified predecessor) arrive per call, so the Signer holds no
// chain state.
//
// Verification has no vcdid type: provenance.Verifier is satisfied by
// *vc.Verifier directly (matching Verify signatures), and the chain-walking
// provenance.ChainVerifier by pipeline/provenance/chainwalk over a vc.Verifier
// ChainCore — wrapping either here would add indirection without responsibility.
package vcdid

import (
	"context"
	"fmt"

	"github.com/provin-line/oss/vc"
)

// Config constructs a Signer. Builder and the credential-identity fields are
// required; Schema and the audit-reachable commitment fields are optional.
type Config struct {
	// Builder signs credentials (Ed25519 Data Integrity) for the issuing
	// process — typically fronting the registry's SignerService (KMS model).
	Builder *vc.Builder
	// IssuerDID is the issuing Process DID; KeyID resolves the signing key in
	// the Builder's keystore; VerificationMethod is the DID URL the proof
	// references (the issuer's assertion key, e.g. IssuerDID + "#signing").
	IssuerDID          string
	KeyID              string
	VerificationMethod string
	// PipelineID / ProcessID / TransformationClaim are the constant subject
	// metadata of every credential this process issues; Schema is the optional
	// content-hashed output-schema reference.
	PipelineID          string
	ProcessID           string
	TransformationClaim vc.TransformationClaim
	Schema              vc.SchemaRef
	// AuditReachable, when set, makes SignChainPreserving attach a source
	// commitment over the consumed conformant set (the audit-reachable
	// conformance class). For a stateless 1:1 chained process that set is
	// exactly {predecessor} (all-consumed semantics). SourceRootCanonical names
	// the canonical-JSON spec for the commitment root (e.g.
	// vc.SourceRootCanonicalJCS) and is required when AuditReachable is set.
	AuditReachable      bool
	SourceRootCanonical string
}

// Signer is the DID/VC-backed provenance signer for one issuing process. It
// satisfies provenance.SourceSigner and provenance.ChainedSigner.
type Signer struct {
	cfg Config
}

// NewSigner validates cfg and returns a Signer. The credential-identity fields
// are contract: a missing one is a construction error, not a deferred signing
// failure.
func NewSigner(cfg Config) (*Signer, error) {
	switch {
	case cfg.Builder == nil:
		return nil, fmt.Errorf("vcdid: nil Builder")
	case cfg.IssuerDID == "":
		return nil, fmt.Errorf("vcdid: empty IssuerDID")
	case cfg.KeyID == "":
		return nil, fmt.Errorf("vcdid: empty KeyID")
	case cfg.VerificationMethod == "":
		return nil, fmt.Errorf("vcdid: empty VerificationMethod")
	case cfg.PipelineID == "":
		return nil, fmt.Errorf("vcdid: empty PipelineID")
	case cfg.ProcessID == "":
		return nil, fmt.Errorf("vcdid: empty ProcessID")
	case cfg.TransformationClaim == "":
		return nil, fmt.Errorf("vcdid: empty TransformationClaim")
	case cfg.AuditReachable && cfg.SourceRootCanonical == "":
		return nil, fmt.Errorf("vcdid: AuditReachable set without SourceRootCanonical")
	}
	// Validate static config fully at construction, not at first sign: a
	// malformed claim token or an unknown commitment canonicalization is a
	// configuration error that should fail loud here.
	if err := cfg.TransformationClaim.Validate(); err != nil {
		return nil, fmt.Errorf("vcdid: invalid TransformationClaim: %w", err)
	}
	if cfg.AuditReachable {
		// Probe the canonicalization via the authoritative root computation
		// (empty set) — errors on an unknown identifier without vcdid having to
		// enumerate the canonical registry.
		if _, err := vc.ComputeSourceRoot(nil, cfg.SourceRootCanonical); err != nil {
			return nil, fmt.Errorf("vcdid: invalid SourceRootCanonical: %w", err)
		}
	}
	return &Signer{cfg: cfg}, nil
}

// SignFirstDrop issues a chain-origin credential (no previousCredential). A
// FirstDrop never attaches a source commitment here — external ingestion (N=0)
// needs none, and audit-reachable aggregation (N pooled inputs) gates with the
// aggregate runtime, not this 1:1 path.
func (s *Signer) SignFirstDrop(ctx context.Context, payload []byte, inputHash, outputHash string) (*vc.PipelinePassCredential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.cfg.Builder.BuildFirstDrop(s.cfg.IssuerDID, s.cfg.KeyID, s.cfg.VerificationMethod, s.subject(inputHash, outputHash), nil)
}

// SignChainPreserving issues a chain-preserving credential linking to
// predecessor (the event's verified input credential). When AuditReachable, it
// attaches a source commitment over {predecessor} — the all-consumed set of a
// stateless 1:1 process.
func (s *Signer) SignChainPreserving(ctx context.Context, payload []byte, inputHash, outputHash string, predecessor *vc.PipelinePassCredential) (*vc.PipelinePassCredential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if predecessor == nil {
		// Guard before the commitment path — NewSourceCommitment would deref a
		// nil predecessor; BuildChainPreserving also rejects nil, but the audit
		// branch runs first.
		return nil, fmt.Errorf("vcdid: SignChainPreserving requires a non-nil predecessor")
	}
	var commitment *vc.SourceCommitment
	if s.cfg.AuditReachable {
		c, err := vc.NewSourceCommitment([]*vc.PipelinePassCredential{predecessor}, s.cfg.SourceRootCanonical)
		if err != nil {
			return nil, fmt.Errorf("vcdid: source commitment: %w", err)
		}
		commitment = c
	}
	return s.cfg.Builder.BuildChainPreserving(s.cfg.IssuerDID, s.cfg.KeyID, s.cfg.VerificationMethod, s.subject(inputHash, outputHash), predecessor, commitment)
}

// subject assembles the credential subject from the process's constant metadata
// and the per-event hashes.
func (s *Signer) subject(inputHash, outputHash string) vc.CredentialSubjectFields {
	return vc.CredentialSubjectFields{
		PipelineID:          s.cfg.PipelineID,
		ProcessID:           s.cfg.ProcessID,
		TransformationClaim: s.cfg.TransformationClaim,
		Schema:              s.cfg.Schema,
		InputHash:           inputHash,
		OutputHash:          outputHash,
	}
}
