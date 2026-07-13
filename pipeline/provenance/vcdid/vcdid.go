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
	"crypto/sha256"
	"encoding/hex"
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
	// exactly {predecessor} (all-consumed semantics).
	AuditReachable bool
	// SourceRootCanonical names the canonical-JSON spec for the commitment root
	// (e.g. vc.SourceRootCanonicalJCS). It is required when AuditReachable is set
	// (the chained commitment path) and, independently, when TransformationClaim
	// is vc.ClaimAggregate (the aggregate path is always commitment-bearing via
	// SignAggregateFirstDrop).
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
	case cfg.TransformationClaim == vc.ClaimAggregate && cfg.SourceRootCanonical == "":
		// The aggregate path is always commitment-bearing (SignAggregateFirstDrop),
		// so it requires SourceRootCanonical independently of the chained
		// AuditReachable flag.
		return nil, fmt.Errorf("vcdid: aggregate signer (ClaimAggregate) requires SourceRootCanonical")
	}
	// Validate static config fully at construction, not at first sign: a
	// malformed claim token or an unknown commitment canonicalization is a
	// configuration error that should fail loud here.
	if err := cfg.TransformationClaim.Validate(); err != nil {
		return nil, fmt.Errorf("vcdid: invalid TransformationClaim: %w", err)
	}
	if cfg.AuditReachable || cfg.TransformationClaim == vc.ClaimAggregate {
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
	if s.cfg.TransformationClaim == vc.ClaimAggregate {
		// Fail closed: an aggregate signer must mint only through
		// SignAggregateFirstDrop. The ingest path would otherwise emit a
		// provin:aggregate FirstDrop with inputHash present and no source
		// commitment — a malformed aggregate. Binds claim↔method both ways.
		return nil, fmt.Errorf("vcdid: SignFirstDrop is not valid for an aggregate signer (TransformationClaim %q); use SignAggregateFirstDrop", vc.ClaimAggregate)
	}
	if err := verifyPayload(payload, outputHash); err != nil {
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
	if s.cfg.TransformationClaim == vc.ClaimAggregate {
		// Fail closed: an aggregate signer must not emit a chain-preserving
		// credential — that would carry previousCredential on a claim that means
		// "fresh aggregation origin". Binds claim↔method both ways.
		return nil, fmt.Errorf("vcdid: SignChainPreserving is not valid for an aggregate signer (TransformationClaim %q); use SignAggregateFirstDrop", vc.ClaimAggregate)
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
	// Defensive gate last, immediately before signing (see verifyPayload): every
	// structural/misuse error surfaces as itself, never masked by a payload mismatch.
	if err := verifyPayload(payload, outputHash); err != nil {
		return nil, err
	}
	return s.cfg.Builder.BuildChainPreserving(s.cfg.IssuerDID, s.cfg.KeyID, s.cfg.VerificationMethod, s.subject(inputHash, outputHash), predecessor, commitment)
}

// SignAggregateFirstDrop issues an aggregate Source Process FirstDrop over the
// consumed set of Pipeline-conformant source credentials (timer/window mechanics,
// transformationClaim provin:aggregate). It is always commitment-bearing: it commits
// to the full set — the sources AS RECEIVED (signed wire form), which is what a
// verifier recomputes against — via vc.NewSourceCommitment, and attaches it to a
// FirstDrop whose InputHash is structurally absent (no single input exists) and whose
// previousCredential is empty (a chain origin; the commitment is an audit attribute,
// never a parent link).
//
// The signer never silently repairs its input: a nil source element, a
// duplicate-content source, or an unknown canonical fails closed (dedup is the
// pool/window's job). Only a signer configured with TransformationClaim ==
// vc.ClaimAggregate may call it — so the commitment-bearing aggregate shape cannot be
// minted under a convert/enrich claim.
func (s *Signer) SignAggregateFirstDrop(ctx context.Context, payload []byte, outputHash string, sources []*vc.PipelinePassCredential) (*vc.PipelinePassCredential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.cfg.TransformationClaim != vc.ClaimAggregate {
		return nil, fmt.Errorf("vcdid: SignAggregateFirstDrop requires an aggregate signer (TransformationClaim %q, want %q)", s.cfg.TransformationClaim, vc.ClaimAggregate)
	}
	for i, src := range sources {
		if src == nil {
			// Fail closed before NewSourceCommitment, which would deref the nil
			// (MarshalJSON / Issuer) and panic.
			return nil, fmt.Errorf("vcdid: nil source credential at index %d", i)
		}
	}
	// NewSourceCommitment also fails closed on a duplicate-content source; running
	// it before the payload gate keeps that (and every structural) error surfacing
	// as itself rather than as a payload mismatch.
	commitment, err := vc.NewSourceCommitment(sources, s.cfg.SourceRootCanonical)
	if err != nil {
		return nil, fmt.Errorf("vcdid: source commitment: %w", err)
	}
	// Defensive gate last, immediately before signing (see verifyPayload).
	if err := verifyPayload(payload, outputHash); err != nil {
		return nil, err
	}
	return s.cfg.Builder.BuildFirstDrop(s.cfg.IssuerDID, s.cfg.KeyID, s.cfg.VerificationMethod, s.aggregateSubject(outputHash), commitment)
}

// hashPayload is the content address of payload — "sha256:" + lowercase hex of
// sha256(payload) — matching the pipeline packages (ingest/chained/sink/aggregate)
// so a recomputed hash compares byte-for-byte against the outputHash they emit.
func hashPayload(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// verifyPayload is the defensive gate: a signer must never attest an outputHash
// for output bytes it was shown that do not produce it. When payload is nil the
// caller supplied no bytes to check (e.g. a sink receipt over an existing
// credential's hash), so the check is skipped — not failed. A non-nil (even
// empty) payload IS checked: a genuinely empty output hashes to sha256("").
func verifyPayload(payload []byte, outputHash string) error {
	if payload == nil {
		return nil
	}
	if got := hashPayload(payload); got != outputHash {
		return fmt.Errorf("vcdid: refusing to sign — payload hash %s does not match outputHash %s", got, outputHash)
	}
	return nil
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

// aggregateSubject assembles the subject for an aggregate FirstDrop: InputHash is
// deliberately left empty — an aggregate folds a consumed set, so there is no single
// input, and vc.New omits an empty InputHash from the wire body. OutputHash is the
// digest of the aggregate output.
func (s *Signer) aggregateSubject(outputHash string) vc.CredentialSubjectFields {
	return vc.CredentialSubjectFields{
		PipelineID:          s.cfg.PipelineID,
		ProcessID:           s.cfg.ProcessID,
		TransformationClaim: s.cfg.TransformationClaim,
		Schema:              s.cfg.Schema,
		OutputHash:          outputHash,
	}
}
