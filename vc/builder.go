package vc

import (
	"fmt"
	"time"

	"github.com/provin-line/oss/crypto"
)

// Builder constructs signed credentials. One Builder serves one issuing
// process; chain state (the previous credential) is supplied per call so the
// caller owns concurrency.
//
// The two build methods mirror the output-side chain behaviours of the
// Pipeline Contract (ChainPreserving / ChainFirstDrop): the method split
// makes the chain-topology choice explicit — a chain-preserving credential
// must be handed its predecessor, and a FirstDrop cannot be handed one. The
// source commitment is orthogonal to that choice: either method accepts an
// optional SourceCommitment (audit-reachable class), committing to the full
// consumed conformant source set.
//
// The issued proof carries the six Data Integrity members
// (type / cryptosuite / verificationMethod / proofPurpose / created /
// proofValue). The provin profile deliberately does NOT emit proof.@context:
// the document @context is bound into the proof config for hashing, and a
// provin verifier reconstructs the config from the document's @context, so the
// closed profile is self-consistent. External W3C-DI-verifier interop is a
// non-goal here, consistent with the int64-preserving JCS deviation.
type Builder struct {
	signer      crypto.Signer
	cryptosuite string
}

// BuilderOption configures a Builder.
type BuilderOption func(*Builder)

// WithCryptosuite selects the proof cryptosuite (default
// CryptosuiteEdDSAJCS2022).
func WithCryptosuite(name string) BuilderOption {
	return func(b *Builder) { b.cryptosuite = name }
}

// NewBuilder returns a Builder signing through signer (KMS model — signer
// typically fronts the registry's SignerService).
func NewBuilder(signer crypto.Signer, opts ...BuilderOption) *Builder {
	b := &Builder{signer: signer, cryptosuite: CryptosuiteEdDSAJCS2022}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// BuildChainPreserving constructs and signs a chain-preserving credential:
// previousCredential is set to previous.Hash() (the boundary was triggered
// by, and keeps identity with, the predecessor event). previous must be
// non-nil — passing nil is an error, not a silent FirstDrop.
//
// commitment, when non-nil, attaches the audit-reachable commitment over
// the FULL consumed conformant source set — including previous itself
// (all-consumed semantics): a commitment whose DerivedFrom omits the
// predecessor's issuer is an emit-time misuse and an error. nil issues a
// plain chain-preserving credential, fully conformant outside the
// audit-reachable class.
//
// Like every issue path, the build enforces the claim MUSTs — presence,
// token grammar, and namespace grounding (ValidateTransformationClaim) —
// before signing.
func (b *Builder) BuildChainPreserving(
	issuerDID, keyID, verificationMethod string,
	subject CredentialSubjectFields,
	previous *PipelinePassCredential,
	commitment *SourceCommitment,
) (*PipelinePassCredential, error) {
	if previous == nil {
		return nil, fmt.Errorf("vc: BuildChainPreserving requires a non-nil predecessor (a nil predecessor is a FirstDrop)")
	}
	prevHash, err := previous.Hash()
	if err != nil {
		return nil, fmt.Errorf("vc: hash predecessor: %w", err)
	}
	if commitment != nil {
		if err := requirePredecessorCommitted(previous, commitment); err != nil {
			return nil, err
		}
	}
	return b.build(issuerDID, keyID, verificationMethod, CredentialFields{
		Issuer:             issuerDID,
		ValidFrom:          time.Now(),
		Subject:            subject,
		PreviousCredential: prevHash,
		SourceCommitment:   commitment,
	})
}

// BuildFirstDrop constructs and signs a chain-origin credential (no
// previousCredential): external ingestion or aggregation. For aggregation,
// subject.TransformationClaim is typically ClaimAggregate — the result has
// no identity relationship with any single input, so a fresh chain begins;
// the chain itself carries no upstream link (Paper 01 §4.8). The topology
// is decided by the trigger rules, not by the claim.
//
// commitment, when non-nil, attaches the audit-reachable commitment over
// the consumed source set (an audit attribute, not a parent link — see
// SourceCommitment). nil issues a plain FirstDrop, which is fully
// conformant outside the audit-reachable class.
//
// Like every issue path, the build enforces the claim MUSTs — presence,
// token grammar, and namespace grounding (ValidateTransformationClaim) —
// before signing.
func (b *Builder) BuildFirstDrop(
	issuerDID, keyID, verificationMethod string,
	subject CredentialSubjectFields,
	commitment *SourceCommitment,
) (*PipelinePassCredential, error) {
	return b.build(issuerDID, keyID, verificationMethod, CredentialFields{
		Issuer:           issuerDID,
		ValidFrom:        time.Now(),
		Subject:          subject,
		SourceCommitment: commitment,
	})
}

// build constructs the unsigned body (via New, which enforces the claim MUSTs),
// signs a Data Integrity proof over it, and attaches the proof.
func (b *Builder) build(issuerDID, keyID, verificationMethod string, fields CredentialFields) (*PipelinePassCredential, error) {
	cred, err := New(fields)
	if err != nil {
		return nil, err
	}
	proof, err := CreateProof(b.signer, issuerDID, keyID, verificationMethod, cred.body, b.cryptosuite)
	if err != nil {
		return nil, err
	}
	cred.proof = proofToMap(proof)
	return cred, nil
}

// requirePredecessorCommitted enforces all-consumed semantics at emit time:
// a chain-preserving credential's source commitment MUST include the
// triggering predecessor's issuer in DerivedFrom.
func requirePredecessorCommitted(previous *PipelinePassCredential, commitment *SourceCommitment) error {
	issuer := previous.Issuer()
	for _, d := range commitment.DerivedFrom {
		if d == issuer {
			return nil
		}
	}
	return fmt.Errorf("vc: source commitment DerivedFrom must include the predecessor's issuer %q (all-consumed semantics)", issuer)
}

// proofToMap renders the typed proof as the raw wire map stored on the
// credential (the form MarshalJSON emits and Proof() reads).
func proofToMap(p *DataIntegrityProof) map[string]any {
	return map[string]any{
		"type":               p.Type,
		"cryptosuite":        p.Cryptosuite,
		"verificationMethod": p.VerificationMethod,
		"proofPurpose":       p.ProofPurpose,
		"created":            p.Created,
		"proofValue":         p.ProofValue,
	}
}
