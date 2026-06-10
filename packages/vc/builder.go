package vc

import "github.com/provin-line/oss/packages/crypto"

// Builder constructs signed credentials. One Builder serves one issuing
// process; chain state (the previous credential) is supplied per call so the
// caller owns concurrency.
type Builder struct {
	signer      crypto.Signer
	cryptosuite string
}

// BuilderOption configures a Builder.
type BuilderOption func(*Builder)

// WithCryptosuite selects the proof cryptosuite (default
// CryptosuiteEdDSAJCS2022).
func WithCryptosuite(name string) BuilderOption { panic("not implemented") }

// NewBuilder returns a Builder signing through signer (KMS model — signer
// typically fronts the registry's SignerService).
func NewBuilder(signer crypto.Signer, opts ...BuilderOption) *Builder { panic("not implemented") }

// Build constructs and signs a credential.
//
// previous non-nil → chain-preserving: previousCredential is set to
// previous.Hash() (the boundary was triggered by, and keeps identity with,
// the predecessor event). origin must be nil — a chain-preserving
// credential never carries an origin commitment; violating this is an
// error, not a silent drop.
//
// previous nil → chain origin (FirstDrop): external ingestion or
// aggregation. For aggregation, subject.TransformationType is
// TransformationAggregate — the result has no identity relationship with
// any single input, so a fresh chain begins; the chain itself carries no
// upstream link (Paper 01 §4.8). origin, when non-nil, attaches the
// audit-reachable commitment over the consumed source set (an audit
// attribute, not a parent link — see OriginCommitment).
func (b *Builder) Build(
	issuerDID, keyID, verificationMethod string,
	subject CredentialSubjectFields,
	previous *PipelinePassCredential,
	origin *OriginCommitment,
) (*PipelinePassCredential, error) {
	panic("not implemented")
}
