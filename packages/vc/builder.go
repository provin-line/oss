package vc

import "github.com/provin-line/oss/packages/crypto"

// Builder constructs signed credentials. One Builder serves one issuing
// process; chain state (the previous credential) is supplied per call so the
// caller owns concurrency.
//
// The two build methods mirror the output-side chain behaviours of the
// Pipeline Contract (ChainPreserving / ChainFirstDrop): the
// previous-XOR-origin invariant is expressed in the method split rather
// than checked at runtime — a chain-preserving credential cannot be handed
// an origin commitment, and a FirstDrop cannot be handed a predecessor.
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

// BuildChainPreserving constructs and signs a chain-preserving credential:
// previousCredential is set to previous.Hash() (the boundary was triggered
// by, and keeps identity with, the predecessor event). previous must be
// non-nil — passing nil is an error, not a silent FirstDrop.
func (b *Builder) BuildChainPreserving(
	issuerDID, keyID, verificationMethod string,
	subject CredentialSubjectFields,
	previous *PipelinePassCredential,
) (*PipelinePassCredential, error) {
	panic("not implemented")
}

// BuildFirstDrop constructs and signs a chain-origin credential (no
// previousCredential): external ingestion or aggregation. For aggregation,
// subject.TransformationType is TransformationAggregate — the result has no
// identity relationship with any single input, so a fresh chain begins; the
// chain itself carries no upstream link (Paper 01 §4.8).
//
// origin, when non-nil, attaches the audit-reachable commitment over the
// consumed source set (an audit attribute, not a parent link — see
// OriginCommitment). nil issues a plain FirstDrop, which is fully
// conformant outside the audit-reachable class.
func (b *Builder) BuildFirstDrop(
	issuerDID, keyID, verificationMethod string,
	subject CredentialSubjectFields,
	origin *OriginCommitment,
) (*PipelinePassCredential, error) {
	panic("not implemented")
}
