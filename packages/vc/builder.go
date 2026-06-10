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

// Build constructs and signs a chain-preserving credential: previousCredential
// is set to previous.Hash() (FilterConvert semantics). previous may be nil
// only for first-stage pipelines consuming non-VC input.
func (b *Builder) Build(
	issuerDID, keyID, verificationMethod string,
	subject CredentialSubjectFields,
	previous *PipelinePassCredential,
) (*PipelinePassCredential, error) {
	panic("not implemented")
}

// SourceRef identifies one Pipeline-conformant source VC an Origin Source
// derives from: the issuer DID and the exact wire bytes as received.
type SourceRef struct {
	IssuerDID string
	WireBytes []byte
}

// BuildOriginSource constructs and signs a FirstDrop credential
// (previousCredential empty) with origin commitments computed from sources:
// derived_from is the deduplicated issuer DID set and source_root is the
// Merkle commitment over the canonicalized wire bytes. Computing both from
// the same input enforces the derived_from ↔ source set equality by
// construction rather than trusting the caller. An empty sources slice
// yields a pure chain origin (External Source variant — no origin fields).
func (b *Builder) BuildOriginSource(
	issuerDID, keyID, verificationMethod string,
	subject CredentialSubjectFields,
	sources []SourceRef,
) (*PipelinePassCredential, error) {
	panic("not implemented")
}
