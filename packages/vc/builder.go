package vc

import "github.com/provin-line/oss/packages/crypto"

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
//
// commitment, when non-nil, attaches the audit-reachable commitment over
// the FULL consumed conformant source set — including previous itself
// (all-consumed semantics): a commitment whose DerivedFrom omits the
// predecessor's issuer is an emit-time misuse and an error. nil issues a
// plain chain-preserving credential, fully conformant outside the
// audit-reachable class.
func (b *Builder) BuildChainPreserving(
	issuerDID, keyID, verificationMethod string,
	subject CredentialSubjectFields,
	previous *PipelinePassCredential,
	commitment *SourceCommitment,
) (*PipelinePassCredential, error) {
	panic("not implemented")
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
func (b *Builder) BuildFirstDrop(
	issuerDID, keyID, verificationMethod string,
	subject CredentialSubjectFields,
	commitment *SourceCommitment,
) (*PipelinePassCredential, error) {
	panic("not implemented")
}
