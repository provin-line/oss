package vc

import (
	_ "embed"
)

// contextCredentialsV2Document is the byte-exact copy of the W3C Verifiable
// Credentials v2 base context, retrieved verbatim from
// https://www.w3.org/ns/credentials/v2 (a permanently-cacheable static
// document). The VCDM 2.0 specification publishes its normative sha256 —
// pinned by TestCredentialsV2ContextMatchesNormativeDigest — so any
// divergence from the official bytes, however it happens, fails the build's
// tests. The RDFC (eddsa-rdfc-2022) canonicalization expands every
// credential against this document, so its bytes sit inside the signing
// scope the same way the two protocol contexts below do. Embedded at
// compile time, never fetched at runtime.
//
//go:embed contexts/credentials-v2.jsonld
var contextCredentialsV2Document []byte

// ContextCredentialsV2Document returns the W3C credentials/v2 base context
// document (defensive copy) served at ContextCredentialsV2.
func ContextCredentialsV2Document() []byte {
	out := make([]byte, len(contextCredentialsV2Document))
	copy(out, contextCredentialsV2Document)
	return out
}

// contextDplaaxVCV1Document is the vendored byte-exact copy of the dplaax
// protocol context (canonical: dplaax.spec contexts/v1.jsonld). The
// @context array rides the signing scope as bytes, so any divergence from
// the canonical document is a cross-implementation hash partition;
// TestContextDocumentMatchesSpec pins the sha256 recorded in the spec's
// contexts/README.md. Embedded at compile time, never fetched at runtime.
//
//go:embed contexts/vc-v1.jsonld
var contextDplaaxVCV1Document []byte

// ContextDplaaxVCV1Document returns the dplaax protocol context document
// (defensive copy) served at ContextDplaaxVCV1. Ownership is two-layer
// (spec Model A): this protocol context maps the dplaax wire keys to IRIs
// and is identical across profiles; a profile may append its own extension
// context for profile-owned custom subject fields, and must not redefine
// protocol terms (@protected enforces this mechanically).
func ContextDplaaxVCV1Document() []byte {
	out := make([]byte, len(contextDplaaxVCV1Document))
	copy(out, contextDplaaxVCV1Document)
	return out
}

// contextProvinVCV1Document is the vendored byte-exact copy of the provin
// PROFILE context (canonical: provin-line/profile.spec contexts/v1.jsonld).
// Model A says the profile context's source of truth lives with the profile;
// until that repository existed this file WAS the canonical, because the
// implementation was standing in for a spec nobody had written. It is now
// vendored like the protocol context, and pinned the same way.
//
// Its job is grounding: it maps the "provin" claim namespace prefix to its
// vocabulary URL, making claim identity the (grounding URL, label) pair
// rather than the bare prefix string (spec rule credential.claim.grounding
// — a bare prefix has no owner; the grounding rides the signing scope, so
// an impostor "provin:" with different grounding is byte-distinguishable).
// It also hosts any future provin-owned custom subject field terms.
//
// What each grounded label ASSERTS is not here and not anywhere in this
// package: that is the profile's claim registry (profile.spec rules/claim.yaml).
// This implementation's claim check is deliberately structural — see
// ValidateTransformationClaim.
//
//go:embed contexts/provin-v1.jsonld
var contextProvinVCV1Document []byte

// ContextProvinVCV1Document returns the provin profile context document
// (defensive copy) served at ContextProvinVCV1.
func ContextProvinVCV1Document() []byte {
	out := make([]byte, len(contextProvinVCV1Document))
	copy(out, contextProvinVCV1Document)
	return out
}
