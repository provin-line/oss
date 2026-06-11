package vc

import (
	_ "embed"
)

// contextDplaaxVCV1Document is the vendored byte-exact copy of the dplaax
// protocol context (canonical: dplaax.spec_draft contexts/v1.jsonld). The
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

// contextProvinVCV1Document is the provin profile context. Unlike the
// protocol context (vendored from the spec), THIS file is the canonical
// document — the profile context's source of truth lives with the profile.
// Its job is grounding: it maps the "provin" claim namespace prefix to its
// vocabulary URL, making claim identity the (grounding URL, label) pair
// rather than the bare prefix string (spec rule credential.claim.grounding
// — a bare prefix has no owner; the grounding rides the signing scope, so
// an impostor "provin:" with different grounding is byte-distinguishable).
// It also hosts any future provin-owned custom subject field terms.
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
