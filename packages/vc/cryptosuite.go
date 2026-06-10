package vc

import "github.com/provin-line/oss/packages/canon"

// Wire identifiers of the supported proof cryptosuites.
const (
	// CryptosuiteEdDSAJCS2022 — Ed25519 over JCS canonicalization (Phase 1,
	// MUST).
	CryptosuiteEdDSAJCS2022 = "eddsa-jcs-2022"
	// CryptosuiteEdDSARDFC2022 — Ed25519 over URDNA2015 canonicalization
	// (Phase 2, MAY).
	CryptosuiteEdDSARDFC2022 = "eddsa-rdfc-2022"
)

// RegisterCryptosuite registers the canonicalizer backing a proof
// cryptosuite. Registration is init-time only; RDF-based suites must pass an
// IRI expansion probe over a real-shape credential or the process panics at
// startup — a binary with broken canonicalization must not serve.
func RegisterCryptosuite(name string, c canon.Canonicalizer) { panic("not implemented") }

// RegisterSourceRootCanonicalizer registers a canonicalizer eligible for the
// source_root_canonical field. No-op identifiers ("", "none", "null",
// "identity") are rejected here and again at verification time (JOSE
// alg:none class defense).
func RegisterSourceRootCanonicalizer(c canon.Canonicalizer) { panic("not implemented") }
