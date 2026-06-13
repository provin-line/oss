package vc

import (
	"fmt"
	"sync"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/canon/jcs"
)

// Wire identifiers of the supported proof cryptosuites.
const (
	// CryptosuiteEdDSAJCS2022 — Ed25519 over JCS canonicalization (Phase 1,
	// MUST).
	CryptosuiteEdDSAJCS2022 = "eddsa-jcs-2022"
	// CryptosuiteEdDSARDFC2022 — Ed25519 over URDNA2015 canonicalization
	// (Phase 2, MAY).
	CryptosuiteEdDSARDFC2022 = "eddsa-rdfc-2022"
)

// noOpCryptosuites are the identifier values that name "no canonicalization /
// no signature" — the JOSE alg:none class. Registering or selecting one is a
// misconfiguration, never a valid suite.
var noOpCryptosuites = map[string]bool{"": true, "none": true, "null": true, "identity": true}

var (
	cryptosuitesMu sync.RWMutex
	cryptosuites   = map[string]canon.Canonicalizer{}
)

// RegisterCryptosuite registers the canonicalizer backing a proof
// cryptosuite. Registration is init-time only; RDF-based suites must pass an
// IRI expansion probe over a real-shape credential or the process panics at
// startup — a binary with broken canonicalization must not serve. No-op
// identifiers ("", "none", "null", "identity") are rejected here and again
// at verification time (JOSE alg:none class defense).
//
// Which registered suites are acceptable at a given proof.created instant is
// governed by the lifecycle policy: the Verifier consults its
// LifecycleRegistry (see lifecycle.go), whose published append-only form is
// backed by tlog.
//
// A no-op identifier or a nil canonicalizer is a startup misconfiguration and
// panics — registration runs at init, before the process serves traffic.
func RegisterCryptosuite(name string, c canon.Canonicalizer) {
	if noOpCryptosuites[name] {
		panic(fmt.Sprintf("vc: refusing to register no-op cryptosuite %q (alg:none class)", name))
	}
	if c == nil {
		panic(fmt.Sprintf("vc: nil canonicalizer for cryptosuite %q", name))
	}
	cryptosuitesMu.Lock()
	defer cryptosuitesMu.Unlock()
	// Reject re-registration: registration is init-time only, and silently
	// overwriting a suite's canonicalizer after init would let a late
	// registration swap in a different (or broken) canonicalization under an
	// already-trusted suite name. A duplicate is a startup misconfiguration.
	if _, exists := cryptosuites[name]; exists {
		panic(fmt.Sprintf("vc: cryptosuite %q already registered (re-registration is forbidden)", name))
	}
	cryptosuites[name] = c
}

// canonicalizerFor returns the registered canonicalizer for a cryptosuite, or
// an error. No-op identifiers are rejected here too — the verification-time
// half of the alg:none defense, independent of what was registered.
func canonicalizerFor(name string) (canon.Canonicalizer, error) {
	if noOpCryptosuites[name] {
		return nil, fmt.Errorf("vc: cryptosuite %q is a no-op identifier (alg:none class), rejected", name)
	}
	cryptosuitesMu.RLock()
	c, ok := cryptosuites[name]
	cryptosuitesMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("vc: unknown cryptosuite %q", name)
	}
	return c, nil
}

func init() {
	// eddsa-jcs-2022 is the Phase-1 MUST suite: JCS canonicalization. JCS needs
	// no IRI-expansion probe (it is structural, not RDF-based).
	RegisterCryptosuite(CryptosuiteEdDSAJCS2022, jcs.Canonicalizer{})
}
