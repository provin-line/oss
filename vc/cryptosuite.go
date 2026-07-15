package vc

import (
	"fmt"
	"sync"
	"time"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/canon/urdna2015"
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
	// eddsa-jcs-2022 is the Phase-1 MUST suite: RFC 8785 canonicalization
	// (canon.jcs.base). JCS needs no IRI-expansion probe (it is structural, not
	// RDF-based).
	//
	// The registry answers "what do we ISSUE?", so it names the conformant
	// canonicalizer only. Verifying an artifact signed under the historical
	// int64-verbatim deviation goes through its claim contract instead
	// (ContractLegacyProvinEdDSAJCSInt64) — the registry must not be able to
	// hand the deviation to a new signature.
	RegisterCryptosuite(CryptosuiteEdDSAJCS2022, jcs.RFC8785{})

	// eddsa-rdfc-2022: URDNA2015 canonicalization over the three frozen
	// context documents, resolved offline from the embedded copies — a
	// credential referencing any other context IRI fails rather than fetches.
	// The suite is registered only after the expansion probe passes.
	rdfc := urdna2015.NewCanonicalizer(map[string][]byte{
		ContextCredentialsV2: contextCredentialsV2Document,
		ContextDplaaxVCV1:    contextDplaaxVCV1Document,
		ContextProvinVCV1:    contextProvinVCV1Document,
	})
	probeRDFC(rdfc)
	RegisterCryptosuite(CryptosuiteEdDSARDFC2022, rdfc)
}

// probeRDFC canonicalizes a full-shape provin credential (every wire member:
// schema, hashes, chain link, source commitment) and its proof config through
// c, panicking on any error. It runs at init: an embedded-context omission or
// a wire term no frozen context defines must fail process startup loudly —
// a binary whose RDF canonicalization cannot cover the wire vocabulary would
// otherwise refuse (or worse, partition) every rdfc proof it touches at
// runtime.
func probeRDFC(c canon.Canonicalizer) {
	cred, err := New(CredentialFields{
		Issuer:    "did:dplaax:probe.dplaax.dev:org:probe:pipeline:p:process:s",
		ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Subject: CredentialSubjectFields{
			PipelineID:          "p",
			ProcessID:           "s",
			TransformationClaim: ClaimAggregate,
			Schema:              SchemaRef{ID: SchemaURI("probe", "1.0.0"), Type: "JsonSchema", ContentHash: "sha256:" + probeHex},
			InputHash:           "sha256:" + probeHex,
			OutputHash:          "sha256:" + probeHex,
		},
		PreviousCredential: "sha256:" + probeHex,
		SourceCommitment: &SourceCommitment{
			DerivedFrom:         []string{"sha256:" + probeHex},
			SourceRoot:          "f1220" + probeHex,
			SourceRootCanonical: "rfc6962-sha256",
		},
	})
	if err != nil {
		panic(fmt.Sprintf("vc: rdfc probe credential: %v", err))
	}
	doc := cred.Body()
	if _, err := c.Canonicalize(doc); err != nil {
		panic(fmt.Sprintf("vc: rdfc expansion probe (credential): %v", err))
	}
	ctx, hasCtx := doc[keyContext]
	cfg := proofConfigMap(proofType, CryptosuiteEdDSARDFC2022,
		"did:dplaax:probe.dplaax.dev:org:probe:pipeline:p:process:s#signing",
		proofPurposeSign, "2026-01-01T00:00:00Z", ctx, hasCtx)
	if _, err := c.Canonicalize(cfg); err != nil {
		panic(fmt.Sprintf("vc: rdfc expansion probe (proof config): %v", err))
	}
}

// probeHex is a fixed 64-hex filler for the probe credential's content
// addresses.
const probeHex = "abababababababababababababababababababababababababababababababab"
