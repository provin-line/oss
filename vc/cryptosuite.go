package vc

import (
	"fmt"
	"sync"
	"time"

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
// cryptosuite. Registration is init-time only (main or init, before the
// process serves). It does not check the canonicalizer: eddsa-rdfc-2022,
// whose canonicalizer RegisterEdDSARDFC2022 checks against a full provin
// credential, is registered only by that function, and a canonicalizer a
// program registers here under another name is the program's to check
// (RegisterEdDSARDFC2022's guarantee covers eddsa-rdfc-2022). No-op
// identifiers ("", "none", "null", "identity") are rejected here and again
// at verification time (JOSE alg:none class defense).
//
// Which registered suites are acceptable at a given proof.created instant is
// governed by the lifecycle policy: the Verifier consults its
// LifecycleRegistry (see lifecycle.go), whose published append-only form is
// backed by tlog.
//
// A no-op identifier, eddsa-rdfc-2022 or a nil canonicalizer is a startup
// misconfiguration and panics — registration runs before the process serves
// traffic.
func RegisterCryptosuite(name string, c canon.Canonicalizer) {
	if name == CryptosuiteEdDSARDFC2022 {
		panic(fmt.Sprintf("vc: cryptosuite %q is registered by vc.RegisterEdDSARDFC2022", name))
	}
	registerCryptosuite(name, c)
}

func registerCryptosuite(name string, c canon.Canonicalizer) {
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
// half of the alg:none defense, independent of what was registered. Issuing a
// proof (CreateProof), verifying one by its suite (VerifyProof), and
// verifying one under the eddsa-rdfc-2022 contract take the canonicalizer
// here, so that suite's canonicalization never runs while it is not
// registered; the eddsa-jcs-2022 and legacy contracts bind their own
// canonicalizers.
func canonicalizerFor(name string) (canon.Canonicalizer, error) {
	if noOpCryptosuites[name] {
		return nil, fmt.Errorf("vc: cryptosuite %q is a no-op identifier (alg:none class), rejected", name)
	}
	cryptosuitesMu.RLock()
	c, ok := cryptosuites[name]
	cryptosuitesMu.RUnlock()
	switch {
	case !ok && name == CryptosuiteEdDSARDFC2022:
		return nil, fmt.Errorf("%w: %q: a process that issues or verifies it calls vc.RegisterEdDSARDFC2022 first", ErrCryptosuiteNotRegistered, name)
	case !ok:
		return nil, fmt.Errorf("%w: unknown cryptosuite %q", ErrCryptosuiteNotRegistered, name)
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
	registerCryptosuite(CryptosuiteEdDSAJCS2022, jcs.RFC8785{})
}

var registerRDFC sync.Once

// RegisterEdDSARDFC2022 registers the eddsa-rdfc-2022 cryptosuite for this
// process. Until it is called, no function or Verifier of this package issues
// or verifies a proof of this suite, and none runs JSON-LD processing:
// CreateProof, VerifyProof, VerifyProofUnderContract and
// VerifyProofWithContract refuse such a proof before reading anything else of
// it with an error that wraps ErrCryptosuiteNotRegistered and names this
// function, and a Verifier finds its signer authenticity failed. Once it is
// called, they issue and verify it, in every package of the process. (A
// program that calls canon/urdna2015 itself runs JSON-LD processing by its
// own choice.)
//
// Read before calling it:
//
//   - Verifying an eddsa-rdfc-2022 proof canonicalizes the document first:
//     JSON-LD processing (expansion and RDF Dataset Canonicalization, through
//     canon/urdna2015 and json-gold) runs on the untrusted document before
//     its signature is checked.
//   - That work is bounded: the comparisons the dataset's node map makes, the
//     length of the canonical form, and the work of labelling blank nodes. A
//     document past one of these bounds is refused with an error wrapping
//     urdna2015.ErrTooComplex, both when a proof is created and when one is
//     verified.
//   - A document nested deeper than encoding/json decodes, more than 10,000
//     objects and arrays, is refused before anything recurses into it: by
//     CreateProof's check of its numbers, with canon's error; when verifying,
//     by the comparison of the proof's @context with the document's, with
//     canon/jcs's error, or else by the suite's canonicalization, with an
//     error wrapping urdna2015.ErrTooComplex.
//   - Within the bounds the work is linear in the document's size, but heavy:
//     of the shapes measured, a 1 MiB document that names a served context
//     again at every node costs the most, about 1 s and 0.9 GB allocated
//     (darwin/arm64). This package does not bound the size of a document;
//     its caller does, as a server bounds the body of a request.
//   - A document some value of which the canonical form would not hold is
//     refused, and so are documents in forms the canonical N-Quads cannot
//     write one-to-one (canon/urdna2015's package doc lists the forms). Only
//     the three contexts this package embeds are resolved, never the
//     network, and a document's @context may hold only their IRIs: a context
//     written in the document, at any depth, is refused before the document
//     is canonicalized, so every term it uses is defined in the embedded
//     contexts.
//
// Call it once, from the program's main or an init function of its main
// package, before the process issues or verifies a proof; a second call does
// nothing. It holds for the whole process, so a library that called it would
// open the suite for every program that imports it: no package of this
// module calls it (scripts/check-rdfc-registration.sh). The canonicalizer is
// checked against a full provin credential before it is registered; a
// failure panics, so a process whose canonicalization cannot cover the wire
// vocabulary does not start.
func RegisterEdDSARDFC2022() {
	registerRDFC.Do(func() {
		// URDNA2015 canonicalization over the three frozen context
		// documents, resolved offline from the embedded copies: a credential
		// holding any other context, an IRI or one written in it, is refused
		// (servedContextsOnly).
		rdfc := servedContextsOnly(map[string][]byte{
			ContextCredentialsV2: contextCredentialsV2Document,
			ContextDplaaxVCV1:    contextDplaaxVCV1Document,
			ContextProvinVCV1:    contextProvinVCV1Document,
		})
		probeRDFC(rdfc)
		registerCryptosuite(CryptosuiteEdDSARDFC2022, rdfc)
	})
}

// probeRDFC canonicalizes a full-shape provin credential (every wire member:
// schema, hashes, chain link, source commitment) and its proof config through
// c, panicking on any error. It runs when the suite is registered
// (RegisterEdDSARDFC2022): an embedded-context omission or
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
