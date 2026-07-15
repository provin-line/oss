package vc

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/canon/urdna2015"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/multibase"
)

// SuiteContract is the claim contract a proof is verified under — the exact
// answer to "what does this signature attest, and by which rules was it
// checked?".
//
// It exists because one cryptosuite identifier covers two different byte
// streams. eddsa-jcs-2022 over a proof-local @context and a Multikey key is the
// W3C suite, canonicalized with RFC 8785. The same identifier over a six-member
// proof and a JWK key is what provin issued before Fork W, canonicalized with
// the int64-verbatim deviation. Reporting both as "eddsa-jcs-2022" would tell a
// consumer nothing about which rules actually ran, so the contract — not the
// suite id — is what reaches the evidence vector (claims.suite.contract-id).
type SuiteContract string

const (
	// ContractW3CEdDSAJCS2022 is the W3C Data Integrity suite: jcs-rfc8785,
	// proof-local @context, Multikey (signer.suite.eddsa-jcs-2022).
	ContractW3CEdDSAJCS2022 SuiteContract = "W3C_EDDSA_JCS_2022_REC_20250515@1"
	// ContractW3CEdDSARDFC2022 is the W3C Data Integrity RDFC suite: urdna2015,
	// proof-local @context, Multikey (signer.suite.eddsa-rdfc-2022). Phase-2
	// opt-in, v0-mandatory.
	ContractW3CEdDSARDFC2022 SuiteContract = "W3C_EDDSA_RDFC_2022_REC_20250515@1"
	// ContractLegacyProvinEdDSAJCSInt64 is the projection of proofs provin
	// issued under the historical int64-verbatim deviation
	// (signer.suite.legacy-projection). It is a read-only contract: it names
	// what old evidence was signed under, and nothing new is issued into it.
	ContractLegacyProvinEdDSAJCSInt64 SuiteContract = "LEGACY_PROVIN_EDDSA_JCS_INT64@1"
)

// CanonicalizerID returns the canonicalization the contract is verified under.
// The contract binds it: a caller cannot pick a contract and a canonicalizer
// independently, which is what keeps one suite identifier from meaning two byte
// streams depending on who is reading.
func (c SuiteContract) CanonicalizerID() string {
	switch c {
	case ContractW3CEdDSAJCS2022:
		return jcs.NameRFC8785
	case ContractW3CEdDSARDFC2022:
		return urdna2015.Name
	case ContractLegacyProvinEdDSAJCSInt64:
		return jcs.Name
	default:
		return ""
	}
}

// canonicalizer returns the canonicalizer this contract is verified under.
func (c SuiteContract) canonicalizer() (canonicalizerFunc, error) {
	switch c {
	case ContractW3CEdDSAJCS2022:
		return jcs.RFC8785{}.Canonicalize, nil
	case ContractW3CEdDSARDFC2022:
		// The registered suite canonicalizer: urdna2015 over the frozen embedded
		// contexts, probed at init. The registry is safe to consult here because
		// it can only ever hold conformant canonicalizers — the legacy deviation
		// is the one thing it structurally cannot hand out.
		rc, err := canonicalizerFor(CryptosuiteEdDSARDFC2022)
		if err != nil {
			return nil, err
		}
		return rc.Canonicalize, nil
	case ContractLegacyProvinEdDSAJCSInt64:
		return jcs.Canonicalizer{}.Canonicalize, nil
	default:
		return nil, fmt.Errorf("vc: no canonicalizer for contract %q", c)
	}
}

type canonicalizerFunc func(any) ([]byte, error)

// ClassifyProof resolves the claim contract from the proof's suite identifier,
// the presence of its proof-local @context, and the encoding of the
// verification method that will check it (signer.suite.exact-dispatch).
//
// The discriminator is the conjunction of shape and key type, exactly as the
// catalog fixes it (signer.suite.legacy-projection: "the distinguisher between
// legacy and the W3C suite is the proof shape and key type (Multikey +
// @context), not the identifier string"). Every combination outside the two
// known contracts fails. It never tries one canonicalizer and falls back to the
// other when a signature does not check out: a fallback would turn the
// signature into an oracle for "which contract is this?", so a proof would be
// verified under whichever rules happened to accept it rather than the rules it
// was issued under.
//
// The two rejected in-suite combinations:
//
//   - @context + JWK claims the W3C suite while missing the Multikey the suite
//     requires — it names a contract it does not satisfy
//     (signer.suite.eddsa-jcs-2022: lacking any element, it must not be named
//     eddsa-jcs-2022).
//   - no @context + Multikey is a shape the profile never issues: every
//     document this repository signs carries an @context
//     (did.IssuedDocumentContexts for DID documents, the frozen credential
//     contexts for credentials, the delegation signing body), so a conformant
//     W3C proof always mirrors one. Accepting the bare shape as W3C would let
//     a pre-Fork-W proof be promoted the moment its DID document was re-issued
//     with a Multikey — reclassifying evidence on the strength of a change made
//     after it was signed.
func ClassifyProof(cryptosuite string, hasProofContext bool, encoding did.KeyEncoding) (SuiteContract, error) {
	switch cryptosuite {
	case CryptosuiteEdDSAJCS2022:
		switch {
		case hasProofContext && encoding == did.EncodingMultikey:
			return ContractW3CEdDSAJCS2022, nil
		case !hasProofContext && encoding == did.EncodingJWK:
			return ContractLegacyProvinEdDSAJCSInt64, nil
		default:
			return "", fmt.Errorf(
				"vc: proof shape does not match any %s contract (proof-local @context: %t, key encoding: %q)",
				cryptosuite, hasProofContext, encoding)
		}
	case CryptosuiteEdDSARDFC2022:
		// One shape only: the suite postdates the legacy era, so there is no
		// projection row — a non-W3C rdfc proof is malformed, not historical.
		if hasProofContext && encoding == did.EncodingMultikey {
			return ContractW3CEdDSARDFC2022, nil
		}
		return "", fmt.Errorf(
			"vc: proof shape does not match the %s contract (proof-local @context: %t, key encoding: %q)",
			cryptosuite, hasProofContext, encoding)
	default:
		return "", fmt.Errorf("vc: cryptosuite %q has no claim contract", cryptosuite)
	}
}

// VerifyProofUnderContract verifies proof under an explicitly named claim
// contract, using the canonicalization that contract binds.
//
// This is the only way to reach the legacy canonicalizer. The suite registry
// deliberately cannot: it names what we issue, and letting it hand the
// int64-verbatim deviation to a verification would resurrect the ambiguity the
// contract exists to remove.
func VerifyProofUnderContract(
	verifier crypto.Verifier,
	publicKey []byte,
	proof *DataIntegrityProof,
	document map[string]any,
	contract SuiteContract,
) error {
	if proof == nil {
		return errors.New("vc: nil proof")
	}
	canonFn, err := contract.canonicalizer()
	if err != nil {
		return err
	}
	ctx, hasCtx := document[keyContext]
	cfg := proofConfigMap(proof.Type, proof.Cryptosuite, proof.VerificationMethod, proof.ProofPurpose, proof.Created, ctx, hasCtx)
	hd, err := proofHashDataFunc(canonFn, cfg, document)
	if err != nil {
		return err
	}
	sig, err := multibase.DecodeBase58Btc(proof.ProofValue)
	if err != nil {
		return fmt.Errorf("vc: decode proofValue: %w", err)
	}
	ok, err := verifier.Verify(publicKey, hd, sig)
	if err != nil {
		return fmt.Errorf("vc: verify proof signature: %w", err)
	}
	if !ok {
		return errors.New("vc: proof signature does not verify")
	}
	return nil
}

// requireProofContextMirrorsDocument enforces, for the W3C contract, that the
// wire proof's @context member equals the document's.
//
// This closes the one malleable member the shape would otherwise admit. The
// proof config is reconstructed from the DOCUMENT's @context on this verify
// path, so the signature does not cover the wire proof.@context member itself —
// swapping it would go unnoticed here while a W3C verifier (which canonicalizes
// the wire proof options as-is, vc-di-eddsa §3.3.2) would reject the same
// artifact. Two verifiers disagreeing about the same bytes is the interop
// failure Fork W exists to end, so the mirror is checked explicitly. Equality
// is on canonical bytes: the member is data, not a string to compare loosely.
func requireProofContextMirrorsDocument(proof *DataIntegrityProof, document map[string]any) error {
	docCtx, docHas := document[keyContext]
	if !docHas {
		// Unreachable for W3C-classified proofs issued by this profile (every
		// signed document carries a context); kept as defense in depth.
		return errors.New("vc: W3C proof carries @context but the document has none")
	}
	pb, err := jcs.CanonicalizeRFC8785(proof.Context)
	if err != nil {
		return fmt.Errorf("vc: canonicalize proof @context: %w", err)
	}
	db, err := jcs.CanonicalizeRFC8785(docCtx)
	if err != nil {
		return fmt.Errorf("vc: canonicalize document @context: %w", err)
	}
	if !bytes.Equal(pb, db) {
		return errors.New("vc: proof-local @context does not mirror the document @context")
	}
	return nil
}

// VerifyProofWithContract classifies the proof from its suite identifier, its
// proof-local @context, and the encoding of the verification method that checks
// it, then verifies it under the contract that classification names. It returns
// the contract so the caller can report WHICH rules ran — a bare "verified"
// hides whether the artifact met the W3C suite or the legacy projection
// (claims.headline.suite-contract).
//
// encoding must come from the same verification-method resolution that produced
// publicKey (did.ExtractPublicKeyAndEncoding). Two separate readings can
// disagree, and a dispatch built on a disagreement is not exact.
func VerifyProofWithContract(
	verifier crypto.Verifier,
	publicKey []byte,
	encoding did.KeyEncoding,
	proof *DataIntegrityProof,
	document map[string]any,
) (SuiteContract, error) {
	if proof == nil {
		return "", errors.New("vc: nil proof")
	}
	contract, err := ClassifyProof(proof.Cryptosuite, proof.Context != nil, encoding)
	if err != nil {
		return "", err
	}
	switch contract {
	case ContractW3CEdDSAJCS2022, ContractW3CEdDSARDFC2022:
		// Both W3C contracts carry the proof-local @context, and on this verify
		// path the wire member is otherwise outside the signature — the mirror
		// is what pins it (see requireProofContextMirrorsDocument).
		if err := requireProofContextMirrorsDocument(proof, document); err != nil {
			return "", err
		}
	}
	if err := VerifyProofUnderContract(verifier, publicKey, proof, document, contract); err != nil {
		return "", err
	}
	return contract, nil
}
