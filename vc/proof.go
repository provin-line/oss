package vc

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/multibase"
)

// Data Integrity proof constants for the provin profile: every issued proof is
// a DataIntegrityProof used for assertionMethod (VC signing).
const (
	proofType        = "DataIntegrityProof"
	proofPurposeSign = "assertionMethod"
)

// CreateProof produces a Data Integrity proof over document:
//
//	hashData = SHA-256(canon(proofConfig)) ‖ SHA-256(canon(document))
//
// where canon is the cryptosuite's canonicalization and proofConfig is the
// proof with ProofValue excluded (inheriting the document's @context). The
// signature is encoded base58btc with the "z" multibase prefix.
//
// document is the credential body WITHOUT its proof — the caller attaches the
// returned proof afterwards. created is stamped at call time (UTC, RFC 3339).
func CreateProof(
	signer crypto.Signer,
	signerDID, keyID, verificationMethod string,
	document map[string]any,
	cryptosuite string,
) (*DataIntegrityProof, error) {
	c, err := canonicalizerFor(cryptosuite)
	if err != nil {
		return nil, err
	}
	// Admission runs before the signature exists (canon.number.safe-integer):
	// an integer outside ±(2^53-1) canonicalizes differently under a parser that
	// rounds, so signing one mints evidence a second implementation cannot
	// reproduce. Refusing here is the only place the failure is still cheap.
	// Verification deliberately does NOT gate — legacy artifacts carry such
	// integers by design, and the int64-verbatim projection exists to read them.
	if err := canon.AdmitSafeNumbers(document); err != nil {
		return nil, err
	}
	created := time.Now().UTC().Format(time.RFC3339)
	ctx, hasCtx := document[keyContext]
	cfg := proofConfigMap(proofType, cryptosuite, verificationMethod, proofPurposeSign, created, ctx, hasCtx)

	hd, err := proofHashData(c, cfg, document)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(signerDID, keyID, hd)
	if err != nil {
		return nil, fmt.Errorf("vc: sign proof: %w", err)
	}
	p := &DataIntegrityProof{
		Type:               proofType,
		Cryptosuite:        cryptosuite,
		VerificationMethod: verificationMethod,
		ProofPurpose:       proofPurposeSign,
		Created:            created,
		ProofValue:         multibase.EncodeBase58Btc(sig),
	}
	if hasCtx {
		// vc-di-eddsa §3.3.1 step 2: the proof's @context is the document's.
		// cfg already carries this value, so the wire member rides inside the
		// signature rather than beside it.
		p.Context = ctx
	}
	return p, nil
}

// VerifyProof reconstructs hashData from proof and document and verifies the
// decoded signature against publicKey. It is pure cryptographic verification:
// because the signature covers the whole proof config, tampering with any of the
// typed proof fields (cryptosuite, created, purpose, verificationMethod) breaks
// the check.
//
// It deliberately does NOT do the following — these are the high-level
// Verifier's obligations (see verifier.go), because VerifyProof is a primitive
// handed an already-resolved key and a typed proof:
//
//   - Resolve publicKey from the signed proof.verificationMethod and confirm
//     that method belongs to the credential's issuer. publicKey is caller-
//     supplied here; a caller passing a key unrelated to verificationMethod
//     gets a meaningless verdict.
//   - Reject a proof carrying members outside the typed DataIntegrityProof set
//     (e.g. domain / challenge / a proof-local @context). The provin profile's
//     proof is exactly {type, cryptosuite, verificationMethod, proofPurpose,
//     created, proofValue}; any extra wire member is NOT covered by the
//     signature and so would be malleable if a consumer ever trusted it. The
//     Verifier MUST reject such proofs.
//   - Validate proof.type == "DataIntegrityProof", the proofPurpose policy, the
//     cryptosuite lifecycle phase at proof.created, and that created is a
//     well-formed, in-window datetime.
//
// document is the credential body WITHOUT its proof.
func VerifyProof(
	verifier crypto.Verifier,
	publicKey []byte,
	proof *DataIntegrityProof,
	document map[string]any,
) error {
	if proof == nil {
		return errors.New("vc: nil proof")
	}
	c, err := canonicalizerFor(proof.Cryptosuite)
	if err != nil {
		return err
	}
	ctx, hasCtx := document[keyContext]
	cfg := proofConfigMap(proof.Type, proof.Cryptosuite, proof.VerificationMethod, proof.ProofPurpose, proof.Created, ctx, hasCtx)

	hd, err := proofHashData(c, cfg, document)
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

// proofConfigMap builds the canonicalization input for the proof options. The
// document @context is keyed on PRESENCE, not non-nil, so an absent context and
// an explicit JSON null context stay distinct (the spec models them as
// distinct). Create and verify build the config through this one helper, so the
// signed and reconstructed bytes are identical by construction.
func proofConfigMap(typ, cryptosuite, verificationMethod, proofPurpose, created string, context any, hasContext bool) map[string]any {
	m := map[string]any{
		"type":               typ,
		"cryptosuite":        cryptosuite,
		"verificationMethod": verificationMethod,
		"proofPurpose":       proofPurpose,
		"created":            created,
	}
	if hasContext {
		m[keyContext] = context
	}
	return m
}

// proofHashData computes SHA-256(canon(proofConfig)) ‖ SHA-256(canon(document)).
func proofHashData(c canon.Canonicalizer, proofConfig, document map[string]any) ([]byte, error) {
	pcBytes, err := c.Canonicalize(proofConfig)
	if err != nil {
		return nil, fmt.Errorf("vc: canonicalize proof config: %w", err)
	}
	docBytes, err := c.Canonicalize(document)
	if err != nil {
		return nil, fmt.Errorf("vc: canonicalize document: %w", err)
	}
	pcHash := sha256.Sum256(pcBytes)
	docHash := sha256.Sum256(docBytes)
	return append(pcHash[:], docHash[:]...), nil
}
