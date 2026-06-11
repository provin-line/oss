package vc

import "github.com/provin-line/oss/packages/crypto"

// CreateProof produces a Data Integrity proof over document:
//
//	hashData = SHA-256(canon(proofConfig)) ‖ SHA-256(canon(document))
//
// where canon is the cryptosuite's canonicalization and proofConfig is the
// proof with ProofValue excluded (inheriting the document's @context). The
// signature is encoded base58btc with the "z" multibase prefix.
func CreateProof(
	signer crypto.Signer,
	signerDID, keyID, verificationMethod string,
	document map[string]any,
	cryptosuite string,
) (*DataIntegrityProof, error) {
	panic("not implemented")
}

// VerifyProof reconstructs hashData from proof and document and verifies the
// decoded signature against publicKey.
func VerifyProof(
	verifier crypto.Verifier,
	publicKey []byte,
	proof *DataIntegrityProof,
	document map[string]any,
) error {
	panic("not implemented")
}
