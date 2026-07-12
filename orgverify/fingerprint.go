package orgverify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/provin-line/oss/did"
)

// signingFragment is the assertionMethod key fragment orgverify fingerprints
// — the DID's credential-issuance key, per README.md and spec §7.1.
const signingFragment = "#signing"

// FingerprintFromDIDDocument computes the wire fingerprint of doc's unique
// #signing assertionMethod key: "sha256:<64-lowercase-hex>" over the key's
// raw 32-byte Ed25519 public key (the target crypto profile — see
// README.md; this is the frozen, unchanging wire definition regardless of
// which key types a future did package version might add).
//
// Key selection and validation are NOT reimplemented here: extraction
// delegates entirely to did.ExtractPublicKey, the repository's single
// key-extraction implementation, which enforces absolute-id matching (not
// fragment-only), the assertionMethod relationship, controller ownership,
// and duplicate-id rejection. orgverify performs no key selection of its
// own — see spec §7.1 (key-confusion class defenses must not be
// reimplemented per consumer).
func FingerprintFromDIDDocument(doc *did.DIDDocument) (string, error) {
	if doc == nil {
		return "", fmt.Errorf("orgverify: nil DID document")
	}
	pub, err := did.ExtractPublicKey(doc, signingFragment, did.RelationshipAssertionMethod)
	if err != nil {
		return "", fmt.Errorf("orgverify: extract %s key: %w", signingFragment, err)
	}
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
