package wireauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/keystore"
)

// Proof is the L2 authentication bundle that accompanies a ChainPeerService RPC.
// It carries everything the verifier needs to rebuild the view header and
// resolve the signer's key; the business fields are reconstructed from the RPC
// request itself (never echoed here), so the signature is always checked against
// the request actually being served.
type Proof struct {
	SignerDID string
	// Audience is the party the proof was signed for. A verifier accepts only
	// a proof for its own audience (VerifierConfig.Audience).
	Audience  string
	Nonce     string
	IssuedAt  time.Time
	Signature []byte
}

// Sign produces a Proof over the per-RPC view for op with the given business
// fields, for audience: the party the request is sent to. The signer signs
// canon(view) with the signer DID's #auth key; issuedAt is truncated to second
// precision (the wire form the verifier rebuilds), and the returned Proof
// carries that truncated instant so the transported value and the signed value
// never diverge.
//
// signerDID, audience, op, and nonce must be non-empty, audience and nonce
// within the lengths a verifier accepts, and fields must satisfy the value
// grammar (ErrInvalidView), which also refuses fields nested more than 9,999
// objects and arrays deep, the fields object counted, so that the view, which
// holds them one level down, nests at most 10,000, as encoding/json decodes;
// a real caller obtains nonce from NewNonce and issuedAt from time.Now().
func Sign(signer crypto.Signer, signerDID, audience, op string, fields map[string]any, nonce string, issuedAt time.Time) (Proof, error) {
	if signerDID == "" || audience == "" || op == "" || nonce == "" {
		return Proof{}, fmt.Errorf("%w: signerDID, audience, op, and nonce must be non-empty", ErrMalformedProof)
	}
	// Mirror the verifier's bounds so Sign never mints a proof a verifier is
	// structurally bound to reject.
	if len(audience) > maxAudienceLen {
		return Proof{}, fmt.Errorf("%w: audience exceeds %d bytes", ErrMalformedProof, maxAudienceLen)
	}
	if len(nonce) > maxNonceLen {
		return Proof{}, fmt.Errorf("%w: nonce exceeds %d bytes", ErrMalformedProof, maxNonceLen)
	}
	issuedAt = issuedAt.UTC().Truncate(time.Second)
	msg, err := viewBytes(signerDID, audience, op, nonce, issuedAt, fields)
	if err != nil {
		return Proof{}, err
	}
	sig, err := signer.Sign(signerDID, string(keystore.KeyIDAuth), msg)
	if err != nil {
		return Proof{}, fmt.Errorf("wireauth: sign view: %w", err)
	}
	return Proof{SignerDID: signerDID, Audience: audience, Nonce: nonce, IssuedAt: issuedAt, Signature: sig}, nil
}

// NewNonce returns an unpredictable 128-bit nonce (base64url, no padding) for
// the signing caller. The nonce is opaque to the verifier, which tracks it only
// for per-signer replay defense.
func NewNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("wireauth: generate nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
