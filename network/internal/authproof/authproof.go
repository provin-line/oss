// Package authproof is the codec of the L2 wire proof between its protobuf
// form, dplaax.chain.v1.AuthProof, and wireauth.Proof. Every handler whose
// RPCs carry a proof decodes it here and every client makes it here, so the
// proof has one wire form. A handler maps ErrMalformedIssuedAt to its own
// status, and wireauth's sentinels through wireautherr.
package authproof

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/provin-line/oss/crypto"
	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/network/pkg/wireauth"
)

// ErrMalformedIssuedAt is an AuthProof.issued_at that is not the canonical
// RFC 3339 UTC second-precision form wireauth signs over.
var ErrMalformedIssuedAt = errors.New("authproof: malformed issued_at")

// Decode converts ap to a wireauth.Proof, reading issued_at strictly (see
// ErrMalformedIssuedAt) before the proof reaches wireauth's verifier. A nil
// ap is wireauth.ErrMissingProof.
func Decode(ap *chainpb.AuthProof) (wireauth.Proof, error) {
	if ap == nil {
		return wireauth.Proof{}, wireauth.ErrMissingProof
	}
	issuedAt, err := parseIssuedAt(ap.GetIssuedAt())
	if err != nil {
		return wireauth.Proof{}, err
	}
	return wireauth.Proof{
		SignerDID:   ap.GetSignerDid(),
		Audience:    ap.GetAudience(),
		Nonce:       ap.GetNonce(),
		IssuedAt:    issuedAt,
		Signature:   ap.GetSignature(),
		ViewVersion: int(ap.GetViewVersion()),
	}, nil
}

// Encode converts p to its wire form, issued_at as canonical second-precision
// UTC RFC 3339, the form Decode reads.
func Encode(p wireauth.Proof) *chainpb.AuthProof {
	return &chainpb.AuthProof{
		SignerDid:   p.SignerDID,
		Audience:    p.Audience,
		Nonce:       p.Nonce,
		IssuedAt:    p.IssuedAt.UTC().Format(time.RFC3339),
		Signature:   p.Signature,
		ViewVersion: wireViewVersion(p.ViewVersion),
	}
}

// wireViewVersion is v as the wire's uint32; a version outside its range is
// 0, which no verifier accepts.
func wireViewVersion(v int) uint32 {
	if v < 0 || int64(v) > math.MaxUint32 {
		return 0
	}
	return uint32(v)
}

// Sign signs op over fields as signerDID for audience, with a fresh nonce
// (wireauth.NewNonce) and the current time, and returns the proof's wire
// form.
func Sign(signer crypto.Signer, op string, fields map[string]any, signerDID, audience string) (*chainpb.AuthProof, error) {
	nonce, err := wireauth.NewNonce()
	if err != nil {
		return nil, fmt.Errorf("authproof: nonce: %w", err)
	}
	p, err := wireauth.Sign(signer, op, fields, wireauth.Claims{SignerDID: signerDID, Audience: audience, Nonce: nonce, IssuedAt: time.Now()})
	if err != nil {
		return nil, fmt.Errorf("authproof: sign %s: %w", op, err)
	}
	return Encode(p), nil
}

// parseIssuedAt reads s only in the canonical RFC 3339 UTC second-precision
// form: a fraction of a second, an offset other than Z, or any other spelling
// is ErrMalformedIssuedAt. The error quotes s whole; the network bounds the
// text of every error it answers where a handler is mounted.
func parseIssuedAt(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %q: %v", ErrMalformedIssuedAt, s, err)
	}
	if s != t.UTC().Format(time.RFC3339) {
		return time.Time{}, fmt.Errorf("%w: %q is not canonical UTC second-precision RFC 3339", ErrMalformedIssuedAt, s)
	}
	return t.UTC(), nil
}
