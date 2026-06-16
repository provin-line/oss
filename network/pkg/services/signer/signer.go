// Package signer is the KMS-model signing service: it exposes the crypto.Signer
// seam over the network so private keys never cross the RPC boundary. The domain
// is a thin, fail-closed wrapper around the seam — it validates the (did, keyID)
// addressing and the signing-domain binding, then delegates the actual Ed25519
// signing to the injected crypto.Signer (in production, the registry's
// keystore-backed signer; in tests, a fake or an in-memory one).
//
// Two signing domains, bound to their key relationship (slice-5 D-s3): Sign uses
// the DID's #signing assertionMethod key (VC proof creation); SignRaw uses the
// #auth authentication key (L2 wire-signing). The two are cryptographically
// identical Ed25519 operations, kept separate so each carries its own
// authorization policy and cannot be used to sign with the other domain's key.
//
// Output is raw signature bytes (D-s1): the multibase/proofValue framing for VC
// proofs lives in the vc consumer, not here.
package signer

import (
	"context"
	"errors"
	"fmt"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/keystore"
)

// Domain sentinel errors. The handler maps these to Connect codes; a signing
// error that is neither of these (e.g. a malformed stored key) is surfaced
// as-is and becomes Internal at the boundary — it is never masked as NotFound.
var (
	// ErrInvalidArgument is an empty DID or a key_id that does not match the
	// RPC's signing domain.
	ErrInvalidArgument = errors.New("signer: invalid argument")
	// ErrKeyNotFound is no key held for (did, keyID) — the seam returned a
	// wrapped keystore.ErrNotFound.
	ErrKeyNotFound = errors.New("signer: key not found")
)

// keyIDSigning / keyIDAuth are the logical key IDs each signing domain binds to.
var (
	keyIDSigning = string(keystore.KeyIDSigning) // "signing" — assertionMethod
	keyIDAuth    = string(keystore.KeyIDAuth)    // "auth" — authentication
)

// Service signs raw bytes under a DID's key over the crypto.Signer seam.
type Service struct {
	signer crypto.Signer
}

// New returns a Service that signs through seam. seam holds (or fronts) the key
// material; the Service never sees private keys itself.
func New(seam crypto.Signer) *Service {
	return &Service{signer: seam}
}

// Sign produces an Ed25519 signature over data with the DID's #signing
// assertionMethod key (VC proof domain). keyID must be "signing".
func (s *Service) Sign(ctx context.Context, did, keyID string, data []byte) ([]byte, error) {
	return s.sign(ctx, did, keyID, data, keyIDSigning)
}

// SignRaw produces an Ed25519 signature over data with the DID's #auth
// authentication key (L2 wire domain). keyID must be "auth".
func (s *Service) SignRaw(ctx context.Context, did, keyID string, data []byte) ([]byte, error) {
	return s.sign(ctx, did, keyID, data, keyIDAuth)
}

// sign validates the request fail-closed, then delegates to the seam. wantKeyID
// is the only key ID this signing domain accepts (D-s3): a crossed binding
// (e.g. the VC endpoint asked to sign with the auth key) is InvalidArgument, not
// a silently honored signature.
func (s *Service) sign(ctx context.Context, did, keyID string, data []byte, wantKeyID string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if did == "" {
		return nil, fmt.Errorf("%w: empty did", ErrInvalidArgument)
	}
	if keyID != wantKeyID {
		return nil, fmt.Errorf("%w: key_id %q is not valid for this signing domain (want %q)", ErrInvalidArgument, keyID, wantKeyID)
	}
	sig, err := s.signer.Sign(did, keyID, data)
	if err != nil {
		if errors.Is(err, keystore.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s#%s", ErrKeyNotFound, did, keyID)
		}
		return nil, err
	}
	return sig, nil
}
