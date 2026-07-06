// Package keyfile persists a CLI-local owner key as a single JWK file — the
// only private key that ever exists outside the registry (KMS model; see
// cmd/provin/README.md). The format is an RFC 8037 OKP Ed25519 private JWK
// ({"kty":"OKP","crv":"Ed25519","x":…,"d":…}) with the owner DID carried in
// "kid", so one self-describing file is the whole owner identity.
//
// Files are written 0600 and create-only: overwriting an owner key in place
// would destroy the only copy of the identity that can issue under that DID.
package keyfile

import (
	stded25519 "crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/keystore"
)

// Key is a loaded CLI-local owner key.
type Key struct {
	// DID is the owner DID (the JWK "kid").
	DID string
	// PublicKey / PrivateKey are the raw Ed25519 keys (32 / 64 bytes).
	PublicKey  []byte
	PrivateKey []byte
}

// Signer returns a crypto.Signer over this key. It signs only for the owner's
// own (DID, "signing") pair — a request for any other identity is an error,
// so a mis-wired caller cannot silently sign as someone it is not.
func (k *Key) Signer() crypto.Signer { return ownerSigner{key: k} }

type ownerSigner struct{ key *Key }

func (s ownerSigner) Sign(did, keyID string, data []byte) ([]byte, error) {
	if did != s.key.DID || keyID != string(keystore.KeyIDSigning) {
		return nil, fmt.Errorf("keyfile: signer holds %s#%s, asked to sign as %s#%s", s.key.DID, keystore.KeyIDSigning, did, keyID)
	}
	return stded25519.Sign(stded25519.PrivateKey(s.key.PrivateKey), data), nil
}

// jwk is the on-disk shape: an OKP Ed25519 private JWK. "d" is the 32-byte
// seed per RFC 8037; the 64-byte Go private key is reconstructed on load.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	D   string `json:"d"`
}

// b64 is the JWK byte encoding (base64url, no padding).
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Write persists the owner key at path (0600, create-only). ownerDID becomes
// the JWK "kid"; priv is the 64-byte Go Ed25519 private key.
func Write(path, ownerDID string, pub, priv []byte) error {
	if len(priv) != stded25519.PrivateKeySize {
		return fmt.Errorf("keyfile: private key size %d, want %d", len(priv), stded25519.PrivateKeySize)
	}
	if len(pub) != stded25519.PublicKeySize {
		return fmt.Errorf("keyfile: public key size %d, want %d", len(pub), stded25519.PublicKeySize)
	}
	// A local custody file, never hashed or signed over — not a signing scope
	// (canonicalizer-hygiene-exempt).
	raw, err := json.MarshalIndent(jwk{
		Kty: "OKP", Crv: "Ed25519", Kid: ownerDID,
		X: b64(pub), D: b64(priv[:stded25519.SeedSize]),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("keyfile: marshal: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("keyfile: %s already exists (refusing to overwrite an owner key)", path)
		}
		return fmt.Errorf("keyfile: create %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(append(raw, '\n')); err != nil {
		return fmt.Errorf("keyfile: write %s: %w", path, err)
	}
	return f.Sync()
}

// Load reads and validates an owner key file. It fails closed on anything but
// a well-formed OKP Ed25519 private JWK with a kid, and rejects a file whose
// public half does not match its private half (a tampered or corrupted key
// would otherwise sign unverifiable proofs at first use).
func Load(path string) (*Key, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keyfile: read %s: %w", path, err)
	}
	var j jwk
	// The key file is a trust boundary (its integrity decides what this CLI
	// signs as), so it gets the same strict gate as wire documents: duplicate
	// members ("d" twice) or trailing data are rejected, not last-wins merged.
	if err := canon.NewStrictDecoder(raw).Decode(&j); err != nil {
		return nil, fmt.Errorf("keyfile: parse %s: %w", path, err)
	}
	if j.Kty != "OKP" || j.Crv != "Ed25519" {
		return nil, fmt.Errorf("keyfile: %s: kty/crv %q/%q, want OKP/Ed25519", path, j.Kty, j.Crv)
	}
	if j.Kid == "" {
		return nil, fmt.Errorf("keyfile: %s: missing kid (owner DID)", path)
	}
	if j.D == "" {
		return nil, fmt.Errorf("keyfile: %s: missing d (private key)", path)
	}
	seed, err := base64.RawURLEncoding.DecodeString(j.D)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %s: decode d: %w", path, err)
	}
	if len(seed) != stded25519.SeedSize {
		return nil, fmt.Errorf("keyfile: %s: d is %d bytes, want %d", path, len(seed), stded25519.SeedSize)
	}
	pubClaimed, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %s: decode x: %w", path, err)
	}
	priv := stded25519.NewKeyFromSeed(seed)
	pub := priv.Public().(stded25519.PublicKey)
	if subtle.ConstantTimeCompare(pubClaimed, pub) != 1 {
		return nil, fmt.Errorf("keyfile: %s: x does not match the key derived from d (tampered or corrupted)", path)
	}
	return &Key{DID: j.Kid, PublicKey: []byte(pub), PrivateKey: []byte(priv)}, nil
}
