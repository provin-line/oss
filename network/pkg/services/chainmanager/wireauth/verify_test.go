package wireauth_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

const (
	subDID = "did:dplaax:poc.dplaax.dev:org:sub"
	pubDID = "did:dplaax:poc.dplaax.dev:org:acme"
)

func at() time.Time { return time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC) }

func ed25519JWK(pub []byte) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
}

// authDoc builds a DID Document listing pub as the subject's #auth key under the
// authentication relationship, controlled by the subject.
func authDoc(subject string, pub []byte) *did.DIDDocument {
	return did.New(did.DocumentFields{
		ID: subject, Controller: subject,
		VerificationMethod: []did.VerificationMethod{{
			ID: subject + "#auth", Type: "JsonWebKey2020", Controller: subject,
			PublicKeyJWK: ed25519JWK(pub),
		}},
		Authentication: []string{subject + "#auth"},
	})
}

// mapResolver resolves DIDs from an in-memory table; an absent DID is an error.
type mapResolver map[string]*did.DIDDocument

func (m mapResolver) Resolve(_ context.Context, d string) (*did.DIDDocument, error) {
	doc, ok := m[d]
	if !ok {
		return nil, errors.New("resolver: not found")
	}
	return doc, nil
}

// signerFor returns an ed25519 Signer holding subject's #auth key plus the
// generated public key bytes.
func signerFor(t *testing.T, subject string) (crypto.Signer, []byte) {
	t.Helper()
	ks := filestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := ks.SaveKeyPair(subject, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
		t.Fatalf("save: %v", err)
	}
	return ed25519.NewSigner(ks), kp.PublicKey
}

// testVerifier builds a Verifier whose clock sits 1s after `at()` (so a proof
// issued at `at()` is just inside the past window) and whose epoch is well
// before it (so the epoch barrier does not interfere with happy-path tests).
func testVerifier(t *testing.T, resolver wireauth.DIDResolver) *wireauth.Verifier {
	t.Helper()
	v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: resolver,
		Crypto:   ed25519.Verifier{},
		Nonces:   wireauth.NewMemoryNonceStore(),
		Clock:    func() time.Time { return at().Add(time.Second) },
		Epoch:    at().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func okFields() map[string]any { return map[string]any{"actor": pubDID, "mode": "by-reference"} }

func TestVerify_RoundTrip(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	v := testVerifier(t, mapResolver{subDID: authDoc(subDID, pub)})
	proof, err := wireauth.Sign(signer, subDID, "RegisterSubscription", okFields(), "n1", at())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// authorizer that accepts, receiving the resolved doc + fields.
	authz := func(s string, doc *did.DIDDocument, f map[string]any) error {
		if s != subDID || doc == nil || f["actor"] != pubDID {
			return errors.New("unexpected authz inputs")
		}
		return nil
	}
	if err := v.Verify(context.Background(), "RegisterSubscription", okFields(), proof, authz); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerify_NilAuthorizerSkipsAuthz(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	v := testVerifier(t, mapResolver{subDID: authDoc(subDID, pub)})
	proof, _ := wireauth.Sign(signer, subDID, "Op", okFields(), "n1", at())
	if err := v.Verify(context.Background(), "Op", okFields(), proof, nil); err != nil {
		t.Fatalf("Verify with nil authorizer: %v", err)
	}
}

func TestVerify_KeyResolutionFailures(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	proof, _ := wireauth.Sign(signer, subDID, "Op", okFields(), "n1", at())

	otherPub := make([]byte, len(pub))

	cases := map[string]wireauth.DIDResolver{
		"resolver miss": mapResolver{}, // subDID not present
		"auth key absent": mapResolver{subDID: did.New(did.DocumentFields{
			ID: subDID, Controller: subDID,
		})},
		"key not under authentication": mapResolver{subDID: did.New(did.DocumentFields{
			ID: subDID, Controller: subDID,
			VerificationMethod: []did.VerificationMethod{{
				ID: subDID + "#auth", Type: "JsonWebKey2020", Controller: subDID,
				PublicKeyJWK: ed25519JWK(pub),
			}},
			AssertionMethod: []string{subDID + "#auth"}, // listed, but wrong relationship
		})},
		"controller mismatch": mapResolver{subDID: did.New(did.DocumentFields{
			ID: subDID, Controller: subDID,
			VerificationMethod: []did.VerificationMethod{{
				ID: subDID + "#auth", Type: "JsonWebKey2020", Controller: "did:dplaax:poc.dplaax.dev:org:evil",
				PublicKeyJWK: ed25519JWK(otherPub),
			}},
			Authentication: []string{subDID + "#auth"},
		})},
	}
	for name, resolver := range cases {
		t.Run(name, func(t *testing.T) {
			v := testVerifier(t, resolver)
			if err := v.Verify(context.Background(), "Op", okFields(), proof, nil); !errors.Is(err, wireauth.ErrKeyResolution) {
				t.Errorf("%s: want ErrKeyResolution, got %v", name, err)
			}
		})
	}
}

// Shared-public-key aliasing: two DIDs list the SAME #auth key. A proof signed
// as subDID must not verify when its SignerDID is swapped to the alias — the
// signed bytes bind signerDID, so the rebuilt view differs and the signature
// fails. This is the unknown-key-share defense (D-w1).
func TestVerify_SharedKeyAliasingRejected(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	alias := "did:dplaax:poc.dplaax.dev:org:alias"
	// Both DIDs resolve to documents carrying the same public key under #auth.
	v := testVerifier(t, mapResolver{
		subDID: authDoc(subDID, pub),
		alias:  authDoc(alias, pub),
	})
	proof, _ := wireauth.Sign(signer, subDID, "Op", okFields(), "n1", at())
	// Attacker re-labels the proof as the alias DID (whose doc shares the key).
	proof.SignerDID = alias
	if err := v.Verify(context.Background(), "Op", okFields(), proof, nil); !errors.Is(err, wireauth.ErrSignatureInvalid) {
		t.Errorf("aliased proof: want ErrSignatureInvalid, got %v", err)
	}
}

func TestNewVerifier_RequiresDeps(t *testing.T) {
	base := wireauth.VerifierConfig{
		Resolver: mapResolver{}, Crypto: ed25519.Verifier{}, Nonces: wireauth.NewMemoryNonceStore(),
	}
	if _, err := wireauth.NewVerifier(base); err != nil {
		t.Fatalf("complete config: %v", err)
	}
	missing := []struct {
		name string
		mut  func(c *wireauth.VerifierConfig)
	}{
		{"no resolver", func(c *wireauth.VerifierConfig) { c.Resolver = nil }},
		{"no crypto", func(c *wireauth.VerifierConfig) { c.Crypto = nil }},
		{"no nonces", func(c *wireauth.VerifierConfig) { c.Nonces = nil }},
	}
	for _, m := range missing {
		t.Run(m.name, func(t *testing.T) {
			c := base
			m.mut(&c)
			if _, err := wireauth.NewVerifier(c); err == nil {
				t.Errorf("%s: want error, got nil", m.name)
			}
		})
	}
}
