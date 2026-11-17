package authproof_test

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/internal/authproof"
	"github.com/provin-line/oss/network/pkg/wireauth"
)

const (
	signerDID = "did:dplaax:a.example:org:o1"
	audience  = "r.example"
)

// Decode carries every member of the wire form over, issued_at as a UTC
// instant.
func TestDecode_CarriesEveryMember(t *testing.T) {
	got, err := authproof.Decode(&chainpb.AuthProof{
		SignerDid:   signerDID,
		Audience:    audience,
		Nonce:       "n1",
		IssuedAt:    "2026-01-02T03:04:05Z",
		Signature:   []byte("sig"),
		ViewVersion: 2,
	})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	want := wireauth.Proof{
		SignerDID: signerDID, Audience: audience, Nonce: "n1",
		IssuedAt:    time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Signature:   []byte("sig"),
		ViewVersion: 2,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Decode = %+v, want %+v", got, want)
	}
}

// A missing proof is wireauth's missing proof.
func TestDecode_NilIsAMissingProof(t *testing.T) {
	if _, err := authproof.Decode(nil); !errors.Is(err, wireauth.ErrMissingProof) {
		t.Errorf("Decode(nil): %v, want wireauth.ErrMissingProof", err)
	}
}

// issued_at is read only in the canonical RFC 3339 UTC second-precision form
// wireauth signs over; any other is ErrMalformedIssuedAt.
func TestDecode_RefusesANonCanonicalIssuedAt(t *testing.T) {
	for name, in := range map[string]string{
		"sub-second":        "2026-06-17T12:00:00.5Z",
		"non-UTC offset":    "2026-06-17T21:00:00+09:00",
		"zero offset not Z": "2026-06-17T12:00:00+00:00",
		"missing offset":    "2026-06-17T12:00:00",
		"date only":         "2026-06-17",
		"garbage":           "not-a-time",
		"empty":             "",
	} {
		_, err := authproof.Decode(&chainpb.AuthProof{SignerDid: signerDID, Audience: audience, Nonce: "n1", IssuedAt: in, Signature: []byte("sig")})
		if !errors.Is(err, authproof.ErrMalformedIssuedAt) {
			t.Errorf("%s: %v, want ErrMalformedIssuedAt", name, err)
		}
	}
}

// Encode is Decode's inverse.
func TestEncode_IsDecodesInverse(t *testing.T) {
	p := wireauth.Proof{
		SignerDID: signerDID, Audience: audience, Nonce: "n1",
		IssuedAt:    time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Signature:   []byte("sig"),
		ViewVersion: 7,
	}
	got, err := authproof.Decode(authproof.Encode(p))
	if err != nil {
		t.Fatalf("Decode(Encode(p)): %v", err)
	}
	if !reflect.DeepEqual(got, p) {
		t.Errorf("Decode(Encode(p)) = %+v, want %+v", got, p)
	}
}

type mapResolver map[string]*did.DIDDocument

func (m mapResolver) Resolve(_ context.Context, d string) (*did.DIDDocument, error) {
	if doc, ok := m[d]; ok {
		return doc, nil
	}
	return nil, errors.New("not found")
}

// Sign makes a fresh proof (a new nonce, the current second) that a verifier
// of the audience accepts.
func TestSign_MakesAFreshProofThatVerifies(t *testing.T) {
	ks := filestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.SaveKeyPair(signerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
		t.Fatal(err)
	}
	doc := did.New(did.DocumentFields{
		ID: signerDID, Controller: signerDID,
		VerificationMethod: []did.VerificationMethod{{
			ID: signerDID + "#auth", Type: "JsonWebKey2020", Controller: signerDID,
			PublicKeyJWK: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(kp.PublicKey)},
		}},
		Authentication: []string{signerDID + "#auth"},
	})
	v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: mapResolver{signerDID: doc},
		Crypto:   ed25519.Verifier{},
		Nonces:   wireauth.NewMemoryNonceStore(),
		Audience: audience,
		Epoch:    time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{"k": "v"}
	before := time.Now().UTC().Truncate(time.Second)
	a, err := authproof.Sign(ks, "Op", fields, signerDID, audience)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	b, err := authproof.Sign(ks, "Op", fields, signerDID, audience)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if a.GetNonce() == "" || a.GetNonce() == b.GetNonce() {
		t.Errorf("nonces %q and %q, want two fresh ones", a.GetNonce(), b.GetNonce())
	}
	p, err := authproof.Decode(a)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if p.SignerDID != signerDID || p.Audience != audience || p.IssuedAt.Before(before) {
		t.Errorf("proof %+v, want %s for %s, issued from %v", p, signerDID, audience, before)
	}
	if err := v.Verify(context.Background(), "Op", fields, p, nil); err != nil {
		t.Errorf("Verify: %v", err)
	}
}
