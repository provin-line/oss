package wireauth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/network/pkg/wireauth"
)

// countingNonces counts the nonces recorded, to show a refusal spent none.
type countingNonces struct {
	inner wireauth.NonceStore
	uses  int
}

func (n *countingNonces) Use(ctx context.Context, signerDID, nonce string, expiresAt time.Time) error {
	n.uses++
	return n.inner.Use(ctx, signerDID, nonce, expiresAt)
}

// audienceVerifier is testVerifier with the given audience and nonce store.
func audienceVerifier(t *testing.T, resolver wireauth.DIDResolver, audience string, nonces wireauth.NonceStore) *wireauth.Verifier {
	t.Helper()
	v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: resolver,
		Crypto:   ed25519.Verifier{},
		Nonces:   nonces,
		Audience: audience,
		Clock:    func() time.Time { return at().Add(time.Second) },
		Epoch:    at().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func TestVerifyRefusesProofForAnotherAudience(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	resolver := &countingResolver{mapResolver: mapResolver{subDID: authDoc(subDID, pub)}}
	nonces := &countingNonces{inner: testNonces()}
	v := audienceVerifier(t, resolver, "b.example", nonces)
	proof, err := wireauth.Sign(signer, "Op", okFields(), wireauth.Claims{SignerDID: subDID, Audience: "a.example", Nonce: "n1", IssuedAt: at()})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	err = v.Verify(context.Background(), "Op", okFields(), proof, nil)
	if !errors.Is(err, wireauth.ErrWrongAudience) {
		t.Fatalf("want ErrWrongAudience, got %v", err)
	}
	if nonces.uses != 0 || resolver.calls != 0 {
		t.Errorf("a proof for another audience reached the store (%d) or the resolver (%d)", nonces.uses, resolver.calls)
	}
}

func TestVerifyRefusesProofNamingNoAudience(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	nonces := &countingNonces{inner: testNonces()}
	v := audienceVerifier(t, mapResolver{subDID: authDoc(subDID, pub)}, "b.example", nonces)
	proof, err := wireauth.Sign(signer, "Op", okFields(), wireauth.Claims{SignerDID: subDID, Audience: "b.example", Nonce: "n1", IssuedAt: at()})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	proof.Audience = ""
	err = v.Verify(context.Background(), "Op", okFields(), proof, nil)
	if !errors.Is(err, wireauth.ErrWrongAudience) {
		t.Fatalf("want ErrWrongAudience, got %v", err)
	}
	if !strings.Contains(err.Error(), "names no audience") {
		t.Errorf("error does not say the proof names no audience: %v", err)
	}
	if nonces.uses != 0 {
		t.Errorf("a proof naming no audience spent a nonce")
	}
}

func TestVerifyRefusesAudienceRewritten(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	nonces := &countingNonces{inner: testNonces()}
	v := audienceVerifier(t, mapResolver{subDID: authDoc(subDID, pub)}, "b.example", nonces)
	proof, err := wireauth.Sign(signer, "Op", okFields(), wireauth.Claims{SignerDID: subDID, Audience: "a.example", Nonce: "n1", IssuedAt: at()})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	proof.Audience = "b.example"
	if err := v.Verify(context.Background(), "Op", okFields(), proof, nil); !errors.Is(err, wireauth.ErrSignatureInvalid) {
		t.Fatalf("want ErrSignatureInvalid, got %v", err)
	}
	if nonces.uses != 0 {
		t.Errorf("a proof whose audience was rewritten spent a nonce")
	}
}

func TestWrongAudienceLeavesNonceUnspent(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	resolver := mapResolver{subDID: authDoc(subDID, pub)}
	store := testNonces()
	a := audienceVerifier(t, resolver, "a.example", store)
	b := audienceVerifier(t, resolver, "b.example", store)
	proof, err := wireauth.Sign(signer, "Op", okFields(), wireauth.Claims{SignerDID: subDID, Audience: "a.example", Nonce: "n1", IssuedAt: at()})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := b.Verify(context.Background(), "Op", okFields(), proof, nil); !errors.Is(err, wireauth.ErrWrongAudience) {
		t.Fatalf("b: want ErrWrongAudience, got %v", err)
	}
	if err := a.Verify(context.Background(), "Op", okFields(), proof, nil); err != nil {
		t.Fatalf("a: the proof was refused after b turned it away: %v", err)
	}
}

func TestVerifyRefusesOverlongAudience(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	resolver := &countingResolver{mapResolver: mapResolver{subDID: authDoc(subDID, pub)}}
	nonces := &countingNonces{inner: testNonces()}
	v := audienceVerifier(t, resolver, "b.example", nonces)
	proof, err := wireauth.Sign(signer, "Op", okFields(), wireauth.Claims{SignerDID: subDID, Audience: "b.example", Nonce: "n1", IssuedAt: at()})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	proof.Audience = strings.Repeat("a", dplaax.MaxRegistryLen+1)
	err = v.Verify(context.Background(), "Op", okFields(), proof, nil)
	if !errors.Is(err, wireauth.ErrMalformedProof) {
		t.Fatalf("want ErrMalformedProof, got %v", err)
	}
	if strings.Contains(err.Error(), proof.Audience) {
		t.Errorf("the error repeats the overlong audience")
	}
	if nonces.uses != 0 || resolver.calls != 0 {
		t.Errorf("an overlong audience reached the store (%d) or the resolver (%d)", nonces.uses, resolver.calls)
	}
}

// An audience is a registry ID, so the longest audience Sign, NewVerifier and
// Verify take is the longest registry a did:dplaax DID may name.
func TestTheAudienceBoundIsTheRegistryBound(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	longest := strings.Repeat("a", dplaax.MaxRegistryLen)
	v := audienceVerifier(t, mapResolver{subDID: authDoc(subDID, pub)}, longest, testNonces())
	proof, err := wireauth.Sign(signer, "Op", okFields(), wireauth.Claims{SignerDID: subDID, Audience: longest, Nonce: "n1", IssuedAt: at()})
	if err != nil {
		t.Fatalf("Sign with an audience of %d bytes: %v", dplaax.MaxRegistryLen, err)
	}
	if err := v.Verify(context.Background(), "Op", okFields(), proof, nil); err != nil {
		t.Errorf("Verify with an audience of %d bytes: %v", dplaax.MaxRegistryLen, err)
	}
}

func TestAudienceComparedExactly(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	v := audienceVerifier(t, mapResolver{subDID: authDoc(subDID, pub)}, "b.example", testNonces())
	for _, spelling := range []string{"B.example", "b.example."} {
		proof, err := wireauth.Sign(signer, "Op", okFields(), wireauth.Claims{SignerDID: subDID, Audience: spelling, Nonce: "n-" + spelling, IssuedAt: at()})
		if err != nil {
			t.Fatalf("Sign %q: %v", spelling, err)
		}
		if err := v.Verify(context.Background(), "Op", okFields(), proof, nil); !errors.Is(err, wireauth.ErrWrongAudience) {
			t.Errorf("%q at a b.example verifier: want ErrWrongAudience, got %v", spelling, err)
		}
	}
}

func TestNewVerifierRequiresAudience(t *testing.T) {
	for name, audience := range map[string]string{"empty": "", "one byte past the registry bound": strings.Repeat("a", dplaax.MaxRegistryLen+1)} {
		t.Run(name, func(t *testing.T) {
			_, err := wireauth.NewVerifier(wireauth.VerifierConfig{
				Resolver: mapResolver{}, Crypto: ed25519.Verifier{}, Nonces: testNonces(),
				Audience: audience,
			})
			if err == nil {
				t.Errorf("audience %s: want error, got nil", name)
			}
		})
	}
}

func TestSignRequiresAudience(t *testing.T) {
	signer, _ := signerFor(t, subDID)
	for name, audience := range map[string]string{"empty": "", "one byte past the registry bound": strings.Repeat("a", dplaax.MaxRegistryLen+1)} {
		t.Run(name, func(t *testing.T) {
			if _, err := wireauth.Sign(signer, "Op", okFields(), wireauth.Claims{SignerDID: subDID, Audience: audience, Nonce: "n1", IssuedAt: at()}); !errors.Is(err, wireauth.ErrMalformedProof) {
				t.Errorf("audience %s: want ErrMalformedProof, got %v", name, err)
			}
		})
	}
}
