package wireauth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

// countingNonces counts the nonces recorded, to show a refusal spent none.
type countingNonces struct {
	inner wireauth.NonceStore
	uses  int
}

func (n *countingNonces) Use(signerDID, nonce string) error {
	n.uses++
	return n.inner.Use(signerDID, nonce)
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
	nonces := &countingNonces{inner: wireauth.NewMemoryNonceStore()}
	v := audienceVerifier(t, resolver, "b.example", nonces)
	proof, err := wireauth.Sign(signer, subDID, "a.example", "Op", okFields(), "n1", at())
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
	nonces := &countingNonces{inner: wireauth.NewMemoryNonceStore()}
	v := audienceVerifier(t, mapResolver{subDID: authDoc(subDID, pub)}, "b.example", nonces)
	proof, err := wireauth.Sign(signer, subDID, "b.example", "Op", okFields(), "n1", at())
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
	nonces := &countingNonces{inner: wireauth.NewMemoryNonceStore()}
	v := audienceVerifier(t, mapResolver{subDID: authDoc(subDID, pub)}, "b.example", nonces)
	proof, err := wireauth.Sign(signer, subDID, "a.example", "Op", okFields(), "n1", at())
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
	store := wireauth.NewMemoryNonceStore()
	a := audienceVerifier(t, resolver, "a.example", store)
	b := audienceVerifier(t, resolver, "b.example", store)
	proof, err := wireauth.Sign(signer, subDID, "a.example", "Op", okFields(), "n1", at())
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
	nonces := &countingNonces{inner: wireauth.NewMemoryNonceStore()}
	v := audienceVerifier(t, resolver, "b.example", nonces)
	proof, err := wireauth.Sign(signer, subDID, "b.example", "Op", okFields(), "n1", at())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	proof.Audience = strings.Repeat("a", 254)
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

func TestAudienceComparedExactly(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	v := audienceVerifier(t, mapResolver{subDID: authDoc(subDID, pub)}, "b.example", wireauth.NewMemoryNonceStore())
	for _, spelling := range []string{"B.example", "b.example."} {
		proof, err := wireauth.Sign(signer, subDID, spelling, "Op", okFields(), "n-"+spelling, at())
		if err != nil {
			t.Fatalf("Sign %q: %v", spelling, err)
		}
		if err := v.Verify(context.Background(), "Op", okFields(), proof, nil); !errors.Is(err, wireauth.ErrWrongAudience) {
			t.Errorf("%q at a b.example verifier: want ErrWrongAudience, got %v", spelling, err)
		}
	}
}

func TestNewVerifierRequiresAudience(t *testing.T) {
	for name, audience := range map[string]string{"empty": "", "254 bytes": strings.Repeat("a", 254)} {
		t.Run(name, func(t *testing.T) {
			_, err := wireauth.NewVerifier(wireauth.VerifierConfig{
				Resolver: mapResolver{}, Crypto: ed25519.Verifier{}, Nonces: wireauth.NewMemoryNonceStore(),
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
	for name, audience := range map[string]string{"empty": "", "254 bytes": strings.Repeat("a", 254)} {
		t.Run(name, func(t *testing.T) {
			if _, err := wireauth.Sign(signer, subDID, audience, "Op", okFields(), "n1", at()); !errors.Is(err, wireauth.ErrMalformedProof) {
				t.Errorf("audience %s: want ErrMalformedProof, got %v", name, err)
			}
		})
	}
}
