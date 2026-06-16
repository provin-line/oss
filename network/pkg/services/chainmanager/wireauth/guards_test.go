package wireauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

// verifierWith builds a Verifier with an explicit clock and epoch for the
// time-bound guard tests.
func verifierWith(t *testing.T, resolver wireauth.DIDResolver, clock func() time.Time, epoch time.Time) *wireauth.Verifier {
	t.Helper()
	v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: resolver, Crypto: ed25519.Verifier{}, Nonces: wireauth.NewMemoryNonceStore(),
		Clock: clock, Epoch: epoch,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func TestVerify_MissingAndMalformed(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	v := testVerifier(t, mapResolver{subDID: authDoc(subDID, pub)})
	good, _ := wireauth.Sign(signer, subDID, "Op", okFields(), "n1", at())

	t.Run("empty signerDID", func(t *testing.T) {
		p := good
		p.SignerDID = ""
		assertErrIs(t, v.Verify(context.Background(), "Op", okFields(), p, nil), wireauth.ErrMissingProof)
	})
	t.Run("empty nonce", func(t *testing.T) {
		p := good
		p.Nonce = ""
		assertErrIs(t, v.Verify(context.Background(), "Op", okFields(), p, nil), wireauth.ErrMissingProof)
	})
	t.Run("empty signature", func(t *testing.T) {
		p := good
		p.Signature = nil
		assertErrIs(t, v.Verify(context.Background(), "Op", okFields(), p, nil), wireauth.ErrMissingProof)
	})
	t.Run("empty op", func(t *testing.T) {
		assertErrIs(t, v.Verify(context.Background(), "", okFields(), good, nil), wireauth.ErrMalformedProof)
	})
	t.Run("oversized nonce", func(t *testing.T) {
		p := good
		p.Nonce = string(make([]byte, 300))
		assertErrIs(t, v.Verify(context.Background(), "Op", okFields(), p, nil), wireauth.ErrMalformedProof)
	})
	t.Run("sub-second issuedAt", func(t *testing.T) {
		p := good
		p.IssuedAt = at().Add(500 * time.Millisecond)
		assertErrIs(t, v.Verify(context.Background(), "Op", okFields(), p, nil), wireauth.ErrMalformedProof)
	})
	t.Run("bad fields grammar", func(t *testing.T) {
		assertErrIs(t, v.Verify(context.Background(), "Op", map[string]any{"n": 1}, good, nil), wireauth.ErrInvalidView)
	})
}

func TestVerify_EpochBarrier(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	proof, _ := wireauth.Sign(signer, subDID, "Op", okFields(), "n1", at())
	// Epoch is one hour AFTER the proof's issuedAt → rejected before any crypto.
	v := verifierWith(t, mapResolver{subDID: authDoc(subDID, pub)},
		func() time.Time { return at().Add(time.Hour + time.Second) }, at().Add(time.Hour))
	assertErrIs(t, v.Verify(context.Background(), "Op", okFields(), proof, nil), wireauth.ErrBeforeEpoch)
}

// A proof issued in the verifier's construction second is rejected because the
// default epoch ceils to the next whole second — closing same-second pre-restart
// replay against the in-memory nonce store.
func TestVerify_SameSecondRestartRejected(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	proof, _ := wireauth.Sign(signer, subDID, "Op", okFields(), "n1", at()) // issuedAt 12:00:00
	// Construct at 12:00:00.5 with the DEFAULT (ceiled) epoch → epoch 12:00:01.
	v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: mapResolver{subDID: authDoc(subDID, pub)}, Crypto: ed25519.Verifier{},
		Nonces: wireauth.NewMemoryNonceStore(),
		Clock:  func() time.Time { return at().Add(500 * time.Millisecond) },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	assertErrIs(t, v.Verify(context.Background(), "Op", okFields(), proof, nil), wireauth.ErrBeforeEpoch)
}

func TestVerify_AcceptanceWindow(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	proof, _ := wireauth.Sign(signer, subDID, "Op", okFields(), "n1", at())
	resolver := mapResolver{subDID: authDoc(subDID, pub)}
	earlyEpoch := at().Add(-1000 * time.Hour)

	t.Run("too old", func(t *testing.T) {
		// now is 70s after issuedAt; MaxPast default 60s → expired.
		v := verifierWith(t, resolver, func() time.Time { return at().Add(70 * time.Second) }, earlyEpoch)
		assertErrIs(t, v.Verify(context.Background(), "Op", okFields(), proof, nil), wireauth.ErrExpired)
	})
	t.Run("too far future", func(t *testing.T) {
		// now is 10s before issuedAt; MaxFuture default 5s → from the future.
		v := verifierWith(t, resolver, func() time.Time { return at().Add(-10 * time.Second) }, earlyEpoch)
		assertErrIs(t, v.Verify(context.Background(), "Op", okFields(), proof, nil), wireauth.ErrFromFuture)
	})
	t.Run("asymmetry: 30s past accepted, 30s future rejected", func(t *testing.T) {
		// 30s past (< 60s MaxPast) is fine.
		vPast := verifierWith(t, resolver, func() time.Time { return at().Add(30 * time.Second) }, earlyEpoch)
		if err := vPast.Verify(context.Background(), "Op", okFields(), proof, nil); err != nil {
			t.Errorf("30s past: want accept, got %v", err)
		}
		// 30s future (> 5s MaxFuture) is rejected.
		vFut := verifierWith(t, resolver, func() time.Time { return at().Add(-30 * time.Second) }, earlyEpoch)
		assertErrIs(t, vFut.Verify(context.Background(), "Op", okFields(), proof, nil), wireauth.ErrFromFuture)
	})
}

func TestNewVerifier_WindowSemantics(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	resolver := mapResolver{subDID: authDoc(subDID, pub)}
	proof, _ := wireauth.Sign(signer, subDID, "Op", okFields(), "n1", at())

	t.Run("explicit MaxFuture:0 rejects a future proof", func(t *testing.T) {
		// now is 1s before issuedAt; an explicit zero future tolerance must reject
		// it rather than fall back to the default 5s.
		v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
			Resolver: resolver, Crypto: ed25519.Verifier{}, Nonces: wireauth.NewMemoryNonceStore(),
			Clock:  func() time.Time { return at().Add(-time.Second) },
			Epoch:  at().Add(-time.Hour),
			Window: wireauth.AcceptanceWindow{MaxPast: 60 * time.Second, MaxFuture: 0},
		})
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		assertErrIs(t, v.Verify(context.Background(), "Op", okFields(), proof, nil), wireauth.ErrFromFuture)
	})

	t.Run("negative window durations rejected", func(t *testing.T) {
		base := wireauth.VerifierConfig{Resolver: resolver, Crypto: ed25519.Verifier{}, Nonces: wireauth.NewMemoryNonceStore()}
		for _, w := range []wireauth.AcceptanceWindow{{MaxPast: -time.Second}, {MaxFuture: -time.Second}} {
			c := base
			c.Window = w
			if _, err := wireauth.NewVerifier(c); err == nil {
				t.Errorf("window %+v: want error, got nil", w)
			}
		}
	})
}

func TestVerify_SignatureGuards(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	resolver := mapResolver{subDID: authDoc(subDID, pub)}
	proof, _ := wireauth.Sign(signer, subDID, "RegisterSubscription", okFields(), "n1", at())

	t.Run("tampered fields", func(t *testing.T) {
		v := testVerifier(t, resolver)
		tampered := map[string]any{"actor": pubDID, "mode": "inline"} // mode changed
		assertErrIs(t, v.Verify(context.Background(), "RegisterSubscription", tampered, proof, nil), wireauth.ErrSignatureInvalid)
	})
	t.Run("tampered op", func(t *testing.T) {
		v := testVerifier(t, resolver)
		assertErrIs(t, v.Verify(context.Background(), "Disconnect", okFields(), proof, nil), wireauth.ErrSignatureInvalid)
	})
	t.Run("wrong key in doc", func(t *testing.T) {
		other, _ := (ed25519.Generator{}).Generate()
		v := testVerifier(t, mapResolver{subDID: authDoc(subDID, other.PublicKey)})
		assertErrIs(t, v.Verify(context.Background(), "RegisterSubscription", okFields(), proof, nil), wireauth.ErrSignatureInvalid)
	})
}

var errPolicy = errors.New("policy: denied")

func TestVerify_Authorization(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	resolver := mapResolver{subDID: authDoc(subDID, pub)}

	t.Run("rejecting authorizer propagates", func(t *testing.T) {
		v := testVerifier(t, resolver)
		proof, _ := wireauth.Sign(signer, subDID, "Op", okFields(), "n1", at())
		deny := func(string, *did.DIDDocument, map[string]any) error { return errPolicy }
		assertErrIs(t, v.Verify(context.Background(), "Op", okFields(), proof, deny), errPolicy)
	})

	t.Run("authorizer not consulted on bad signature", func(t *testing.T) {
		v := testVerifier(t, resolver)
		proof, _ := wireauth.Sign(signer, subDID, "Op", okFields(), "n1", at())
		called := false
		spy := func(string, *did.DIDDocument, map[string]any) error { called = true; return errPolicy }
		// Tampered op → signature fails before authz.
		err := v.Verify(context.Background(), "OtherOp", okFields(), proof, spy)
		assertErrIs(t, err, wireauth.ErrSignatureInvalid)
		if called {
			t.Error("authorizer was consulted before signature verification (policy oracle)")
		}
	})

	t.Run("authorizer mutation cannot affect outcome or caller fields", func(t *testing.T) {
		v := testVerifier(t, resolver)
		proof, _ := wireauth.Sign(signer, subDID, "Op", okFields(), "n1", at())
		callerFields := okFields()
		mutate := func(_ string, _ *did.DIDDocument, f map[string]any) error {
			f["actor"] = "did:dplaax:poc.dplaax.io:org:evil"
			f["injected"] = "x"
			return nil
		}
		if err := v.Verify(context.Background(), "Op", callerFields, proof, mutate); err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if callerFields["actor"] != pubDID || callerFields["injected"] != nil {
			t.Errorf("authorizer mutated the caller's fields: %+v", callerFields)
		}
	})
}

func TestVerify_ReplayAndNoBurn(t *testing.T) {
	t.Run("replay rejected", func(t *testing.T) {
		signer, pub := signerFor(t, subDID)
		v := testVerifier(t, mapResolver{subDID: authDoc(subDID, pub)})
		proof, _ := wireauth.Sign(signer, subDID, "Op", okFields(), "n1", at())
		if err := v.Verify(context.Background(), "Op", okFields(), proof, nil); err != nil {
			t.Fatalf("first verify: %v", err)
		}
		assertErrIs(t, v.Verify(context.Background(), "Op", okFields(), proof, nil), wireauth.ErrReplay)
	})

	t.Run("forgery does not burn a legitimate nonce", func(t *testing.T) {
		signer, pub := signerFor(t, subDID)
		v := testVerifier(t, mapResolver{subDID: authDoc(subDID, pub)})
		genuine, _ := wireauth.Sign(signer, subDID, "Op", okFields(), "shared-nonce", at())
		// Forgery: same nonce, corrupted signature.
		forgery := genuine
		forgery.Signature = append([]byte(nil), genuine.Signature...)
		forgery.Signature[0] ^= 0xff
		assertErrIs(t, v.Verify(context.Background(), "Op", okFields(), forgery, nil), wireauth.ErrSignatureInvalid)
		// The genuine proof with the same nonce must still verify — the forgery
		// must not have recorded "shared-nonce".
		if err := v.Verify(context.Background(), "Op", okFields(), genuine, nil); err != nil {
			t.Errorf("genuine proof after forgery: want accept (nonce not burned), got %v", err)
		}
	})
}

// per-signer isolation: the same nonce under two different signer DIDs does not
// collide in the nonce store.
func TestVerify_PerSignerNonceIsolation(t *testing.T) {
	signerA, pubA := signerFor(t, subDID)
	otherDID := "did:dplaax:poc.dplaax.io:org:sub2"
	signerB, pubB := signerFor(t, otherDID)
	v := testVerifier(t, mapResolver{
		subDID:   authDoc(subDID, pubA),
		otherDID: authDoc(otherDID, pubB),
	})
	pa, _ := wireauth.Sign(signerA, subDID, "Op", okFields(), "same-nonce", at())
	pb, _ := wireauth.Sign(signerB, otherDID, "Op", okFields(), "same-nonce", at())
	if err := v.Verify(context.Background(), "Op", okFields(), pa, nil); err != nil {
		t.Fatalf("signer A: %v", err)
	}
	if err := v.Verify(context.Background(), "Op", okFields(), pb, nil); err != nil {
		t.Errorf("signer B with same nonce: want accept (per-signer keying), got %v", err)
	}
}

func assertErrIs(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Errorf("want errors.Is %v, got %v", want, got)
	}
}
