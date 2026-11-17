package wireauth_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/didresolver"
	"github.com/provin-line/oss/network/pkg/wireauth"
)

const (
	// testAudience is the audience the tests sign for and their verifiers accept.
	testAudience = "verifier.example"

	subDID = "did:dplaax:poc.dplaax.dev:org:sub"
	pubDID = "did:dplaax:poc.dplaax.dev:org:acme"
)

func at() time.Time { return time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC) }

// testNonces is a memory nonce store on the tests' clock: a store decides a
// nonce's expiry by its own clock, which must agree with the verifier's.
func testNonces() wireauth.NonceStore {
	return wireauth.NewMemoryNonceStore(wireauth.WithNonceClock(at))
}

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
	return ks, kp.PublicKey
}

// testVerifier builds a Verifier whose clock sits 1s after `at()` (so a proof
// issued at `at()` is just inside the past window) and whose epoch is well
// before it (so the epoch barrier does not interfere with happy-path tests).
func testVerifier(t *testing.T, resolver wireauth.DIDResolver) *wireauth.Verifier {
	t.Helper()
	v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: resolver,
		Crypto:   ed25519.Verifier{},
		Nonces:   testNonces(), Audience: testAudience,
		Clock: func() time.Time { return at().Add(time.Second) },
		Epoch: at().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func okFields() map[string]any { return map[string]any{"actor": pubDID, "mode": "by-reference"} }

// Sign takes the members of the view that the request does not carry as
// Claims, and the proof carries them back, issuedAt at second precision.
func TestSign_TakesClaims(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	v := testVerifier(t, mapResolver{subDID: authDoc(subDID, pub)})
	proof, err := wireauth.Sign(signer, "Op", okFields(), wireauth.Claims{
		SignerDID: subDID, Audience: testAudience, Nonce: "n1", IssuedAt: at().Add(300 * time.Millisecond),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if proof.SignerDID != subDID || proof.Audience != testAudience || proof.Nonce != "n1" || !proof.IssuedAt.Equal(at()) {
		t.Errorf("proof = %+v, want the claims back with issuedAt %v", proof, at())
	}
	if err := v.Verify(context.Background(), "Op", okFields(), proof, nil); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerify_RoundTrip(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	v := testVerifier(t, mapResolver{subDID: authDoc(subDID, pub)})
	proof, err := wireauth.Sign(signer, "RegisterSubscription", okFields(), wireauth.Claims{SignerDID: subDID, Audience: testAudience, Nonce: "n1", IssuedAt: at()})
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

// recordingNonces is a NonceStore that keeps what it was handed.
type recordingNonces struct {
	ctx           context.Context
	signer, nonce string
	expiresAt     time.Time
	calls         int
}

func (r *recordingNonces) Use(ctx context.Context, signerDID, nonce string, expiresAt time.Time) error {
	r.ctx, r.signer, r.nonce, r.expiresAt = ctx, signerDID, nonce, expiresAt
	r.calls++
	return nil
}

// Verify hands the nonce store the request's context and when the proof
// stops being acceptable (its issuedAt plus the window's MaxPast), so a store
// may forget the nonce after that.
func TestVerify_HandsTheNonceStoreTheContextAndExpiry(t *testing.T) {
	type key struct{}
	signer, pub := signerFor(t, subDID)
	nonces := &recordingNonces{}
	v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: mapResolver{subDID: authDoc(subDID, pub)},
		Crypto:   ed25519.Verifier{},
		Nonces:   nonces, Audience: testAudience,
		Clock:  func() time.Time { return at().Add(time.Second) },
		Epoch:  at().Add(-time.Hour),
		Window: wireauth.AcceptanceWindow{MaxPast: 30 * time.Second, MaxFuture: 2 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := wireauth.Sign(signer, "Op", okFields(), wireauth.Claims{SignerDID: subDID, Audience: testAudience, Nonce: "n1", IssuedAt: at()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), key{}, "the request")
	if err := v.Verify(ctx, "Op", okFields(), proof, nil); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if nonces.calls != 1 || nonces.ctx == nil || nonces.ctx.Value(key{}) != "the request" || nonces.signer != subDID || nonces.nonce != "n1" || !nonces.expiresAt.Equal(at().Add(30*time.Second)) {
		t.Errorf("nonce store handed %+v, want the request's context, %s, n1 and %v", nonces, subDID, at().Add(30*time.Second))
	}
}

// clockedResolver resolves as its map does, after running before, which a
// test uses to move the clock while a verification waits on resolution.
type clockedResolver struct {
	mapResolver
	before func()
}

func (r clockedResolver) Resolve(ctx context.Context, d string) (*did.DIDDocument, error) {
	if r.before != nil {
		r.before()
	}
	return r.mapResolver.Resolve(ctx, d)
}

// The nonce store decides at admission whether the proof has expired: a
// proof whose nonce reaches the store after the proof's expiry is refused
// with ErrExpired, whatever the checks before it found.
func TestVerify_ANonceAdmittedAfterItsExpiryIsRefused(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	now := at().Add(time.Second)
	clock := func() time.Time { return now }
	window := wireauth.AcceptanceWindow{MaxPast: 30 * time.Second, MaxFuture: 2 * time.Second}
	resolver := clockedResolver{mapResolver: mapResolver{subDID: authDoc(subDID, pub)}}
	v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: &resolver, Crypto: ed25519.Verifier{},
		Nonces:   wireauth.NewMemoryNonceStore(wireauth.WithNonceRetention(window.NonceRetention()), wireauth.WithNonceClock(clock)),
		Audience: testAudience, Clock: clock, Epoch: at().Add(-time.Hour), Window: window,
	})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := wireauth.Sign(signer, "Op", okFields(), wireauth.Claims{SignerDID: subDID, Audience: testAudience, Nonce: "n1", IssuedAt: at()})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(context.Background(), "Op", okFields(), proof, nil); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	resolver.before = func() { now = at().Add(window.MaxPast + window.NonceRetention() + time.Minute) }
	if err := v.Verify(context.Background(), "Op", okFields(), proof, nil); !errors.Is(err, wireauth.ErrExpired) {
		t.Fatalf("a nonce admitted after its expiry: %v, want ErrExpired", err)
	}
}

func TestVerify_NilAuthorizerSkipsAuthz(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	v := testVerifier(t, mapResolver{subDID: authDoc(subDID, pub)})
	proof, _ := wireauth.Sign(signer, "Op", okFields(), wireauth.Claims{SignerDID: subDID, Audience: testAudience, Nonce: "n1", IssuedAt: at()})
	if err := v.Verify(context.Background(), "Op", okFields(), proof, nil); err != nil {
		t.Fatalf("Verify with nil authorizer: %v", err)
	}
}

func TestVerify_KeyResolutionFailures(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	proof, _ := wireauth.Sign(signer, "Op", okFields(), wireauth.Claims{SignerDID: subDID, Audience: testAudience, Nonce: "n1", IssuedAt: at()})

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
	proof, _ := wireauth.Sign(signer, "Op", okFields(), wireauth.Claims{SignerDID: subDID, Audience: testAudience, Nonce: "n1", IssuedAt: at()})
	// Attacker re-labels the proof as the alias DID (whose doc shares the key).
	proof.SignerDID = alias
	if err := v.Verify(context.Background(), "Op", okFields(), proof, nil); !errors.Is(err, wireauth.ErrSignatureInvalid) {
		t.Errorf("aliased proof: want ErrSignatureInvalid, got %v", err)
	}
}

func TestNewVerifier_RequiresDeps(t *testing.T) {
	base := wireauth.VerifierConfig{
		Resolver: mapResolver{}, Crypto: ed25519.Verifier{}, Nonces: testNonces(), Audience: testAudience,
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

// errResolver always fails resolution with a fixed error — to exercise the
// transient (retryable) vs definitive (identity-failure) classification.
type errResolver struct{ err error }

func (e errResolver) Resolve(context.Context, string) (*did.DIDDocument, error) {
	return nil, e.err
}

// A transient resolver condition (timeout, cancellation, at-capacity) must
// surface as ErrResolverUnavailable — NOT ErrKeyResolution — so the signer's
// authenticity is reported "could not be evaluated, retry", never "rejected".
func TestVerify_TransientResolverError_IsUnavailableNotKeyResolution(t *testing.T) {
	signer, _ := signerFor(t, subDID)
	proof, _ := wireauth.Sign(signer, "Op", okFields(), wireauth.Claims{SignerDID: subDID, Audience: testAudience, Nonce: "n1", IssuedAt: at()})

	for name, resErr := range map[string]error{
		"timeout":      context.DeadlineExceeded,
		"cancelled":    context.Canceled,
		"at capacity":  didresolver.ErrResolverBusy,
		"wrapped busy": fmt.Errorf("resolve chain: %w", didresolver.ErrResolverBusy),
		"registry 5xx": didresolver.ErrRegistryUnavailable,
		"wrapped 5xx":  fmt.Errorf("resolve chain: %w", didresolver.ErrRegistryUnavailable),
	} {
		t.Run(name, func(t *testing.T) {
			v := testVerifier(t, errResolver{err: resErr})
			err := v.Verify(context.Background(), "Op", okFields(), proof, nil)
			if !errors.Is(err, wireauth.ErrResolverUnavailable) {
				t.Errorf("err = %v, want ErrResolverUnavailable", err)
			}
			if errors.Is(err, wireauth.ErrKeyResolution) {
				t.Errorf("transient resolver error misclassified as ErrKeyResolution: %v", err)
			}
		})
	}
}

// A definitive resolver failure (a plain not-found, no transient marker) stays
// ErrKeyResolution → Unauthenticated.
func TestVerify_DefinitiveResolverError_IsKeyResolution(t *testing.T) {
	signer, _ := signerFor(t, subDID)
	proof, _ := wireauth.Sign(signer, "Op", okFields(), wireauth.Claims{SignerDID: subDID, Audience: testAudience, Nonce: "n1", IssuedAt: at()})
	v := testVerifier(t, errResolver{err: errors.New("registry: no such DID")})
	err := v.Verify(context.Background(), "Op", okFields(), proof, nil)
	if !errors.Is(err, wireauth.ErrKeyResolution) {
		t.Errorf("err = %v, want ErrKeyResolution", err)
	}
	if errors.Is(err, wireauth.ErrResolverUnavailable) {
		t.Errorf("definitive failure misclassified as transient: %v", err)
	}
}
