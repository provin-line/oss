package ed25519_test

import (
	stded25519 "crypto/ed25519"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
)

// compile-time: the concrete types satisfy the crypto interfaces.
var (
	_ crypto.KeyGenerator = ed25519.Generator{}
	_ crypto.Verifier     = ed25519.Verifier{}
)

// ---------------------------------------------------------------------------
// KeyGenerator
// ---------------------------------------------------------------------------

func TestGenerator_Generate(t *testing.T) {
	g := ed25519.Generator{}
	if g.Algorithm() != ed25519.Algorithm {
		t.Errorf("Algorithm()=%q, want %q", g.Algorithm(), ed25519.Algorithm)
	}
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if kp.Algorithm != ed25519.Algorithm {
		t.Errorf("KeyPair.Algorithm=%q, want %q", kp.Algorithm, ed25519.Algorithm)
	}
	if len(kp.PublicKey) != stded25519.PublicKeySize {
		t.Errorf("PublicKey len=%d, want %d", len(kp.PublicKey), stded25519.PublicKeySize)
	}
	if len(kp.PrivateKey) != stded25519.PrivateKeySize {
		t.Errorf("PrivateKey len=%d, want %d", len(kp.PrivateKey), stded25519.PrivateKeySize)
	}
}

func TestGenerator_DistinctKeys(t *testing.T) {
	g := ed25519.Generator{}
	a, _ := g.Generate()
	b, _ := g.Generate()
	if string(a.PrivateKey) == string(b.PrivateKey) {
		t.Error("two Generate calls produced identical private keys")
	}
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

func TestVerifier_RoundTrip(t *testing.T) {
	pub, priv, err := stded25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	data := []byte("provenance event bytes")
	sig := stded25519.Sign(priv, data)

	v := ed25519.Verifier{}
	ok, err := v.Verify(pub, data, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("valid signature did not verify")
	}
}

func TestVerifier_TamperedData(t *testing.T) {
	pub, priv, _ := stded25519.GenerateKey(nil)
	sig := stded25519.Sign(priv, []byte("original"))

	v := ed25519.Verifier{}
	ok, err := v.Verify(pub, []byte("tampered"), sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Error("tampered data verified — must not")
	}
}

func TestVerifier_WrongKey(t *testing.T) {
	_, priv, _ := stded25519.GenerateKey(nil)
	otherPub, _, _ := stded25519.GenerateKey(nil)
	data := []byte("x")
	sig := stded25519.Sign(priv, data)

	v := ed25519.Verifier{}
	ok, err := v.Verify(otherPub, data, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Error("signature verified under the wrong key — must not")
	}
}

func TestVerifier_MalformedSizes(t *testing.T) {
	v := ed25519.Verifier{}
	pub, priv, _ := stded25519.GenerateKey(nil)
	sig := stded25519.Sign(priv, []byte("x"))

	if _, err := v.Verify(pub[:10], []byte("x"), sig); err == nil {
		t.Error("short public key: want error")
	}
	if _, err := v.Verify(pub, []byte("x"), sig[:10]); err == nil {
		t.Error("short signature: want error")
	}
}

func TestVerifier_Algorithm(t *testing.T) {
	if (ed25519.Verifier{}).Algorithm() != ed25519.Algorithm {
		t.Errorf("Verifier.Algorithm()=%q, want %q", (ed25519.Verifier{}).Algorithm(), ed25519.Algorithm)
	}
}

// ---------------------------------------------------------------------------
// Sign (raw signing primitive over key bytes; keystore-backed stores compose it)
// ---------------------------------------------------------------------------

func TestSign_VerifyRoundTrip(t *testing.T) {
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data := []byte("credential hashData")
	sig, err := ed25519.Sign(kp.PrivateKey, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != stded25519.SignatureSize {
		t.Errorf("signature len=%d, want %d", len(sig), stded25519.SignatureSize)
	}
	ok, err := (ed25519.Verifier{}).Verify(kp.PublicKey, data, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("Sign output did not verify under the keypair's public key")
	}
}

func TestSign_MalformedKey(t *testing.T) {
	// A private key of the wrong size must be a typed error, not a panic.
	if _, err := ed25519.Sign([]byte("too short"), []byte("x")); err == nil {
		t.Error("signing with a malformed key: want error (not panic)")
	}
}

func TestSign_Deterministic(t *testing.T) {
	kp, _ := (ed25519.Generator{}).Generate()
	data := []byte("same bytes")
	s1, _ := ed25519.Sign(kp.PrivateKey, data)
	s2, _ := ed25519.Sign(kp.PrivateKey, data)
	if string(s1) != string(s2) {
		t.Error("Ed25519 signatures over identical input must be deterministic")
	}
}
