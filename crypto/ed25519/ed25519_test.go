package ed25519_test

import (
	stded25519 "crypto/ed25519"
	"errors"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
)

// compile-time: the concrete types satisfy the crypto interfaces.
var (
	_ crypto.KeyGenerator = ed25519.Generator{}
	_ crypto.Verifier     = ed25519.Verifier{}
	_ crypto.Signer       = (*ed25519.Signer)(nil)
)

// ---------------------------------------------------------------------------
// In-memory keystore (test-local) — the custody seam the raw-key Signer reads.
// ---------------------------------------------------------------------------

type memKeyStore struct {
	keys map[string]map[keystore.KeyID][]byte
}

func newMemKeyStore() *memKeyStore {
	return &memKeyStore{keys: map[string]map[keystore.KeyID][]byte{}}
}

func (m *memKeyStore) SaveKeyPair(did string, keys map[keystore.KeyID]*crypto.KeyPair) error {
	byID := map[keystore.KeyID][]byte{}
	for id, kp := range keys {
		byID[id] = kp.PrivateKey
	}
	m.keys[did] = byID
	return nil
}

func (m *memKeyStore) GetPrivateKey(did string, keyID keystore.KeyID) ([]byte, error) {
	byID, ok := m.keys[did]
	if !ok {
		return nil, errors.New("memKeyStore: unknown did")
	}
	k, ok := byID[keyID]
	if !ok {
		return nil, errors.New("memKeyStore: unknown keyID")
	}
	return k, nil
}

func (m *memKeyStore) DeleteKeys(did string) error {
	delete(m.keys, did)
	return nil
}

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
// Signer (KeyStore-backed raw-key signer; tests / CLI-local keys)
// ---------------------------------------------------------------------------

func TestSigner_SignVerifyRoundTrip(t *testing.T) {
	g := ed25519.Generator{}
	kp, _ := g.Generate()

	ks := newMemKeyStore()
	const did = "did:dplaax:proc1"
	if err := ks.SaveKeyPair(did, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatalf("SaveKeyPair: %v", err)
	}

	signer := ed25519.NewSigner(ks)
	data := []byte("credential hashData")
	sig, err := signer.Sign(did, string(keystore.KeyIDSigning), data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != stded25519.SignatureSize {
		t.Errorf("signature len=%d, want %d", len(sig), stded25519.SignatureSize)
	}

	// The signature verifies under the keypair's public key.
	ok, err := (ed25519.Verifier{}).Verify(kp.PublicKey, data, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("Signer output did not verify under the keypair's public key")
	}
}

func TestSigner_MissingKey(t *testing.T) {
	signer := ed25519.NewSigner(newMemKeyStore())
	if _, err := signer.Sign("did:dplaax:absent", string(keystore.KeyIDSigning), []byte("x")); err == nil {
		t.Error("signing with an absent key: want error")
	}
}

func TestSigner_MalformedKey(t *testing.T) {
	ks := newMemKeyStore()
	const did = "did:dplaax:bad"
	// A private key of the wrong size must be rejected, not panic.
	ks.keys[did] = map[keystore.KeyID][]byte{keystore.KeyIDSigning: []byte("too short")}
	signer := ed25519.NewSigner(ks)
	if _, err := signer.Sign(did, string(keystore.KeyIDSigning), []byte("x")); err == nil {
		t.Error("signing with a malformed key: want error (not panic)")
	}
}

func TestSigner_Deterministic(t *testing.T) {
	g := ed25519.Generator{}
	kp, _ := g.Generate()
	ks := newMemKeyStore()
	const did = "did:dplaax:det"
	_ = ks.SaveKeyPair(did, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp})
	signer := ed25519.NewSigner(ks)

	data := []byte("same bytes")
	s1, _ := signer.Sign(did, string(keystore.KeyIDSigning), data)
	s2, _ := signer.Sign(did, string(keystore.KeyIDSigning), data)
	if string(s1) != string(s2) {
		t.Error("Ed25519 signatures over identical input must be deterministic")
	}
}
