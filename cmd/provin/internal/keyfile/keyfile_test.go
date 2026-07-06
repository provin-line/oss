package keyfile_test

import (
	stded25519 "crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/provin-line/oss/cmd/provin/internal/keyfile"
	"github.com/provin-line/oss/crypto/ed25519"
)

const ownerDID = "did:dplaax:poc.dplaax.dev:org:acme"

func genKP(t *testing.T) ([]byte, []byte) {
	t.Helper()
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return kp.PublicKey, kp.PrivateKey
}

func TestWriteLoad_Roundtrip(t *testing.T) {
	pub, priv := genKP(t)
	path := filepath.Join(t.TempDir(), "acme-owner.jwk")

	if err := keyfile.Write(path, ownerDID, pub, priv); err != nil {
		t.Fatalf("Write: %v", err)
	}
	key, err := keyfile.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if key.DID != ownerDID {
		t.Errorf("DID = %q, want %q", key.DID, ownerDID)
	}
	if string(key.PublicKey) != string(pub) {
		t.Error("public key does not roundtrip")
	}
	if string(key.PrivateKey) != string(priv) {
		t.Error("private key does not roundtrip")
	}
	// The private key must still sign verifiably.
	sig := stded25519.Sign(stded25519.PrivateKey(key.PrivateKey), []byte("msg"))
	if !stded25519.Verify(stded25519.PublicKey(key.PublicKey), []byte("msg"), sig) {
		t.Error("loaded key does not sign/verify")
	}
}

func TestWrite_Permissions0600(t *testing.T) {
	pub, priv := genKP(t)
	path := filepath.Join(t.TempDir(), "k.jwk")
	if err := keyfile.Write(path, ownerDID, pub, priv); err != nil {
		t.Fatalf("Write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 600", perm)
	}
}

func TestWrite_RefusesOverwrite(t *testing.T) {
	pub, priv := genKP(t)
	path := filepath.Join(t.TempDir(), "k.jwk")
	if err := keyfile.Write(path, ownerDID, pub, priv); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	err := keyfile.Write(path, ownerDID, pub, priv)
	if err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("overwrite: want already-exists error, got %v", err)
	}
}

func TestLoad_Malformed(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"not json":    `nope`,
		"wrong kty":   `{"kty":"EC","crv":"Ed25519","kid":"did:x","x":"AA","d":"AA"}`,
		"wrong crv":   `{"kty":"OKP","crv":"P-256","kid":"did:x","x":"AA","d":"AA"}`,
		"missing kid": `{"kty":"OKP","crv":"Ed25519","x":"AA","d":"AA"}`,
		"missing d":   `{"kty":"OKP","crv":"Ed25519","kid":"did:x","x":"AA"}`,
		"bad d b64":   `{"kty":"OKP","crv":"Ed25519","kid":"did:x","x":"AA","d":"!!!"}`,
		"short d":     `{"kty":"OKP","crv":"Ed25519","kid":"did:x","x":"AA","d":"AAAA"}`,
	}
	i := 0
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, "bad"+strings.Repeat("x", i)+".jwk")
			i++
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := keyfile.Load(p); err == nil {
				t.Fatalf("%s: want error, got nil", name)
			}
		})
	}
}

// The x (public) field must be consistent with d: a JWK whose public half was
// tampered with must not load (the signer would produce signatures that never
// verify against the registered document — fail at load, not at first use).
func TestLoad_RejectsMismatchedPublicKey(t *testing.T) {
	pub, priv := genKP(t)
	otherPub, _ := genKP(t)
	path := filepath.Join(t.TempDir(), "k.jwk")
	if err := keyfile.Write(path, ownerDID, pub, priv); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	tampered := strings.Replace(string(raw), b64(pub), b64(otherPub), 1)
	if tampered == string(raw) {
		t.Fatal("tamper substitution did not apply")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := keyfile.Load(path); err == nil {
		t.Fatal("mismatched x: want error, got nil")
	}
}
