package client_test

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/gen/go/dplaax/signer/v1/signerpbconnect"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/network/pkg/services/signer"
	"github.com/provin-line/oss/network/pkg/services/signer/client"
	"github.com/provin-line/oss/network/pkg/services/signer/handler"
	"github.com/provin-line/oss/vc"
)

const did = "did:dplaax:poc.dplaax.dev:org:acme"

type memKeyStore struct {
	keys map[string]map[keystore.KeyID]*crypto.KeyPair
}

func (m *memKeyStore) SaveKeyPair(d string, ks map[keystore.KeyID]*crypto.KeyPair) error {
	m.keys[d] = ks
	return nil
}

func (m *memKeyStore) GetPrivateKey(d string, keyID keystore.KeyID) ([]byte, error) {
	if ks, ok := m.keys[d]; ok {
		if kp, ok := ks[keyID]; ok {
			return kp.PrivateKey, nil
		}
	}
	return nil, keystore.ErrNotFound
}

func (m *memKeyStore) DeleteKeys(d string) error { delete(m.keys, d); return nil }

// wireSigner stands up an in-process SignerService over a keystore holding fresh
// #signing and #auth keys for did, and returns a client-side crypto.Signer that
// reaches it over a real Connect server, plus the two public keys.
func wireSigner(t *testing.T) (sig crypto.Signer, signPub, authPub []byte) {
	t.Helper()
	signKP, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate signing: %v", err)
	}
	authKP, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate auth: %v", err)
	}
	ks := &memKeyStore{keys: map[string]map[keystore.KeyID]*crypto.KeyPair{}}
	ks.SaveKeyPair(did, map[keystore.KeyID]*crypto.KeyPair{
		keystore.KeyIDSigning: signKP,
		keystore.KeyIDAuth:    authKP,
	})

	_, h := signerpbconnect.NewSignerServiceHandler(handler.New(signer.New(ed25519.NewSigner(ks))))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	c := client.New(signerpbconnect.NewSignerServiceClient(srv.Client(), srv.URL))
	return c, signKP.PublicKey, authKP.PublicKey
}

// The headline proof: a VC proof created with the client crypto.Signer — keys
// never leave the server — verifies. CreateProof passes raw hashData to Sign and
// multibase-encodes the raw signature the wire returns (D-s1), so the whole KMS
// seam round-trips through Create→wire→Verify.
func TestE2E_VCProof_RoundTripsThroughWire(t *testing.T) {
	clientSigner, signPub, _ := wireSigner(t)

	body := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"id":       did,
		"claim":    "hello",
	}
	proof, err := vc.CreateProof(clientSigner, did, string(keystore.KeyIDSigning), did+"#signing", body, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof over wire: %v", err)
	}
	if err := vc.VerifyProof(ed25519.Verifier{}, signPub, proof, body); err != nil {
		t.Fatalf("VerifyProof: %v", err)
	}
}

// The wire (SignRaw) path: a raw signature over arbitrary bytes with the #auth
// key verifies directly.
func TestE2E_SignRaw_RoundTripsThroughWire(t *testing.T) {
	clientSigner, _, authPub := wireSigner(t)

	data := []byte("canonical AuthProof view")
	sig, err := clientSigner.Sign(did, string(keystore.KeyIDAuth), data)
	if err != nil {
		t.Fatalf("Sign(auth) over wire: %v", err)
	}
	ok, err := (ed25519.Verifier{}).Verify(authPub, data, sig)
	if err != nil || !ok {
		t.Fatalf("verify raw: ok=%v err=%v", ok, err)
	}
}

// The client dispatches by keyID; an unknown key has no RPC to route to and is a
// client-local error (no network call).
func TestE2E_UnknownKeyID_IsClientLocal(t *testing.T) {
	clientSigner, _, _ := wireSigner(t)
	_, err := clientSigner.Sign(did, "rotation", []byte("x"))
	if !errors.Is(err, client.ErrUnsupportedKeyID) {
		t.Fatalf("unknown keyID: want ErrUnsupportedKeyID, got %v", err)
	}
}
