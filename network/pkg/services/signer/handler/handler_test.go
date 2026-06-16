package handler_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	signerpb "github.com/provin-line/oss/gen/go/dplaax/signer/v1"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/network/pkg/services/signer"
	"github.com/provin-line/oss/network/pkg/services/signer/handler"
)

const did = "did:dplaax:poc.dplaax.io:org:acme"

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

// handlerOver builds a Handler over the real domain backed by ks, so the domain
// sentinels actually flow through mapError to Connect codes.
func handlerOver(ks *memKeyStore) *handler.Handler {
	return handler.New(signer.New(ed25519.NewSigner(ks)))
}

func newKS() *memKeyStore {
	return &memKeyStore{keys: map[string]map[keystore.KeyID]*crypto.KeyPair{}}
}

func withKey(t *testing.T, keyID keystore.KeyID) *memKeyStore {
	t.Helper()
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	ks := newKS()
	ks.SaveKeyPair(did, map[keystore.KeyID]*crypto.KeyPair{keyID: kp})
	return ks
}

// mapError is exercised through the real domain: absent key → NotFound, malformed
// key → Internal (never masked as NotFound), crossed binding → InvalidArgument.
func TestHandler_Sign_ErrorCodes(t *testing.T) {
	malformed := newKS()
	malformed.SaveKeyPair(did, map[keystore.KeyID]*crypto.KeyPair{
		keystore.KeyIDSigning: {Algorithm: "Ed25519", PrivateKey: []byte{1, 2, 3}},
	})

	cases := []struct {
		name  string
		ks    *memKeyStore
		keyID string
		want  connect.Code
	}{
		{"absent key → NotFound", newKS(), "signing", connect.CodeNotFound},
		{"malformed key → Internal", malformed, "signing", connect.CodeInternal},
		{"crossed binding → InvalidArgument", withKey(t, keystore.KeyIDSigning), "auth", connect.CodeInvalidArgument},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := handlerOver(c.ks).Sign(context.Background(),
				connect.NewRequest(&signerpb.SignRequest{Did: did, KeyId: c.keyID, Data: []byte("x")}))
			if got := connect.CodeOf(err); got != c.want {
				t.Errorf("code = %v, want %v (err=%v)", got, c.want, err)
			}
		})
	}
}

func TestHandler_Sign_Success(t *testing.T) {
	resp, err := handlerOver(withKey(t, keystore.KeyIDSigning)).Sign(context.Background(),
		connect.NewRequest(&signerpb.SignRequest{Did: did, KeyId: "signing", Data: []byte("x")}))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(resp.Msg.GetSignature()) == 0 {
		t.Error("empty signature")
	}
}

func TestHandler_SignRaw_ErrorCodes(t *testing.T) {
	// Crossed binding on the wire domain: the #signing key on the SignRaw
	// endpoint is InvalidArgument.
	_, err := handlerOver(withKey(t, keystore.KeyIDAuth)).SignRaw(context.Background(),
		connect.NewRequest(&signerpb.SignRawRequest{Did: did, KeyId: "signing", Data: []byte("x")}))
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Errorf("SignRaw(signing): code = %v, want InvalidArgument (err=%v)", got, err)
	}
}
