package signer_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/network/pkg/services/signer"
)

const did = "did:dplaax:poc.dplaax.io:org:acme"

// --- in-memory keystore wrapping keystore.ErrNotFound (the contract) ---------

type memKeyStore struct {
	keys map[string]map[keystore.KeyID]*crypto.KeyPair
}

func newMemKS() *memKeyStore {
	return &memKeyStore{keys: map[string]map[keystore.KeyID]*crypto.KeyPair{}}
}

func (m *memKeyStore) put(d string, keyID keystore.KeyID, kp *crypto.KeyPair) {
	if m.keys[d] == nil {
		m.keys[d] = map[keystore.KeyID]*crypto.KeyPair{}
	}
	m.keys[d][keyID] = kp
}

func (m *memKeyStore) SaveKeyPair(d string, ks map[keystore.KeyID]*crypto.KeyPair) error {
	for k, v := range ks {
		m.put(d, k, v)
	}
	return nil
}

func (m *memKeyStore) GetPrivateKey(d string, keyID keystore.KeyID) ([]byte, error) {
	if ks, ok := m.keys[d]; ok {
		if kp, ok := ks[keyID]; ok {
			return kp.PrivateKey, nil
		}
	}
	return nil, fmt.Errorf("memKeyStore: %s#%s: %w", d, keyID, keystore.ErrNotFound)
}

func (m *memKeyStore) DeleteKeys(d string) error {
	delete(m.keys, d)
	return nil
}

// svcWithKey returns a Service over a real keystore-backed ed25519 signer, with
// a fresh key saved under (did, keyID), and that key's public bytes.
func svcWithKey(t *testing.T, keyID keystore.KeyID) (*signer.Service, []byte) {
	t.Helper()
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	ks := newMemKS()
	ks.put(did, keyID, kp)
	return signer.New(ed25519.NewSigner(ks)), kp.PublicKey
}

// --- happy paths: each domain signs with its bound key, signature verifies ----

func TestSign_VCDomain_RoundTrip(t *testing.T) {
	svc, pub := svcWithKey(t, keystore.KeyIDSigning)
	data := []byte("vc proof hashData")
	sig, err := svc.Sign(context.Background(), did, "signing", data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := (ed25519.Verifier{}).Verify(pub, data, sig)
	if err != nil || !ok {
		t.Fatalf("verify: ok=%v err=%v", ok, err)
	}
}

func TestSignRaw_WireDomain_RoundTrip(t *testing.T) {
	svc, pub := svcWithKey(t, keystore.KeyIDAuth)
	data := []byte("canonical AuthProof view")
	sig, err := svc.SignRaw(context.Background(), did, "auth", data)
	if err != nil {
		t.Fatalf("SignRaw: %v", err)
	}
	ok, err := (ed25519.Verifier{}).Verify(pub, data, sig)
	if err != nil || !ok {
		t.Fatalf("verify: ok=%v err=%v", ok, err)
	}
}

// --- D-s3 crossed bindings: each endpoint rejects the other domain's key ------

func TestSign_RejectsAuthKey(t *testing.T) {
	svc, _ := svcWithKey(t, keystore.KeyIDSigning)
	_, err := svc.Sign(context.Background(), did, "auth", []byte("x"))
	if !errors.Is(err, signer.ErrInvalidArgument) {
		t.Fatalf("Sign(auth): want ErrInvalidArgument, got %v", err)
	}
}

func TestSignRaw_RejectsSigningKey(t *testing.T) {
	svc, _ := svcWithKey(t, keystore.KeyIDAuth)
	_, err := svc.SignRaw(context.Background(), did, "signing", []byte("x"))
	if !errors.Is(err, signer.ErrInvalidArgument) {
		t.Fatalf("SignRaw(signing): want ErrInvalidArgument, got %v", err)
	}
}

func TestSign_EmptyDID(t *testing.T) {
	svc, _ := svcWithKey(t, keystore.KeyIDSigning)
	_, err := svc.Sign(context.Background(), "", "signing", []byte("x"))
	if !errors.Is(err, signer.ErrInvalidArgument) {
		t.Fatalf("empty did: want ErrInvalidArgument, got %v", err)
	}
}

// --- error typing: absent key is NotFound; malformed key is neither -----------

func TestSign_AbsentKey_IsKeyNotFound(t *testing.T) {
	svc := signer.New(ed25519.NewSigner(newMemKS())) // empty keystore
	_, err := svc.Sign(context.Background(), did, "signing", []byte("x"))
	if !errors.Is(err, signer.ErrKeyNotFound) {
		t.Fatalf("absent key: want ErrKeyNotFound, got %v", err)
	}
}

func TestSign_MalformedKey_IsNotMaskedAsNotFound(t *testing.T) {
	ks := newMemKS()
	ks.put(did, keystore.KeyIDSigning, &crypto.KeyPair{Algorithm: "Ed25519", PrivateKey: []byte{1, 2, 3}})
	svc := signer.New(ed25519.NewSigner(ks))
	_, err := svc.Sign(context.Background(), did, "signing", []byte("x"))
	if err == nil {
		t.Fatal("malformed key: want error, got nil")
	}
	if errors.Is(err, signer.ErrKeyNotFound) {
		t.Errorf("malformed key masked as ErrKeyNotFound: %v", err)
	}
	if errors.Is(err, signer.ErrInvalidArgument) {
		t.Errorf("malformed key misclassified as ErrInvalidArgument: %v", err)
	}
}
