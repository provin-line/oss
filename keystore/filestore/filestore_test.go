package filestore_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
)

const did = "did:dplaax:poc.dplaax.io:org:acme:pipeline:p1"

func kp(b byte) *crypto.KeyPair {
	return &crypto.KeyPair{Algorithm: "Ed25519", PrivateKey: []byte{b, b, b, b}, PublicKey: []byte{b}}
}

func newStore(t *testing.T) *filestore.Store {
	t.Helper()
	return filestore.New(t.TempDir())
}

func TestSaveAndGet(t *testing.T) {
	s := newStore(t)
	if err := s.SaveKeyPair(did, map[keystore.KeyID]*crypto.KeyPair{
		keystore.KeyIDAuth:    kp(1),
		keystore.KeyIDSigning: kp(2),
	}); err != nil {
		t.Fatalf("SaveKeyPair: %v", err)
	}
	auth, err := s.GetPrivateKey(did, keystore.KeyIDAuth)
	if err != nil || string(auth) != string([]byte{1, 1, 1, 1}) {
		t.Fatalf("auth: got %v err %v", auth, err)
	}
	sign, err := s.GetPrivateKey(did, keystore.KeyIDSigning)
	if err != nil || string(sign) != string([]byte{2, 2, 2, 2}) {
		t.Fatalf("signing: got %v err %v", sign, err)
	}
}

func TestGet_Absent_IsErrNotFound(t *testing.T) {
	s := newStore(t)
	if _, err := s.GetPrivateKey(did, keystore.KeyIDSigning); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("absent: want ErrNotFound, got %v", err)
	}
	// Saved DID, absent keyID is also ErrNotFound.
	s.SaveKeyPair(did, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp(2)})
	if _, err := s.GetPrivateKey(did, keystore.KeyIDAuth); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("absent keyID: want ErrNotFound, got %v", err)
	}
}

// Create-only: re-saving an existing DID is rejected and the original keyset is
// left untouched — never destroyed in a non-atomic replace window.
func TestSave_RejectsExisting(t *testing.T) {
	s := newStore(t)
	if err := s.SaveKeyPair(did, map[keystore.KeyID]*crypto.KeyPair{
		keystore.KeyIDAuth:    kp(1),
		keystore.KeyIDSigning: kp(2),
	}); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if err := s.SaveKeyPair(did, map[keystore.KeyID]*crypto.KeyPair{
		keystore.KeyIDAuth:    kp(3),
		keystore.KeyIDSigning: kp(4),
	}); err == nil {
		t.Fatal("re-save: want error (create-only), got nil")
	}
	// Original keyset is intact.
	auth, _ := s.GetPrivateKey(did, keystore.KeyIDAuth)
	sign, _ := s.GetPrivateKey(did, keystore.KeyIDSigning)
	if string(auth) != string([]byte{1, 1, 1, 1}) || string(sign) != string([]byte{2, 2, 2, 2}) {
		t.Fatalf("original keyset altered: auth=%v sign=%v", auth, sign)
	}
}

func TestDeleteKeys(t *testing.T) {
	s := newStore(t)
	s.SaveKeyPair(did, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp(2)})
	if err := s.DeleteKeys(did); err != nil {
		t.Fatalf("DeleteKeys: %v", err)
	}
	if _, err := s.GetPrivateKey(did, keystore.KeyIDSigning); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("after delete: want ErrNotFound, got %v", err)
	}
	// Deleting an absent DID is a no-op, not an error.
	if err := s.DeleteKeys("did:dplaax:poc.dplaax.io:org:absent"); err != nil {
		t.Errorf("delete absent: %v", err)
	}
}

func TestKeyFilePerms0600(t *testing.T) {
	root := t.TempDir()
	s := filestore.New(root)
	s.SaveKeyPair(did, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp(2)})
	var found string
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			found = p
		}
		return nil
	})
	if found == "" {
		t.Fatal("no key file written")
	}
	fi, err := os.Stat(found)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("key file perm = %v, want 0600", fi.Mode().Perm())
	}
}

func TestPathTraversalRejected(t *testing.T) {
	s := newStore(t)
	for _, bad := range []string{
		"did:dplaax:poc.dplaax.io:org:..",  // traversal segment
		"did:dplaax:poc.dplaax.io:org:a/b", // separator in segment
		"did:dplaax:poc.dplaax.io:org:",    // empty segment
	} {
		if err := s.SaveKeyPair(bad, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp(2)}); err == nil {
			t.Errorf("SaveKeyPair(%q): want error, got nil", bad)
		}
		if _, err := s.GetPrivateKey(bad, keystore.KeyIDSigning); err == nil {
			t.Errorf("GetPrivateKey(%q): want error, got nil", bad)
		}
	}
}
