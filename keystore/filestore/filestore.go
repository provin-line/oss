// Package filestore is the file-backed keystore.KeyStore: the production
// key-at-rest store for the registry process (KMS model). Keys are plaintext at
// rest behind 0600 file perms in a 0700 tree — the keystore.KeyStore contract
// hides whether the backend encrypts, so an encrypted store is a later drop-in.
//
// Each DID owns a directory under the root (path built only from safety-checked
// DID segments); each logical key is one 0600 file holding the raw private key.
// SaveKeyPair publishes the whole DID keyset atomically (temp dir + fsync +
// rename), so a reader observes either a complete keyset or none — never a
// partial one (e.g. an auth key without its signing key).
package filestore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/keystore"
)

// Store is a file-backed keystore.KeyStore rooted at a directory.
type Store struct {
	root string
}

var _ keystore.KeyStore = (*Store)(nil)

// New returns a Store persisting keys under root.
func New(root string) *Store {
	return &Store{root: root}
}

// SaveKeyPair persists every key pair for did atomically: the whole keyset is
// written into a temp directory (each file fsynced), then published with a
// single rename onto the (absent) target. A mid-write failure leaves only an
// orphaned temp dir, never a partial keyset.
//
// It is create-only: an existing keyset is never overwritten (matching the
// sibling didregistry yamlstore, and the actual issuance contract — keys are
// saved once per fresh DID, after the document store has already won the
// uniqueness race). Replacing a directory in place cannot be made atomic with a
// single rename, so rather than destroy a live keyset in a non-atomic window
// (the failure this store exists to prevent), a re-save fails. Rotation, if it
// ever lands, introduces a genuinely-atomic replace with its own contract.
func (s *Store) SaveKeyPair(did string, keys map[keystore.KeyID]*crypto.KeyPair) error {
	dir, err := s.didDir(did)
	if err != nil {
		return err
	}
	for keyID := range keys {
		if err := safeSegment(string(keyID)); err != nil {
			return err
		}
	}
	if _, err := os.Stat(dir); err == nil {
		return fmt.Errorf("filestore: keyset already exists for %s", did)
	}
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("filestore: mkdir: %w", err)
	}
	tmp, err := os.MkdirTemp(parent, ".tmp-keys-*")
	if err != nil {
		return fmt.Errorf("filestore: temp dir: %w", err)
	}
	defer os.RemoveAll(tmp) // a no-op once renamed away.

	for keyID, kp := range keys {
		if kp == nil {
			return fmt.Errorf("filestore: nil key pair for %q", keyID)
		}
		if err := writeFileSync(filepath.Join(tmp, keyFile(keyID)), kp.PrivateKey); err != nil {
			return err
		}
	}
	if err := fsyncDir(tmp); err != nil {
		return err
	}

	// Publish atomically onto the absent target. A lost create race (the target
	// appeared since the Stat above) fails the rename onto a non-empty dir — never
	// a destroyed keyset.
	if err := os.Rename(tmp, dir); err != nil {
		if _, statErr := os.Stat(dir); statErr == nil {
			return fmt.Errorf("filestore: keyset already exists for %s", did)
		}
		return fmt.Errorf("filestore: publish keyset: %w", err)
	}
	return fsyncDir(parent)
}

// GetPrivateKey returns the raw private key for (did, keyID), or a wrapped
// keystore.ErrNotFound when no such key is held.
func (s *Store) GetPrivateKey(did string, keyID keystore.KeyID) ([]byte, error) {
	dir, err := s.didDir(did)
	if err != nil {
		return nil, err
	}
	if err := safeSegment(string(keyID)); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, keyFile(keyID)))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("filestore: %s#%s: %w", did, keyID, keystore.ErrNotFound)
		}
		return nil, fmt.Errorf("filestore: read key: %w", err)
	}
	return data, nil
}

// DeleteKeys removes every key held for did. An absent DID is a no-op.
func (s *Store) DeleteKeys(did string) error {
	dir, err := s.didDir(did)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("filestore: delete keys: %w", err)
	}
	return nil
}

// didDir maps a DID to its key directory under root, building the path only from
// safety-checked segments (the DID's colon-delimited parts). The mapping is
// injective among valid DIDs: a path separator never appears inside a segment.
func (s *Store) didDir(did string) (string, error) {
	if did == "" {
		return "", fmt.Errorf("filestore: empty did")
	}
	parts := strings.Split(did, ":")
	for _, seg := range parts {
		if err := safeSegment(seg); err != nil {
			return "", err
		}
	}
	return filepath.Join(append([]string{s.root}, parts...)...), nil
}

func keyFile(keyID keystore.KeyID) string { return string(keyID) + ".key" }

// safeSegment rejects anything that is not a single, non-traversing path
// component (mirrors the didregistry yamlstore guard).
func safeSegment(s string) error {
	if s == "" || s == "." || s == ".." || s != filepath.Base(s) || strings.ContainsAny(s, `/\`+"\x00") {
		return fmt.Errorf("filestore: invalid path segment %q", s)
	}
	return nil
}

// writeFileSync creates p exclusively with 0600 perms, writes data, and fsyncs
// before close so the bytes are durable before the keyset is published.
func writeFileSync(p string, data []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("filestore: create key file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("filestore: write key file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("filestore: fsync key file: %w", err)
	}
	return f.Close()
}

// fsyncDir flushes a directory entry so a rename/create is durable.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("filestore: open dir for fsync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("filestore: fsync dir: %w", err)
	}
	return nil
}
