// Package memstore is the in-memory payloadresolver.Store — the non-durable
// sibling of filestore, for tests and ephemeral deployments. It reproduces the
// filestore's content-addressing and owner-set-append semantics exactly.
package memstore

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"

	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
)

type entry struct {
	payload []byte
	owners  []string
}

// Store is the in-memory payloadresolver.Store.
type Store struct {
	mu sync.RWMutex
	m  map[string]*entry
}

var _ payloadresolver.Store = (*Store)(nil)

// New returns an empty in-memory store.
func New() *Store {
	return &Store{m: make(map[string]*entry)}
}

func hashPayload(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Put stores payload at its content address and appends ownerDID to the owner
// set (a repeat owner is a no-op). The bytes are content-addressed, so a repeat
// Put with the same bytes is idempotent.
func (s *Store) Put(payload []byte, ownerDID string) (string, error) {
	hash := hashPayload(payload)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[hash]
	if !ok {
		// Copy the bytes: the caller may reuse its buffer.
		buf := make([]byte, len(payload))
		copy(buf, payload)
		e = &entry{payload: buf}
		s.m[hash] = e
	}
	for _, o := range e.owners {
		if o == ownerDID {
			return hash, nil
		}
	}
	e.owners = append(e.owners, ownerDID)
	return hash, nil
}

// Get returns a copy of the payload bytes and owner set at hash, or ErrNotFound.
func (s *Store) Get(hash string) ([]byte, []string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.m[hash]
	if !ok {
		return nil, nil, payloadresolver.ErrNotFound
	}
	payload := make([]byte, len(e.payload))
	copy(payload, e.payload)
	owners := append([]string(nil), e.owners...)
	return payload, owners, nil
}
