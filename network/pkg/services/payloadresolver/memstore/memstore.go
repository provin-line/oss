// Package memstore is the in-memory payloadresolver.Store — the non-durable
// sibling of filestore, for tests and ephemeral deployments. It reproduces the
// filestore's content-addressing and owner-set-append semantics exactly.
package memstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"hash"
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

// Put stores payload at its content address and appends ownerDID to the owner
// set (a repeat owner is a no-op). The bytes are content-addressed, so a repeat
// Put with the same bytes is idempotent.
//
// Put is a thin wrapper over StoreWriter: the whole payload is written to the
// streaming writer in one call and immediately committed, so there is exactly
// ONE code path for hashing and owner-set bookkeeping between the
// whole-buffer and streaming retain APIs.
func (s *Store) Put(payload []byte, ownerDID string) (string, error) {
	w, err := s.StoreWriter(context.Background(), ownerDID)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(payload); err != nil {
		_ = w.Abort()
		return "", err
	}
	return w.Commit()
}

// StoreWriter returns a streaming retain handle: it buffers written bytes
// in memory and hashes them incrementally, so Commit derives the SAME content
// address Put would derive for the same bytes.
//
// ctx gates creation only (checked once, above) — it is not retained, so
// cancellation after this call returns has no effect on the returned writer.
// A caller that must abandon an in-progress write on cancellation is
// responsible for calling Abort itself (see payloadresolver.Store.StoreWriter).
func (s *Store) StoreWriter(ctx context.Context, ownerDID string) (payloadresolver.PayloadWriter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &memWriter{store: s, ownerDID: ownerDID, hasher: sha256.New()}, nil
}

// memWriter is the memstore PayloadWriter: an in-memory buffer plus an
// incremental SHA-256 hasher fed the same bytes as they are buffered.
type memWriter struct {
	store    *Store
	ownerDID string
	buf      bytes.Buffer
	hasher   hash.Hash
	done     bool
}

// Write appends p to the buffer and feeds it to the incremental hasher.
func (w *memWriter) Write(p []byte) (int, error) {
	if w.done {
		return 0, payloadresolver.ErrWriterFinalized
	}
	w.hasher.Write(p)
	return w.buf.Write(p)
}

// Commit derives the content address from the bytes written so far and
// records the buffered payload and ownerDID — the same bookkeeping Put
// performs, applied to an already-accumulated buffer instead of a caller-
// supplied slice.
func (w *memWriter) Commit() (string, error) {
	if w.done {
		return "", payloadresolver.ErrWriterFinalized
	}
	w.done = true
	sum := w.hasher.Sum(nil)
	contentAddr := "sha256:" + hex.EncodeToString(sum)

	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	e, ok := w.store.m[contentAddr]
	if !ok {
		buf := make([]byte, w.buf.Len())
		copy(buf, w.buf.Bytes())
		e = &entry{payload: buf}
		w.store.m[contentAddr] = e
	}
	for _, o := range e.owners {
		if o == w.ownerDID {
			return contentAddr, nil // already an owner
		}
	}
	e.owners = append(e.owners, w.ownerDID)
	return contentAddr, nil
}

// Abort discards the buffer: nothing written to it is persisted.
func (w *memWriter) Abort() error {
	if w.done {
		return payloadresolver.ErrWriterFinalized
	}
	w.done = true
	w.buf.Reset()
	return nil
}

// Owners returns a copy of the owner set at hash without materializing the
// payload bytes (the cheap authorization basis), or ErrNotFound.
func (s *Store) Owners(hash string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.m[hash]
	if !ok {
		return nil, payloadresolver.ErrNotFound
	}
	return append([]string(nil), e.owners...), nil
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
