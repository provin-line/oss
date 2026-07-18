package payloadresolver_test

import (
	"context"
	"errors"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
)

// TestStoreWriter_CommitMatchesLegacyAddress pins that the streaming writer and
// the legacy byte-slice Put derive the SAME content address for identical
// bytes, across both store backends — a client-streaming retain (Task 8) must
// be indistinguishable, address-wise, from a whole-buffer retain.
func TestStoreWriter_CommitMatchesLegacyAddress(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			store := f.make(t)
			payload := []byte("the produced data bytes, streamed incrementally")
			owner := "did:dplaax:reg:org:acme:pipeline:pipe-a"

			legacyHash, err := store.Put(payload, owner)
			if err != nil {
				t.Fatalf("Put: %v", err)
			}

			w, err := store.StoreWriter(context.Background(), owner)
			if err != nil {
				t.Fatalf("StoreWriter: %v", err)
			}
			// Write in multiple chunks to exercise incremental hashing.
			if _, err := w.Write(payload[:10]); err != nil {
				t.Fatalf("Write chunk1: %v", err)
			}
			if _, err := w.Write(payload[10:]); err != nil {
				t.Fatalf("Write chunk2: %v", err)
			}
			streamHash, err := w.Commit()
			if err != nil {
				t.Fatalf("Commit: %v", err)
			}
			if streamHash != legacyHash {
				t.Errorf("Commit hash = %q, want legacy Put hash %q", streamHash, legacyHash)
			}
			if streamHash != addr(payload) {
				t.Errorf("Commit hash = %q, want recomputed %q", streamHash, addr(payload))
			}
		})
	}
}

// TestStoreWriter_CommitReadableViaGet pins that a committed streaming write is
// readable through the existing Get path, with the owner recorded exactly as
// legacy Put would record it.
func TestStoreWriter_CommitReadableViaGet(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			store := f.make(t)
			payload := []byte("bytes retained via the streaming writer")
			owner := "did:dplaax:reg:org:acme:pipeline:pipe-a"

			w, err := store.StoreWriter(context.Background(), owner)
			if err != nil {
				t.Fatalf("StoreWriter: %v", err)
			}
			if _, err := w.Write(payload); err != nil {
				t.Fatalf("Write: %v", err)
			}
			hash, err := w.Commit()
			if err != nil {
				t.Fatalf("Commit: %v", err)
			}

			got, owners, err := store.Get(hash)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if string(got) != string(payload) {
				t.Errorf("Get payload = %q, want %q", got, payload)
			}
			if len(owners) != 1 || owners[0] != owner {
				t.Errorf("Get owners = %v, want [%q]", owners, owner)
			}
		})
	}
}

// TestStoreWriter_MultiOwnerAppend pins the owner-set append semantics
// (mirroring TestService_MultiOwner) for the streaming path: two writers
// committing bit-identical bytes converge on one entry whose owner set holds
// BOTH, and a repeat owner is idempotent.
func TestStoreWriter_MultiOwnerAppend(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			store := f.make(t)
			payload := []byte("identical streamed output of two pipelines")
			a := "did:dplaax:reg:org:acme:pipeline:pipe-a"
			b := "did:dplaax:reg:org:beta:pipeline:pipe-b"

			commit := func(owner string) string {
				w, err := store.StoreWriter(context.Background(), owner)
				if err != nil {
					t.Fatalf("StoreWriter(%s): %v", owner, err)
				}
				if _, err := w.Write(payload); err != nil {
					t.Fatalf("Write(%s): %v", owner, err)
				}
				hash, err := w.Commit()
				if err != nil {
					t.Fatalf("Commit(%s): %v", owner, err)
				}
				return hash
			}

			h1 := commit(a)
			h2 := commit(b)
			if h1 != h2 {
				t.Fatalf("same bytes committed at different addresses %q vs %q", h1, h2)
			}
			h3 := commit(a) // repeat owner — idempotent, no duplicate
			if h3 != h1 {
				t.Fatalf("repeat owner commit address changed: %q vs %q", h3, h1)
			}

			_, owners, err := store.Get(h1)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if len(owners) != 2 {
				t.Fatalf("owners = %v, want exactly 2 (a,b, no dup)", owners)
			}
			seen := map[string]bool{}
			for _, o := range owners {
				seen[o] = true
			}
			if !seen[a] || !seen[b] {
				t.Errorf("owners = %v, want both %q and %q", owners, a, b)
			}
		})
	}
}

// TestStoreWriter_Abort pins that an aborted writer persists nothing: the
// content address it would have produced is not retrievable afterward.
func TestStoreWriter_Abort(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			store := f.make(t)
			payload := []byte("bytes that must never be committed")
			owner := "did:dplaax:reg:org:acme:pipeline:pipe-a"

			w, err := store.StoreWriter(context.Background(), owner)
			if err != nil {
				t.Fatalf("StoreWriter: %v", err)
			}
			if _, err := w.Write(payload); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if err := w.Abort(); err != nil {
				t.Fatalf("Abort: %v", err)
			}

			if _, _, err := store.Get(addr(payload)); !errors.Is(err, payloadresolver.ErrNotFound) {
				t.Errorf("Get(aborted) err = %v, want ErrNotFound", err)
			}
			if _, err := store.Owners(addr(payload)); !errors.Is(err, payloadresolver.ErrNotFound) {
				t.Errorf("Owners(aborted) err = %v, want ErrNotFound", err)
			}
		})
	}
}

// TestStoreWriter_DoubleCommit pins that a second Commit call is an error —
// a PayloadWriter is single-use past its first finalization.
func TestStoreWriter_DoubleCommit(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			store := f.make(t)
			w, err := store.StoreWriter(context.Background(), "did:dplaax:reg:org:acme:pipeline:pipe-a")
			if err != nil {
				t.Fatalf("StoreWriter: %v", err)
			}
			if _, err := w.Write([]byte("payload")); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if _, err := w.Commit(); err != nil {
				t.Fatalf("first Commit: %v", err)
			}
			if _, err := w.Commit(); !errors.Is(err, payloadresolver.ErrWriterFinalized) {
				t.Errorf("second Commit err = %v, want ErrWriterFinalized", err)
			}
		})
	}
}

// TestStoreWriter_WriteAfterCommit pins that writing after Commit is an error.
func TestStoreWriter_WriteAfterCommit(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			store := f.make(t)
			w, err := store.StoreWriter(context.Background(), "did:dplaax:reg:org:acme:pipeline:pipe-a")
			if err != nil {
				t.Fatalf("StoreWriter: %v", err)
			}
			if _, err := w.Write([]byte("payload")); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if _, err := w.Commit(); err != nil {
				t.Fatalf("Commit: %v", err)
			}
			if _, err := w.Write([]byte("more")); !errors.Is(err, payloadresolver.ErrWriterFinalized) {
				t.Errorf("Write-after-Commit err = %v, want ErrWriterFinalized", err)
			}
		})
	}
}

// TestStoreWriter_WriteAfterAbort pins that writing after Abort is an error,
// and a second Abort is also an error (single-use past first finalization).
func TestStoreWriter_WriteAfterAbort(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			store := f.make(t)
			w, err := store.StoreWriter(context.Background(), "did:dplaax:reg:org:acme:pipeline:pipe-a")
			if err != nil {
				t.Fatalf("StoreWriter: %v", err)
			}
			if _, err := w.Write([]byte("payload")); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if err := w.Abort(); err != nil {
				t.Fatalf("Abort: %v", err)
			}
			if _, err := w.Write([]byte("more")); !errors.Is(err, payloadresolver.ErrWriterFinalized) {
				t.Errorf("Write-after-Abort err = %v, want ErrWriterFinalized", err)
			}
			if err := w.Abort(); !errors.Is(err, payloadresolver.ErrWriterFinalized) {
				t.Errorf("second Abort err = %v, want ErrWriterFinalized", err)
			}
		})
	}
}
