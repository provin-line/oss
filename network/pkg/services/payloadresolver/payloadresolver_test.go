package payloadresolver_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/filestore"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/memstore"
)

func addr(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// storeFactory builds a fresh, empty Store for the shared contract.
type storeFactory struct {
	name string
	make func(t *testing.T) payloadresolver.Store
}

func factories() []storeFactory {
	return []storeFactory{
		{"memstore", func(t *testing.T) payloadresolver.Store { return memstore.New() }},
		{"filestore", func(t *testing.T) payloadresolver.Store {
			s, err := filestore.NewStore(t.TempDir())
			if err != nil {
				t.Fatalf("NewStore: %v", err)
			}
			return s
		}},
	}
}

// TestService_StoreResolve_RoundTrip pins the core retain→serve behaviour
// across both store backends: the address is recomputed from the bytes, the
// owner is recorded, and Resolve returns the exact bytes and owner set.
func TestService_StoreResolve_RoundTrip(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			svc := payloadresolver.New(f.make(t))
			payload := []byte("the produced data bytes")
			owner := "did:dplaax:reg:org:acme:pipeline:pipe-a"

			hash, err := svc.Store(context.Background(), payload, owner)
			if err != nil {
				t.Fatalf("Store: %v", err)
			}
			if hash != addr(payload) {
				t.Fatalf("Store hash = %q, want recomputed %q", hash, addr(payload))
			}
			got, owners, err := svc.Resolve(context.Background(), hash)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if string(got) != string(payload) {
				t.Errorf("Resolve payload = %q, want %q", got, payload)
			}
			if len(owners) != 1 || owners[0] != owner {
				t.Errorf("Resolve owners = %v, want [%q]", owners, owner)
			}
		})
	}
}

// TestService_MultiOwner pins the owner-set append: two pipelines emitting
// bit-identical bytes converge on one entry whose owner set holds BOTH — the
// second retain must not clobber the first's ownership (Codex High-1). A repeat
// owner is idempotent.
func TestService_MultiOwner(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			svc := payloadresolver.New(f.make(t))
			payload := []byte("identical output of two pipelines")
			a := "did:dplaax:reg:org:acme:pipeline:pipe-a"
			b := "did:dplaax:reg:org:beta:pipeline:pipe-b"

			h1, err := svc.Store(context.Background(), payload, a)
			if err != nil {
				t.Fatalf("Store a: %v", err)
			}
			h2, err := svc.Store(context.Background(), payload, b)
			if err != nil {
				t.Fatalf("Store b: %v", err)
			}
			if h1 != h2 {
				t.Fatalf("same bytes stored at different addresses %q vs %q", h1, h2)
			}
			// Repeat owner a — idempotent, no duplicate.
			if _, err := svc.Store(context.Background(), payload, a); err != nil {
				t.Fatalf("Store a again: %v", err)
			}
			_, owners, err := svc.Resolve(context.Background(), h1)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
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

// TestService_Resolve_NotFound pins a well-formed miss.
func TestService_Resolve_NotFound(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			svc := payloadresolver.New(f.make(t))
			_, _, err := svc.Resolve(context.Background(), addr([]byte("never stored")))
			if !errors.Is(err, payloadresolver.ErrNotFound) {
				t.Errorf("Resolve miss err = %v, want ErrNotFound", err)
			}
		})
	}
}

// TestService_Resolve_InvalidHash pins a malformed address.
func TestService_Resolve_InvalidHash(t *testing.T) {
	svc := payloadresolver.New(memstore.New())
	for _, bad := range []string{"", "not-a-hash", "sha256:xyz", "md5:abc"} {
		_, _, err := svc.Resolve(context.Background(), bad)
		if !errors.Is(err, payloadresolver.ErrInvalidArgument) {
			t.Errorf("Resolve(%q) err = %v, want ErrInvalidArgument", bad, err)
		}
	}
}

// TestService_Store_FailClosedInputs pins the retain guards: no owner and empty
// bytes are both rejected (a serve-deny orphan / an unbindable payload).
func TestService_Store_FailClosedInputs(t *testing.T) {
	svc := payloadresolver.New(memstore.New())
	if _, err := svc.Store(context.Background(), []byte("data"), ""); !errors.Is(err, payloadresolver.ErrInvalidArgument) {
		t.Errorf("Store with empty owner err = %v, want ErrInvalidArgument", err)
	}
	if _, err := svc.Store(context.Background(), nil, "did:dplaax:reg:org:a:pipeline:p"); !errors.Is(err, payloadresolver.ErrInvalidArgument) {
		t.Errorf("Store with empty payload err = %v, want ErrInvalidArgument", err)
	}
}

// TestFilestore_DamagedEntry pins the tamper doctrine: bytes that no longer
// hash to the key are a damaged entry (an error), never a silent miss.
func TestFilestore_DamagedEntry(t *testing.T) {
	dir := t.TempDir()
	store, err := filestore.NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	payload := []byte("evidence bytes")
	hash, err := store.Put(payload, "did:dplaax:reg:org:a:pipeline:p")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Corrupt the bin file in place.
	binPath := filepath.Join(dir, hex.EncodeToString(sha256sum(payload))+".bin")
	if err := os.WriteFile(binPath, []byte("tampered"), 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	if _, _, err := store.Get(hash); err == nil || errors.Is(err, payloadresolver.ErrNotFound) {
		t.Errorf("Get on tampered entry err = %v, want a damage error (not nil, not ErrNotFound)", err)
	}
}

func sha256sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
