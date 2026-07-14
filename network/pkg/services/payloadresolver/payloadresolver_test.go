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

// --- F9: authorize-before-read + owner-metadata-only lookup ---

// TestStore_Owners_Contract pins the cheap owner-metadata lookup across both
// backends: Owners returns the recorded set for a present entry and ErrNotFound
// for a miss, WITHOUT the caller having to read the payload bytes.
func TestStore_Owners_Contract(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			store := f.make(t)
			payload := []byte("the produced bytes")
			owner := "did:dplaax:reg:org:acme:pipeline:pipe-a"
			hash, err := store.Put(payload, owner)
			if err != nil {
				t.Fatalf("Put: %v", err)
			}
			owners, err := store.Owners(hash)
			if err != nil {
				t.Fatalf("Owners: %v", err)
			}
			if len(owners) != 1 || owners[0] != owner {
				t.Errorf("Owners = %v, want [%s]", owners, owner)
			}
			if _, err := store.Owners(addr([]byte("never stored"))); !errors.Is(err, payloadresolver.ErrNotFound) {
				t.Errorf("Owners(absent) err = %v, want ErrNotFound", err)
			}
		})
	}
}

// TestStore_Owners_CrashResidual_FailsClosed pins the fail-closed security
// property for the bin-present/owners-absent crash residual (a crash between the
// bin write and the .owners write): Owners must return an EMPTY owner set — NOT
// ErrNotFound (the bytes DO exist) — so the serving boundary admits no one and
// still returns ErrNotFound, leaking neither the bytes nor their existence.
func TestStore_Owners_CrashResidual_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	store, err := filestore.NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	payload := []byte("bytes present but owner sidecar lost to a crash")
	owner := "did:dplaax:reg:org:acme:pipeline:pipe-a"
	hash, err := store.Put(payload, owner)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Simulate the crash: remove the .owners sidecar, leaving the bin present.
	hexPart := hash[len("sha256:"):]
	if err := os.Remove(filepath.Join(dir, hexPart+".owners")); err != nil {
		t.Fatalf("remove owners sidecar: %v", err)
	}
	// Owners: present entry, empty owner set (NOT ErrNotFound).
	owners, err := store.Owners(hash)
	if err != nil {
		t.Fatalf("Owners(residual): %v", err)
	}
	if len(owners) != 0 {
		t.Errorf("Owners(residual) = %v, want empty set (fail-closed)", owners)
	}
	// Serve denies even an admit-everyone allow-list: an empty owner set has no
	// owner to admit against, so no caller is served → ErrNotFound.
	sb := payloadresolver.NewServingBoundary(payloadresolver.New(store), allowFunc(func(string, string) error { return nil }))
	if _, err := sb.Serve(context.Background(), hash, "did:dplaax:reg:org:sub"); err != payloadresolver.ErrNotFound {
		t.Errorf("Serve(residual) = %v, want ErrNotFound (fail-closed, no leak)", err)
	}
}

// spyStore records which read path Serve takes, proving it authorizes on owner
// metadata BEFORE reading (and hashing) the payload bytes (F9).
type spyStore struct {
	owners      []string
	payload     []byte
	ownersErr   error
	ownersCalls int
	getCalls    int
}

func (s *spyStore) Put(payload []byte, owner string) (string, error) { return addr(payload), nil }
func (s *spyStore) Owners(hash string) ([]string, error) {
	s.ownersCalls++
	if s.ownersErr != nil {
		return nil, s.ownersErr
	}
	return append([]string(nil), s.owners...), nil
}
func (s *spyStore) Get(hash string) ([]byte, []string, error) {
	s.getCalls++
	return s.payload, append([]string(nil), s.owners...), nil
}

type allowFunc func(pipelineDID, callerDID string) error

func (f allowFunc) Admit(pipelineDID, callerDID string) error { return f(pipelineDID, callerDID) }

// TestServingBoundary_Serve_AuthorizeBeforeRead is the F9 core: a valid-signer-
// but-not-admitted caller and an absent hash both get ErrNotFound (oracle
// collapse), and in neither denial case are the payload bytes read.
func TestServingBoundary_Serve_AuthorizeBeforeRead(t *testing.T) {
	want := []byte("the confidential payload bytes")
	hash := addr(want)
	caller := "did:dplaax:reg:org:sub"
	owner := "did:dplaax:reg:org:acme:pipeline:pipe-a"

	t.Run("not admitted → NotFound, bytes never read", func(t *testing.T) {
		store := &spyStore{owners: []string{owner}, payload: want}
		deny := allowFunc(func(string, string) error { return errors.New("not admitted") })
		sb := payloadresolver.NewServingBoundary(payloadresolver.New(store), deny)
		_, err := sb.Serve(context.Background(), hash, caller)
		// Byte-identical to the absent case below (== the bare sentinel): the
		// serving boundary must not wrap the cause, or the differing message
		// would itself be an existence oracle (Codex-3).
		if err != payloadresolver.ErrNotFound {
			t.Fatalf("Serve(not admitted) err = %v, want the bare payloadresolver.ErrNotFound (collapsed, unwrapped)", err)
		}
		if store.getCalls != 0 {
			t.Errorf("Get called %d times — payload bytes must NOT be read for a non-admitted caller", store.getCalls)
		}
		if store.ownersCalls == 0 {
			t.Error("Owners was never consulted")
		}
	})

	t.Run("absent → NotFound, bytes never read", func(t *testing.T) {
		store := &spyStore{ownersErr: payloadresolver.ErrNotFound}
		allow := allowFunc(func(string, string) error { return nil })
		sb := payloadresolver.NewServingBoundary(payloadresolver.New(store), allow)
		_, err := sb.Serve(context.Background(), hash, caller)
		if err != payloadresolver.ErrNotFound {
			t.Fatalf("Serve(absent) err = %v, want the bare payloadresolver.ErrNotFound (identical to not-admitted)", err)
		}
		if store.getCalls != 0 {
			t.Errorf("Get called %d times for an absent hash", store.getCalls)
		}
	})

	t.Run("admitted → bytes served", func(t *testing.T) {
		store := &spyStore{owners: []string{owner}, payload: want}
		allow := allowFunc(func(pipelineDID, _ string) error {
			if pipelineDID == owner {
				return nil
			}
			return errors.New("no")
		})
		sb := payloadresolver.NewServingBoundary(payloadresolver.New(store), allow)
		got, err := sb.Serve(context.Background(), hash, caller)
		if err != nil {
			t.Fatalf("Serve(admitted): %v", err)
		}
		if string(got) != string(want) {
			t.Errorf("Serve = %q, want %q", got, want)
		}
	})
}
