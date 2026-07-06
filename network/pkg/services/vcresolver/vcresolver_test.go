package vcresolver_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/vc"
)

const issuer = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1"

func newSvc() *vcresolver.Service {
	return vcresolver.New(memstore.NewStore(), memstore.NewPool())
}

// vcBytes builds a minimal VC. prev sets credentialSubject.previousCredential
// (any type — pass a string for a valid link, a non-string to exercise the
// malformed path); nil omits it.
func vcBytes(t *testing.T, issuerDID string, prev any) []byte {
	t.Helper()
	subject := map[string]any{"pipelineId": "p1", "processId": "proc1"}
	if prev != nil {
		subject["previousCredential"] = prev
	}
	b, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            issuerDID,
		"credentialSubject": subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStoreVC_StoreAndResolve(t *testing.T) {
	svc := newSvc()
	hash, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, nil), "", 0)
	if err != nil {
		t.Fatalf("StoreVC: %v", err)
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Errorf("hash = %q, want sha256: prefix", hash)
	}
	got, err := svc.ResolveVC(context.Background(), hash)
	if err != nil {
		t.Fatalf("ResolveVC: %v", err)
	}
	if got.Issuer() != issuer {
		t.Errorf("issuer = %q, want %q", got.Issuer(), issuer)
	}
}

func TestStoreVC_EnqueuesUnheldPredecessor(t *testing.T) {
	store := memstore.NewStore()
	pool := memstore.NewPool()
	svc := vcresolver.New(store, pool)
	prev := "sha256:" + strings.Repeat("a", 64)

	if _, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, prev), "https://up.example/vc", 0); err != nil {
		t.Fatalf("StoreVC: %v", err)
	}
	if pool.Len() != 1 {
		t.Fatalf("pool len = %d, want 1", pool.Len())
	}
	list, _ := pool.ListNewest(1)
	if list[0].Hash != prev || list[0].UpstreamEndpoint != "https://up.example/vc" || list[0].ReferrerIssuer != issuer {
		t.Errorf("entry = %+v", list[0])
	}
}

func TestStoreVC_HeldPredecessor_NoEnqueue(t *testing.T) {
	store := memstore.NewStore()
	pool := memstore.NewPool()
	svc := vcresolver.New(store, pool)

	// Store the predecessor first, then a successor referencing it.
	prevHash, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, nil), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, prevHash), "", 0); err != nil {
		t.Fatalf("StoreVC successor: %v", err)
	}
	if pool.Len() != 0 {
		t.Errorf("pool len = %d, want 0 (predecessor held)", pool.Len())
	}
}

func TestStoreVC_RejectsMalformedPrev(t *testing.T) {
	svc := newSvc()
	cases := map[string]any{
		"non-string previousCredential":  123,
		"bad-grammar previousCredential": "not-a-hash",
		"short hex":                      "sha256:abc",
	}
	for name, prev := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, prev), "", 0)
			if !errors.Is(err, vcresolver.ErrInvalidArgument) {
				t.Errorf("%s: want ErrInvalidArgument, got %v", name, err)
			}
		})
	}
}

// A JSON null previousCredential is a conformant chain origin — equivalent to
// omission (spec credential.subject.previous-credential) — so the store must
// accept it and queue nothing.
func TestStoreVC_NullPreviousCredential_AcceptedAsOrigin(t *testing.T) {
	svc := newSvc()
	subject := map[string]any{"pipelineId": "p1", "processId": "proc1", "previousCredential": nil}
	b, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            issuer,
		"credentialSubject": subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StoreVC(context.Background(), b, "", 0); err != nil {
		t.Fatalf("StoreVC rejected a null-previousCredential origin: %v", err)
	}
}

func TestStoreVC_Idempotent(t *testing.T) {
	store := memstore.NewStore()
	svc := vcresolver.New(store, memstore.NewPool())
	b := vcBytes(t, issuer, nil)
	h1, _ := svc.StoreVC(context.Background(), b, "", 0)
	h2, err := svc.StoreVC(context.Background(), b, "", 0)
	if err != nil || h1 != h2 {
		t.Fatalf("idempotent: h1=%q h2=%q err=%v", h1, h2, err)
	}
}

func TestResolveVC_Errors(t *testing.T) {
	svc := newSvc()
	if _, err := svc.ResolveVC(context.Background(), "not-a-hash"); !errors.Is(err, vcresolver.ErrInvalidArgument) {
		t.Errorf("bad hash: want ErrInvalidArgument, got %v", err)
	}
	wellFormedAbsent := "sha256:" + strings.Repeat("b", 64)
	if _, err := svc.ResolveVC(context.Background(), wellFormedAbsent); !errors.Is(err, vcresolver.ErrNotFound) {
		t.Errorf("absent: want ErrNotFound, got %v", err)
	}
}

// Out-of-order submission: a successor queues its predecessor as a hole; when
// the predecessor later arrives, storing it removes the now-resolved hole.
func TestStoreVC_OutOfOrder_RemovesResolvedHole(t *testing.T) {
	store := memstore.NewStore()
	pool := memstore.NewPool()
	svc := vcresolver.New(store, pool)

	// Learn the predecessor's content address without storing it.
	pBytes := vcBytes(t, issuer, nil)
	var p vc.PipelinePassCredential
	if err := json.Unmarshal(pBytes, &p); err != nil {
		t.Fatal(err)
	}
	pHash, err := p.Hash()
	if err != nil {
		t.Fatal(err)
	}

	// Successor arrives first → P is queued.
	if _, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, pHash), "", 0); err != nil {
		t.Fatal(err)
	}
	if pool.Len() != 1 {
		t.Fatalf("after successor: pool len = %d, want 1", pool.Len())
	}
	// P arrives later → its hole is removed.
	if _, err := svc.StoreVC(context.Background(), pBytes, "", 0); err != nil {
		t.Fatal(err)
	}
	if pool.Len() != 0 {
		t.Fatalf("after predecessor: pool len = %d, want 0", pool.Len())
	}
}

// hashOf returns the content address of a VC body without storing it.
func hashOf(t *testing.T, b []byte) string {
	t.Helper()
	var c vc.PipelinePassCredential
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	h, err := c.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// entryFor returns the pool entry for hash, or fails.
func entryFor(t *testing.T, pool *memstore.Pool, hash string) vcresolver.UnresolvedEntry {
	t.Helper()
	list, _ := pool.ListNewest(1 << 30)
	for _, e := range list {
		if e.Hash == hash {
			return e
		}
	}
	t.Fatalf("no pool entry for %s (pool: %+v)", hash, list)
	return vcresolver.UnresolvedEntry{}
}

// StoreVC enqueues a missing predecessor at assemblyDepth+1: a directly-received
// credential (depth 0) queues its predecessor at depth 1; the batch resolver
// re-submitting a depth-d fill queues the next at d+1.
func TestStoreVC_EnqueuesPredecessorAtDepthPlusOne(t *testing.T) {
	for _, tc := range []struct {
		name        string
		depth, want int
	}{
		{"head", 0, 1},
		{"depth-5 fill", 5, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := memstore.NewPool()
			svc := vcresolver.New(memstore.NewStore(), pool)
			prev := "sha256:" + strings.Repeat("a", 64)
			if _, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, prev), "", tc.depth); err != nil {
				t.Fatal(err)
			}
			if got := entryFor(t, pool, prev).AssemblyDepth; got != tc.want {
				t.Errorf("AssemblyDepth = %d, want %d", got, tc.want)
			}
		})
	}
}

// CA#3: a credential that is BOTH already queued as a deep predecessor AND then
// directly received (depth 0) must enqueue its own predecessor at depth 1 — the
// head depth — not the stale deep-hole depth+1.
func TestStoreVC_HeadAlsoQueuedHole_UsesHeadDepth(t *testing.T) {
	pool := memstore.NewPool()
	svc := vcresolver.New(memstore.NewStore(), pool)

	pAddr := "sha256:" + strings.Repeat("e", 64) // P: H's predecessor, never stored
	hBytes := vcBytes(t, issuer, pAddr)
	hAddr := hashOf(t, hBytes)

	// A deep successor (depth 5) references H → H queued at depth 6.
	if _, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, hAddr), "", 5); err != nil {
		t.Fatal(err)
	}
	if got := entryFor(t, pool, hAddr).AssemblyDepth; got != 6 {
		t.Fatalf("precondition: H queued at depth %d, want 6", got)
	}

	// H itself is directly received (depth 0) → H's hole removed, P queued at depth 1.
	if _, err := svc.StoreVC(context.Background(), hBytes, "", 0); err != nil {
		t.Fatal(err)
	}
	if got := entryFor(t, pool, pAddr).AssemblyDepth; got != 1 {
		t.Errorf("P AssemblyDepth = %d, want 1 (head depth, not stale 7)", got)
	}
}

// A negative assemblyDepth is a programming error — StoreVC rejects it rather than
// enqueueing a hole at depth <= 0.
func TestStoreVC_NegativeDepth_Rejected(t *testing.T) {
	svc := newSvc()
	prev := "sha256:" + strings.Repeat("a", 64)
	_, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, prev), "", -1)
	if !errors.Is(err, vcresolver.ErrInvalidArgument) {
		t.Errorf("negative depth: want ErrInvalidArgument, got %v", err)
	}
}

// getErrStore returns a non-ErrNotFound error from Get to exercise the
// store-failure path; Put delegates to a real store.
type getErrStore struct {
	inner *memstore.Store
	err   error
}

func (s getErrStore) Put(hash string, c *vc.PipelinePassCredential) error {
	return s.inner.Put(hash, c)
}
func (s getErrStore) Get(string) (*vc.PipelinePassCredential, error) { return nil, s.err }
func (s getErrStore) ListHashes(string, int) ([]string, error)       { return nil, s.err }

// A predecessor lookup that fails for a real reason (not a miss) must propagate,
// not be swallowed into a silent success that drops the chain hole.
func TestStoreVC_PropagatesStoreError(t *testing.T) {
	sentinel := errors.New("boom")
	svc := vcresolver.New(getErrStore{inner: memstore.NewStore(), err: sentinel}, memstore.NewPool())
	prev := "sha256:" + strings.Repeat("a", 64)
	_, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, prev), "", 0)
	if !errors.Is(err, sentinel) {
		t.Fatalf("want propagated store error, got %v", err)
	}
}

func TestStoreVC_UpsertRepairsHint(t *testing.T) {
	store := memstore.NewStore()
	pool := memstore.NewPool()
	svc := vcresolver.New(store, pool)
	prev := "sha256:" + strings.Repeat("c", 64)

	// First referrer supplies no upstream hint.
	if _, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, prev), "", 0); err != nil {
		t.Fatal(err)
	}
	// A second, distinct referrer of the same hole supplies the hint.
	other := issuer + "x"
	if _, err := svc.StoreVC(context.Background(), vcBytes(t, other, prev), "https://up.example/vc", 0); err != nil {
		t.Fatal(err)
	}
	if pool.Len() != 1 {
		t.Fatalf("pool len = %d, want 1 (deduped)", pool.Len())
	}
	list, _ := pool.ListNewest(1)
	if list[0].UpstreamEndpoint != "https://up.example/vc" {
		t.Errorf("hint not repaired: %+v", list[0])
	}
}

// opRecordingPool wraps the mem pool, recording Add/Remove order.
type opRecordingPool struct {
	*memstore.Pool
	ops []string
}

func (p *opRecordingPool) Add(e vcresolver.UnresolvedEntry) error {
	p.ops = append(p.ops, "add:"+e.Hash)
	return p.Pool.Add(e)
}

func (p *opRecordingPool) Remove(hash string) error {
	p.ops = append(p.ops, "remove:"+hash)
	return p.Pool.Remove(hash)
}

// TestStoreVC_AddsNextHoleBeforeRemovingResolved pins the crash-safe ordering
// for durable stores: the successor's hole is queued BEFORE the resolved hole
// is removed, so a crash between the two leaves a re-fetchable hole (replay
// converges via idempotent Put/Add) instead of a permanently stalled chain.
func TestStoreVC_AddsNextHoleBeforeRemovingResolved(t *testing.T) {
	ctx := context.Background()
	pool := &opRecordingPool{Pool: memstore.NewPool()}
	svc := vcresolver.New(memstore.NewStore(), pool)

	// A middle credential referencing a missing predecessor: storing it must
	// add the predecessor hole first, then remove its own (possibly queued) hash.
	missingPrev := "sha256:" + strings.Repeat("ab", 32)
	mid := vcBytes(t, issuer, missingPrev)
	midHash, err := svc.StoreVC(ctx, mid, "", 0)
	if err != nil {
		t.Fatalf("StoreVC: %v", err)
	}
	if len(pool.ops) != 2 || pool.ops[0] != "add:"+missingPrev || pool.ops[1] != "remove:"+midHash {
		t.Fatalf("pool op order = %v, want [add:%s remove:%s]", pool.ops, missingPrev, midHash)
	}
}
