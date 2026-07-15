package vcresolver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/vc"
)

const issuer = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1"

func newSvc() *vcresolver.Service {
	return vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), memstore.NewPool())
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
	res, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, nil), "", 0)
	if err != nil {
		t.Fatalf("StoreVC: %v", err)
	}
	if !strings.HasPrefix(res.BodyAddress, "sha256:") {
		t.Errorf("body address = %q, want sha256: prefix", res.BodyAddress)
	}
	if !vc.IsWireVariantID(res.WireVariantID) {
		t.Errorf("wire variant id = %q, want a well-formed variant id", res.WireVariantID)
	}
	got, err := svc.ResolveVC(context.Background(), res.BodyAddress)
	if err != nil {
		t.Fatalf("ResolveVC: %v", err)
	}
	if got.Issuer() != issuer {
		t.Errorf("issuer = %q, want %q", got.Issuer(), issuer)
	}
}

func TestStoreVC_EnqueuesUnheldPredecessor(t *testing.T) {
	store := vcresolver.NewVariantStore(memstore.NewBackend())
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
	store := vcresolver.NewVariantStore(memstore.NewBackend())
	pool := memstore.NewPool()
	svc := vcresolver.New(store, pool)

	// Store the predecessor first, then a successor referencing it.
	prev, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, nil), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, prev.BodyAddress), "", 0); err != nil {
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
	store := vcresolver.NewVariantStore(memstore.NewBackend())
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
	store := vcresolver.NewVariantStore(memstore.NewBackend())
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
			svc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), pool)
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
	svc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), pool)

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

// readErrBackend fails every read with a real error (not a miss), exercising
// the store-failure path. Writes go to a real backend, so the failure is
// isolated to reads.
type readErrBackend struct {
	vcresolver.VariantBackend
	err error
}

func (b readErrBackend) ReadVariant(string, string) ([]byte, error) { return nil, b.err }
func (b readErrBackend) ReadProjection(string) ([]byte, error)      { return nil, b.err }

// A predecessor lookup that fails for a real reason (not a miss) must propagate,
// not be swallowed into a silent success that drops the chain hole.
func TestStoreVC_PropagatesStoreError(t *testing.T) {
	sentinel := errors.New("boom")
	failing := vcresolver.NewVariantStore(readErrBackend{VariantBackend: memstore.NewBackend(), err: sentinel})
	svc := vcresolver.New(failing, memstore.NewPool())
	prev := "sha256:" + strings.Repeat("a", 64)
	_, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, prev), "", 0)
	if !errors.Is(err, sentinel) {
		t.Fatalf("want propagated store error, got %v", err)
	}
}

func TestStoreVC_UpsertRepairsHint(t *testing.T) {
	store := vcresolver.NewVariantStore(memstore.NewBackend())
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
	svc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), pool)

	// A middle credential referencing a missing predecessor: storing it must
	// add the predecessor hole first, then remove its own (possibly queued) hash.
	missingPrev := "sha256:" + strings.Repeat("ab", 32)
	mid := vcBytes(t, issuer, missingPrev)
	midRes, err := svc.StoreVC(ctx, mid, "", 0)
	if err != nil {
		t.Fatalf("StoreVC: %v", err)
	}
	if len(pool.ops) != 2 || pool.ops[0] != "add:"+missingPrev || pool.ops[1] != "remove:"+midRes.BodyAddress {
		t.Fatalf("pool op order = %v, want [add:%s remove:%s]", pool.ops, missingPrev, midRes.BodyAddress)
	}
}

// TestNoWriterTakesACallerSuppliedKey is FCoT counter-argument #2, made
// mechanical.
//
// Replacing an interface does not remove a method from a concrete type: the old
// Put(hash, cred) could have stayed exported on memstore and filestore, still
// compiling, still overwriting — the very semantics this slice exists to end,
// reachable by anyone who happened to hold the concrete type. Deleting it is
// what actually removed it; this asserts it stays deleted, because reintroducing
// a keyed writer would silently reopen the hole rather than fail a build.
//
// reflect is the point: a compile-time reference would only prove the method is
// gone from the ONE type named, and would itself stop compiling — which is not
// an assertion, it is a deletion.
func TestNoWriterTakesACallerSuppliedKey(t *testing.T) {
	types := []struct {
		name string
		v    any
	}{
		{"vcresolver.VariantStore", vcresolver.NewVariantStore(memstore.NewBackend())},
		{"memstore.Backend", memstore.NewBackend()},
	}
	for _, tc := range types {
		t.Run(tc.name, func(t *testing.T) {
			rt := reflect.TypeOf(tc.v)
			for i := 0; i < rt.NumMethod(); i++ {
				m := rt.Method(i)
				if m.Name == "Put" {
					t.Errorf("%s exposes Put again: a caller-supplied key means misfiling is expressible, and overwriting is back", tc.name)
				}
			}
		})
	}
}

// TestStoreVCGatesUnsafeIntegersInTheProofToo is Codex spec-review #6.
//
// The gate used to run on cred.Body(), which is the wrong scope by exactly one
// member: the variant id digests the FULL wire document, so an unsafe integer in
// a proof member would be silently rounded by the RFC 8785 re-serialization and
// then admitted under an id naming bytes the submitter never sent — with the
// signature over the original literal.
func TestStoreVCGatesUnsafeIntegersInTheProofToo(t *testing.T) {
	unsafeInt := "9007199254740993" // 2^53+1: the first integer float64 cannot hold
	tests := []struct {
		name string
		wire string
	}{
		{
			name: "in the body",
			wire: `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],` +
				`"issuer":"` + issuer + `","credentialSubject":{"pipelineId":"p1","processId":"p","seq":` + unsafeInt + `}}`,
		},
		{
			name: "in a proof member",
			wire: `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],` +
				`"issuer":"` + issuer + `","credentialSubject":{"pipelineId":"p1","processId":"p"},` +
				`"proof":{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022",` +
				`"verificationMethod":"did:dplaax:poc.dplaax.dev:org:acme#signing","proofPurpose":"assertionMethod",` +
				`"created":"2026-07-01T00:00:01Z","proofValue":"zA","nonce":` + unsafeInt + `}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := newSvc()
			_, err := svc.StoreVC(context.Background(), []byte(tc.wire), "", 0)
			if !errors.Is(err, vcresolver.ErrInvalidArgument) {
				t.Fatalf("StoreVC = %v, want ErrInvalidArgument (an unsafe integer must not be admitted)", err)
			}
			if !strings.Contains(err.Error(), unsafeInt) {
				t.Errorf("the rejection does not name the offending literal: %v", err)
			}
		})
	}
}

// TestStoreVCAdmitsSafeIntegers: the gate is bounded by what the canonical
// re-serialization can round, not by "numbers are scary". A safe integer
// survives the round trip exactly, so it is admitted.
func TestStoreVCAdmitsSafeIntegers(t *testing.T) {
	svc := newSvc()
	wire := `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],` +
		`"issuer":"` + issuer + `","credentialSubject":{"pipelineId":"p1","processId":"p","seq":9007199254740991}}`
	res, err := svc.StoreVC(context.Background(), []byte(wire), "", 0)
	if err != nil {
		t.Fatalf("StoreVC rejected a safe integer (2^53-1): %v", err)
	}
	got, err := svc.ResolveVariant(context.Background(), res.BodyAddress, res.WireVariantID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "9007199254740991") {
		t.Errorf("the stored bytes lost the literal: %s", got)
	}
}

// TestResolveVariantServesExactlyWhatWasAdmitted is what evidence needs and
// ResolveVC cannot give: the bytes that were evaluated, not a re-serialization
// of an equivalent document, and not whichever variant the projection currently
// favours.
func TestResolveVariantServesExactlyWhatWasAdmitted(t *testing.T) {
	ctx := context.Background()
	svc := newSvc()
	a := signedWire(t, "zA")
	b := signedWire(t, "zB")
	resA, err := svc.StoreVC(ctx, a, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	resB, err := svc.StoreVC(ctx, b, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if resA.BodyAddress != resB.BodyAddress {
		t.Fatalf("two proofs over one body landed on different bodies")
	}
	for _, tc := range []struct {
		variant string
		want    []byte
	}{{resA.WireVariantID, a}, {resB.WireVariantID, b}} {
		got, err := svc.ResolveVariant(ctx, resA.BodyAddress, tc.variant)
		if err != nil {
			t.Fatalf("ResolveVariant(%s): %v", tc.variant, err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("ResolveVariant(%s) =\n%s\nwant\n%s", tc.variant, got, tc.want)
		}
	}

	// ...while ResolveVC answers with ONE of them, and does not say which.
	// That is the asymmetry: a chain hole can take any signed form of the body,
	// an audit cannot.
	served, err := svc.ResolveVC(ctx, resA.BodyAddress)
	if err != nil {
		t.Fatal(err)
	}
	servedBytes, err := served.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(servedBytes, a) && !bytes.Equal(servedBytes, b) {
		t.Errorf("ResolveVC served bytes that are neither variant: %s", servedBytes)
	}
}

// TestListVariantsPagesAndReportsMore: the service hands back a plain cursor
// and a more flag; opaque tokens are the handler's business (matching
// ListSuccessors).
func TestListVariantsPagesAndReportsMore(t *testing.T) {
	ctx := context.Background()
	svc := newSvc()
	var body string
	var want []string
	for _, pv := range []string{"zA", "zB", "zC"} {
		res, err := svc.StoreVC(ctx, signedWire(t, pv), "", 0)
		if err != nil {
			t.Fatal(err)
		}
		body = res.BodyAddress
		want = append(want, res.WireVariantID)
	}
	sort.Strings(want)

	var paged []string
	cursor := ""
	for {
		page, more, err := svc.ListVariants(ctx, body, cursor, 2)
		if err != nil {
			t.Fatalf("ListVariants: %v", err)
		}
		paged = append(paged, page...)
		if !more {
			break
		}
		cursor = page[len(page)-1]
	}
	if !reflect.DeepEqual(paged, want) {
		t.Errorf("paged variants = %v, want %v", paged, want)
	}

	// A page that exactly exhausts the set must not claim more: the store's
	// full-page rule is what makes that answerable without a second call.
	if page, more, err := svc.ListVariants(ctx, body, "", 3); err != nil || more || len(page) != 3 {
		t.Errorf("ListVariants(limit=3) = %v more=%v err=%v, want the whole set and more=false", page, more, err)
	}
	if _, _, err := svc.ListVariants(ctx, body, "", 0); !errors.Is(err, vcresolver.ErrInvalidArgument) {
		t.Errorf("ListVariants(limit=0) = %v, want ErrInvalidArgument", err)
	}
}

// signedWire builds a signed credential's canonical wire bytes; distinct
// proofValues are distinct variants of one body.
func signedWire(t *testing.T, proofValue string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            issuer,
		"credentialSubject": map[string]any{"pipelineId": "p1", "processId": "proc1"},
		"proof": map[string]any{
			"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
			"verificationMethod": "did:dplaax:poc.dplaax.dev:org:acme#signing",
			"proofPurpose":       "assertionMethod", "created": "2026-07-01T00:00:01Z",
			"proofValue": proofValue,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var c vc.PipelinePassCredential
	if err := c.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	canonical, err := c.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}
