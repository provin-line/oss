package handler_test

// Tests for MirrorLogSegment / GetMirrorState (tlog-custody spec D-T2/D-T3/
// D-T4, Task 5). The fixture below wires REAL production components — a
// didregistry.Service issuing real pipeline/process DIDs, a real
// wireauth.Verifier, a real mirrorstore.Store — rather than spies, so each
// negative test below fails to reproduce its expected connect code if the
// specific acceptance-rule check it targets is ever removed from the
// handler/service.

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	tlogpb "github.com/provin-line/oss/gen/go/dplaax/tlog/v1"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/network/pkg/didresolver"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/didregistry"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store/yamlstore"
	"github.com/provin-line/oss/network/pkg/services/tlogservice"
	"github.com/provin-line/oss/network/pkg/services/tlogservice/handler"
	"github.com/provin-line/oss/network/pkg/services/tlogservice/logident"
	"github.com/provin-line/oss/network/pkg/services/tlogservice/mirrorstore"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/vc"
)

// --- fixture: real didregistry.Service issuing real pipeline/process DIDs
// (mirrors logident/ancestry_test.go's own fixture — narrowest existing
// precedent for this exact ceremony), a real wireauth.Verifier, and a real
// mirrorstore.Store. Two pipelines, three processes: A1 and A2 are SIBLINGS
// under pipeline A (A2 exists for the signer-pinning test — a second valid
// signer under the SAME pipeline must still be rejected once the log is
// pinned to A1); B1 is under a DIFFERENT pipeline (for the ancestry-mismatch
// test).

const (
	mirrorRegistry  = "poc.dplaax.dev"
	mirrorOwnerDID  = "did:dplaax:poc.dplaax.dev:org:acme"
	mirrorPipelineA = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pa"
	mirrorProcessA1 = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pa:process:proc1"
	mirrorProcessA2 = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pa:process:proc2"
	mirrorPipelineB = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pb"
	mirrorProcessB1 = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pb:process:proc1"
)

func mirrorFixedClock() time.Time { return time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC) }

// fixtureKeyStore is a minimal in-memory keystore.KeyStore: it backs BOTH
// didregistry.Service's internal key persistence (issuance saves the
// auth/signing pair here) and every signer this test needs (owner
// delegations, a process's wireauth proof, a process's checkpoint
// signature) — one instance serves all three, unlike
// logident/ancestry_test.go's fixture (which never needs to sign AS an
// issued process, only to read ancestry).
type fixtureKeyStore struct {
	mu   sync.Mutex
	keys map[string]map[keystore.KeyID]*crypto.KeyPair
}

func newFixtureKeyStore() *fixtureKeyStore {
	return &fixtureKeyStore{keys: map[string]map[keystore.KeyID]*crypto.KeyPair{}}
}

func (f *fixtureKeyStore) SaveKeyPair(d string, ks map[keystore.KeyID]*crypto.KeyPair) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[d] = ks
	return nil
}

func (f *fixtureKeyStore) Sign(d string, keyID string, data []byte) ([]byte, error) {
	f.mu.Lock()
	kp, ok := f.keys[d][keystore.KeyID(keyID)]
	f.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("fixtureKeyStore: no key %s#%s", d, keyID)
	}
	return ed25519.Sign(kp.PrivateKey, data)
}

func (f *fixtureKeyStore) DeleteKeys(d string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.keys, d)
	return nil
}

// mirrorResolverAdapter wraps *didregistry.Service.ResolveDID (method name
// "ResolveDID") behind the "Resolve" method shape both wireauth.DIDResolver
// and tlogservice.DIDResolver expect — the same adapter satisfies both
// seams, mirroring how the composition root reuses one concrete resolver
// for both in production (BuildHandler's *didresolver.Resolver).
type mirrorResolverAdapter struct{ svc *didregistry.Service }

func (r mirrorResolverAdapter) Resolve(ctx context.Context, didStr string) (*did.DIDDocument, error) {
	return r.svc.ResolveDID(ctx, didStr)
}

func mirrorSignedOwnerDoc(t *testing.T, signer crypto.Signer, signPub []byte) *did.DIDDocument {
	t.Helper()
	vm, err := did.NewMultikeyVerificationMethod(mirrorOwnerDID+"#signing", mirrorOwnerDID, signPub)
	if err != nil {
		t.Fatalf("NewMultikeyVerificationMethod: %v", err)
	}
	base := did.New(did.DocumentFields{
		Context:            did.IssuedDocumentContexts(),
		ID:                 mirrorOwnerDID,
		Controller:         mirrorOwnerDID,
		VerificationMethod: []did.VerificationMethod{vm},
		AssertionMethod:    []string{mirrorOwnerDID + "#signing"},
	})
	body := base.Body()
	proof, err := vc.CreateProof(signer, mirrorOwnerDID, string(keystore.KeyIDSigning), mirrorOwnerDID+"#signing", body, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	pb, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var pm map[string]any
	if err := json.Unmarshal(pb, &pm); err != nil {
		t.Fatal(err)
	}
	body["proof"] = pm
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var full did.DIDDocument
	if err := json.Unmarshal(raw, &full); err != nil {
		t.Fatalf("unmarshal signed owner doc: %v", err)
	}
	return &full
}

func mirrorMustDelegate(t *testing.T, signer crypto.Signer, subject string) *delegation.DelegationCredential {
	t.Helper()
	dlg, err := delegation.Build(signer, mirrorOwnerDID, delegation.DelegationSubject{ID: subject, DelegatedBy: mirrorOwnerDID})
	if err != nil {
		t.Fatalf("delegation.Build(%s): %v", subject, err)
	}
	return dlg
}

// mirrorFixture bundles the real components a MirrorLogSegment call is
// verified against: didSvc/resolver back BOTH wireauth's caller-identity
// resolution and the domain Service's checkpoint-signer/ancestry
// resolution; store is the durable mirror MirrorSegment writes to and
// GetMirrorState/Checkpoint/Records read from.
type mirrorFixture struct {
	ks        *fixtureKeyStore
	didSvc    *didregistry.Service
	resolver  mirrorResolverAdapter
	store     *mirrorstore.Store
	storeRoot string
	svc       *tlogservice.Service
	handler   *handler.Handler
	// verifier is the SAME wireauth verifier the fixture handler uses; exposed
	// so a test can wire it into a handler over a differently-configured Service
	// (e.g. a domain resolver that fails transiently) while keeping wireauth's
	// caller-identity check backed by the real resolver.
	verifier *wireauth.Verifier
}

func newMirrorFixture(t *testing.T, maxRecords, maxBytes int) *mirrorFixture {
	t.Helper()
	ks := newFixtureKeyStore()
	ownerKP, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate owner key: %v", err)
	}
	if err := ks.SaveKeyPair(mirrorOwnerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: ownerKP}); err != nil {
		t.Fatalf("save owner key: %v", err)
	}
	didSvc := didregistry.New(
		yamlstore.New(t.TempDir()), ks, ed25519.Generator{}, ed25519.Verifier{}, mirrorRegistry,
		didregistry.WithClock(mirrorFixedClock),
	)

	ctx := context.Background()
	if _, err := didSvc.RegisterOwner(ctx, mirrorSignedOwnerDoc(t, ks, ownerKP.PublicKey), nil); err != nil {
		t.Fatalf("RegisterOwner: %v", err)
	}
	for _, pipeline := range []string{mirrorPipelineA, mirrorPipelineB} {
		if _, _, err := didSvc.IssuePipeline(ctx, pipeline, mirrorMustDelegate(t, ks, pipeline)); err != nil {
			t.Fatalf("IssuePipeline(%s): %v", pipeline, err)
		}
	}
	for _, process := range []string{mirrorProcessA1, mirrorProcessA2, mirrorProcessB1} {
		if _, _, err := didSvc.IssueProcess(ctx, process, mirrorMustDelegate(t, ks, process)); err != nil {
			t.Fatalf("IssueProcess(%s): %v", process, err)
		}
	}

	resolver := mirrorResolverAdapter{svc: didSvc}
	verifier, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: resolver,
		Crypto:   ed25519.Verifier{},
		Nonces:   wireauth.NewMemoryNonceStore(),
		Clock:    mirrorFixedClock,
		// An explicit, far-past epoch so the restart-replay barrier never
		// rejects the fixture's fixed-clock issuedAt values (NewVerifier's
		// default epoch is boot-time-derived, which would reject anything
		// issued "now" under a clock pinned to a fixed instant).
		Epoch: time.Unix(0, 0),
	})
	if err != nil {
		t.Fatalf("wireauth.NewVerifier: %v", err)
	}

	storeRoot := t.TempDir()
	store, err := mirrorstore.Open(storeRoot)
	if err != nil {
		t.Fatalf("mirrorstore.Open: %v", err)
	}

	svc := tlogservice.New(map[string]tlog.Log{}, &tlogservice.MirrorConfig{
		Store:           store,
		DIDResolver:     resolver,
		Ancestry:        logident.NewDIDRegistryAncestry(didSvc),
		Crypto:          ed25519.Verifier{},
		MaxBatchRecords: maxRecords,
		MaxBatchBytes:   maxBytes,
	})

	return &mirrorFixture{
		ks: ks, didSvc: didSvc, resolver: resolver, store: store, storeRoot: storeRoot,
		svc: svc, handler: handler.New(svc, verifier), verifier: verifier,
	}
}

// handlerForStore builds a Handler over an arbitrary mirror store (e.g. a
// reopened one) bound to the fixture's issued DIDs / resolver / verifier — for
// tests that must exercise MirrorLogSegment across a store restart.
func (f *mirrorFixture) handlerForStore(store *mirrorstore.Store) *handler.Handler {
	svc := tlogservice.New(map[string]tlog.Log{}, &tlogservice.MirrorConfig{
		Store: store, DIDResolver: f.resolver, Ancestry: logident.NewDIDRegistryAncestry(f.didSvc),
		Crypto: ed25519.Verifier{}, MaxBatchRecords: 256, MaxBatchBytes: 4 << 20,
	})
	return handler.New(svc, f.verifier)
}

// mirrorReqParams is a MirrorLogSegmentRequest's fully explicit ingredients:
// CheckpointSize/CheckpointHead are broken out (rather than always derived)
// so a test can deliberately misalign or corrupt them.
type mirrorReqParams struct {
	LogID               string
	FromIndex           uint64
	Payloads            [][]byte
	CheckpointSize      uint64
	CheckpointHead      string
	CheckpointSignerDID string
	ProofSignerDID      string
	Timestamp           time.Time
	// CheckpointTSOverride, when non-nil, is the instant the CHECKPOINT is
	// signed over (its zone preserved into SignedView), independent of the
	// wireauth proof's Timestamp above. WireTSOverride, when non-empty, is the
	// literal string placed on the wire checkpoint.timestamp field (instead of
	// the default canonical-UTC form). Together they let a test build a
	// genuinely-signed checkpoint whose wire timestamp carries a non-Z offset —
	// the P1-A canonical-UTC-enforcement case.
	CheckpointTSOverride *time.Time
	WireTSOverride       string
}

// validParams returns the correctly-aligned, correctly-chained parameters
// for extending logID from tail (the chain hash of the record immediately
// before fromIndex, or "" at the log's start) through payloads, signed by
// signerDID both as the checkpoint signer and the wireauth caller.
func validParams(logID string, fromIndex uint64, payloads [][]byte, tail, signerDID string) mirrorReqParams {
	head := tail
	for _, p := range payloads {
		head = mirrorstore.ChainHash(head, p)
	}
	return mirrorReqParams{
		LogID: logID, FromIndex: fromIndex, Payloads: payloads,
		CheckpointSize: fromIndex + uint64(len(payloads)), CheckpointHead: head,
		CheckpointSignerDID: signerDID, ProofSignerDID: signerDID,
		Timestamp: mirrorFixedClock(),
	}
}

func (f *mirrorFixture) buildRequest(t *testing.T, p mirrorReqParams) *tlogpb.MirrorLogSegmentRequest {
	t.Helper()
	checkpointTS := p.Timestamp
	if p.CheckpointTSOverride != nil {
		checkpointTS = *p.CheckpointTSOverride
	}
	cp, err := tlog.SignCheckpoint(p.CheckpointSize, p.CheckpointHead, &tlog.CheckpointSigner{
		Signer: f.ks, SignerDID: p.CheckpointSignerDID, KeyID: string(keystore.KeyIDSigning),
		VerificationMethod: p.CheckpointSignerDID + "#signing", LogID: p.LogID,
	}, checkpointTS)
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}
	wireTS := cp.Timestamp.UTC().Format(time.RFC3339)
	if p.WireTSOverride != "" {
		wireTS = p.WireTSOverride
	}
	wireCP := &tlogpb.GetLogCheckpointResponse{
		LogId: cp.Origin, Size: strconv.FormatUint(cp.Size, 10), Head: cp.Head,
		Timestamp: wireTS, SignedBy: cp.SignedBy, Signature: cp.Signature,
	}
	digest := tlogservice.SegmentDigest(p.Payloads)
	fields := tlogservice.MirrorLogSegmentFields(p.LogID, p.FromIndex, cp.Head, digest)
	nonce, err := wireauth.NewNonce()
	if err != nil {
		t.Fatalf("NewNonce: %v", err)
	}
	proof, err := wireauth.Sign(f.ks, p.ProofSignerDID, tlogservice.OpMirrorLogSegment, fields, nonce, p.Timestamp)
	if err != nil {
		t.Fatalf("wireauth.Sign: %v", err)
	}
	return &tlogpb.MirrorLogSegmentRequest{
		LogId: p.LogID, FromIndex: p.FromIndex, RecordPayloads: p.Payloads, Checkpoint: wireCP,
		AuthProof: &chainpb.AuthProof{
			SignerDid: proof.SignerDID, Nonce: proof.Nonce,
			IssuedAt: proof.IssuedAt.Format(time.RFC3339), Signature: proof.Signature,
		},
	}
}

func (f *mirrorFixture) call(req *tlogpb.MirrorLogSegmentRequest) (*connect.Response[tlogpb.MirrorLogSegmentResponse], error) {
	return f.handler.MirrorLogSegment(context.Background(), connect.NewRequest(req))
}

// mirrorState reads GetMirrorState through the handler (custody/state path).
func (f *mirrorFixture) mirrorState(t *testing.T, logID string) uint64 {
	t.Helper()
	resp, err := f.handler.GetMirrorState(context.Background(), connect.NewRequest(&tlogpb.GetMirrorStateRequest{LogId: logID}))
	if err != nil {
		t.Fatalf("GetMirrorState(%s): %v", logID, err)
	}
	return resp.Msg.GetAckedSize()
}

// freshStoreHandler builds a NEW mirror store (acked 0) + Service + Handler
// bound to the fixture's SAME issued DIDs / resolver / wireauth verifier —
// so a test needing many independent fresh-log runs (the concurrency race)
// pays the DID-issuance ceremony once.
func (f *mirrorFixture) freshStoreHandler(t *testing.T, maxRecords, maxBytes int) (*mirrorstore.Store, *handler.Handler) {
	t.Helper()
	store, err := mirrorstore.Open(t.TempDir())
	if err != nil {
		t.Fatalf("mirrorstore.Open: %v", err)
	}
	svc := tlogservice.New(map[string]tlog.Log{}, &tlogservice.MirrorConfig{
		Store: store, DIDResolver: f.resolver, Ancestry: logident.NewDIDRegistryAncestry(f.didSvc),
		Crypto: ed25519.Verifier{}, MaxBatchRecords: maxRecords, MaxBatchBytes: maxBytes,
	})
	return store, handler.New(svc, f.verifier)
}

// --- P1-A: canonical-UTC enforcement on the wire checkpoint timestamp.

// TestMirrorLogSegment_CanonicalUTCTimestampEnforced proves a
// legitimately-SIGNED checkpoint whose wire timestamp carries a non-Z offset
// (+09:00, or +00:00 instead of Z) is rejected as InvalidArgument BEFORE any
// store write. On the pre-fix code checkpointFromWire accepted the string
// verbatim and the segment was STORED (the checkpoint verifies over the
// as-stamped offset), but GetLogCheckpoint would later reformat the served
// timestamp to UTC-Z while re-serving the original signature — an
// unverifiable served checkpoint.
func TestMirrorLogSegment_CanonicalUTCTimestampEnforced(t *testing.T) {
	jst := time.FixedZone("JST", 9*3600)
	plus9 := mirrorFixedClock().In(jst) // 2026-07-19T18:00:00+09:00 — SAME instant as the fixed clock
	for _, tc := range []struct {
		name       string
		tsOverride *time.Time
		wireTS     string
	}{
		{"plus-09:00", &plus9, plus9.Format(time.RFC3339)},
		// Signed over the canonical "...Z" but shipped as "+00:00": the parsed
		// zero-offset time re-derives to "Z" so the signature still verifies —
		// the non-canonical STRING is the only defect, which the fix rejects.
		{"plus-00:00-not-Z", nil, "2026-07-19T09:00:00+00:00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMirrorFixture(t, 256, 4<<20)
			p := validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA1)
			p.CheckpointTSOverride = tc.tsOverride
			p.WireTSOverride = tc.wireTS
			if _, err := f.call(f.buildRequest(t, p)); connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Fatalf("non-canonical UTC timestamp %q: code = %v, want InvalidArgument (err=%v)", tc.wireTS, connect.CodeOf(err), err)
			}
			if got := f.mirrorState(t, mirrorPipelineA); got != 0 {
				t.Fatalf("acked after rejected non-canonical checkpoint = %d, want 0 (must not be stored)", got)
			}
		})
	}
	// Control: a canonical UTC-Z timestamp still works.
	f := newMirrorFixture(t, 256, 4<<20)
	if _, err := f.call(f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA1))); err != nil {
		t.Fatalf("canonical UTC-Z timestamp: unexpected error %v", err)
	}
}

// --- P1-B: sink-reject logs are custodied but never served via TlogService reads.

// TestMirrorLogSegment_SinkRejectCustodyOnly proves a mirrored sink-reject log
// returns NotFound from BOTH read RPCs (GetLogCheckpoint, ListLogRecords) while
// staying fully available to the custody paths (GetMirrorState, the store, and
// a MirrorSegment replay). A mirrored emission log is still served normally.
func TestMirrorLogSegment_SinkRejectCustodyOnly(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	ctx := context.Background()
	rejectLog := "sink-reject:" + mirrorProcessA1 // owner == the process DID that signs it

	if resp, err := f.call(f.buildRequest(t, validParams(rejectLog, 0, payloads(2), "", mirrorProcessA1))); err != nil {
		t.Fatalf("mirror sink-reject segment: %v", err)
	} else if resp.Msg.GetAckedSize() != 2 {
		t.Fatalf("mirror sink-reject segment: acked=%d, want 2", resp.Msg.GetAckedSize())
	}

	// Custody/state paths remain available.
	if got := f.mirrorState(t, rejectLog); got != 2 {
		t.Fatalf("GetMirrorState(sink-reject) = %d, want 2 (custody available)", got)
	}
	if n, err := f.store.AckedSize(rejectLog); err != nil || n != 2 {
		t.Fatalf("store.AckedSize(sink-reject) = %d, %v; want 2, nil (operator tooling reads here)", n, err)
	}

	// Read RPCs must refuse it (custody-only, D-T5).
	if _, err := f.handler.GetLogCheckpoint(ctx, connect.NewRequest(&tlogpb.GetLogCheckpointRequest{LogId: rejectLog})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("GetLogCheckpoint(sink-reject): code = %v, want NotFound (err=%v)", connect.CodeOf(err), err)
	}
	if _, err := f.handler.ListLogRecords(ctx, connect.NewRequest(&tlogpb.ListLogRecordsRequest{LogId: rejectLog, Count: 10})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("ListLogRecords(sink-reject): code = %v, want NotFound (err=%v)", connect.CodeOf(err), err)
	}

	// A MirrorSegment replay of the sink-reject log still succeeds (write path).
	if resp, err := f.call(f.buildRequest(t, validParams(rejectLog, 0, payloads(2), "", mirrorProcessA1))); err != nil {
		t.Fatalf("replay sink-reject segment: %v", err)
	} else if resp.Msg.GetAckedSize() != 2 {
		t.Fatalf("replay sink-reject segment: acked=%d, want 2", resp.Msg.GetAckedSize())
	}

	// Control: a mirrored EMISSION log IS served through the read RPCs.
	if _, err := f.call(f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA1))); err != nil {
		t.Fatalf("mirror emission segment: %v", err)
	}
	if _, err := f.handler.GetLogCheckpoint(ctx, connect.NewRequest(&tlogpb.GetLogCheckpointRequest{LogId: mirrorPipelineA})); err != nil {
		t.Fatalf("GetLogCheckpoint(emission): want served, got %v", err)
	}
	if _, err := f.handler.ListLogRecords(ctx, connect.NewRequest(&tlogpb.ListLogRecordsRequest{LogId: mirrorPipelineA, Count: 10})); err != nil {
		t.Fatalf("ListLogRecords(emission): want served, got %v", err)
	}
}

// --- P2-D: batch caps enforced BEFORE hashing payloads / verifying the proof.

// TestMirrorLogSegment_CapEnforcedBeforeWireauth proves the batch cap runs
// before SegmentDigest and wireauth.Verify: an over-cap batch carrying an
// INVALID proof returns ResourceExhausted (the cap), not the Unauthenticated
// the wireauth check would return if it ran first (pre-fix, the cap was only
// checked inside Service.MirrorSegment, AFTER the handler hashed + verified).
func TestMirrorLogSegment_CapEnforcedBeforeWireauth(t *testing.T) {
	t.Run("record count cap", func(t *testing.T) {
		f := newMirrorFixture(t, 2, 4<<20) // max-batch-records = 2
		req := f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(3), "", mirrorProcessA1))
		req.AuthProof.Signature[0] ^= 0xFF // the proof no longer verifies
		if _, err := f.call(req); connect.CodeOf(err) != connect.CodeResourceExhausted {
			t.Fatalf("over-count batch + invalid proof: code = %v, want ResourceExhausted (cap must precede wireauth) (err=%v)", connect.CodeOf(err), err)
		}
	})
	t.Run("byte cap", func(t *testing.T) {
		f := newMirrorFixture(t, 256, 5) // max-batch-bytes = 5
		req := f.buildRequest(t, validParams(mirrorPipelineA, 0, [][]byte{[]byte("0123456789")}, "", mirrorProcessA1))
		req.AuthProof.Signature[0] ^= 0xFF
		if _, err := f.call(req); connect.CodeOf(err) != connect.CodeResourceExhausted {
			t.Fatalf("over-byte batch + invalid proof: code = %v, want ResourceExhausted (err=%v)", connect.CodeOf(err), err)
		}
	})
}

// --- P2-E: replay detection atomic with append (no Internal under concurrent retry).

// TestMirrorLogSegment_ConcurrentIdenticalRetry_NoInternal fires two
// byte-identical MirrorLogSegment calls concurrently at a FRESH (acked 0) log.
// Both must succeed — one commits the extend, the other resolves as a
// byte-identical replay no-op — and the store must end at a single acked size
// of 2. Pre-fix, the Service read the acked size and appended in two separate
// store calls, so both goroutines could read acked 0, the first extend, and
// the second fail the exact-extend arithmetic with a plain error → Internal.
func TestMirrorLogSegment_ConcurrentIdenticalRetry_NoInternal(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	const iterations = 100
	for i := 0; i < iterations; i++ {
		_, h := f.freshStoreHandler(t, 256, 4<<20)
		reqs := [2]*tlogpb.MirrorLogSegmentRequest{
			f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA1)),
			f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA1)),
		}
		var wg sync.WaitGroup
		start := make(chan struct{})
		var resp [2]*connect.Response[tlogpb.MirrorLogSegmentResponse]
		var errs [2]error
		for j := range reqs {
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				<-start
				resp[j], errs[j] = h.MirrorLogSegment(context.Background(), connect.NewRequest(reqs[j]))
			}(j)
		}
		close(start)
		wg.Wait()
		for j := range reqs {
			if errs[j] != nil {
				t.Fatalf("iter %d call %d: concurrent identical retry failed: code=%v err=%v", i, j, connect.CodeOf(errs[j]), errs[j])
			}
			if resp[j].Msg.GetAckedSize() != 2 {
				t.Fatalf("iter %d call %d: acked=%d, want 2 (one extend, one replay no-op)", i, j, resp[j].Msg.GetAckedSize())
			}
		}
		state, err := h.GetMirrorState(context.Background(), connect.NewRequest(&tlogpb.GetMirrorStateRequest{LogId: mirrorPipelineA}))
		if err != nil || state.Msg.GetAckedSize() != 2 {
			t.Fatalf("iter %d: final acked = %d (err %v), want a single 2", i, state.Msg.GetAckedSize(), err)
		}
	}
}

// --- F1: first-signer pin is atomic with append (concurrency-safe).

// TestMirrorLogSegment_ConcurrentInitialSiblingSigners_ExactlyOnePins fires
// two INITIAL segments for the SAME emission log from two DIFFERENT valid
// sibling signers (A1, A2 — both ancestry-valid under pipeline A) concurrently.
// Exactly one must pin the signer; the other must be PermissionDenied. The pin
// then survives a restart: the losing signer stays rejected against a reopened
// store. Pre-fix, the pin was checked in the Service (read Store.Checkpoint)
// BEFORE the append, so both could observe "no checkpoint yet" and both be
// accepted — a signer-replacement race.
func TestMirrorLogSegment_ConcurrentInitialSiblingSigners_ExactlyOnePins(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	reqs := [2]*tlogpb.MirrorLogSegmentRequest{
		f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA1)),
		f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA2)),
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	var errs [2]error
	for j := range reqs {
		wg.Add(1)
		go func(j int) {
			defer wg.Done()
			<-start
			_, errs[j] = f.call(reqs[j])
		}(j)
	}
	close(start)
	wg.Wait()

	successes := 0
	for j := range reqs {
		switch {
		case errs[j] == nil:
			successes++
		case connect.CodeOf(errs[j]) != connect.CodePermissionDenied:
			t.Fatalf("call %d: code = %v, want PermissionDenied for the loser (err=%v)", j, connect.CodeOf(errs[j]), errs[j])
		}
	}
	if successes != 1 {
		t.Fatalf("successes = %d, want exactly 1 (one signer pins, the other rejected — never a signer replacement)", successes)
	}

	// The store must hold exactly one signer, at the winner's size.
	cp, err := f.store.Checkpoint(mirrorPipelineA)
	if err != nil {
		t.Fatalf("store.Checkpoint: %v", err)
	}
	loser := mirrorProcessA1
	if cp.SignedBy == mirrorProcessA1+"#signing" {
		loser = mirrorProcessA2
	}

	// The losing signer stays rejected ACROSS A RESTART (the pin is persisted
	// in the stored checkpoint's SignedBy, re-read on reopen).
	reopened, err := mirrorstore.Open(f.storeRoot)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	h2 := f.handlerForStore(reopened)
	tail := ""
	for _, p := range payloads(2) {
		tail = mirrorstore.ChainHash(tail, p)
	}
	loserExt := f.buildRequest(t, validParams(mirrorPipelineA, 2, payloads(1), tail, loser))
	if _, err := h2.MirrorLogSegment(context.Background(), connect.NewRequest(loserExt)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("losing signer %q after restart: code = %v, want PermissionDenied (pin persisted); err=%v", loser, connect.CodeOf(err), err)
	}
}

// --- F2: a byte-identical replay still has its checkpoint head verified.

// TestMirrorLogSegment_ReplayWrongHeadRejected proves a replay whose records
// byte-match the stored segment but whose (genuinely-signed) checkpoint Head is
// wrong is rejected (FailedPrecondition), not acked. D-T2 rule 1 requires
// recomputing every checkpoint head, replay included; pre-fix the replay branch
// returned success before the head check, so a pinned signer could ack an
// arbitrary Head.
func TestMirrorLogSegment_ReplayWrongHeadRejected(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	seed := payloads(2)
	if _, err := f.call(f.buildRequest(t, validParams(mirrorPipelineA, 0, seed, "", mirrorProcessA1))); err != nil {
		t.Fatalf("seed segment: %v", err)
	}
	// Replay [0,2): identical records, but a WRONG checkpoint Head — signed
	// over that wrong head (buildRequest signs whatever CheckpointHead is), so
	// it passes signature verification and reaches the store's replay branch.
	p := validParams(mirrorPipelineA, 0, seed, "", mirrorProcessA1)
	p.CheckpointHead = "0000000000000000000000000000000000000000000000000000000000000bad"
	if _, err := f.call(f.buildRequest(t, p)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("replay with a wrong (but signed) head: code = %v, want FailedPrecondition (err=%v)", connect.CodeOf(err), err)
	}
}

// --- P2-G: transient resolver errors preserved (not mapped to PermissionDenied).

type failingResolver struct{ err error }

func (r failingResolver) Resolve(context.Context, string) (*did.DIDDocument, error) {
	return nil, r.err
}

type failingAncestry struct{ err error }

func (a failingAncestry) AncestorPipeline(context.Context, string) (string, error) {
	return "", a.err
}

// TestMirrorLogSegment_TransientResolverError proves a transient failure of the
// D-T3 checkpoint-signer resolution OR the ancestry lookup (context
// canceled/deadline, or the resolver at capacity) surfaces as the appropriate
// retryable code — NOT PermissionDenied. The wireauth verifier keeps the REAL
// resolver so the proof verifies and we reach the domain identity check; only
// the domain-side resolver/ancestry fails. Pre-fix, both were wrapped into
// ErrIdentityMismatch → PermissionDenied for every transient cause.
func TestMirrorLogSegment_TransientResolverError(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	realAncestry := logident.NewDIDRegistryAncestry(f.didSvc)
	newHandler := func(resolver tlogservice.DIDResolver, ancestry logident.PipelineAncestry) *handler.Handler {
		svc := tlogservice.New(map[string]tlog.Log{}, &tlogservice.MirrorConfig{
			Store: f.store, DIDResolver: resolver, Ancestry: ancestry,
			Crypto: ed25519.Verifier{}, MaxBatchRecords: 256, MaxBatchBytes: 4 << 20,
		})
		return handler.New(svc, f.verifier)
	}
	valid := func() *connect.Request[tlogpb.MirrorLogSegmentRequest] {
		return connect.NewRequest(f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA1)))
	}
	for _, tc := range []struct {
		name string
		err  error
		want connect.Code
	}{
		{"resolver busy", fmt.Errorf("wrap: %w", didresolver.ErrResolverBusy), connect.CodeUnavailable},
		{"deadline exceeded", context.DeadlineExceeded, connect.CodeDeadlineExceeded},
		{"canceled", context.Canceled, connect.CodeCanceled},
	} {
		t.Run("signer-resolve/"+tc.name, func(t *testing.T) {
			h := newHandler(failingResolver{err: tc.err}, realAncestry)
			if _, err := h.MirrorLogSegment(context.Background(), valid()); connect.CodeOf(err) != tc.want {
				t.Fatalf("transient signer resolve: code = %v, want %v (err=%v)", connect.CodeOf(err), tc.want, err)
			}
		})
		t.Run("ancestry/"+tc.name, func(t *testing.T) {
			h := newHandler(f.resolver, failingAncestry{err: tc.err})
			if _, err := h.MirrorLogSegment(context.Background(), valid()); connect.CodeOf(err) != tc.want {
				t.Fatalf("transient ancestry: code = %v, want %v (err=%v)", connect.CodeOf(err), tc.want, err)
			}
		})
	}
	// Control: a genuine identity mismatch STILL returns PermissionDenied.
	h := newHandler(f.resolver, realAncestry)
	mismatch := connect.NewRequest(f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessB1))) // B1's pipeline != A
	if _, err := h.MirrorLogSegment(context.Background(), mismatch); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("genuine ancestry mismatch: code = %v, want PermissionDenied (err=%v)", connect.CodeOf(err), err)
	}
}

func payloads(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("record-%d", i))
	}
	return out
}

// --- rule 1 (wireauth): a tampered proof signature must be Unauthenticated,
// never any other code — this is the ONLY rule whose failure originates in
// the handler's wireauth.Verify call, before the domain Service is ever
// reached.
func TestMirrorLogSegment_Rule1_WireauthSignatureInvalid_Unauthenticated(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	req := f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA1))
	req.AuthProof.Signature[0] ^= 0xFF // flip a bit: the proof no longer verifies
	if _, err := f.call(req); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("tampered proof: code = %v, want Unauthenticated (err=%v)", connect.CodeOf(err), err)
	}
}

func TestMirrorLogSegment_Rule1_MissingAuthProof_InvalidArgument(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	req := f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA1))
	req.AuthProof = nil
	if _, err := f.call(req); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("missing proof: code = %v, want InvalidArgument", connect.CodeOf(err))
	}
}

// --- rule 2 (D-T3 identity): every sub-case maps to PermissionDenied.
func TestMirrorLogSegment_Rule2_IdentityMismatch_PermissionDenied(t *testing.T) {
	t.Run("checkpoint signature invalid", func(t *testing.T) {
		f := newMirrorFixture(t, 256, 4<<20)
		req := f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA1))
		req.Checkpoint.Signature[0] ^= 0xFF // the checkpoint's OWN signature no longer verifies
		if _, err := f.call(req); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("corrupt checkpoint signature: code = %v, want PermissionDenied (err=%v)", connect.CodeOf(err), err)
		}
	})
	t.Run("caller does not equal checkpoint signer", func(t *testing.T) {
		f := newMirrorFixture(t, 256, 4<<20)
		p := validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA1)
		p.ProofSignerDID = mirrorProcessA2 // wireauth-proven caller != checkpoint's SignedBy base
		req := f.buildRequest(t, p)
		if _, err := f.call(req); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("caller != checkpoint signer: code = %v, want PermissionDenied (err=%v)", connect.CodeOf(err), err)
		}
	})
	t.Run("ancestry mismatch", func(t *testing.T) {
		f := newMirrorFixture(t, 256, 4<<20)
		// processB1's pipeline ancestor is pipeline B, not pipeline A — the
		// log id this segment targets.
		req := f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessB1))
		if _, err := f.call(req); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("ancestry mismatch: code = %v, want PermissionDenied (err=%v)", connect.CodeOf(err), err)
		}
	})
}

// --- rule 3 (D-T2 rule 5): caps — ResourceExhausted.
func TestMirrorLogSegment_Rule3_CapsExceeded_ResourceExhausted(t *testing.T) {
	t.Run("record count cap", func(t *testing.T) {
		f := newMirrorFixture(t, 2, 4<<20) // max-batch-records = 2
		req := f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(3), "", mirrorProcessA1))
		if _, err := f.call(req); connect.CodeOf(err) != connect.CodeResourceExhausted {
			t.Fatalf("3 records over a cap of 2: code = %v, want ResourceExhausted (err=%v)", connect.CodeOf(err), err)
		}
	})
	t.Run("byte cap", func(t *testing.T) {
		f := newMirrorFixture(t, 256, 5) // max-batch-bytes = 5
		req := f.buildRequest(t, validParams(mirrorPipelineA, 0, [][]byte{[]byte("0123456789")}, "", mirrorProcessA1))
		if _, err := f.call(req); connect.CodeOf(err) != connect.CodeResourceExhausted {
			t.Fatalf("10 bytes over a cap of 5: code = %v, want ResourceExhausted (err=%v)", connect.CodeOf(err), err)
		}
	})
}

// --- rule 4 (D-T2 rules 1/2): alignment / extend / overflow.
func TestMirrorLogSegment_Rule4_ChecklistSizeMismatch_InvalidArgument(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	p := validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA1)
	p.CheckpointSize = 99 // != from_index + len(records)
	req := f.buildRequest(t, p)
	if _, err := f.call(req); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("checkpoint.size misaligned: code = %v, want InvalidArgument (err=%v)", connect.CodeOf(err), err)
	}
}

func TestMirrorLogSegment_Rule4_Overflow_InvalidArgument(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	p := validParams(mirrorPipelineA, ^uint64(0), payloads(1), "", mirrorProcessA1) // MaxUint64 + 1 wraps
	req := f.buildRequest(t, p)
	if _, err := f.call(req); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("from_index+len overflow: code = %v, want InvalidArgument (err=%v)", connect.CodeOf(err), err)
	}
}

func TestMirrorLogSegment_Rule4_Gap_FailedPrecondition(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	// acked_size is 0 (nothing mirrored yet); from_index 5 is ahead of it.
	req := f.buildRequest(t, validParams(mirrorPipelineA, 5, payloads(2), "", mirrorProcessA1))
	if _, err := f.call(req); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("gap ahead of acked size: code = %v, want FailedPrecondition (err=%v)", connect.CodeOf(err), err)
	}
}

func TestMirrorLogSegment_Rule4_PartialOverlap_FailedPrecondition(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	first := f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA1))
	if _, err := f.call(first); err != nil {
		t.Fatalf("seed segment: %v", err)
	}
	// Replay range [0,2) again, but record 0's payload does NOT byte-match
	// what is already stored — a conflicting overlap, not a clean replay.
	conflicting := [][]byte{[]byte("DIFFERENT"), payloads(2)[1]}
	req := f.buildRequest(t, validParams(mirrorPipelineA, 0, conflicting, "", mirrorProcessA1))
	if _, err := f.call(req); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("conflicting partial overlap: code = %v, want FailedPrecondition (err=%v)", connect.CodeOf(err), err)
	}
}

// TestMirrorLogSegment_Rule4_PartialOverlapExtendingPastAcked_FailedPrecondition
// covers the overlap shape the within-range test above does NOT: a segment
// whose range [from_index, from_index+len) starts BEFORE the acked size but
// ALSO extends PAST it (K < acked < K+L). Even though the overlapping
// prefix byte-matches exactly, this is still a partial overlap (D-T2 rule
// 2) — it must be rejected as FailedPrecondition, never treated as a clean
// replay or allowed to fall through to a Store.Get past the acked size
// (whose plain out-of-range error would otherwise surface as CodeInternal).
func TestMirrorLogSegment_Rule4_PartialOverlapExtendingPastAcked_FailedPrecondition(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	seed := payloads(2) // acked becomes 2 after this seed: "record-0","record-1".
	first := f.buildRequest(t, validParams(mirrorPipelineA, 0, seed, "", mirrorProcessA1))
	if _, err := f.call(first); err != nil {
		t.Fatalf("seed segment: %v", err)
	}
	tailBeforeOne := mirrorstore.ChainHash("", seed[0])
	// from_index=1 (< acked=2) re-includes the already-mirrored record at
	// index 1 (byte-matching) AND claims a genuinely new record at index 2,
	// past the acked size.
	overlapping := [][]byte{seed[1], []byte("record-2")}
	req := f.buildRequest(t, validParams(mirrorPipelineA, 1, overlapping, tailBeforeOne, mirrorProcessA1))
	if _, err := f.call(req); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("partial overlap extending past acked: code = %v, want FailedPrecondition (err=%v)", connect.CodeOf(err), err)
	}
}

// --- rule 5 (D-T2 rule 1): chain-to-head — FailedPrecondition.
func TestMirrorLogSegment_Rule5_ChainToHeadMismatch_FailedPrecondition(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	p := validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA1)
	p.CheckpointHead = "0000000000000000000000000000000000000000000000000000000000dead" // wrong, but genuinely signed
	req := f.buildRequest(t, p)
	if _, err := f.call(req); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("wrong (but signed) chain head: code = %v, want FailedPrecondition (err=%v)", connect.CodeOf(err), err)
	}
}

// --- rule 6 (store append) + signer pinning + replay no-op + the full
// happy-path round trip.

func TestMirrorLogSegment_Rule6_StoreAppend_Success(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	req := f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(3), "", mirrorProcessA1))
	resp, err := f.call(req)
	if err != nil {
		t.Fatalf("MirrorLogSegment: %v", err)
	}
	if resp.Msg.GetAckedSize() != 3 {
		t.Fatalf("acked_size = %d, want 3", resp.Msg.GetAckedSize())
	}
}

// TestMirrorLogSegment_SignerPinning proves the FIRST accepted segment pins
// the exact signer for the log: a second, otherwise entirely valid signer
// (A2, a genuine sibling process under the SAME pipeline — ancestry alone
// would accept it) is rejected once the log is pinned to A1.
func TestMirrorLogSegment_SignerPinning(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	first := f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA1))
	if _, err := f.call(first); err != nil {
		t.Fatalf("seed segment (A1): %v", err)
	}
	tail := ""
	for _, pl := range payloads(2) {
		tail = mirrorstore.ChainHash(tail, pl)
	}
	sibling := f.buildRequest(t, validParams(mirrorPipelineA, 2, payloads(1), tail, mirrorProcessA2))
	if _, err := f.call(sibling); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("sibling process A2 after A1 pinned: code = %v, want PermissionDenied (err=%v)", connect.CodeOf(err), err)
	}
}

// TestMirrorLogSegment_ReplayNoOp proves a byte-identical resend of an
// already-accepted segment (e.g. a lost-ack retry) is a no-op success that
// returns the unchanged acked size, never re-appending.
func TestMirrorLogSegment_ReplayNoOp(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	req := f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA1))
	first, err := f.call(req)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if first.Msg.GetAckedSize() != 2 {
		t.Fatalf("first acked_size = %d, want 2", first.Msg.GetAckedSize())
	}
	// Byte-identical replay: same log, same from_index, same payloads. A
	// fresh proof (nonce/timestamp) is fine — replay no-op-ness is about the
	// SEGMENT content, not the wireauth envelope.
	replay := f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA1))
	second, err := f.call(replay)
	if err != nil {
		t.Fatalf("replay call: %v", err)
	}
	if second.Msg.GetAckedSize() != 2 {
		t.Fatalf("replay acked_size = %d, want unchanged 2", second.Msg.GetAckedSize())
	}
}

// TestGetMirrorState_RoundTrip exercises GetMirrorState before any segment
// (0, no error — a fresh shipper's first call), and after two successive
// accepted segments (the growing acked size).
func TestGetMirrorState_RoundTrip(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	state := func() uint64 {
		resp, err := f.handler.GetMirrorState(context.Background(), connect.NewRequest(&tlogpb.GetMirrorStateRequest{LogId: mirrorPipelineA}))
		if err != nil {
			t.Fatalf("GetMirrorState: %v", err)
		}
		return resp.Msg.GetAckedSize()
	}
	if got := state(); got != 0 {
		t.Fatalf("acked_size before any segment = %d, want 0", got)
	}
	seg1 := f.buildRequest(t, validParams(mirrorPipelineA, 0, payloads(2), "", mirrorProcessA1))
	if _, err := f.call(seg1); err != nil {
		t.Fatalf("segment 1: %v", err)
	}
	if got := state(); got != 2 {
		t.Fatalf("acked_size after segment 1 = %d, want 2", got)
	}
	tail := ""
	for _, pl := range payloads(2) {
		tail = mirrorstore.ChainHash(tail, pl)
	}
	seg2 := f.buildRequest(t, validParams(mirrorPipelineA, 2, payloads(1), tail, mirrorProcessA1))
	if _, err := f.call(seg2); err != nil {
		t.Fatalf("segment 2: %v", err)
	}
	if got := state(); got != 3 {
		t.Fatalf("acked_size after segment 2 = %d, want 3", got)
	}
}

func TestGetMirrorState_InvalidLogID_InvalidArgument(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	_, err := f.handler.GetMirrorState(context.Background(), connect.NewRequest(&tlogpb.GetMirrorStateRequest{LogId: "not-a-did"}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("malformed log_id: code = %v, want InvalidArgument", connect.CodeOf(err))
	}
}

// TestMirrorLogSegment_FullHappyPathRoundTrip is the end-to-end proof: two
// checkpoint-aligned segments through the REAL mirror store, wireauth
// verifier, and DID resolver with genuinely issued pipeline/process DIDs,
// followed by reads through tlogservice.Service's map-then-mirror "second
// source" (D-T4) — GetLogCheckpoint-equivalent and ListLogRecords-equivalent
// both serve the mirrored data once nothing local claims the log id.
func TestMirrorLogSegment_FullHappyPathRoundTrip(t *testing.T) {
	f := newMirrorFixture(t, 256, 4<<20)
	ctx := context.Background()

	seg1 := payloads(2)
	req1 := f.buildRequest(t, validParams(mirrorPipelineA, 0, seg1, "", mirrorProcessA1))
	resp1, err := f.call(req1)
	if err != nil {
		t.Fatalf("segment 1: %v", err)
	}
	if resp1.Msg.GetAckedSize() != 2 {
		t.Fatalf("segment 1 acked_size = %d, want 2", resp1.Msg.GetAckedSize())
	}

	tail := ""
	for _, pl := range seg1 {
		tail = mirrorstore.ChainHash(tail, pl)
	}
	seg2 := [][]byte{[]byte("record-2")}
	req2 := f.buildRequest(t, validParams(mirrorPipelineA, 2, seg2, tail, mirrorProcessA1))
	resp2, err := f.call(req2)
	if err != nil {
		t.Fatalf("segment 2: %v", err)
	}
	if resp2.Msg.GetAckedSize() != 3 {
		t.Fatalf("segment 2 acked_size = %d, want 3", resp2.Msg.GetAckedSize())
	}

	// GetMirrorState reflects the durable size.
	state, err := f.handler.GetMirrorState(ctx, connect.NewRequest(&tlogpb.GetMirrorStateRequest{LogId: mirrorPipelineA}))
	if err != nil {
		t.Fatalf("GetMirrorState: %v", err)
	}
	if state.Msg.GetAckedSize() != 3 {
		t.Fatalf("GetMirrorState.acked_size = %d, want 3", state.Msg.GetAckedSize())
	}

	// The domain Service's read path (map-then-mirror, D-T4) serves the
	// mirrored checkpoint and records: this node runs no local log for
	// mirrorPipelineA (an empty map), so both reads fall through to the
	// mirror store.
	cp, err := f.svc.Checkpoint(ctx, mirrorPipelineA)
	if err != nil {
		t.Fatalf("Checkpoint (mirror fallback): %v", err)
	}
	if cp.Size != 3 || cp.SignedBy != mirrorProcessA1+"#signing" {
		t.Fatalf("mirrored checkpoint = %+v, want size 3 signed by %s#signing", cp, mirrorProcessA1)
	}
	recs, err := f.svc.Records(ctx, mirrorPipelineA, 0, 10)
	if err != nil {
		t.Fatalf("Records (mirror fallback): %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("mirrored records = %d, want 3", len(recs))
	}
	wantPayloads := append(append([][]byte{}, seg1...), seg2...)
	for i, rec := range recs {
		if string(rec.Payload) != string(wantPayloads[i]) {
			t.Errorf("record %d payload = %q, want %q", i, rec.Payload, wantPayloads[i])
		}
	}
}

// --- ErrMirrorNotConfigured: a node that never wired a mirror store
// (cmd/standalone's map-only posture) reports Unimplemented, not a silent
// zero/empty result.

// stubVerifier always succeeds — used only for the not-configured tests
// below, which exercise the SERVICE's ErrMirrorNotConfigured path and have
// no need for a genuine wireauth proof.
type stubVerifier struct{}

func (stubVerifier) Verify(context.Context, string, map[string]any, wireauth.Proof, wireauth.Authorizer) error {
	return nil
}

func TestMirrorLogSegment_NotConfigured_Unimplemented(t *testing.T) {
	h := handler.New(&fakeService{err: tlogservice.ErrMirrorNotConfigured}, stubVerifier{})
	req := &tlogpb.MirrorLogSegmentRequest{
		LogId: "x",
		Checkpoint: &tlogpb.GetLogCheckpointResponse{
			LogId: "x", Size: "0", Head: "", Timestamp: mirrorFixedClock().Format(time.RFC3339),
			SignedBy: "did:x#signing", Signature: []byte("s"),
		},
		AuthProof: &chainpb.AuthProof{SignerDid: "did:x", Nonce: "n", IssuedAt: mirrorFixedClock().Format(time.RFC3339), Signature: []byte("s")},
	}
	_, err := h.MirrorLogSegment(context.Background(), connect.NewRequest(req))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("no mirror store wired: code = %v, want Unimplemented", connect.CodeOf(err))
	}
}

func TestGetMirrorState_NotConfigured_Unimplemented(t *testing.T) {
	h := handler.New(&fakeService{err: tlogservice.ErrMirrorNotConfigured}, stubVerifier{})
	_, err := h.GetMirrorState(context.Background(), connect.NewRequest(&tlogpb.GetMirrorStateRequest{LogId: "x"}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("no mirror store wired: code = %v, want Unimplemented", connect.CodeOf(err))
	}
}
