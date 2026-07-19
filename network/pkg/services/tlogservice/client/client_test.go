package client_test

// Round-trip tests for tlogservice/client against the REAL production
// stack (task-6 brief): a real didregistry.Service issuing real
// pipeline/process DIDs, a real wireauth.Verifier, a real
// mirrorstore.Store, and the real handler.Handler — served over httptest,
// exercised only through client.Client. Modeled on
// tlogservice/handler/mirror_test.go's fixture (the narrowest existing
// precedent for this exact ceremony) and auditor/client/client_test.go's
// httptest-harness shape; reproduced rather than shared, since a client
// package and a handler package's _test helpers are not importable across
// package boundaries and the codebase's own convention (see this client's
// own bearerInterceptor doc) is to duplicate such small fixtures.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/gen/go/dplaax/tlog/v1/tlogpbconnect"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/didregistry"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store/yamlstore"
	"github.com/provin-line/oss/network/pkg/services/tlogservice"
	"github.com/provin-line/oss/network/pkg/services/tlogservice/client"
	"github.com/provin-line/oss/network/pkg/services/tlogservice/handler"
	"github.com/provin-line/oss/network/pkg/services/tlogservice/logident"
	"github.com/provin-line/oss/network/pkg/services/tlogservice/mirrorstore"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/tlog/filelog"
	"github.com/provin-line/oss/vc"
)

const (
	clientRegistry  = "poc.dplaax.dev"
	clientOwnerDID  = "did:dplaax:poc.dplaax.dev:org:acme"
	clientPipeline  = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pa"
	clientProcessA1 = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pa:process:proc1"
)

// fixtureKeyStore is a minimal in-memory keystore.KeyStore backing both
// didregistry.Service's internal key persistence and every signer this test
// needs (owner delegations, the process's wireauth proof — via
// client.Config.Signer — and its checkpoint signature).
type fixtureKeyStore struct {
	keys map[string]map[keystore.KeyID]*crypto.KeyPair
}

func newFixtureKeyStore() *fixtureKeyStore {
	return &fixtureKeyStore{keys: map[string]map[keystore.KeyID]*crypto.KeyPair{}}
}

func (f *fixtureKeyStore) SaveKeyPair(d string, ks map[keystore.KeyID]*crypto.KeyPair) error {
	f.keys[d] = ks
	return nil
}

func (f *fixtureKeyStore) Sign(d string, keyID string, data []byte) ([]byte, error) {
	kp, ok := f.keys[d][keystore.KeyID(keyID)]
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, nil)
	}
	return ed25519.Sign(kp.PrivateKey, data)
}

func (f *fixtureKeyStore) DeleteKeys(d string) error {
	delete(f.keys, d)
	return nil
}

type resolverAdapter struct{ svc *didregistry.Service }

func (r resolverAdapter) Resolve(ctx context.Context, didStr string) (*did.DIDDocument, error) {
	return r.svc.ResolveDID(ctx, didStr)
}

func signedOwnerDoc(t *testing.T, signer crypto.Signer, signPub []byte) *did.DIDDocument {
	t.Helper()
	vm, err := did.NewMultikeyVerificationMethod(clientOwnerDID+"#signing", clientOwnerDID, signPub)
	if err != nil {
		t.Fatalf("NewMultikeyVerificationMethod: %v", err)
	}
	base := did.New(did.DocumentFields{
		Context:            did.IssuedDocumentContexts(),
		ID:                 clientOwnerDID,
		Controller:         clientOwnerDID,
		VerificationMethod: []did.VerificationMethod{vm},
		AssertionMethod:    []string{clientOwnerDID + "#signing"},
	})
	body := base.Body()
	proof, err := vc.CreateProof(signer, clientOwnerDID, string(keystore.KeyIDSigning), clientOwnerDID+"#signing", body, vc.CryptosuiteEdDSAJCS2022)
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
	var fullDoc did.DIDDocument
	if err := json.Unmarshal(raw, &fullDoc); err != nil {
		t.Fatalf("unmarshal signed owner doc: %v", err)
	}
	return &fullDoc
}

func mustDelegate(t *testing.T, signer crypto.Signer, subject string) *delegation.DelegationCredential {
	t.Helper()
	dlg, err := delegation.Build(signer, clientOwnerDID, delegation.DelegationSubject{ID: subject, DelegatedBy: clientOwnerDID})
	if err != nil {
		t.Fatalf("delegation.Build(%s): %v", subject, err)
	}
	return dlg
}

// harness wires a real TlogService (real mirrorstore, real wireauth
// verifier, real didregistry-issued pipeline/process DIDs) behind
// httptest, plus a real filelog.Log for clientProcessA1 (the "live tlog.Log
// handle" the shipper would share) armed with a CheckpointSigner under the
// SAME key the client signs wireauth proofs with — so a checkpoint this
// test builds from the log and a client this test builds from the same
// keystore are mutually consistent, exactly as a real shipper+log pairing
// would be.
type harness struct {
	log    tlog.Log
	client *client.Client
	url    string
}

func newHarness(t *testing.T, maxRecords, maxBytes int) *harness {
	t.Helper()
	ks := newFixtureKeyStore()
	ownerKP, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate owner key: %v", err)
	}
	if err := ks.SaveKeyPair(clientOwnerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: ownerKP}); err != nil {
		t.Fatalf("save owner key: %v", err)
	}
	didSvc := didregistry.New(yamlstore.New(t.TempDir()), ks, ed25519.Generator{}, ed25519.Verifier{}, clientRegistry)

	ctx := context.Background()
	if _, err := didSvc.RegisterOwner(ctx, signedOwnerDoc(t, ks, ownerKP.PublicKey), nil); err != nil {
		t.Fatalf("RegisterOwner: %v", err)
	}
	if _, _, err := didSvc.IssuePipeline(ctx, clientPipeline, mustDelegate(t, ks, clientPipeline)); err != nil {
		t.Fatalf("IssuePipeline: %v", err)
	}
	if _, _, err := didSvc.IssueProcess(ctx, clientProcessA1, mustDelegate(t, ks, clientProcessA1)); err != nil {
		t.Fatalf("IssueProcess: %v", err)
	}

	resolver := resolverAdapter{svc: didSvc}
	verifier, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: resolver,
		Crypto:   ed25519.Verifier{},
		Nonces:   wireauth.NewMemoryNonceStore(),
		// The real client signs with time.Now(); a past epoch + generous
		// window keep the proof inside the acceptance boundary (mirrors
		// auditor/client_test.go's own real-clock harness).
		Epoch:  time.Now().Add(-time.Hour),
		Window: wireauth.AcceptanceWindow{MaxPast: time.Hour, MaxFuture: time.Minute},
	})
	if err != nil {
		t.Fatalf("wireauth.NewVerifier: %v", err)
	}

	store, err := mirrorstore.Open(t.TempDir())
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

	h := handler.New(svc, verifier)
	path, hh := tlogpbconnect.NewTlogServiceHandler(h)
	mux := http.NewServeMux()
	mux.Handle(path, hh)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	log, err := filelog.New(t.TempDir(), filelog.WithCheckpointSigner(tlog.CheckpointSigner{
		Signer: ks, SignerDID: clientProcessA1, KeyID: string(keystore.KeyIDSigning),
		VerificationMethod: clientProcessA1 + "#signing", LogID: clientPipeline,
	}))
	if err != nil {
		t.Fatalf("filelog.New: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	return &harness{
		log: log,
		client: client.New(client.Config{
			Signer: ks, SignerDID: clientProcessA1, BaseURL: srv.URL, HTTPClient: srv.Client(),
		}),
		url: srv.URL,
	}
}

// appendAndCheckpoint appends payloads to h.log and returns the resulting
// signed checkpoint (the log's OWN Checkpoint(), never synthesized) —
// mirrors the shipper's "checkpoint-then-Get" enumeration: append first
// (durable), then take the checkpoint covering exactly that new size.
func (h *harness) appendAndCheckpoint(t *testing.T, ctx context.Context, payloads [][]byte) *tlog.Checkpoint {
	t.Helper()
	for _, p := range payloads {
		if _, err := h.log.Append(ctx, p); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	cp, err := h.log.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	return cp
}

func recPayloads(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte("record-" + string(rune('a'+i)))
	}
	return out
}

// TestMirrorLogSegment_RoundTrip proves the client's signed view is exactly
// what the real handler verifies end-to-end: two successive
// checkpoint-aligned segments land through the wireauth verifier, D-T3
// identity binding, and the real mirror store, with GetMirrorState
// reflecting the growing durable size.
func TestMirrorLogSegment_RoundTrip(t *testing.T) {
	h := newHarness(t, 256, 4<<20)
	ctx := context.Background()

	seg1 := recPayloads(2)
	cp1 := h.appendAndCheckpoint(t, ctx, seg1)
	acked, err := h.client.MirrorLogSegment(ctx, clientPipeline, 0, seg1, cp1)
	if err != nil {
		t.Fatalf("MirrorLogSegment (segment 1): %v", err)
	}
	if acked != 2 {
		t.Fatalf("acked_size after segment 1 = %d, want 2", acked)
	}

	state, err := h.client.GetMirrorState(ctx, clientPipeline)
	if err != nil {
		t.Fatalf("GetMirrorState: %v", err)
	}
	if state != 2 {
		t.Fatalf("GetMirrorState after segment 1 = %d, want 2", state)
	}

	seg2 := [][]byte{[]byte("record-c")}
	cp2 := h.appendAndCheckpoint(t, ctx, seg2)
	acked, err = h.client.MirrorLogSegment(ctx, clientPipeline, 2, seg2, cp2)
	if err != nil {
		t.Fatalf("MirrorLogSegment (segment 2): %v", err)
	}
	if acked != 3 {
		t.Fatalf("acked_size after segment 2 = %d, want 3", acked)
	}

	state, err = h.client.GetMirrorState(ctx, clientPipeline)
	if err != nil {
		t.Fatalf("GetMirrorState: %v", err)
	}
	if state != 3 {
		t.Fatalf("GetMirrorState after segment 2 = %d, want 3", state)
	}
}

// TestMirrorLogSegment_ReplayNoOp proves a byte-identical resend (e.g. a
// lost-ack retry) round-trips through the client as a no-op success,
// returning the unchanged acked size.
func TestMirrorLogSegment_ReplayNoOp(t *testing.T) {
	h := newHarness(t, 256, 4<<20)
	ctx := context.Background()

	seg := recPayloads(2)
	cp := h.appendAndCheckpoint(t, ctx, seg)
	if _, err := h.client.MirrorLogSegment(ctx, clientPipeline, 0, seg, cp); err != nil {
		t.Fatalf("first MirrorLogSegment: %v", err)
	}
	acked, err := h.client.MirrorLogSegment(ctx, clientPipeline, 0, seg, cp)
	if err != nil {
		t.Fatalf("replay MirrorLogSegment: %v", err)
	}
	if acked != 2 {
		t.Fatalf("replay acked_size = %d, want unchanged 2", acked)
	}
}

// TestMirrorLogSegment_CapExceeded_ResourceExhausted proves the real
// connect code passes through unmangled: a batch over the registry's
// configured max-batch-records surfaces as CodeResourceExhausted.
func TestMirrorLogSegment_CapExceeded_ResourceExhausted(t *testing.T) {
	h := newHarness(t, 1, 4<<20) // max-batch-records = 1
	ctx := context.Background()

	seg := recPayloads(2)
	cp := h.appendAndCheckpoint(t, ctx, seg)
	_, err := h.client.MirrorLogSegment(ctx, clientPipeline, 0, seg, cp)
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("2 records over a cap of 1: code = %v, want ResourceExhausted (err=%v)", connect.CodeOf(err), err)
	}
}

// TestMirrorLogSegment_WrongSigner_Unauthenticated proves a client signing
// as a DID the harness never issued fails wireauth verification end-to-end
// (CodeUnauthenticated), never silently accepted.
func TestMirrorLogSegment_WrongSigner_Unauthenticated(t *testing.T) {
	h := newHarness(t, 256, 4<<20)
	ctx := context.Background()

	seg := recPayloads(1)
	cp := h.appendAndCheckpoint(t, ctx, seg)

	unknownSigner := newFixtureKeyStore()
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := unknownSigner.SaveKeyPair(clientProcessA1, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
		t.Fatalf("save: %v", err)
	}
	bad := client.New(client.Config{Signer: unknownSigner, SignerDID: clientProcessA1, BaseURL: h.url, HTTPClient: http.DefaultClient})
	_, err = bad.MirrorLogSegment(ctx, clientPipeline, 0, seg, cp)
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("wrong signer key: code = %v, want Unauthenticated (err=%v)", connect.CodeOf(err), err)
	}
}

// TestMirrorLogSegment_NilCheckpoint_RejectedClientSide proves a nil
// checkpoint is rejected before any signing or network call — a
// MirrorLogSegment call always carries one (D-T2 rule 1).
func TestMirrorLogSegment_NilCheckpoint_RejectedClientSide(t *testing.T) {
	h := newHarness(t, 256, 4<<20)
	_, err := h.client.MirrorLogSegment(context.Background(), clientPipeline, 0, recPayloads(1), nil)
	if err == nil {
		t.Fatal("nil checkpoint: want error, got nil")
	}
}

// TestGetMirrorState_BeforeAnySegment_Zero proves a fresh log id (nothing
// mirrored yet) reads back acked_size 0 with no error — the shipper's
// first-ever resume read.
func TestGetMirrorState_BeforeAnySegment_Zero(t *testing.T) {
	h := newHarness(t, 256, 4<<20)
	state, err := h.client.GetMirrorState(context.Background(), clientPipeline)
	if err != nil {
		t.Fatalf("GetMirrorState: %v", err)
	}
	if state != 0 {
		t.Fatalf("acked_size before any segment = %d, want 0", state)
	}
}
