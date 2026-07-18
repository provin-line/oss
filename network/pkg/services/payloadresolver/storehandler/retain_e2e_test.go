package storehandler_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	payloadpb "github.com/provin-line/oss/gen/go/dplaax/payload/v1"
	"github.com/provin-line/oss/gen/go/dplaax/payload/v1/payloadpbconnect"
	"github.com/provin-line/oss/keystore"
	ksfilestore "github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/client"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/memstore"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/storehandler"
)

// nodeDID signs every proof in this suite AND is the common-case owner_did
// (a producing process retains its own emitted payload).
const nodeDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pipe-a"

func jwk(pub []byte) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
}

func authDoc(subject string, pub []byte) *did.DIDDocument {
	return did.New(did.DocumentFields{
		ID: subject, Controller: subject,
		VerificationMethod: []did.VerificationMethod{{
			ID: subject + "#auth", Type: "JsonWebKey2020", Controller: subject,
			PublicKeyJWK: jwk(pub),
		}},
		Authentication: []string{subject + "#auth"},
	})
}

type didResolver map[string]*did.DIDDocument

func (m didResolver) Resolve(_ context.Context, d string) (*did.DIDDocument, error) {
	doc, ok := m[d]
	if !ok {
		return nil, wireauth.ErrKeyResolution
	}
	return doc, nil
}

func signer(t *testing.T, subject string) (crypto.Signer, []byte) {
	t.Helper()
	ks := ksfilestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := ks.SaveKeyPair(subject, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
		t.Fatalf("save: %v", err)
	}
	return ks, kp.PublicKey
}

// spyWriter wraps a real payloadresolver.PayloadWriter, counting Commit/Abort
// calls so a test can observe finalization without inspecting store internals.
type spyWriter struct {
	payloadresolver.PayloadWriter
	commits int
	aborts  int
}

func (w *spyWriter) Commit() (string, error) {
	w.commits++
	return w.PayloadWriter.Commit()
}

func (w *spyWriter) Abort() error {
	w.aborts++
	return w.PayloadWriter.Abort()
}

// spyStore wraps a real payloadresolver.Store, capturing the LAST writer it
// minted so a test can inspect its Commit/Abort call counts after the RPC
// returns. It also satisfies storehandler.WriterStore structurally (the only
// method that interface needs).
type spyStore struct {
	inner payloadresolver.Store
	last  *spyWriter
}

func (s *spyStore) StoreWriter(ctx context.Context, ownerDID string) (payloadresolver.PayloadWriter, error) {
	w, err := s.inner.StoreWriter(ctx, ownerDID)
	if err != nil {
		return nil, err
	}
	s.last = &spyWriter{PayloadWriter: w}
	return s.last, nil
}

// harness wires a real storehandler.Handler (over a spyStore backed by a real
// memstore) behind a real wireauth.Verifier, served over httptest, with the
// real streaming client.Resolver signing every call as nodeDID. opts are
// passed through to the generated handler constructor (e.g. a tiny
// connect.WithReadMaxBytes to exercise the per-chunk mount cap).
type harness struct {
	store  *spyStore
	signer crypto.Signer
	client *client.Resolver
	url    string
	httpc  connect.HTTPClient
}

func newHarness(t *testing.T, maxPayloadSize uint64, opts ...connect.HandlerOption) *harness {
	t.Helper()
	sgn, pub := signer(t, nodeDID)
	res := didResolver{nodeDID: authDoc(nodeDID, pub)}
	v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: res,
		Crypto:   ed25519.Verifier{},
		Nonces:   wireauth.NewMemoryNonceStore(),
		// The real client signs with time.Now(); a past epoch + generous window
		// keep the proof inside the acceptance boundary without a fixed clock.
		Epoch:  time.Now().Add(-time.Hour),
		Window: wireauth.AcceptanceWindow{MaxPast: time.Hour, MaxFuture: time.Minute},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	st := &spyStore{inner: memstore.New()}
	h := storehandler.New(st, v, maxPayloadSize)
	path, hh := payloadpbconnect.NewPayloadStoreServiceHandler(h, opts...)
	mux := http.NewServeMux()
	mux.Handle(path, hh)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	httpc := srv.Client()
	return &harness{
		store:  st,
		signer: sgn,
		client: client.New(client.Config{Signer: sgn, SignerDID: nodeDID, HTTPClient: httpc, StoreEndpoint: srv.URL}),
		url:    srv.URL,
		httpc:  httpc,
	}
}

// mustProof signs a RetainPayload metadata proof directly (bypassing
// client.Resolver.Retain), for driving raw/malformed frame sequences the
// high-level client would never produce.
func mustProof(t *testing.T, sgn crypto.Signer, signerDID, ownerDID string, size uint64) *chainpb.AuthProof {
	t.Helper()
	nonce, err := wireauth.NewNonce()
	if err != nil {
		t.Fatalf("NewNonce: %v", err)
	}
	p, err := wireauth.Sign(sgn, signerDID, payloadresolver.OpRetainPayload, payloadresolver.RetainPayloadFields(ownerDID, size), nonce, time.Now())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return &chainpb.AuthProof{
		SignerDid: p.SignerDID,
		Nonce:     p.Nonce,
		IssuedAt:  p.IssuedAt.UTC().Format(time.RFC3339),
		Signature: p.Signature,
	}
}

// TestRetainPayload_RoundTrip_HappyPath streams via the real client and reads
// the committed bytes back through the real store — the content address the
// client gets back must be the address the store actually holds the bytes at.
func TestRetainPayload_RoundTrip_HappyPath(t *testing.T) {
	h := newHarness(t, 1<<20)
	payload := []byte("the produced data bytes, streamed incrementally over the wire")

	addr, err := h.client.Retain(context.Background(), bytes.NewReader(payload), nodeDID, uint64(len(payload)))
	if err != nil {
		t.Fatalf("Retain: %v", err)
	}

	got, owners, err := h.store.inner.Get(addr)
	if err != nil {
		t.Fatalf("Get(%q): %v", addr, err)
	}
	if string(got) != string(payload) {
		t.Errorf("stored payload = %q, want %q", got, payload)
	}
	if len(owners) != 1 || owners[0] != nodeDID {
		t.Errorf("owners = %v, want [%q]", owners, nodeDID)
	}
	if h.store.last == nil || h.store.last.commits != 1 || h.store.last.aborts != 0 {
		t.Errorf("writer commits/aborts = %+v, want exactly one Commit and no Abort", h.store.last)
	}
}

// TestRetainPayload_MultiChunkAssembly proves the client's own chunking (a
// payload several times its configured RetainChunkSize) reassembles correctly
// server-side — the entire reason RetainChunkSize is configurable client-side.
func TestRetainPayload_MultiChunkAssembly(t *testing.T) {
	h := newHarness(t, 1<<20)
	small := client.New(client.Config{
		Signer: h.signer, SignerDID: nodeDID, HTTPClient: h.httpc, StoreEndpoint: h.url,
		RetainChunkSize: 16, // forces many frames for a payload well over 16 bytes
	})
	payload := bytes.Repeat([]byte("0123456789"), 20) // 200 bytes, 16-byte chunks

	addr, err := small.Retain(context.Background(), bytes.NewReader(payload), nodeDID, uint64(len(payload)))
	if err != nil {
		t.Fatalf("Retain: %v", err)
	}
	got, _, err := h.store.inner.Get(addr)
	if err != nil {
		t.Fatalf("Get(%q): %v", addr, err)
	}
	if string(got) != string(payload) {
		t.Errorf("stored payload mismatched after multi-chunk assembly (len got=%d want=%d)", len(got), len(payload))
	}
}

// TestRetainPayload_OwnerMismatch_PermissionDenied proves the proven signer DID
// is authoritative over a claimed owner_did that does not match it.
func TestRetainPayload_OwnerMismatch_PermissionDenied(t *testing.T) {
	h := newHarness(t, 1<<20)
	const claimedOwner = "did:dplaax:poc.dplaax.dev:org:other:pipeline:pipe-b"
	payload := []byte("bytes claimed under someone else's owner_did")

	_, err := h.client.Retain(context.Background(), bytes.NewReader(payload), claimedOwner, uint64(len(payload)))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("owner mismatch: code = %v (%v), want PermissionDenied", connect.CodeOf(err), err)
	}
}

// TestRetainPayload_WireauthFail_Unauthenticated proves a signature that does
// not verify (a different keypair bound to the same claimed DID string) is
// rejected as CodeUnauthenticated, mirroring auditor/client's mismatched-key
// test.
func TestRetainPayload_WireauthFail_Unauthenticated(t *testing.T) {
	h := newHarness(t, 1<<20)
	wrongSigner, _ := signer(t, nodeDID) // a DIFFERENT keypair than the one the verifier's resolver bound to nodeDID
	bad := client.New(client.Config{Signer: wrongSigner, SignerDID: nodeDID, HTTPClient: h.httpc, StoreEndpoint: h.url})

	payload := []byte("bytes signed with the wrong key")
	_, err := bad.Retain(context.Background(), bytes.NewReader(payload), nodeDID, uint64(len(payload)))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("mismatched key: code = %v, want Unauthenticated", connect.CodeOf(err))
	}
}

// TestRetainPayload_ZeroDeclaredSize_InvalidArgument proves this handler
// re-enforces the domain's "no empty payload" invariant even though it
// bypasses payloadresolver.Service.Store (which normally enforces it) by
// streaming directly to Store.StoreWriter.
func TestRetainPayload_ZeroDeclaredSize_InvalidArgument(t *testing.T) {
	h := newHarness(t, 1<<20)

	_, err := h.client.Retain(context.Background(), bytes.NewReader(nil), nodeDID, 0)
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("declared_size=0: code = %v (%v), want InvalidArgument", connect.CodeOf(err), err)
	}
	if h.store.last != nil {
		t.Error("a writer must never be created for declared_size=0")
	}
}

// TestRetainPayload_CumulativeOverrun_ResourceExhausted_AbortObserved declares
// a size SMALLER than what is actually streamed: the server must reject with
// ResourceExhausted (not silently truncate) and Abort the writer — nothing
// half-written is ever committed.
func TestRetainPayload_CumulativeOverrun_ResourceExhausted_AbortObserved(t *testing.T) {
	h := newHarness(t, 1<<20)
	payload := bytes.Repeat([]byte("x"), 100)

	_, err := h.client.Retain(context.Background(), bytes.NewReader(payload), nodeDID, 50)
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("overrun: code = %v (%v), want ResourceExhausted", connect.CodeOf(err), err)
	}
	if h.store.last == nil {
		t.Fatal("no writer was created")
	}
	if h.store.last.aborts != 1 || h.store.last.commits != 0 {
		t.Errorf("writer commits/aborts = %+v, want exactly one Abort and no Commit", h.store.last)
	}
}

// TestRetainPayload_Undershoot_InvalidArgument_AbortObserved declares a size
// LARGER than what is actually streamed: declared_size is a commitment, not a
// hint, so a short stream is InvalidArgument (never a silent pad), and the
// writer is Aborted.
func TestRetainPayload_Undershoot_InvalidArgument_AbortObserved(t *testing.T) {
	h := newHarness(t, 1<<20)
	payload := []byte("short")

	_, err := h.client.Retain(context.Background(), bytes.NewReader(payload), nodeDID, uint64(len(payload))+10)
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("undershoot: code = %v (%v), want InvalidArgument", connect.CodeOf(err), err)
	}
	if h.store.last == nil {
		t.Fatal("no writer was created")
	}
	if h.store.last.aborts != 1 || h.store.last.commits != 0 {
		t.Errorf("writer commits/aborts = %+v, want exactly one Abort and no Commit", h.store.last)
	}
}

// TestRetainPayload_DeclaredSizeExceedsQuota_ResourceExhausted proves
// declared_size itself is bounded by the configured max-retain-payload-size
// quota, rejected BEFORE any store interaction (no writer ever opens).
func TestRetainPayload_DeclaredSizeExceedsQuota_ResourceExhausted(t *testing.T) {
	h := newHarness(t, 10) // tiny quota
	payload := []byte("this payload's declared size is above the tiny quota")

	_, err := h.client.Retain(context.Background(), bytes.NewReader(payload), nodeDID, uint64(len(payload)))
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("quota: code = %v (%v), want ResourceExhausted", connect.CodeOf(err), err)
	}
	if h.store.last != nil {
		t.Error("a writer must never be created when declared_size exceeds the quota")
	}
}

// TestRetainPayload_ChunkBeforeMetadata_InvalidArgument drives a raw stream
// (bypassing the high-level client, which would never produce this sequence)
// whose FIRST frame is a chunk — the wire contract requires metadata first.
func TestRetainPayload_ChunkBeforeMetadata_InvalidArgument(t *testing.T) {
	h := newHarness(t, 1<<20)
	raw := payloadpbconnect.NewPayloadStoreServiceClient(h.httpc, h.url)
	stream := raw.RetainPayload(context.Background())

	if err := stream.Send(&payloadpb.RetainPayloadRequest{
		Frame: &payloadpb.RetainPayloadRequest_Chunk{Chunk: []byte("x")},
	}); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("send chunk: %v", err)
	}
	_, err := stream.CloseAndReceive()
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("chunk-before-metadata: code = %v (%v), want InvalidArgument", connect.CodeOf(err), err)
	}
}

// TestRetainPayload_DoubleMetadata_InvalidArgument_AbortObserved drives a raw
// stream whose SECOND frame is ALSO metadata — every frame after the first
// must be a chunk. The writer opened after the first (valid) metadata must be
// Aborted, not left dangling.
func TestRetainPayload_DoubleMetadata_InvalidArgument_AbortObserved(t *testing.T) {
	h := newHarness(t, 1<<20)
	raw := payloadpbconnect.NewPayloadStoreServiceClient(h.httpc, h.url)
	stream := raw.RetainPayload(context.Background())

	meta := &payloadpb.RetainPayloadRequest{Frame: &payloadpb.RetainPayloadRequest_Metadata{
		Metadata: &payloadpb.RetainPayloadMetadata{
			OwnerDid:     nodeDID,
			DeclaredSize: 5,
			AuthProof:    mustProof(t, h.signer, nodeDID, nodeDID, 5),
		},
	}}
	if err := stream.Send(meta); err != nil {
		t.Fatalf("send first metadata: %v", err)
	}
	if err := stream.Send(meta); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("send second metadata: %v", err)
	}
	_, err := stream.CloseAndReceive()
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("double metadata: code = %v (%v), want InvalidArgument", connect.CodeOf(err), err)
	}
	if h.store.last == nil || h.store.last.aborts != 1 {
		t.Errorf("writer must be Aborted on a duplicate metadata frame, got %+v", h.store.last)
	}
}

// TestRetainPayload_PerChunkReadCap_ResourceExhausted_AbortObserved proves the
// mount-level connect.WithReadMaxBytes cap (max-retain-chunk-size in
// production) is this RPC's real per-chunk defense: a single chunk frame over
// the cap is rejected by connect itself (never reaching the handler's own
// byte-accounting), and the handler must still Abort on that receive error —
// not swallow it into CodeInternal (mapError must pass an already-coded
// connect error through unchanged).
func TestRetainPayload_PerChunkReadCap_ResourceExhausted_AbortObserved(t *testing.T) {
	const readCap = 1000 // comfortably above one metadata frame, well below one 5000-byte chunk
	h := newHarness(t, 1<<20, connect.WithReadMaxBytes(readCap))
	payload := bytes.Repeat([]byte("y"), 5000) // one chunk frame (default RetainChunkSize) >> readCap

	_, err := h.client.Retain(context.Background(), bytes.NewReader(payload), nodeDID, uint64(len(payload)))
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("per-chunk cap: code = %v (%v), want ResourceExhausted", connect.CodeOf(err), err)
	}
	if h.store.last == nil || h.store.last.aborts != 1 {
		t.Errorf("writer must be Aborted when a chunk frame exceeds the mount's read cap, got %+v", h.store.last)
	}
}
