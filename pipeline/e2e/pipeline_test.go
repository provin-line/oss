// Package e2e is an in-memory integration test wiring all three process-type
// runtimes through real transport.Loops: a raw external push becomes a Source
// FirstDrop, a Chained Process verifies + transforms + re-signs chain-preserving,
// and a Sink Process verifies the adjacent credential and writes an NDJSON record.
//
// Everything on this path is REAL: real Ed25519 Data Integrity signing through
// vcdid.Signer (over a keystore-backed vc.Builder), real credential
// verification through vc.Verifier resolving Process DID Documents from a local
// resolver — the three confidence axes, the controller-chain walk to the owner,
// the previousCredential linkage, the outputHash[n] == inputHash[n+1] data-flow
// invariant, and proof.created monotonicity. Around the crypto: the envelope
// codec round-trip, the payload↔credential binding gates, the transport loop's
// sequence numbering and emission logging, the ingress-VC stores, and the
// console NDJSON output. A genuine source→chained→sink flow ends in a
// cryptographically verified sink record.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/pipeline/chained"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/provenance/vcdid"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/pipeline/sink/console"
	"github.com/provin-line/oss/pipeline/source/ingest"
	"github.com/provin-line/oss/pipeline/transport"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	"github.com/provin-line/oss/resolver/local"
	schemalocal "github.com/provin-line/oss/schema/local"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/vc"
)

// readingSchema constrains the pipeline payload: an object with a numeric
// "reading". The chained process validates its input and output against it.
var readingSchema = []byte(`{
	"type": "object",
	"required": ["reading"],
	"properties": { "reading": { "type": "number" } },
	"additionalProperties": false
}`)

const readingSchemaID = "schema:reading"

// readingValidator builds a schema validator registered with readingSchema and
// the matching content-addressed SchemaRef.
func readingValidator(t *testing.T) (*schemalocal.Validator, vc.SchemaRef) {
	t.Helper()
	v := schemalocal.New()
	if err := v.Add(readingSchemaID, readingSchema); err != nil {
		t.Fatalf("schema Add: %v", err)
	}
	sum := sha256.Sum256(readingSchema)
	return v, vc.SchemaRef{ID: readingSchemaID, Type: "JsonSchema", ContentHash: "sha256:" + hex.EncodeToString(sum[:])}
}

// Process / owner identities for the two issuing processes, under one owner.
const (
	ownerDID   = "did:dplaax:poc.dplaax.dev:org:acme"
	sourceDID  = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pipe:process:source"
	chainedDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pipe:process:chained"
)

// ---------------------------------------------------------------------------
// In-memory transport: one broker links an upstream Publisher to a downstream
// Subscriber. Publish dispatches synchronously to the registered handler, so a
// single injected event drives the whole chain on the caller's goroutine.
// ---------------------------------------------------------------------------

type broker struct {
	mu      sync.Mutex
	handler func([]byte)
	ready   chan struct{}
}

func newBroker() *broker { return &broker{ready: make(chan struct{})} }

func (b *broker) Subscribe(h func([]byte)) error {
	b.mu.Lock()
	b.handler = h
	b.mu.Unlock()
	close(b.ready)
	return nil
}

func (b *broker) Drain() error { return nil }

func (b *broker) Publish(data []byte) error {
	b.mu.Lock()
	h := b.handler
	b.mu.Unlock()
	if h == nil {
		return errors.New("broker: no subscriber")
	}
	h(data)
	return nil
}

func (b *broker) Healthy() bool { return true }
func (b *broker) Close() error  { return nil }

// ---------------------------------------------------------------------------
// In-memory credential resolver (shared) — the chainwalk's CredentialResolver.
// The registering signers record issued credentials by content address; the
// sink's chainwalk resolves predecessors from it.
// ---------------------------------------------------------------------------

type memResolver struct {
	mu      sync.Mutex
	byAddr  map[string]*vc.PipelinePassCredential
	resolns []string
}

func newMemResolver() *memResolver {
	return &memResolver{byAddr: map[string]*vc.PipelinePassCredential{}}
}

func (m *memResolver) register(t *testing.T, c *vc.PipelinePassCredential) {
	t.Helper()
	a, err := c.Hash()
	if err != nil {
		t.Fatalf("resolver register hash: %v", err)
	}
	m.mu.Lock()
	m.byAddr[a] = c
	m.mu.Unlock()
}

func (m *memResolver) ResolveCredential(_ context.Context, addr string) (*vc.PipelinePassCredential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resolns = append(m.resolns, addr)
	c, ok := m.byAddr[addr]
	if !ok {
		return nil, errors.New("not found: " + addr)
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// Real signing: a keystore-backed vc.Builder behind vcdid.Signers, one per
// issuing process. registeringSigner records every issued credential in the
// shared resolver so the sink's chainwalk can reassemble the chain.
// ---------------------------------------------------------------------------

type memKeyStore struct{ keys map[string][]byte }

func newMemKeyStore() *memKeyStore { return &memKeyStore{keys: map[string][]byte{}} }
func (m *memKeyStore) SaveKeyPair(d string, keys map[keystore.KeyID]*crypto.KeyPair) error {
	for id, kp := range keys {
		m.keys[d+"#"+string(id)] = kp.PrivateKey
	}
	return nil
}
func (m *memKeyStore) GetPrivateKey(d string, id keystore.KeyID) ([]byte, error) {
	k, ok := m.keys[d+"#"+string(id)]
	if !ok {
		return nil, fmt.Errorf("key not found: %w", keystore.ErrNotFound)
	}
	return k, nil
}
func (m *memKeyStore) Sign(d string, id string, data []byte) ([]byte, error) {
	priv, err := m.GetPrivateKey(d, keystore.KeyID(id))
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, data)
}
func (m *memKeyStore) DeleteKeys(string) error { return nil }

// registeringSigner adds resolver registration around a vcdid.Signer — a test
// stand-in for the network layer that publishes issued credentials to the VC
// store. It carries both signing capabilities through the embedded Signer.
type registeringSigner struct {
	*vcdid.Signer
	res *memResolver
	t   *testing.T
}

func (r *registeringSigner) SignFirstDrop(ctx context.Context, payload []byte, inputHash, outputHash string) (*vc.PipelinePassCredential, error) {
	c, err := r.Signer.SignFirstDrop(ctx, payload, inputHash, outputHash)
	if err == nil {
		r.res.register(r.t, c)
	}
	return c, err
}

func (r *registeringSigner) SignChainPreserving(ctx context.Context, payload []byte, inputHash, outputHash string, predecessor *vc.PipelinePassCredential) (*vc.PipelinePassCredential, error) {
	c, err := r.Signer.SignChainPreserving(ctx, payload, inputHash, outputHash, predecessor)
	if err == nil {
		r.res.register(r.t, c)
	}
	return c, err
}

// SignAggregateFirstDrop MUST be overridden explicitly: the embedded *vcdid.Signer
// now carries this method, and Go method promotion would otherwise expose it directly
// — bypassing the resolver registration this decorator exists to perform (D-17k-6).
func (r *registeringSigner) SignAggregateFirstDrop(ctx context.Context, payload []byte, outputHash string, sources []*vc.PipelinePassCredential) (*vc.PipelinePassCredential, error) {
	c, err := r.Signer.SignAggregateFirstDrop(ctx, payload, outputHash, sources)
	if err == nil {
		r.res.register(r.t, c)
	}
	return c, err
}

// TestRegisteringSigner_AggregateOverridden guards D-17k-6: because registeringSigner
// EMBEDS *vcdid.Signer, the newly added SignAggregateFirstDrop would be promoted and
// expose the embedded method directly — bypassing res.register. The explicit override
// above prevents that; this test fails if the override is removed (the issued
// aggregate credential would not be resolvable).
func TestRegisteringSigner_AggregateOverridden(t *testing.T) {
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	ks := newMemKeyStore()
	if err := ks.SaveKeyPair(sourceDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatalf("save key: %v", err)
	}
	builder := vc.NewBuilder(ks)
	aggSig, err := vcdid.NewSigner(vcdid.Config{
		Builder: builder, IssuerDID: sourceDID, KeyID: string(keystore.KeyIDSigning),
		VerificationMethod: sourceDID + "#signing", PipelineID: "pipe", ProcessID: "agg",
		TransformationClaim: vc.ClaimAggregate, SourceRootCanonical: vc.SourceRootCanonicalJCS,
	})
	if err != nil {
		t.Fatalf("aggregate vcdid.NewSigner: %v", err)
	}
	res := newMemResolver()
	rs := &registeringSigner{Signer: aggSig, res: res, t: t}

	// One signed source to fold (its own issuer); register it so the consumed set is
	// resolvable, then aggregate over it.
	src, err := aggSig.SignAggregateFirstDrop(context.Background(), []byte(`{"s":1}`), "sha256:src", nil)
	if err != nil {
		t.Fatalf("source aggregate sign: %v", err)
	}
	cred, err := rs.SignAggregateFirstDrop(context.Background(), []byte(`{"agg":1}`), "sha256:out",
		[]*vc.PipelinePassCredential{src})
	if err != nil {
		t.Fatalf("registeringSigner.SignAggregateFirstDrop: %v", err)
	}
	addr, err := cred.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := res.ResolveCredential(context.Background(), addr); err != nil {
		t.Fatalf("aggregate credential was not registered (promotion bypassed the decorator?): %v", err)
	}
}

// ---------------------------------------------------------------------------
// DID documents: each process's #signing assertion key, controlled by the
// process and the process controlled by the owner; the owner self-controlled.
// ---------------------------------------------------------------------------

func processDoc(processDID, owner string, pub []byte) *did.DIDDocument {
	return did.New(did.DocumentFields{
		ID:         processDID,
		Controller: owner,
		VerificationMethod: []did.VerificationMethod{{
			ID:         processDID + "#signing",
			Type:       "JsonWebKey2020",
			Controller: processDID,
			PublicKeyJWK: map[string]any{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(pub),
			},
		}},
		AssertionMethod: []string{processDID + "#signing"},
	})
}

func ownerDoc(owner string) *did.DIDDocument {
	return did.New(did.DocumentFields{ID: owner, Controller: owner})
}

// ---------------------------------------------------------------------------
// In-memory ingress store and emission log.
// ---------------------------------------------------------------------------

type memStore struct {
	mu    sync.Mutex
	creds []*vc.PipelinePassCredential
}

func (m *memStore) StoreIngressVC(_ context.Context, c *vc.PipelinePassCredential, _ string) error {
	m.mu.Lock()
	m.creds = append(m.creds, c)
	m.mu.Unlock()
	return nil
}

func (m *memStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.creds)
}

type memLog struct {
	mu      sync.Mutex
	records [][]byte
}

func (m *memLog) Append(_ context.Context, payload []byte) (*tlog.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := uint64(len(m.records))
	cp := append([]byte(nil), payload...)
	m.records = append(m.records, cp)
	return &tlog.Record{Index: idx, Payload: cp, Hash: "sha256:" + hex.EncodeToString(sha256Sum(cp))}, nil
}

func (m *memLog) Get(_ context.Context, i uint64) (*tlog.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if i >= uint64(len(m.records)) {
		return nil, errors.New("out of range")
	}
	return &tlog.Record{Index: i, Payload: m.records[i]}, nil
}

func (m *memLog) Size(_ context.Context) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return uint64(len(m.records)), nil
}

func (m *memLog) Checkpoint(_ context.Context) (*tlog.Checkpoint, error) {
	return &tlog.Checkpoint{}, nil
}

func (m *memLog) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.records)
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// ---------------------------------------------------------------------------
// The end-to-end flow
// ---------------------------------------------------------------------------

// e2eOutcome is what one pipeline run produced, for the test to assert over.
type e2eOutcome struct {
	out          *bytes.Buffer
	res          *memResolver
	srcLog       *memLog
	chLog        *memLog
	chainedStore *memStore
	sinkStore    *memStore
	payload      []byte
}

// runPipeline wires and runs the full source→chained→sink pipeline with real
// signing and verification, injecting one event. wireDocs populates the DID
// resolver from the issuers' public keys — letting a caller omit a document to
// exercise a verification failure end to end.
func runPipeline(t *testing.T, payload []byte, wireDocs func(didRes *local.Resolver, srcPub, chPub []byte)) e2eOutcome {
	t.Helper()
	codec := envelopecodec.New()
	res := newMemResolver()
	schemaValidator, schemaRef := readingValidator(t)

	kpSource, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("keygen source: %v", err)
	}
	kpChained, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("keygen chained: %v", err)
	}
	ks := newMemKeyStore()
	if err := ks.SaveKeyPair(sourceDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kpSource}); err != nil {
		t.Fatalf("save source key: %v", err)
	}
	if err := ks.SaveKeyPair(chainedDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kpChained}); err != nil {
		t.Fatalf("save chained key: %v", err)
	}
	builder := vc.NewBuilder(ks)

	didRes := local.New()
	wireDocs(didRes, kpSource.PublicKey, kpChained.PublicKey)
	verifier := vc.NewVerifier(didRes, ed25519.Verifier{})

	sourceSig, err := vcdid.NewSigner(vcdid.Config{
		Builder: builder, IssuerDID: sourceDID, KeyID: string(keystore.KeyIDSigning),
		VerificationMethod: sourceDID + "#signing",
		PipelineID:         "pipe", ProcessID: "source", TransformationClaim: vc.ClaimConvert,
	})
	if err != nil {
		t.Fatalf("source vcdid.NewSigner: %v", err)
	}
	chainedSig, err := vcdid.NewSigner(vcdid.Config{
		Builder: builder, IssuerDID: chainedDID, KeyID: string(keystore.KeyIDSigning),
		VerificationMethod: chainedDID + "#signing",
		PipelineID:         "pipe", ProcessID: "chained", TransformationClaim: vc.ClaimConvert,
	})
	if err != nil {
		t.Fatalf("chained vcdid.NewSigner: %v", err)
	}

	// Brokers: ingress (raw push → source), source → chained, chained → sink.
	bIngress := newBroker()
	bSourceChained := newBroker()
	bChainedSink := newBroker()

	// --- Source (ingest, FirstDrop) ---
	srcProc, err := ingest.New(ingest.Config{Signer: &registeringSigner{Signer: sourceSig, res: res, t: t}})
	if err != nil {
		t.Fatalf("ingest.New: %v", err)
	}
	srcLog := &memLog{}
	srcLoop, err := transport.NewLoop(transport.LoopConfig{
		Behavior:   contract.ChainFirstDrop,
		Strategy:   contract.VerificationNone,
		Processor:  srcProc,
		Subscriber: bIngress,
		Publisher:  bSourceChained,
		Codec:      codec,
		Emission:   srcLog,
	})
	if err != nil {
		t.Fatalf("source NewLoop: %v", err)
	}

	// --- Chained (verify adjacent, passthrough, chain-preserving) ---
	chainedStore := &memStore{}
	chProc, err := chained.New(chained.Config{
		Strategy:          contract.VerificationAdjacent,
		IngressConformant: true,
		UpstreamEndpoint:  "mem://source",
		Codec:             codec,
		Verifier:          verifier,
		Store:             chainedStore,
		Signer:            &registeringSigner{Signer: chainedSig, res: res, t: t},
		// Real schema validation on input and output (passthrough: output == input).
		InputValidator:  schemaValidator,
		InputSchemaRef:  schemaRef,
		OutputValidator: schemaValidator,
		OutputSchemaRef: schemaRef,
		// nil Converter → passthrough; output == input payload.
	})
	if err != nil {
		t.Fatalf("chained.New: %v", err)
	}
	chLog := &memLog{}
	chLoop, err := transport.NewLoop(transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  chProc,
		Subscriber: bSourceChained,
		Publisher:  bChainedSink,
		Codec:      codec,
		Emission:   chLog,
	})
	if err != nil {
		t.Fatalf("chained NewLoop: %v", err)
	}

	// --- Sink (verify adjacent, console NDJSON) ---
	var out bytes.Buffer
	sinkStore := &memStore{}
	skProc, err := sink.New(sink.Config{
		Strategy:         contract.VerificationAdjacent,
		Kind:             contract.SinkObservationOnly,
		Codec:            codec,
		Verifier:         verifier,
		Store:            sinkStore,
		Writer:           console.New(&out),
		UpstreamEndpoint: "mem://chained",
	})
	if err != nil {
		t.Fatalf("sink.New: %v", err)
	}
	skLoop, err := transport.NewLoop(transport.LoopConfig{
		Behavior:   contract.ChainTerminating,
		Strategy:   contract.VerificationAdjacent,
		Processor:  skProc,
		Subscriber: bChainedSink,
		// ChainTerminating: no Publisher/Codec/Emission.
	})
	if err != nil {
		t.Fatalf("sink NewLoop: %v", err)
	}

	// Run all three loops; wait until each has subscribed.
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, l := range []*transport.Loop{srcLoop, chLoop, skLoop} {
		wg.Add(1)
		go func(lp *transport.Loop) { defer wg.Done(); _ = lp.Run(ctx) }(l)
	}
	<-bIngress.ready
	<-bSourceChained.ready
	<-bChainedSink.ready

	// Inject the raw external push. Publish dispatches synchronously, so the
	// full source→chained→sink chain completes before Publish returns.
	if err := bIngress.Publish(payload); err != nil {
		t.Fatalf("inject: %v", err)
	}

	cancel()
	wg.Wait()
	return e2eOutcome{
		out: &out, res: res,
		srcLog: srcLog, chLog: chLog,
		chainedStore: chainedStore, sinkStore: sinkStore,
		payload: payload,
	}
}

// allDocs registers every Process and Owner document — the genuine-verification
// wiring.
func allDocs(didRes *local.Resolver, srcPub, chPub []byte) {
	didRes.Add(processDoc(sourceDID, ownerDID, srcPub))
	didRes.Add(processDoc(chainedDID, ownerDID, chPub))
	didRes.Add(ownerDoc(ownerDID))
}

// sinkRecord parses the single NDJSON line the observation sink wrote.
func sinkRecord(t *testing.T, out *bytes.Buffer) (confidence string, payload []byte) {
	t.Helper()
	line := bytes.TrimSpace(out.Bytes())
	if len(line) == 0 {
		t.Fatal("sink wrote nothing — the event did not flow end to end")
	}
	if n := countLines(out.Bytes()); n != 1 {
		t.Fatalf("sink wrote %d NDJSON lines, want exactly 1", n)
	}
	var rec struct {
		Confidence string          `json:"confidence"`
		Payload    json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		t.Fatalf("sink record is not valid JSON: %v (%q)", err, line)
	}
	return rec.Confidence, rec.Payload
}

// With every DID document present, the event reaches the sink as a genuinely
// verified record: the verdict required both Process DIDs to resolve, both
// signatures to verify, both controller chains to reach the owner, and the
// chain structure (linkage / data-flow / ordering) to hold.
func TestPipeline_SourceChainedSink_EndToEnd(t *testing.T) {
	o := runPipeline(t, []byte(`{"reading":42}`), allDocs)

	confidence, payload := sinkRecord(t, o.out)
	if confidence != "verified" {
		t.Errorf("sink confidence=%q, want verified", confidence)
	}
	// The payload survived source (verbatim) and chained (passthrough) intact.
	if string(payload) != string(o.payload) {
		t.Errorf("sink payload=%q, want %q", payload, o.payload)
	}

	// Both producing processes recorded an emission; both consuming boundaries
	// stored their ingress VC.
	if o.srcLog.count() != 1 {
		t.Errorf("source emission records=%d, want 1", o.srcLog.count())
	}
	if o.chLog.count() != 1 {
		t.Errorf("chained emission records=%d, want 1", o.chLog.count())
	}
	if o.chainedStore.count() != 1 {
		t.Errorf("chained ingress store=%d, want 1 (the source FirstDrop)", o.chainedStore.count())
	}
	if o.sinkStore.count() != 1 {
		t.Errorf("sink ingress store=%d, want 1 (the chained credential)", o.sinkStore.count())
	}
}

// Negative control: with the chained Process's DID document absent, the sink's
// full-chain verification cannot authenticate the chained credential, so the
// observation sink still writes the record (its policy surfaces failures) but
// NOT as verified. This proves the positive test's "verified" is sensitive to a
// real cryptographic failure, not a constant.
func TestPipeline_MissingChainedDoc_NotVerified(t *testing.T) {
	o := runPipeline(t, []byte(`{"reading":42}`), func(didRes *local.Resolver, srcPub, chPub []byte) {
		didRes.Add(processDoc(sourceDID, ownerDID, srcPub))
		// chainedDID document deliberately omitted.
		didRes.Add(ownerDoc(ownerDID))
	})

	confidence, _ := sinkRecord(t, o.out)
	if confidence == "verified" {
		t.Errorf("sink confidence=%q, want a non-verified verdict (chained DID doc absent)", confidence)
	}
}

// Negative control: a payload that violates the input schema is dropped by the
// chained process (StatusErrored — a loud drop), so nothing is ever published
// downstream and the sink writes nothing. This proves the schema gate is active
// and actually gating, not a no-op.
func TestPipeline_SchemaViolation_DroppedAtChained(t *testing.T) {
	o := runPipeline(t, []byte(`{"reading":"hot"}`), allDocs) // reading must be a number

	if line := bytes.TrimSpace(o.out.Bytes()); len(line) != 0 {
		t.Errorf("sink wrote %q, want nothing (schema-violating payload must be dropped at the chained process)", line)
	}
	// The chained process recorded no emission and stored no ingress VC beyond
	// the (verified) source credential it consumed before validating.
	if o.chLog.count() != 0 {
		t.Errorf("chained emission records=%d, want 0 (input rejected)", o.chLog.count())
	}
}

func countLines(b []byte) int {
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) > 0 {
			n++
		}
	}
	return n
}
