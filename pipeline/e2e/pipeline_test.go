// Package e2e is an in-memory integration test wiring all three process-type
// runtimes through real transport.Loops: a raw external push becomes a Source
// FirstDrop, a Chained Process verifies + transforms + re-signs chain-preserving,
// and a Sink Process verifies the full chain and writes an NDJSON record.
//
// What is REAL here: the envelope codec round-trip, the payload↔credential
// binding gates, the previousCredential chain linkage, the chainwalk resolver
// walk assembling the 2-hop chain, the transport loop's sequence numbering and
// emission logging, the ingress-VC stores, and the console NDJSON output.
//
// What is FAKED: the verification VERDICTS. vc.Verifier.Verify / VerifyChain
// are panic stubs pending the resolver/crypto layer, so the injected
// provenance.Verifier and chainwalk.ChainCore return ConfidenceVerified. The
// signers use vc.New (unsigned) — real DID-backed signing also lands with the
// network layer. This test proves the pipeline WIRES and FLOWS end to end; real
// cryptographic verification is the network/crypto step.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/provin-line/oss/pipeline/chained"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/provenance/chainwalk"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/pipeline/sink/console"
	"github.com/provin-line/oss/pipeline/source/ingest"
	"github.com/provin-line/oss/pipeline/transport"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/vc"
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
// Signers register issued credentials by content address; the sink's chainwalk
// resolves predecessors from it.
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
// Signers (vc.New, unsigned) — register every issued credential in the resolver.
// ---------------------------------------------------------------------------

type sourceSigner struct {
	t   *testing.T
	res *memResolver
}

func (s *sourceSigner) SignFirstDrop(_ context.Context, _ []byte, inputHash, outputHash string) (*vc.PipelinePassCredential, error) {
	c, err := vc.New(vc.CredentialFields{
		Issuer:    "did:example:source",
		ValidFrom: time.Now(),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "pipe",
			ProcessID:           "source",
			TransformationClaim: vc.ClaimConvert,
			InputHash:           inputHash,
			OutputHash:          outputHash,
		},
	})
	if err != nil {
		return nil, err
	}
	s.res.register(s.t, c)
	return c, nil
}

type chainedSigner struct {
	t   *testing.T
	res *memResolver
}

func (s *chainedSigner) SignChainPreserving(_ context.Context, _ []byte, inputHash, outputHash string, predecessor *vc.PipelinePassCredential) (*vc.PipelinePassCredential, error) {
	prevAddr, err := predecessor.Hash()
	if err != nil {
		return nil, err
	}
	c, err := vc.New(vc.CredentialFields{
		Issuer:    "did:example:chained",
		ValidFrom: time.Now(),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "pipe",
			ProcessID:           "chained",
			TransformationClaim: vc.ClaimConvert,
			InputHash:           inputHash,
			OutputHash:          outputHash,
		},
		PreviousCredential: prevAddr,
	})
	if err != nil {
		return nil, err
	}
	s.res.register(s.t, c)
	return c, nil
}

// ---------------------------------------------------------------------------
// Faked verification verdicts (vc.Verifier is a stub today).
// ---------------------------------------------------------------------------

type okVerifier struct{}

func (okVerifier) Verify(_ context.Context, _ *vc.PipelinePassCredential) (*vc.VerifyResult, error) {
	return &vc.VerifyResult{Overall: vc.ConfidenceVerified}, nil
}

// okChainCore is the chainwalk.ChainCore: it receives the assembled chain and
// returns a verdict. It records the assembled length so the test can assert the
// walk reached the origin.
type okChainCore struct {
	gotLen int
}

func (c *okChainCore) VerifyChain(_ context.Context, chain []*vc.PipelinePassCredential) (*vc.VerifyResult, error) {
	c.gotLen = len(chain)
	return &vc.VerifyResult{Overall: vc.ConfidenceVerified}, nil
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

func TestPipeline_SourceChainedSink_EndToEnd(t *testing.T) {
	codec := envelopecodec.New()
	res := newMemResolver()

	// Brokers: ingress (raw push → source), source → chained, chained → sink.
	bIngress := newBroker()
	bSourceChained := newBroker()
	bChainedSink := newBroker()

	// --- Source (ingest, FirstDrop) ---
	srcProc, err := ingest.New(ingest.Config{Signer: &sourceSigner{t: t, res: res}})
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
		Verifier:          okVerifier{},
		Store:             chainedStore,
		Signer:            &chainedSigner{t: t, res: res},
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

	// --- Sink (verify full via chainwalk, console NDJSON) ---
	core := &okChainCore{}
	chainVerifier, err := chainwalk.New(res, core)
	if err != nil {
		t.Fatalf("chainwalk.New: %v", err)
	}
	var out bytes.Buffer
	sinkStore := &memStore{}
	skProc, err := sink.New(sink.Config{
		Strategy:         contract.VerificationFull,
		Kind:             contract.SinkObservationOnly,
		Codec:            codec,
		ChainVerifier:    chainVerifier,
		Store:            sinkStore,
		Writer:           console.New(&out),
		UpstreamEndpoint: "mem://chained",
	})
	if err != nil {
		t.Fatalf("sink.New: %v", err)
	}
	skLoop, err := transport.NewLoop(transport.LoopConfig{
		Behavior:   contract.ChainTerminating,
		Strategy:   contract.VerificationFull,
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

	// Inject one raw external push. Publish dispatches synchronously, so the
	// full source→chained→sink chain completes before Publish returns.
	payload := []byte(`{"reading":42}`)
	if err := bIngress.Publish(payload); err != nil {
		t.Fatalf("inject: %v", err)
	}

	// --- Assertions: the event reached the sink as a verified NDJSON record ---
	line := bytes.TrimSpace(out.Bytes())
	if len(line) == 0 {
		t.Fatal("sink wrote nothing — the event did not flow end to end")
	}
	if n := countLines(out.Bytes()); n != 1 {
		t.Fatalf("sink wrote %d NDJSON lines, want exactly 1", n)
	}
	var rec struct {
		Credential string          `json:"credential"`
		Confidence string          `json:"confidence"`
		Payload    json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		t.Fatalf("sink record is not valid JSON: %v (%q)", err, line)
	}
	if rec.Confidence != "verified" {
		t.Errorf("sink confidence=%q, want verified", rec.Confidence)
	}
	// The payload survived source (verbatim) and chained (passthrough) intact.
	if string(rec.Payload) != string(payload) {
		t.Errorf("sink payload=%q, want %q", rec.Payload, payload)
	}

	// The sink's chainwalk assembled the full 2-hop chain (chained head + source
	// origin) — proving the resolver walk followed previousCredential to the
	// FirstDrop.
	if core.gotLen != 2 {
		t.Errorf("chainwalk assembled chain length=%d, want 2 (chained + source origin)", core.gotLen)
	}
	if len(res.resolns) != 1 {
		t.Errorf("resolver resolutions=%d, want 1 (the source origin)", len(res.resolns))
	}

	// Both producing processes recorded an emission; both consuming boundaries
	// stored their ingress VC.
	if srcLog.count() != 1 {
		t.Errorf("source emission records=%d, want 1", srcLog.count())
	}
	if chLog.count() != 1 {
		t.Errorf("chained emission records=%d, want 1", chLog.count())
	}
	if chainedStore.count() != 1 {
		t.Errorf("chained ingress store=%d, want 1 (the source FirstDrop)", chainedStore.count())
	}
	if sinkStore.count() != 1 {
		t.Errorf("sink ingress store=%d, want 1 (the chained credential)", sinkStore.count())
	}

	cancel()
	wg.Wait()
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
