package aggregate

// In-package tests drive the runtime SYNCHRONOUSLY: handleIngress and foldOnce
// are called directly (no goroutine, no ticker, no sleep), so every assertion is
// deterministic and race-free by construction — fitting for the slice whose
// thesis is concurrency correctness. Two dedicated tests exercise the Run
// lifecycle (subscribe + shutdown, and subscribe-failure drain) with a goroutine,
// reading stubs only after Run has returned.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	"github.com/provin-line/oss/tlog/memlog"
	"github.com/provin-line/oss/vc"
)

// --- stubs ------------------------------------------------------------------

type captureSubscriber struct {
	handler      func([]byte)
	subscribeErr error
	drained      bool
}

func (s *captureSubscriber) Subscribe(h func([]byte)) error {
	if s.subscribeErr != nil {
		return s.subscribeErr
	}
	s.handler = h
	return nil
}
func (s *captureSubscriber) Drain() error { s.drained = true; return nil }

type stubVerifier struct{ state vc.ConfidenceState }

func (v stubVerifier) Verify(_ context.Context, _ *vc.PipelinePassCredential) (*vc.VerifyResult, error) {
	return &vc.VerifyResult{Overall: v.state}, nil
}

type recordStore struct {
	calls   []string
	failErr error
}

func (s *recordStore) StoreIngressVC(_ context.Context, _ *vc.PipelinePassCredential, upstream string) error {
	if s.failErr != nil {
		return s.failErr
	}
	s.calls = append(s.calls, upstream)
	return nil
}

type recordPublisher struct {
	calls  [][]byte
	closed bool
}

func (p *recordPublisher) Publish(data []byte) error {
	p.calls = append(p.calls, append([]byte(nil), data...))
	return nil
}
func (p *recordPublisher) Healthy() bool { return true }
func (p *recordPublisher) Close() error  { p.closed = true; return nil }

type recordSigner struct {
	gotSources [][]*vc.PipelinePassCredential
	failErr    error
}

func (s *recordSigner) SignAggregateFirstDrop(_ context.Context, _ []byte, outputHash string, sources []*vc.PipelinePassCredential) (*vc.PipelinePassCredential, error) {
	if s.failErr != nil {
		return nil, s.failErr
	}
	s.gotSources = append(s.gotSources, sources)
	return vc.New(vc.CredentialFields{
		Issuer:    "did:example:aggregator",
		ValidFrom: time.Unix(0, 0),
		Subject: vc.CredentialSubjectFields{
			PipelineID: "agg", ProcessID: "a1",
			TransformationClaim: vc.ClaimAggregate, OutputHash: outputHash,
		},
	})
}

type recordObserver struct{ events []contract.ProcessEvent }

func (o *recordObserver) OnProcessComplete(_ context.Context, ev contract.ProcessEvent) error {
	o.events = append(o.events, ev)
	return nil
}

// --- helpers ----------------------------------------------------------------

func testHash(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// ingressEnvelope builds a wire envelope whose credential OutputHash binds to
// payload, carried inline. issuer varies so the consumed set spans issuers.
func ingressEnvelope(t *testing.T, issuer string, payload []byte) []byte {
	t.Helper()
	return ingressEnvelopeWith(t, issuer, payload, payload)
}

// ingressEnvelopeWith binds the credential OutputHash to hashSrc while carrying
// data — a mismatch (hashSrc != data) exercises the binding gate.
func ingressEnvelopeWith(t *testing.T, issuer string, hashSrc, data []byte) []byte {
	t.Helper()
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    issuer,
		ValidFrom: time.Unix(0, 0),
		Subject: vc.CredentialSubjectFields{
			PipelineID: "src", ProcessID: "p",
			TransformationClaim: vc.ClaimConvert, OutputHash: testHash(hashSrc),
		},
	})
	if err != nil {
		t.Fatalf("vc.New: %v", err)
	}
	wire, err := envelopecodec.New().MarshalEnvelope(&contract.Envelope{Credential: cred, Payload: data, SequenceNo: 1})
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	return wire
}

type harness struct {
	p     *Process
	sub   *captureSubscriber
	store *recordStore
	pub   *recordPublisher
	sign  *recordSigner
	obs   *recordObserver
	emis  *memlog.Log
}

func newHarness(t *testing.T, opts func(*Config)) *harness {
	t.Helper()
	sub := &captureSubscriber{}
	store := &recordStore{}
	pub := &recordPublisher{}
	sign := &recordSigner{}
	obs := &recordObserver{}
	emis := memlog.New()
	cfg := Config{
		Ingress:   []Ingress{{Subscriber: sub, UpstreamEndpoint: "https://up.example/src"}},
		Window:    time.Hour,
		Signer:    sign,
		Verifier:  stubVerifier{state: vc.ConfidenceVerified},
		Store:     store,
		Publisher: pub,
		Codec:     envelopecodec.New(),
		Emission:  emis,
		Fold:      ManifestFold{},
		Observers: []contract.ProcessObserver{obs},
		Now:       func() time.Time { return time.Unix(0, 0) },
	}
	if opts != nil {
		opts(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &harness{p: p, sub: sub, store: store, pub: pub, sign: sign, obs: obs, emis: emis}
}

// feed drives one ingress input synchronously through the handler.
func (h *harness) feed(wire []byte) {
	h.p.handleIngress(context.Background(), wire, "https://up.example/src")
}

// --- tests ------------------------------------------------------------------

// Capstone: two distinct-issuer inputs are pooled and folded into one aggregate
// FirstDrop. The signer gets both credentials, the emitted payload is the fold
// output with a matching outputHash, claim is aggregate, the emission log
// advanced, and an observer event fired with OutputHash + IssuedVCRef + a
// Verified confidence (inputs were adjacent-verified).
func TestProcess_Capstone_PoolsFoldsSignsEmits(t *testing.T) {
	h := newHarness(t, nil)
	h.feed(ingressEnvelope(t, "did:example:a", []byte(`{"v":1}`)))
	h.feed(ingressEnvelope(t, "did:example:b", []byte(`{"v":2}`)))

	if !h.p.foldOnce(context.Background()) {
		t.Fatal("foldOnce returned false, want emitted")
	}

	if len(h.store.calls) != 2 {
		t.Errorf("StoreIngressVC calls = %d, want 2", len(h.store.calls))
	}
	if len(h.sign.gotSources) != 1 || len(h.sign.gotSources[0]) != 2 {
		t.Fatalf("signer sources = %v, want one fold of 2", h.sign.gotSources)
	}
	if len(h.pub.calls) != 1 {
		t.Fatalf("published = %d, want 1", len(h.pub.calls))
	}
	env, err := envelopecodec.New().UnmarshalEnvelope(h.pub.calls[0])
	if err != nil {
		t.Fatalf("decode emitted: %v", err)
	}
	var manifest struct {
		Sources []string `json:"sources"`
		Count   int      `json:"count"`
	}
	if err := json.Unmarshal(env.Payload, &manifest); err != nil {
		t.Fatalf("fold output not JSON: %v", err)
	}
	if manifest.Count != 2 {
		t.Errorf("manifest count = %d, want 2", manifest.Count)
	}
	subj, _ := env.Credential.Subject()
	if subj.OutputHash != testHash(env.Payload) {
		t.Errorf("outputHash %q != sha256(payload) %q", subj.OutputHash, testHash(env.Payload))
	}
	if subj.TransformationClaim != vc.ClaimAggregate {
		t.Errorf("claim = %q, want aggregate", subj.TransformationClaim)
	}
	if sz, _ := h.emis.Size(context.Background()); sz != 1 {
		t.Errorf("emission size = %d, want 1", sz)
	}
	if len(h.obs.events) != 1 {
		t.Fatalf("observer events = %d, want 1", len(h.obs.events))
	}
	ev := h.obs.events[0]
	if ev.OutputHash == "" || ev.IssuedVCRef == "" || ev.InputHash != "" {
		t.Errorf("observer event = %+v, want OutputHash+IssuedVCRef set, InputHash empty", ev)
	}
	if ev.Result == nil || ev.Result.Confidence == nil || *ev.Result.Confidence != vc.ConfidenceVerified {
		t.Errorf("observer Confidence = %v, want Verified (inputs were adjacent-verified)", ev.Result)
	}
}

// A verify-fail, a tampered payload, and a store-fail each drop the input —
// nothing pools, so foldOnce emits nothing.
func TestProcess_Ingress_FailClosed(t *testing.T) {
	cases := []struct {
		name string
		opts func(*Config)
		wire func(t *testing.T) []byte
	}{
		{"verify fail", func(c *Config) { c.Verifier = stubVerifier{state: vc.ConfidenceFailed} },
			func(t *testing.T) []byte { return ingressEnvelope(t, "did:example:a", []byte(`{"v":1}`)) }},
		{"store fail", func(c *Config) { c.Store = &recordStore{failErr: errors.New("store down")} },
			func(t *testing.T) []byte { return ingressEnvelope(t, "did:example:a", []byte(`{"v":1}`)) }},
		{"tampered payload", nil, func(t *testing.T) []byte {
			return ingressEnvelopeWith(t, "did:example:a", []byte(`{"v":1}`), []byte(`{"v":999}`))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.opts)
			h.feed(tc.wire(t))
			if h.p.foldOnce(context.Background()) {
				t.Errorf("%s: foldOnce emitted, want skip (input must be dropped)", tc.name)
			}
			if len(h.sign.gotSources) != 0 {
				t.Errorf("%s: signer called, want not called", tc.name)
			}
		})
	}
}

// An empty window emits nothing and notifies no observer.
func TestProcess_EmptyWindow_Skips(t *testing.T) {
	h := newHarness(t, nil)
	if h.p.foldOnce(context.Background()) {
		t.Error("empty window: foldOnce emitted, want skip")
	}
	if len(h.pub.calls) != 0 || len(h.obs.events) != 0 {
		t.Errorf("empty window: emitted=%d events=%d, want 0/0", len(h.pub.calls), len(h.obs.events))
	}
}

// A duplicate-content input is deduped before the signer (one fold of one cred).
func TestProcess_DuplicateDeduped(t *testing.T) {
	h := newHarness(t, nil)
	wire := ingressEnvelope(t, "did:example:a", []byte(`{"v":1}`))
	h.feed(wire)
	h.feed(wire)
	if !h.p.foldOnce(context.Background()) {
		t.Fatal("foldOnce returned false, want emitted")
	}
	if len(h.sign.gotSources) != 1 || len(h.sign.gotSources[0]) != 1 {
		t.Fatalf("dedup: signer sources = %v, want one fold of 1", h.sign.gotSources)
	}
}

// A malformed fold output is rejected by the strict-JSON gate — nothing emitted,
// but the window is consumed and an errored observer event fires.
func TestProcess_FoldOutput_StrictGated(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Fold = badFold{} })
	h.feed(ingressEnvelope(t, "did:example:a", []byte(`{"v":1}`)))
	if h.p.foldOnce(context.Background()) {
		t.Error("malformed fold output: foldOnce emitted, want skip")
	}
	if len(h.pub.calls) != 0 {
		t.Errorf("malformed fold output: emitted %d, want 0", len(h.pub.calls))
	}
	if len(h.obs.events) != 1 || h.obs.events[0].Result.Status != contract.StatusErrored {
		t.Errorf("want one errored observer event, got %+v", h.obs.events)
	}
}

type badFold struct{}

func (badFold) Fold(_ context.Context, _ []PooledInput) ([]byte, error) {
	return []byte(`{"a":1}{"b":2}`), nil // trailing data → strict decode fails
}

// Declarations are pinned: ChainFirstDrop + VerificationAdjacent.
func TestProcess_Declarations(t *testing.T) {
	h := newHarness(t, nil)
	if h.p.ChainBehavior() != contract.ChainFirstDrop {
		t.Errorf("ChainBehavior = %v, want ChainFirstDrop", h.p.ChainBehavior())
	}
	if h.p.VerificationStrategy() != contract.VerificationAdjacent {
		t.Errorf("VerificationStrategy = %v, want VerificationAdjacent", h.p.VerificationStrategy())
	}
}

// Run subscribes every ingress, then on ctx cancel drains the subscriber and
// closes the publisher (partial windows are discarded). Stubs are read only after
// <-done, so the read is synchronized.
func TestProcess_Run_SubscribesDrainsCloses(t *testing.T) {
	tickCh := make(chan time.Time)
	h := newHarness(t, func(c *Config) { c.Tick = tickCh })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.p.Run(ctx) }()

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !h.sub.drained {
		t.Error("subscriber not drained on shutdown")
	}
	if !h.pub.closed {
		t.Error("publisher not closed on shutdown")
	}
}

// Run drains already-subscribed ingresses when a later Subscribe fails, and
// returns the error (Codex P2#2).
func TestProcess_Run_SubscribeFailureDrainsPrior(t *testing.T) {
	first := &captureSubscriber{}
	second := &captureSubscriber{subscribeErr: errors.New("subscribe boom")}
	h := newHarness(t, func(c *Config) {
		c.Ingress = []Ingress{
			{Subscriber: first, UpstreamEndpoint: "a"},
			{Subscriber: second, UpstreamEndpoint: "b"},
		}
	})
	if err := h.p.Run(context.Background()); err == nil {
		t.Fatal("Run: want subscribe error")
	}
	if !first.drained {
		t.Error("first (successful) subscription was not drained after the later failure")
	}
}

// New validates required deps, including a nil Subscriber inside an Ingress
// (Codex P2#1).
func TestNew_RequiresDeps(t *testing.T) {
	base := func() Config {
		return Config{
			Ingress: []Ingress{{Subscriber: &captureSubscriber{}}}, Window: time.Hour,
			Signer: &recordSigner{}, Verifier: stubVerifier{}, Store: &recordStore{},
			Publisher: &recordPublisher{}, Codec: envelopecodec.New(), Emission: memlog.New(),
			Fold: ManifestFold{},
		}
	}
	muts := map[string]func(*Config){
		"no ingress":     func(c *Config) { c.Ingress = nil },
		"nil subscriber": func(c *Config) { c.Ingress = []Ingress{{Subscriber: nil}} },
		"no signer":      func(c *Config) { c.Signer = nil },
		"no store":       func(c *Config) { c.Store = nil },
		"no fold":        func(c *Config) { c.Fold = nil },
		"bad window":     func(c *Config) { c.Window = 0 },
	}
	for name, m := range muts {
		cfg := base()
		m(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%s): want error", name)
		}
	}
}
