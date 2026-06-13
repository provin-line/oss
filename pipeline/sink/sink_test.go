// Package sink_test tests the Sink Process runtime.
//
// Test strategy: real codec (envelopecodec); recording fakes for Verifier,
// ChainVerifier, Store, SinkWriter, and Observers so verdict policy, the
// payload↔credential binding gate, the store-on-verified rule, and the
// external write can each be asserted independently.
package sink_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	"github.com/provin-line/oss/vc"
)

// compile-time: *Processor implements contract.EventProcessor.
var _ contract.EventProcessor = (*sink.Processor)(nil)

// ---------------------------------------------------------------------------
// Recording fakes
// ---------------------------------------------------------------------------

type fakeVerifier struct {
	calls  int
	result *vc.VerifyResult
	err    error
}

func (f *fakeVerifier) Verify(_ context.Context, _ *vc.PipelinePassCredential) (*vc.VerifyResult, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

type fakeChainVerifier struct {
	calls  int
	result *vc.VerifyResult
	err    error
}

func (f *fakeChainVerifier) VerifyChain(_ context.Context, _ *vc.PipelinePassCredential) (*vc.VerifyResult, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

type fakeStore struct {
	calls     int
	returnErr error
}

func (f *fakeStore) StoreIngressVC(_ context.Context, _ *vc.PipelinePassCredential, _ string) error {
	f.calls++
	return f.returnErr
}

type fakeWriter struct {
	records   []sink.SinkRecord
	returnErr error
}

func (f *fakeWriter) Write(_ context.Context, rec sink.SinkRecord) error {
	f.records = append(f.records, rec)
	return f.returnErr
}

type fakeObserver struct {
	events []contract.ProcessEvent
}

func (f *fakeObserver) OnProcessComplete(_ context.Context, ev contract.ProcessEvent) error {
	f.events = append(f.events, ev)
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func rawHash(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// boundCred builds a credential whose outputHash equals sha256 over payload —
// the binding the sink enforces.
func boundCred(t *testing.T, payload []byte) *vc.PipelinePassCredential {
	t.Helper()
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    "did:example:upstream",
		ValidFrom: time.Now(),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "p",
			ProcessID:           "upstream",
			TransformationClaim: vc.ClaimConvert,
			OutputHash:          rawHash(payload),
		},
	})
	if err != nil {
		t.Fatalf("boundCred: %v", err)
	}
	return cred
}

func encode(t *testing.T, cred *vc.PipelinePassCredential, payload []byte) []byte {
	t.Helper()
	wire, err := envelopecodec.New().MarshalEnvelope(&contract.Envelope{
		Credential: cred,
		Payload:    payload,
		SequenceNo: 1,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return wire
}

func verified() *vc.VerifyResult { return &vc.VerifyResult{Overall: vc.ConfidenceVerified} }

// baseConfig returns a valid observation-only adjacent config.
func baseConfig(v *fakeVerifier, s *fakeStore, w *fakeWriter) sink.Config {
	return sink.Config{
		Strategy:         contract.VerificationAdjacent,
		Kind:             contract.SinkObservationOnly,
		Codec:            envelopecodec.New(),
		Verifier:         v,
		Store:            s,
		Writer:           w,
		UpstreamEndpoint: "https://example.com/upstream",
	}
}

// ---------------------------------------------------------------------------
// Construction validation
// ---------------------------------------------------------------------------

func TestNew_Validation(t *testing.T) {
	codec := envelopecodec.New()
	v := &fakeVerifier{result: verified()}
	cvf := &fakeChainVerifier{result: verified()}
	s := &fakeStore{}
	w := &fakeWriter{}
	full := func() sink.Config {
		return sink.Config{Strategy: contract.VerificationAdjacent, Kind: contract.SinkObservationOnly, Codec: codec, Verifier: v, Store: s, Writer: w, UpstreamEndpoint: "u"}
	}

	tests := []struct {
		name    string
		mutate  func(sink.Config) sink.Config
		wantErr bool
	}{
		{"valid adjacent observation", func(c sink.Config) sink.Config { return c }, false},
		{"strategy None rejected", func(c sink.Config) sink.Config { c.Strategy = contract.VerificationNone; return c }, true},
		{"strategy Unknown rejected", func(c sink.Config) sink.Config { c.Strategy = contract.VerificationUnknown; return c }, true},
		{"kind Unknown rejected", func(c sink.Config) sink.Config { c.Kind = contract.SinkKindUnknown; return c }, true},
		{"missing codec rejected", func(c sink.Config) sink.Config { c.Codec = nil; return c }, true},
		{"missing store rejected", func(c sink.Config) sink.Config { c.Store = nil; return c }, true},
		{"missing writer rejected", func(c sink.Config) sink.Config { c.Writer = nil; return c }, true},
		{"missing upstream rejected", func(c sink.Config) sink.Config { c.UpstreamEndpoint = ""; return c }, true},
		{"adjacent missing verifier rejected", func(c sink.Config) sink.Config { c.Verifier = nil; return c }, true},
		{"full missing chainverifier rejected", func(c sink.Config) sink.Config {
			c.Strategy = contract.VerificationFull
			c.Verifier = nil
			c.ChainVerifier = nil
			return c
		}, true},
		{"valid full with chainverifier", func(c sink.Config) sink.Config {
			c.Strategy = contract.VerificationFull
			c.Verifier = nil
			c.ChainVerifier = cvf
			return c
		}, false},
		{"valid production", func(c sink.Config) sink.Config { c.Kind = contract.SinkProduction; return c }, false},
		{"valid archival", func(c sink.Config) sink.Config { c.Kind = contract.SinkArchival; return c }, false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := sink.New(tc.mutate(full()))
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Observation happy path: verified → store + write, terminal Result
// ---------------------------------------------------------------------------

func TestProcess_Observation_Verified(t *testing.T) {
	payload := []byte(`{"msg":"hi"}`)
	cred := boundCred(t, payload)
	wire := encode(t, cred, payload)

	v := &fakeVerifier{result: verified()}
	s := &fakeStore{}
	w := &fakeWriter{}
	obs := &fakeObserver{}

	cfg := baseConfig(v, s, w)
	cfg.Observers = []contract.ProcessObserver{obs}
	p, err := sink.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("Process: %v", goErr)
	}
	if result.Status != contract.StatusPassed {
		t.Errorf("Status=%v, want StatusPassed", result.Status)
	}
	// A sink produces nothing in-network.
	if result.VC != nil {
		t.Error("VC must be nil (a sink produces no in-network credential)")
	}
	if result.Payload != nil {
		t.Error("Payload must be nil (a sink produces nothing in-network)")
	}
	if result.Confidence == nil || *result.Confidence != vc.ConfidenceVerified {
		t.Errorf("Confidence=%v, want ConfidenceVerified", result.Confidence)
	}
	if v.calls != 1 {
		t.Errorf("Verify calls=%d, want 1", v.calls)
	}
	if s.calls != 1 {
		t.Errorf("Store calls=%d, want 1 (verified ⇒ store)", s.calls)
	}
	if len(w.records) != 1 {
		t.Fatalf("Writer records=%d, want 1", len(w.records))
	}
	rec := w.records[0]
	if string(rec.Payload) != string(payload) {
		t.Errorf("written payload=%q, want %q", rec.Payload, payload)
	}
	// The codec round-trips the credential (body-as-source-of-truth), so the
	// decoded value is a fresh object — compare by content address, not pointer.
	gotAddr, err := rec.Credential.Hash()
	if err != nil {
		t.Fatalf("rec.Credential.Hash: %v", err)
	}
	wantAddr, err := cred.Hash()
	if err != nil {
		t.Fatalf("cred.Hash: %v", err)
	}
	if gotAddr != wantAddr {
		t.Errorf("written credential addr=%q, want %q", gotAddr, wantAddr)
	}
	if rec.Verdict == nil || rec.Verdict.Overall != vc.ConfidenceVerified {
		t.Errorf("written verdict=%v, want ConfidenceVerified", rec.Verdict)
	}
	if len(obs.events) != 1 {
		t.Fatalf("Observer events=%d, want 1", len(obs.events))
	}
	// The observer event carries the consumed-credential audit identity, named
	// by role: a sink issues nothing (IssuedVCRef/OutputHash empty) and consumes
	// the head credential (ConsumedVCRef = its content address; InputHash = the
	// consumed payload hash).
	ev := obs.events[0]
	if ev.ConsumedVCRef != wantAddr {
		t.Errorf("ConsumedVCRef=%q, want %q (consumed head credential)", ev.ConsumedVCRef, wantAddr)
	}
	if ev.InputHash != rawHash(payload) {
		t.Errorf("InputHash=%q, want %q (consumed payload hash)", ev.InputHash, rawHash(payload))
	}
	if ev.IssuedVCRef != "" {
		t.Errorf("IssuedVCRef=%q, want empty (a sink issues nothing)", ev.IssuedVCRef)
	}
	if ev.OutputHash != "" {
		t.Errorf("OutputHash=%q, want empty (a sink produces nothing in-network)", ev.OutputHash)
	}
}

// ---------------------------------------------------------------------------
// Observation leniency: a failed/indeterminate verdict still WRITES (surfacing
// the verdict), but is NOT stored (store is for verified ingress VCs).
// ---------------------------------------------------------------------------

func TestProcess_Observation_InvalidVerdict_WritesNoStore(t *testing.T) {
	for _, verdict := range []vc.ConfidenceState{vc.ConfidenceFailed, vc.ConfidenceIndeterminate} {
		payload := []byte(`{"x":1}`)
		cred := boundCred(t, payload)
		wire := encode(t, cred, payload)

		v := &fakeVerifier{result: &vc.VerifyResult{Overall: verdict}}
		s := &fakeStore{}
		w := &fakeWriter{}

		p, _ := sink.New(baseConfig(v, s, w))
		result, goErr := p.Process(context.Background(), wire)
		if goErr != nil {
			t.Fatalf("Process: %v", goErr)
		}
		if result.Status != contract.StatusPassed {
			t.Errorf("verdict %v: Status=%v, want StatusPassed (observation writes regardless)", verdict, result.Status)
		}
		if len(w.records) != 1 {
			t.Errorf("verdict %v: Writer records=%d, want 1", verdict, len(w.records))
		}
		if s.calls != 0 {
			t.Errorf("verdict %v: Store calls=%d, want 0 (only verified ingress VCs are stored)", verdict, s.calls)
		}
		if result.Confidence == nil || *result.Confidence != verdict {
			t.Errorf("Confidence=%v, want %v", result.Confidence, verdict)
		}
	}
}

// ---------------------------------------------------------------------------
// Production / archival fail-closed: invalid verdict ⇒ reject, no write/store
// ---------------------------------------------------------------------------

func TestProcess_ProductionArchival_InvalidVerdict_Rejected(t *testing.T) {
	for _, kind := range []contract.SinkKind{contract.SinkProduction, contract.SinkArchival} {
		for _, verdict := range []vc.ConfidenceState{vc.ConfidenceFailed, vc.ConfidenceIndeterminate} {
			payload := []byte(`{"x":1}`)
			cred := boundCred(t, payload)
			wire := encode(t, cred, payload)

			v := &fakeVerifier{result: &vc.VerifyResult{Overall: verdict}}
			s := &fakeStore{}
			w := &fakeWriter{}

			cfg := baseConfig(v, s, w)
			cfg.Kind = kind
			p, _ := sink.New(cfg)

			result, goErr := p.Process(context.Background(), wire)
			if goErr != nil {
				t.Fatalf("Process: %v", goErr)
			}
			if result.Status != contract.StatusErrored {
				t.Errorf("kind %v verdict %v: Status=%v, want StatusErrored (fail-closed)", kind, verdict, result.Status)
			}
			if len(w.records) != 0 {
				t.Errorf("kind %v verdict %v: Writer must not run on rejected event", kind, verdict)
			}
			if s.calls != 0 {
				t.Errorf("kind %v verdict %v: Store must not run on rejected event", kind, verdict)
			}
			if result.Confidence == nil || *result.Confidence != verdict {
				t.Errorf("Confidence=%v, want %v", result.Confidence, verdict)
			}
		}
	}
}

func TestProcess_Production_Verified_Writes(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := boundCred(t, payload)
	wire := encode(t, cred, payload)

	v := &fakeVerifier{result: verified()}
	s := &fakeStore{}
	w := &fakeWriter{}

	cfg := baseConfig(v, s, w)
	cfg.Kind = contract.SinkProduction
	p, _ := sink.New(cfg)

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("Process: %v", goErr)
	}
	if result.Status != contract.StatusPassed {
		t.Errorf("Status=%v, want StatusPassed", result.Status)
	}
	if s.calls != 1 || len(w.records) != 1 {
		t.Errorf("store=%d write=%d, want 1/1", s.calls, len(w.records))
	}
}

// ---------------------------------------------------------------------------
// Payload↔credential binding is unconditional (even observation rejects a
// mismatch — leniency covers the verdict, not structural correspondence)
// ---------------------------------------------------------------------------

func TestProcess_BindingMismatch_Errored_AllKinds(t *testing.T) {
	for _, kind := range []contract.SinkKind{contract.SinkObservationOnly, contract.SinkProduction, contract.SinkArchival} {
		cred := boundCred(t, []byte(`{"genuine":true}`))
		wire := encode(t, cred, []byte(`{"tampered":true}`))

		v := &fakeVerifier{result: verified()}
		s := &fakeStore{}
		w := &fakeWriter{}

		cfg := baseConfig(v, s, w)
		cfg.Kind = kind
		p, _ := sink.New(cfg)

		result, goErr := p.Process(context.Background(), wire)
		if goErr != nil {
			t.Fatalf("Process: %v", goErr)
		}
		if result.Status != contract.StatusErrored {
			t.Errorf("kind %v: Status=%v, want StatusErrored on payload/credential mismatch", kind, result.Status)
		}
		if len(w.records) != 0 {
			t.Errorf("kind %v: Writer must never receive a tampered payload", kind)
		}
		// The verdict was verified, so the ingress VC is stored (Stage 4) BEFORE
		// the binding gate (Stage 6) rejects the tampered payload — the
		// credential is genuine; only its transport was tampered. Pin the
		// deliberate store-before-binding order (parity with chained).
		if s.calls != 1 {
			t.Errorf("kind %v: Store calls=%d, want 1 (verified credential is stored before the binding gate rejects the tampered payload)", kind, s.calls)
		}
	}
}

func TestProcess_PredecessorNoOutputHash_Errored(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    "did:example:upstream",
		ValidFrom: time.Now(),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "p",
			ProcessID:           "upstream",
			TransformationClaim: vc.ClaimConvert,
			// OutputHash absent → binding undecidable.
		},
	})
	if err != nil {
		t.Fatalf("vc.New: %v", err)
	}
	wire := encode(t, cred, payload)

	v := &fakeVerifier{result: verified()}
	s := &fakeStore{}
	w := &fakeWriter{}
	p, _ := sink.New(baseConfig(v, s, w))

	result, _ := p.Process(context.Background(), wire)
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored when credential declares no outputHash", result.Status)
	}
	if len(w.records) != 0 {
		t.Error("Writer must not run without a decidable binding")
	}
}

// ---------------------------------------------------------------------------
// Full strategy uses ChainVerifier
// ---------------------------------------------------------------------------

func TestProcess_FullStrategy_UsesChainVerifier(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := boundCred(t, payload)
	wire := encode(t, cred, payload)

	cvf := &fakeChainVerifier{result: verified()}
	v := &fakeVerifier{result: verified()} // must NOT be called
	s := &fakeStore{}
	w := &fakeWriter{}

	cfg := baseConfig(v, s, w)
	cfg.Strategy = contract.VerificationFull
	cfg.ChainVerifier = cvf
	p, err := sink.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("Process: %v", goErr)
	}
	if result.Status != contract.StatusPassed {
		t.Errorf("Status=%v, want StatusPassed", result.Status)
	}
	if cvf.calls != 1 {
		t.Errorf("ChainVerifier calls=%d, want 1", cvf.calls)
	}
	if v.calls != 0 {
		t.Errorf("Verifier must not be called for Full strategy, got %d", v.calls)
	}
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

func TestProcess_DecodeFails_Errored(t *testing.T) {
	v := &fakeVerifier{result: verified()}
	p, _ := sink.New(baseConfig(v, &fakeStore{}, &fakeWriter{}))
	result, goErr := p.Process(context.Background(), []byte("not-a-proto"))
	if goErr != nil {
		t.Fatalf("Process: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored on decode failure", result.Status)
	}
}

func TestProcess_NilPayload_Errored(t *testing.T) {
	cred := boundCred(t, []byte(`{"x":1}`))
	// Envelope with nil payload (by-reference) — craft via codec by passing nil.
	wire, err := envelopecodec.New().MarshalEnvelope(&contract.Envelope{Credential: cred, Payload: nil, SequenceNo: 1})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	v := &fakeVerifier{result: verified()}
	w := &fakeWriter{}
	p, _ := sink.New(baseConfig(v, &fakeStore{}, w))
	result, _ := p.Process(context.Background(), wire)
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored for by-reference (nil) payload", result.Status)
	}
	if len(w.records) != 0 {
		t.Error("Writer must not run without a payload")
	}
}

func TestProcess_VerifierError_Indeterminate(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := boundCred(t, payload)
	wire := encode(t, cred, payload)

	// Production rejects on the indeterminate a verifier transport error implies.
	v := &fakeVerifier{err: errors.New("resolver down")}
	s := &fakeStore{}
	w := &fakeWriter{}
	cfg := baseConfig(v, s, w)
	cfg.Kind = contract.SinkProduction
	p, _ := sink.New(cfg)

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("Process: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored", result.Status)
	}
	if result.Confidence == nil || *result.Confidence != vc.ConfidenceIndeterminate {
		t.Errorf("Confidence=%v, want ConfidenceIndeterminate (a verification transport error)", result.Confidence)
	}
}

// Observation surfaces an un-verifiable event (resolver outage / chain hole)
// as an indeterminate WRITE — it must not be dropped. The error path must flow
// through the same SinkKind policy as a verdict of indeterminate.
func TestProcess_Observation_VerifierError_WritesIndeterminate(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := boundCred(t, payload)
	wire := encode(t, cred, payload)

	v := &fakeVerifier{err: errors.New("resolver down")}
	s := &fakeStore{}
	w := &fakeWriter{}
	p, _ := sink.New(baseConfig(v, s, w)) // baseConfig is observation-only

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("Process: %v", goErr)
	}
	if result.Status != contract.StatusPassed {
		t.Errorf("Status=%v, want StatusPassed (observation surfaces un-verifiable events)", result.Status)
	}
	if len(w.records) != 1 {
		t.Fatalf("Writer records=%d, want 1 (observation must write the indeterminate event)", len(w.records))
	}
	if w.records[0].Verdict == nil || w.records[0].Verdict.Overall != vc.ConfidenceIndeterminate {
		t.Errorf("written verdict=%v, want ConfidenceIndeterminate", w.records[0].Verdict)
	}
	if s.calls != 0 {
		t.Errorf("Store calls=%d, want 0 (indeterminate is not a verified ingress VC)", s.calls)
	}
	if result.Confidence == nil || *result.Confidence != vc.ConfidenceIndeterminate {
		t.Errorf("Confidence=%v, want ConfidenceIndeterminate", result.Confidence)
	}
}

func TestProcess_StoreFails_Errored(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := boundCred(t, payload)
	wire := encode(t, cred, payload)

	v := &fakeVerifier{result: verified()}
	s := &fakeStore{returnErr: errors.New("storage down")}
	w := &fakeWriter{}
	p, _ := sink.New(baseConfig(v, s, w))

	result, _ := p.Process(context.Background(), wire)
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored on store failure", result.Status)
	}
	if len(w.records) != 0 {
		t.Error("Writer must not run after store failure")
	}
}

func TestProcess_WriterFails_Errored(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := boundCred(t, payload)
	wire := encode(t, cred, payload)

	v := &fakeVerifier{result: verified()}
	s := &fakeStore{}
	w := &fakeWriter{returnErr: errors.New("stdout closed")}
	p, _ := sink.New(baseConfig(v, s, w))

	result, _ := p.Process(context.Background(), wire)
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored on writer failure", result.Status)
	}
}

func TestProcess_CtxCancelled_GoError(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := boundCred(t, payload)
	wire := encode(t, cred, payload)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	v := &fakeVerifier{result: verified()}
	p, _ := sink.New(baseConfig(v, &fakeStore{}, &fakeWriter{}))
	result, goErr := p.Process(ctx, wire)
	if !errors.Is(goErr, context.Canceled) {
		t.Fatalf("goErr=%v, want context.Canceled", goErr)
	}
	if result != nil {
		t.Errorf("result=%v, want nil alongside the Go error", result)
	}
}

func TestProcess_VerifierCancellation_PropagatesGoError(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := boundCred(t, payload)
	wire := encode(t, cred, payload)

	v := &fakeVerifier{err: context.Canceled}
	p, _ := sink.New(baseConfig(v, &fakeStore{}, &fakeWriter{}))
	result, goErr := p.Process(context.Background(), wire)
	if !errors.Is(goErr, context.Canceled) {
		t.Fatalf("goErr=%v, want context.Canceled propagated", goErr)
	}
	if result != nil {
		t.Errorf("result=%v, want nil", result)
	}
}

// Observer notified on the errored path too.
func TestProcess_ObserverNotifiedOnErrored(t *testing.T) {
	cred := boundCred(t, []byte(`{"genuine":true}`))
	wire := encode(t, cred, []byte(`{"tampered":true}`))
	v := &fakeVerifier{result: verified()}
	obs := &fakeObserver{}
	cfg := baseConfig(v, &fakeStore{}, &fakeWriter{})
	cfg.Observers = []contract.ProcessObserver{obs}
	p, _ := sink.New(cfg)

	_, _ = p.Process(context.Background(), wire)
	if len(obs.events) != 1 {
		t.Errorf("Observer events=%d, want 1 on errored event", len(obs.events))
	}
	// Even on the binding-mismatch error path, the consumed-credential handle is
	// surfaced to the observer (decode succeeded, so consumedRef is known).
	if obs.events[0].ConsumedVCRef == "" {
		t.Error("ConsumedVCRef should be set on the errored path once the credential is decoded")
	}
}
