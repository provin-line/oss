// Package sink_test tests the Sink Process runtime.
//
// Test strategy: real codec (envelopecodec); recording fakes for Verifier,
// ChainVerifier, Store, Writer, and Observers so verdict policy, the
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

type fakeStore struct {
	calls     int
	returnErr error
}

func (f *fakeStore) StoreIngressVC(_ context.Context, _ *vc.PipelinePassCredential, _ string) error {
	f.calls++
	return f.returnErr
}

type fakeWriter struct {
	records   []sink.Record
	returnErr error
}

func (f *fakeWriter) Write(_ context.Context, rec sink.Record) error {
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
	return boundCredIssuer(t, payload, "did:example:upstream")
}

// boundCredIssuer is boundCred with an explicit issuer DID (for allow-list tests).
func boundCredIssuer(t *testing.T, payload []byte, issuer string) *vc.PipelinePassCredential {
	t.Helper()
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    issuer,
		ValidFrom: time.Now(),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "p",
			ProcessID:           "upstream",
			TransformationClaim: vc.ClaimConvert,
			OutputHash:          rawHash(payload),
		},
	})
	if err != nil {
		t.Fatalf("boundCredIssuer: %v", err)
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

// ---------------------------------------------------------------------------
// Allow-list gate (production/archival): the consumed credential's issuer DID
// must match a configured allow-issuers pattern, else reject before write.
// ---------------------------------------------------------------------------

func TestProcess_Production_AllowList(t *testing.T) {
	payload := []byte(`{"x":1}`)
	const allowedIssuer = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:readings:process:s1"
	const disallowedIssuer = "did:dplaax:poc.dplaax.dev:org:evil:pipeline:readings:process:s1"

	run := func(t *testing.T, issuer string) (*contract.Result, *fakeWriter) {
		t.Helper()
		cred := boundCredIssuer(t, payload, issuer)
		w := &fakeWriter{}
		cfg := baseConfig(&fakeVerifier{result: verified()}, &fakeStore{}, w)
		cfg.Kind = contract.SinkProduction
		cfg.AllowIssuers = []string{"did:dplaax:poc.dplaax.dev:org:acme:*"}
		p, err := sink.New(cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		r, err := p.Process(context.Background(), encode(t, cred, payload))
		if err != nil {
			t.Fatalf("Process: %v", err)
		}
		return r, w
	}

	t.Run("allowed issuer passes and writes", func(t *testing.T) {
		r, w := run(t, allowedIssuer)
		if r.Status != contract.StatusPassed {
			t.Errorf("status = %v (%s), want Passed", r.Status, r.Error)
		}
		if len(w.records) != 1 {
			t.Errorf("writer got %d records, want 1", len(w.records))
		}
	})

	t.Run("disallowed issuer rejected before write", func(t *testing.T) {
		r, w := run(t, disallowedIssuer)
		if r.Status != contract.StatusErrored {
			t.Errorf("status = %v, want Errored (issuer not allow-listed)", r.Status)
		}
		if len(w.records) != 0 {
			t.Errorf("writer got %d records, want 0 (rejected before write)", len(w.records))
		}
	})
}

// ---------------------------------------------------------------------------
// Receipt issuance (D-1): after a successful external write, a receipt-issuing
// sink signs + registers a provin:sink-receipt over the consumed credential.
// ---------------------------------------------------------------------------

type fakeReceiptIssuer struct {
	calls    int
	consumed []*vc.PipelinePassCredential
	err      error
}

func (f *fakeReceiptIssuer) IssueReceipt(_ context.Context, consumed *vc.PipelinePassCredential) error {
	f.calls++
	f.consumed = append(f.consumed, consumed)
	return f.err
}

func TestProcess_Receipt_IssuedAfterWrite(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := boundCred(t, payload)

	ri := &fakeReceiptIssuer{}
	w := &fakeWriter{}
	cfg := baseConfig(&fakeVerifier{result: verified()}, &fakeStore{}, w)
	cfg.Kind = contract.SinkProduction // AllowIssuers empty ⇒ gate skipped (receipt behavior isolated)
	cfg.Receipts = ri
	p, err := sink.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r, err := p.Process(context.Background(), encode(t, cred, payload))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if r.Status != contract.StatusPassed {
		t.Fatalf("status = %v (%s), want Passed", r.Status, r.Error)
	}
	if len(w.records) != 1 {
		t.Errorf("writer records = %d, want 1", len(w.records))
	}
	// Receipt issued after the write, for the consumed credential.
	if ri.calls != 1 {
		t.Fatalf("IssueReceipt calls = %d, want 1", ri.calls)
	}
	consumedHash, _ := cred.Hash()
	gotHash, _ := ri.consumed[0].Hash()
	if gotHash != consumedHash {
		t.Errorf("receipt consumed = %q, want the consumed credential %q", gotHash, consumedHash)
	}
}

func TestProcess_Receipt_FailureIsErrored(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := boundCred(t, payload)

	ri := &fakeReceiptIssuer{err: errors.New("tlog append failed")}
	w := &fakeWriter{}
	cfg := baseConfig(&fakeVerifier{result: verified()}, &fakeStore{}, w)
	cfg.Kind = contract.SinkProduction
	cfg.Receipts = ri
	p, err := sink.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r, err := p.Process(context.Background(), encode(t, cred, payload))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	// The external write happened (at-most-once, not rolled back)...
	if len(w.records) != 1 {
		t.Errorf("writer records = %d, want 1 (write not rolled back)", len(w.records))
	}
	// ...but a receipt failure surfaces as StatusErrored.
	if r.Status != contract.StatusErrored {
		t.Errorf("status = %v, want Errored (receipt failed)", r.Status)
	}
}

func TestProcess_NoReceiptIssuerNoCall(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := boundCred(t, payload)
	w := &fakeWriter{}
	cfg := baseConfig(&fakeVerifier{result: verified()}, &fakeStore{}, w) // observation-only, no Receipts
	p, err := sink.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := p.Process(context.Background(), encode(t, cred, payload)); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(w.records) != 1 {
		t.Errorf("writer records = %d, want 1", len(w.records))
	}
}

// ---------------------------------------------------------------------------
// Reject log (D-3): every reject path durably records a RejectRecord with a
// closed-set reason. Post-acceptance failures (write) do NOT record.
// ---------------------------------------------------------------------------

type fakeRejectLog struct {
	records []sink.RejectRecord
	err     error
}

func (f *fakeRejectLog) RecordReject(_ context.Context, rec sink.RejectRecord) error {
	f.records = append(f.records, rec)
	return f.err
}

func TestProcess_RejectLog_EveryRejectPathRecords(t *testing.T) {
	good := []byte(`{"v":1}`)

	cases := []struct {
		name       string
		verifier   *fakeVerifier
		store      *fakeStore
		allow      []string
		wire       func(t *testing.T) []byte
		wantReason sink.RejectReason
	}{
		{
			name:       "decode-failure",
			verifier:   &fakeVerifier{result: verified()},
			store:      &fakeStore{},
			wire:       func(t *testing.T) []byte { return []byte("not-an-envelope") },
			wantReason: sink.RejectDecodeFailure,
		},
		{
			name:       "verdict",
			verifier:   &fakeVerifier{result: &vc.VerifyResult{Overall: vc.ConfidenceFailed}},
			store:      &fakeStore{},
			wire:       func(t *testing.T) []byte { return encode(t, boundCred(t, good), good) },
			wantReason: sink.RejectVerdict,
		},
		{
			name:     "allow-list",
			verifier: &fakeVerifier{result: verified()},
			store:    &fakeStore{},
			allow:    []string{"did:dplaax:reg:org:acme:*"},
			wire: func(t *testing.T) []byte {
				c := boundCredIssuer(t, good, "did:dplaax:reg:org:evil:pipeline:p:process:up")
				return encode(t, c, good)
			},
			wantReason: sink.RejectAllowList,
		},
		{
			name:       "ingress-store-failure",
			verifier:   &fakeVerifier{result: verified()},
			store:      &fakeStore{returnErr: errors.New("store down")},
			wire:       func(t *testing.T) []byte { return encode(t, boundCred(t, good), good) },
			wantReason: sink.RejectIngressStoreFailure,
		},
		{
			name:       "binding-gate",
			verifier:   &fakeVerifier{result: verified()},
			store:      &fakeStore{},
			wire:       func(t *testing.T) []byte { return encode(t, boundCred(t, good), []byte(`{"tampered":true}`)) },
			wantReason: sink.RejectBindingGate,
		},
		{
			// A verified, allow-listed credential declaring NO outputHash reaches
			// the binding gate as malformed (binding undecidable).
			name:     "malformed-credential",
			verifier: &fakeVerifier{result: verified()},
			store:    &fakeStore{},
			wire: func(t *testing.T) []byte {
				cred, err := vc.New(vc.CredentialFields{
					Issuer: "did:example:upstream", ValidFrom: time.Now(),
					Subject: vc.CredentialSubjectFields{PipelineID: "p", ProcessID: "u", TransformationClaim: vc.ClaimConvert, OutputHash: ""},
				})
				if err != nil {
					t.Fatalf("unbound cred: %v", err)
				}
				return encode(t, cred, good)
			},
			wantReason: sink.RejectMalformedCredential,
		},
		{
			// A nil payload under the default (inline) delivery mode is now a
			// decidable protocol violation (stripped in error) — no longer the
			// deprecated by-reference-unsupported reject.
			name:     "payload-delivery-violation",
			verifier: &fakeVerifier{result: verified()},
			store:    &fakeStore{},
			wire: func(t *testing.T) []byte {
				wire, err := envelopecodec.New().MarshalEnvelope(&contract.Envelope{Credential: boundCred(t, good), Payload: nil, SequenceNo: 1})
				if err != nil {
					t.Fatalf("encode nil payload: %v", err)
				}
				return wire
			},
			wantReason: sink.RejectPayloadDeliveryViolation,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.wantReason), func(t *testing.T) {
			rl := &fakeRejectLog{}
			cfg := baseConfig(tc.verifier, tc.store, &fakeWriter{})
			cfg.Kind = contract.SinkArchival
			cfg.AllowIssuers = tc.allow
			cfg.RejectLog = rl
			p, err := sink.New(cfg)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			r, err := p.Process(context.Background(), tc.wire(t))
			if err != nil {
				t.Fatalf("Process: %v", err)
			}
			if r.Status != contract.StatusErrored {
				t.Fatalf("status = %v, want Errored", r.Status)
			}
			if len(rl.records) != 1 {
				t.Fatalf("reject records = %d, want 1", len(rl.records))
			}
			if rl.records[0].Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", rl.records[0].Reason, tc.wantReason)
			}
			if rl.records[0].Detail == "" {
				t.Error("reject record has empty Detail")
			}
		})
	}
}

// A post-acceptance external-write failure is StatusErrored but NOT a reject:
// the credential was accepted, so it writes no reject-log record.
func TestProcess_RejectLog_WriteFailureNotRecorded(t *testing.T) {
	good := []byte(`{"v":1}`)
	rl := &fakeRejectLog{}
	cfg := baseConfig(&fakeVerifier{result: verified()}, &fakeStore{}, &fakeWriter{returnErr: errors.New("archive down")})
	cfg.Kind = contract.SinkArchival
	cfg.RejectLog = rl
	p, err := sink.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r, err := p.Process(context.Background(), encode(t, boundCred(t, good), good))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if r.Status != contract.StatusErrored {
		t.Fatalf("status = %v, want Errored", r.Status)
	}
	if len(rl.records) != 0 {
		t.Errorf("reject records = %d, want 0 (write failure is not a reject)", len(rl.records))
	}
}
