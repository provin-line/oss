package sink_test

import (
	"context"
	"errors"
	"testing"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/vc"
)

// fakePayloadResolver records the (endpoint, hash) it was asked to resolve and
// returns configured bytes or an error.
type fakePayloadResolver struct {
	gotEndpoint string
	gotHash     string
	bytes       []byte
	err         error
	calls       int
}

func (f *fakePayloadResolver) ResolvePayload(_ context.Context, endpoint, hash string) ([]byte, error) {
	f.calls++
	f.gotEndpoint = endpoint
	f.gotHash = hash
	return f.bytes, f.err
}

func byRefConfig(v *fakeVerifier, s *fakeStore, w *fakeWriter, r contract.PayloadResolver) sink.Config {
	cfg := baseConfig(v, s, w)
	cfg.PayloadDelivery = contract.DeliveryByReference
	cfg.PayloadResolver = r
	return cfg
}

// A by-reference ingress needs a PayloadResolver at construction (fail closed).
func TestNew_ByReferenceRequiresResolver(t *testing.T) {
	cfg := baseConfig(&fakeVerifier{result: verified()}, &fakeStore{}, &fakeWriter{})
	cfg.PayloadDelivery = contract.DeliveryByReference
	if _, err := sink.New(cfg); !errors.Is(err, sink.ErrMissingPayloadResolver) {
		t.Fatalf("New by-reference without resolver err = %v, want ErrMissingPayloadResolver", err)
	}
	cfg.PayloadResolver = &fakePayloadResolver{}
	if _, err := sink.New(cfg); err != nil {
		t.Fatalf("New by-reference with resolver: %v", err)
	}
}

// by-reference + nil payload: fetch by the credential's outputHash, the fetched
// bytes pass binding, and the write carries them. The resolver is asked for the
// exact (UpstreamEndpoint, outputHash).
func TestProcess_ByReference_Fetches(t *testing.T) {
	payload := []byte(`{"produced":"data"}`)
	cred := boundCred(t, payload)
	subj, err := cred.Subject()
	if err != nil {
		t.Fatalf("Subject: %v", err)
	}
	wire := encode(t, cred, nil) // by-reference: no inline payload

	v := &fakeVerifier{result: verified()}
	s := &fakeStore{}
	w := &fakeWriter{}
	r := &fakePayloadResolver{bytes: payload}
	cfg := byRefConfig(v, s, w, r)
	cfg.Kind = contract.SinkProduction
	p, err := sink.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("Process: %v", goErr)
	}
	if result.Status != contract.StatusPassed {
		t.Fatalf("Status = %v, want StatusPassed", result.Status)
	}
	if r.calls != 1 {
		t.Errorf("resolver calls = %d, want 1", r.calls)
	}
	if r.gotEndpoint != cfg.UpstreamEndpoint {
		t.Errorf("resolver endpoint = %q, want %q", r.gotEndpoint, cfg.UpstreamEndpoint)
	}
	if r.gotHash != subj.OutputHash {
		t.Errorf("resolver hash = %q, want outputHash %q", r.gotHash, subj.OutputHash)
	}
	if len(w.records) != 1 || string(w.records[0].Payload) != string(payload) {
		t.Errorf("written payload = %v, want the fetched bytes %q", w.records, payload)
	}
}

// by-reference + a fetch that returns tampered bytes → RejectBindingGate (the
// serving boundary is untrusted; the binding gate is the sole integrity check).
func TestProcess_ByReference_TamperedFetch_BindingGate(t *testing.T) {
	payload := []byte(`{"produced":"data"}`)
	cred := boundCred(t, payload)
	wire := encode(t, cred, nil)

	r := &fakePayloadResolver{bytes: []byte(`{"tampered":"bytes"}`)}
	rl := &fakeRejectLog{}
	cfg := byRefConfig(&fakeVerifier{result: verified()}, &fakeStore{}, &fakeWriter{}, r)
	cfg.Kind = contract.SinkArchival
	cfg.RejectLog = rl
	p, _ := sink.New(cfg)

	result, _ := p.Process(context.Background(), wire)
	if result.Status != contract.StatusErrored {
		t.Fatalf("Status = %v, want StatusErrored", result.Status)
	}
	if len(rl.records) != 1 || rl.records[0].Reason != sink.RejectBindingGate {
		t.Errorf("reject reason = %v, want RejectBindingGate", rl.records)
	}
}

// by-reference + a fetch failure → RejectPayloadFetch (a liveness failure, the
// confidence verdict is preserved, not demoted).
func TestProcess_ByReference_FetchFailure_PayloadFetch(t *testing.T) {
	payload := []byte(`{"produced":"data"}`)
	cred := boundCred(t, payload)
	wire := encode(t, cred, nil)

	r := &fakePayloadResolver{err: errors.New("serving boundary down")}
	rl := &fakeRejectLog{}
	cfg := byRefConfig(&fakeVerifier{result: verified()}, &fakeStore{}, &fakeWriter{}, r)
	cfg.Kind = contract.SinkArchival
	cfg.RejectLog = rl
	p, _ := sink.New(cfg)

	result, _ := p.Process(context.Background(), wire)
	if result.Status != contract.StatusErrored {
		t.Fatalf("Status = %v, want StatusErrored", result.Status)
	}
	if len(rl.records) != 1 || rl.records[0].Reason != sink.RejectPayloadFetch {
		t.Errorf("reject reason = %v, want RejectPayloadFetch", rl.records)
	}
	if result.Confidence == nil || *result.Confidence != vc.ConfidenceVerified {
		t.Errorf("Confidence = %v, want ConfidenceVerified preserved (fetch is liveness, not verdict)", result.Confidence)
	}
}

// by-reference + an inline payload present → RejectPayloadDeliveryViolation
// (export-seam misconfiguration; the resolver is never consulted).
func TestProcess_ByReference_InlinePresent_Violation(t *testing.T) {
	payload := []byte(`{"produced":"data"}`)
	cred := boundCred(t, payload)
	wire := encode(t, cred, payload) // inline bytes present under by-reference mode

	r := &fakePayloadResolver{bytes: payload}
	rl := &fakeRejectLog{}
	cfg := byRefConfig(&fakeVerifier{result: verified()}, &fakeStore{}, &fakeWriter{}, r)
	cfg.Kind = contract.SinkArchival
	cfg.RejectLog = rl
	p, _ := sink.New(cfg)

	result, _ := p.Process(context.Background(), wire)
	if result.Status != contract.StatusErrored {
		t.Fatalf("Status = %v, want StatusErrored", result.Status)
	}
	if len(rl.records) != 1 || rl.records[0].Reason != sink.RejectPayloadDeliveryViolation {
		t.Errorf("reject reason = %v, want RejectPayloadDeliveryViolation", rl.records)
	}
	if r.calls != 0 {
		t.Errorf("resolver was consulted (%d calls) despite a delivery violation", r.calls)
	}
}

// cancelingResolver cancels the context mid-fetch and returns a transport-shaped
// error that does NOT unwrap to context.Canceled — the network client's wrapped
// error shape. It exercises the ctx.Err()-based cancellation detection.
type cancelingResolver struct{ cancel context.CancelFunc }

func (r *cancelingResolver) ResolvePayload(_ context.Context, _, _ string) ([]byte, error) {
	r.cancel()
	return nil, errors.New("connect: canceled (transport-wrapped, not context.Canceled)")
}

// A by-reference fetch interrupted by context cancellation propagates as a Go
// error (NOT a reject Result) and records NO reject-log entry — a shutdown must
// not pollute an archival sink's durable reject log.
func TestProcess_ByReference_ContextCanceled_PropagatesGoError(t *testing.T) {
	payload := []byte(`{"produced":"data"}`)
	cred := boundCred(t, payload)
	wire := encode(t, cred, nil)

	ctx, cancel := context.WithCancel(context.Background())
	rl := &fakeRejectLog{}
	cfg := byRefConfig(&fakeVerifier{result: verified()}, &fakeStore{}, &fakeWriter{}, &cancelingResolver{cancel: cancel})
	cfg.Kind = contract.SinkArchival
	cfg.RejectLog = rl
	p, _ := sink.New(cfg)

	result, goErr := p.Process(ctx, wire)
	if goErr == nil {
		t.Fatalf("Process on cancellation: want a Go error, got result %+v", result)
	}
	if len(rl.records) != 0 {
		t.Errorf("reject-log records = %v, want 0 (cancellation must not write a reject)", rl.records)
	}
}

// inline (default) + nil payload → RejectPayloadDeliveryViolation (stripped in
// error): the mismatch is now decidable.
func TestProcess_Inline_NilPayload_Violation(t *testing.T) {
	payload := []byte(`{"produced":"data"}`)
	cred := boundCred(t, payload)
	wire := encode(t, cred, nil) // no payload under inline mode

	rl := &fakeRejectLog{}
	cfg := baseConfig(&fakeVerifier{result: verified()}, &fakeStore{}, &fakeWriter{})
	cfg.Kind = contract.SinkArchival
	cfg.RejectLog = rl
	p, _ := sink.New(cfg)

	result, _ := p.Process(context.Background(), wire)
	if result.Status != contract.StatusErrored {
		t.Fatalf("Status = %v, want StatusErrored", result.Status)
	}
	if len(rl.records) != 1 || rl.records[0].Reason != sink.RejectPayloadDeliveryViolation {
		t.Errorf("reject reason = %v, want RejectPayloadDeliveryViolation", rl.records)
	}
}
