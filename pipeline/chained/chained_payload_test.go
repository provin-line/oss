package chained_test

import (
	"context"
	"errors"
	"testing"

	"github.com/provin-line/oss/pipeline/chained"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/vc"
)

// fakePayloadResolver records the (endpoint, hash) it was asked to resolve.
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

func byRefConfig(v *fakeVerifier, s *fakeStore, sig *fakeSigner, r contract.PayloadResolver) chained.Config {
	cfg := baseAdjacentConfig(v, s, sig)
	cfg.PayloadDelivery = contract.DeliveryByReference
	cfg.PayloadResolver = r
	return cfg
}

// A by-reference ingress needs a PayloadResolver at construction.
func TestNew_ByReferenceRequiresResolver(t *testing.T) {
	cfg := baseAdjacentConfig(&fakeVerifier{result: verifiedResult()}, &fakeStore{}, &fakeSigner{})
	cfg.PayloadDelivery = contract.DeliveryByReference
	if _, err := chained.New(cfg); !errors.Is(err, chained.ErrMissingPayloadResolver) {
		t.Fatalf("New by-reference without resolver err = %v, want ErrMissingPayloadResolver", err)
	}
	cfg.PayloadResolver = &fakePayloadResolver{}
	if _, err := chained.New(cfg); err != nil {
		t.Fatalf("New by-reference with resolver: %v", err)
	}
}

// by-reference + nil payload: fetch by outputHash, bind, and produce output.
func TestProcess_ByReference_Fetches(t *testing.T) {
	payload := []byte(`{"produced":"data"}`)
	cred := newIngressCred(t, payload)
	subj, err := cred.Subject()
	if err != nil {
		t.Fatalf("Subject: %v", err)
	}
	wire := encodeEnvelopeByRef(t, cred)

	r := &fakePayloadResolver{bytes: payload}
	p, err := chained.New(byRefConfig(&fakeVerifier{result: verifiedResult()}, &fakeStore{}, &fakeSigner{}, r))
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
	if r.calls != 1 || r.gotEndpoint != "https://example.com/upstream" || r.gotHash != subj.OutputHash {
		t.Errorf("resolver got (calls=%d, endpoint=%q, hash=%q), want (1, upstream, %q)", r.calls, r.gotEndpoint, r.gotHash, subj.OutputHash)
	}
}

// by-reference + tampered fetch → errored at the binding gate.
func TestProcess_ByReference_TamperedFetch_Errored(t *testing.T) {
	cred := newIngressCred(t, []byte(`{"produced":"data"}`))
	wire := encodeEnvelopeByRef(t, cred)
	r := &fakePayloadResolver{bytes: []byte(`{"tampered":true}`)}
	p, _ := chained.New(byRefConfig(&fakeVerifier{result: verifiedResult()}, &fakeStore{}, &fakeSigner{}, r))
	result, _ := p.Process(context.Background(), wire)
	if result.Status != contract.StatusErrored {
		t.Errorf("Status = %v, want StatusErrored (binding gate)", result.Status)
	}
}

// by-reference + fetch failure → errored, confidence preserved (liveness).
func TestProcess_ByReference_FetchFailure_Errored(t *testing.T) {
	cred := newIngressCred(t, []byte(`{"produced":"data"}`))
	wire := encodeEnvelopeByRef(t, cred)
	r := &fakePayloadResolver{err: errors.New("serving boundary down")}
	p, _ := chained.New(byRefConfig(&fakeVerifier{result: verifiedResult()}, &fakeStore{}, &fakeSigner{}, r))
	result, _ := p.Process(context.Background(), wire)
	if result.Status != contract.StatusErrored {
		t.Fatalf("Status = %v, want StatusErrored", result.Status)
	}
	if result.Confidence == nil || *result.Confidence != vc.ConfidenceVerified {
		t.Errorf("Confidence = %v, want ConfidenceVerified preserved (fetch is liveness)", result.Confidence)
	}
}

// by-reference + inline payload present → errored (violation), resolver unused.
func TestProcess_ByReference_InlinePresent_Errored(t *testing.T) {
	payload := []byte(`{"produced":"data"}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload) // inline bytes under by-reference mode
	r := &fakePayloadResolver{bytes: payload}
	p, _ := chained.New(byRefConfig(&fakeVerifier{result: verifiedResult()}, &fakeStore{}, &fakeSigner{}, r))
	result, _ := p.Process(context.Background(), wire)
	if result.Status != contract.StatusErrored {
		t.Errorf("Status = %v, want StatusErrored (delivery violation)", result.Status)
	}
	if r.calls != 0 {
		t.Errorf("resolver consulted (%d calls) despite a delivery violation", r.calls)
	}
}
