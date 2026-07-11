package aggregate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	"github.com/provin-line/oss/vc"
)

// fakePayloadResolver records what it was asked to resolve.
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

// byRefEnvelope builds a wire envelope binding OutputHash to payload but
// carrying NO inline payload (by-reference delivery).
func byRefEnvelope(t *testing.T, issuer string, payload []byte) []byte {
	t.Helper()
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    issuer,
		ValidFrom: time.Unix(0, 0),
		Subject: vc.CredentialSubjectFields{
			PipelineID: "src", ProcessID: "p",
			TransformationClaim: vc.ClaimConvert, OutputHash: testHash(payload),
		},
	})
	if err != nil {
		t.Fatalf("vc.New: %v", err)
	}
	wire, err := envelopecodec.New().MarshalEnvelope(&contract.Envelope{Credential: cred, Payload: nil, SequenceNo: 1})
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	return wire
}

func byRefIngress(r contract.PayloadResolver) Ingress {
	return Ingress{UpstreamEndpoint: "https://up.example/src", PayloadDelivery: contract.DeliveryByReference, PayloadResolver: r}
}

// A by-reference ingress without a resolver fails construction.
func TestNew_ByReferenceIngressRequiresResolver(t *testing.T) {
	h := newHarness(t, nil)
	cfg := Config{
		Ingress:   []Ingress{{Subscriber: h.sub, UpstreamEndpoint: "u", PayloadDelivery: contract.DeliveryByReference}},
		Window:    time.Hour,
		Signer:    h.sign,
		Verifier:  stubVerifier{state: vc.ConfidenceVerified},
		Store:     h.store,
		Publisher: h.pub,
		Codec:     envelopecodec.New(),
		Emission:  h.emis,
		Fold:      ManifestFold{},
	}
	if _, err := New(cfg); !errors.Is(err, ErrMissingPayloadResolver) {
		t.Fatalf("New by-reference ingress without resolver err = %v, want ErrMissingPayloadResolver", err)
	}
}

// by-reference + nil payload: fetch by outputHash, bind, pool.
func TestHandleIngress_ByReference_Fetches(t *testing.T) {
	h := newHarness(t, nil)
	payload := []byte(`{"produced":"data"}`)
	wire := byRefEnvelope(t, "did:example:a", payload)
	r := &fakePayloadResolver{bytes: payload}

	h.feedIngress(wire, byRefIngress(r))

	if got := poolLen(h); got != 1 {
		t.Fatalf("pool len = %d, want 1 (fetched + bound + pooled)", got)
	}
	if r.calls != 1 || r.gotEndpoint != "https://up.example/src" || r.gotHash != testHash(payload) {
		t.Errorf("resolver got (calls=%d, endpoint=%q, hash=%q), want (1, upstream, %q)", r.calls, r.gotEndpoint, r.gotHash, testHash(payload))
	}
}

// by-reference + inline payload present → drop (violation), resolver unused.
func TestHandleIngress_ByReference_InlinePresent_Drops(t *testing.T) {
	h := newHarness(t, nil)
	payload := []byte(`{"produced":"data"}`)
	wire := ingressEnvelope(t, "did:example:a", payload) // inline present
	r := &fakePayloadResolver{bytes: payload}

	h.feedIngress(wire, byRefIngress(r))

	if got := poolLen(h); got != 0 {
		t.Errorf("pool len = %d, want 0 (delivery violation dropped)", got)
	}
	if r.calls != 0 {
		t.Errorf("resolver consulted (%d) despite a violation", r.calls)
	}
}

// by-reference + fetch failure → drop.
func TestHandleIngress_ByReference_FetchFailure_Drops(t *testing.T) {
	h := newHarness(t, nil)
	wire := byRefEnvelope(t, "did:example:a", []byte(`{"produced":"data"}`))
	r := &fakePayloadResolver{err: errors.New("serving boundary down")}

	h.feedIngress(wire, byRefIngress(r))

	if got := poolLen(h); got != 0 {
		t.Errorf("pool len = %d, want 0 (fetch failure dropped)", got)
	}
}

// by-reference + tampered fetch → drop at the binding gate.
func TestHandleIngress_ByReference_TamperedFetch_Drops(t *testing.T) {
	h := newHarness(t, nil)
	wire := byRefEnvelope(t, "did:example:a", []byte(`{"produced":"data"}`))
	r := &fakePayloadResolver{bytes: []byte(`{"tampered":true}`)}

	h.feedIngress(wire, byRefIngress(r))

	if got := poolLen(h); got != 0 {
		t.Errorf("pool len = %d, want 0 (binding gate dropped)", got)
	}
}

// inline + nil payload → drop (stripped in error).
func TestHandleIngress_Inline_NilPayload_Drops(t *testing.T) {
	h := newHarness(t, nil)
	wire := byRefEnvelope(t, "did:example:a", []byte(`{"produced":"data"}`)) // nil payload
	h.feedIngress(wire, Ingress{UpstreamEndpoint: "https://up.example/src"}) // inline mode

	if got := poolLen(h); got != 0 {
		t.Errorf("pool len = %d, want 0 (inline + nil dropped)", got)
	}
}

func poolLen(h *harness) int {
	h.p.mu.Lock()
	defer h.p.mu.Unlock()
	return len(h.p.pool)
}
