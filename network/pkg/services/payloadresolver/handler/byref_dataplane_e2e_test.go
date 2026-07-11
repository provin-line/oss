package handler_test

import (
	"context"
	"testing"
	"time"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	"github.com/provin-line/oss/vc"
)

// This is the by-reference DATA PATH e2e: a payload is retained at the serving
// boundary, an envelope is delivered WITHOUT the payload (by-reference), and a
// consuming sink dereferences it over the real PayloadService, binds it against
// the credential's outputHash, and delivers it. Everything but the (non-goal)
// export-seam stripping is exercised end-to-end.

type e2eVerifier struct{}

func (e2eVerifier) Verify(_ context.Context, _ *vc.PipelinePassCredential) (*vc.VerifyResult, error) {
	return &vc.VerifyResult{Overall: vc.ConfidenceVerified}, nil
}

type e2eIngressStore struct{}

func (e2eIngressStore) StoreIngressVC(_ context.Context, _ *vc.PipelinePassCredential, _ string) error {
	return nil
}

type e2eWriter struct{ records []sink.Record }

func (w *e2eWriter) Write(_ context.Context, rec sink.Record) error {
	w.records = append(w.records, rec)
	return nil
}

func e2eCred(t *testing.T, outputHash string) *vc.PipelinePassCredential {
	t.Helper()
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pa:process:p1",
		ValidFrom: time.Unix(0, 0),
		Subject: vc.CredentialSubjectFields{
			PipelineID: "pa", ProcessID: "p1",
			TransformationClaim: vc.ClaimConvert, OutputHash: outputHash,
		},
	})
	if err != nil {
		t.Fatalf("vc.New: %v", err)
	}
	return cred
}

// A by-reference sink dereferences the payload from the serving boundary, binds
// it, and writes it — proving retain → serve → fetch → bind → deliver.
func TestByReference_DataPath_SinkFetchesAndDelivers(t *testing.T) {
	h := newHarness(t, 0)
	payload := []byte(`{"produced":"the-data","n":42}`)

	// Publisher retains the payload (owner = a pipeline that admits the node).
	hash, err := h.svc.Store(context.Background(), payload, ownerPBA)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	// Consumer sink, by-reference, resolving through the real PayloadService client.
	w := &e2eWriter{}
	p, err := sink.New(sink.Config{
		Strategy:         contract.VerificationAdjacent,
		Kind:             contract.SinkObservationOnly,
		Codec:            envelopecodec.New(),
		Verifier:         e2eVerifier{},
		Store:            e2eIngressStore{},
		Writer:           w,
		UpstreamEndpoint: h.url,
		PayloadDelivery:  contract.DeliveryByReference,
		PayloadResolver:  h.client,
	})
	if err != nil {
		t.Fatalf("sink.New: %v", err)
	}

	// A by-reference envelope: the credential binds to the payload, but no
	// payload rides inline.
	wire, err := envelopecodec.New().MarshalEnvelope(&contract.Envelope{
		Credential: e2eCred(t, hash), Payload: nil, SequenceNo: 1,
	})
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("Process: %v", goErr)
	}
	if result.Status != contract.StatusPassed {
		t.Fatalf("Status = %v, want StatusPassed", result.Status)
	}
	if len(w.records) != 1 || string(w.records[0].Payload) != string(payload) {
		t.Fatalf("delivered payload = %v, want the fetched %q", w.records, payload)
	}
}

// If the serving boundary holds no payload, the by-reference sink rejects the
// event (a liveness failure) rather than delivering unbound bytes.
func TestByReference_DataPath_MissingPayload_Rejected(t *testing.T) {
	h := newHarness(t, 0)
	// Never stored; the credential binds to a hash the boundary does not hold.
	missing := "sha256:" + "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

	w := &e2eWriter{}
	p, err := sink.New(sink.Config{
		Strategy:         contract.VerificationAdjacent,
		Kind:             contract.SinkObservationOnly,
		Codec:            envelopecodec.New(),
		Verifier:         e2eVerifier{},
		Store:            e2eIngressStore{},
		Writer:           w,
		UpstreamEndpoint: h.url,
		PayloadDelivery:  contract.DeliveryByReference,
		PayloadResolver:  h.client,
	})
	if err != nil {
		t.Fatalf("sink.New: %v", err)
	}
	wire, err := envelopecodec.New().MarshalEnvelope(&contract.Envelope{
		Credential: e2eCred(t, missing), Payload: nil, SequenceNo: 1,
	})
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	result, _ := p.Process(context.Background(), wire)
	if result.Status != contract.StatusErrored {
		t.Errorf("Status = %v, want StatusErrored (payload not servable)", result.Status)
	}
	if len(w.records) != 0 {
		t.Error("delivered a record despite an unresolvable payload")
	}
}
