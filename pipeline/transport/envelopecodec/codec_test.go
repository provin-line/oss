package envelopecodec_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/provin-line/oss/gen/go/dplaax/pipeline/v1"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	"github.com/provin-line/oss/vc"
	"google.golang.org/protobuf/proto"
)

var _ contract.EnvelopeCodec = (*envelopecodec.Codec)(nil)

func newTestCredential(t *testing.T) *vc.PipelinePassCredential {
	t.Helper()
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    "did:dplaax:poc.dplaax.io:org:acme:process:p1",
		ValidFrom: time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "pipe-1",
			ProcessID:           "proc-1",
			TransformationClaim: vc.ClaimFilter,
			InputHash:           "uEiB0000000000000000000000000000000000000000000",
			OutputHash:          "uEiB1111111111111111111111111111111111111111111",
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return cred
}

// newCredentialWithUnknownMember returns a credential whose body carries a
// member this implementation does not know — the round-trip invariant must
// hold for it (body-as-source-of-truth).
func newCredentialWithUnknownMember(t *testing.T) *vc.PipelinePassCredential {
	t.Helper()
	canonical, err := json.Marshal(newTestCredential(t))
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(canonical, &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	body["x-future-vocabulary"] = "must-survive"
	widened, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("re-marshal body: %v", err)
	}
	cred := new(vc.PipelinePassCredential)
	if err := json.Unmarshal(widened, cred); err != nil {
		t.Fatalf("UnmarshalJSON with unknown member: %v", err)
	}
	return cred
}

func credentialHash(t *testing.T, c *vc.PipelinePassCredential) string {
	t.Helper()
	h, err := c.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	return h
}

func TestRoundTrip(t *testing.T) {
	cases := map[string]*vc.PipelinePassCredential{
		"plain":          newTestCredential(t),
		"unknown-member": newCredentialWithUnknownMember(t),
	}
	for name, cred := range cases {
		t.Run(name, func(t *testing.T) {
			codec := envelopecodec.New()
			in := &contract.Envelope{
				Credential: cred,
				Payload:    []byte(`{"v":1}`),
				SequenceNo: 42,
			}
			wire, err := codec.MarshalEnvelope(in)
			if err != nil {
				t.Fatalf("MarshalEnvelope: %v", err)
			}
			out, err := codec.UnmarshalEnvelope(wire)
			if err != nil {
				t.Fatalf("UnmarshalEnvelope: %v", err)
			}
			// The invariant is canonical-form equality (content hash), never
			// lexical byte preservation.
			if got, want := credentialHash(t, out.Credential), credentialHash(t, in.Credential); got != want {
				t.Errorf("credential hash changed across round-trip: got %s want %s", got, want)
			}
			if string(out.Payload) != string(in.Payload) {
				t.Errorf("payload changed: got %q want %q", out.Payload, in.Payload)
			}
			if out.SequenceNo != in.SequenceNo {
				t.Errorf("sequence_no changed: got %d want %d", out.SequenceNo, in.SequenceNo)
			}
		})
	}
}

// TestWireCredentialIsCanonical pins the producer-side norm: the embedded
// credential bytes are exactly the credential's own canonical marshal —
// Go's generic json.Marshal would HTML-escape <, >, & and break JCS
// (RFC 8785), which the content-hash round-trip invariant cannot detect.
func TestWireCredentialIsCanonical(t *testing.T) {
	canonical, err := json.Marshal(newTestCredential(t))
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(canonical, &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	body["x-source-url"] = "https://example.com/?a=1&b=<2>"
	widened, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("re-marshal body: %v", err)
	}
	cred := new(vc.PipelinePassCredential)
	if err := cred.UnmarshalJSON(widened); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	want, err := cred.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	wire, err := envelopecodec.New().MarshalEnvelope(&contract.Envelope{
		Credential: cred,
		Payload:    []byte(`{"v":1}`),
		SequenceNo: 1,
	})
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	var pb pipeline.Envelope
	if err := proto.Unmarshal(wire, &pb); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if string(pb.Credential) != string(want) {
		t.Errorf("wire credential is not the canonical marshal:\n got %s\nwant %s", pb.Credential, want)
	}
}

func TestRoundTripByReference(t *testing.T) {
	codec := envelopecodec.New()
	in := &contract.Envelope{
		Credential: newTestCredential(t),
		Payload:    nil, // by-reference delivery
		SequenceNo: 7,
	}
	wire, err := codec.MarshalEnvelope(in)
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	out, err := codec.UnmarshalEnvelope(wire)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope: %v", err)
	}
	if out.Payload != nil {
		t.Errorf("by-reference payload must unmarshal to nil, got %d bytes", len(out.Payload))
	}
}

func TestMarshalRejections(t *testing.T) {
	codec := envelopecodec.New()
	cred := newTestCredential(t)
	cases := []struct {
		name string
		in   *contract.Envelope
		want error
	}{
		{"nil envelope", nil, envelopecodec.ErrNilEnvelope},
		{"nil credential", &contract.Envelope{Payload: []byte("x"), SequenceNo: 1}, envelopecodec.ErrNilCredential},
		{"empty payload", &contract.Envelope{Credential: cred, Payload: []byte{}, SequenceNo: 1}, envelopecodec.ErrEmptyPayload},
		{"zero sequence", &contract.Envelope{Credential: cred, Payload: []byte("x"), SequenceNo: 0}, envelopecodec.ErrZeroSequenceNo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := codec.MarshalEnvelope(tc.in); !errors.Is(err, tc.want) {
				t.Errorf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestUnmarshalRejections(t *testing.T) {
	codec := envelopecodec.New()
	mustWire := func(pb *pipeline.Envelope) []byte {
		t.Helper()
		b, err := proto.Marshal(pb)
		if err != nil {
			t.Fatalf("proto.Marshal: %v", err)
		}
		return b
	}
	validCred, err := json.Marshal(newTestCredential(t))
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	t.Run("malformed proto bytes", func(t *testing.T) {
		if _, err := codec.UnmarshalEnvelope([]byte{0xff, 0xff, 0xff, 0xff}); err == nil {
			t.Error("malformed proto bytes must not unmarshal")
		}
	})
	t.Run("missing credential", func(t *testing.T) {
		wire := mustWire(&pipeline.Envelope{Payload: []byte("x"), SequenceNo: 1})
		if _, err := codec.UnmarshalEnvelope(wire); !errors.Is(err, envelopecodec.ErrMissingCredential) {
			t.Errorf("got %v, want ErrMissingCredential", err)
		}
	})
	t.Run("zero sequence", func(t *testing.T) {
		wire := mustWire(&pipeline.Envelope{Credential: validCred, Payload: []byte("x")})
		if _, err := codec.UnmarshalEnvelope(wire); !errors.Is(err, envelopecodec.ErrZeroSequenceNo) {
			t.Errorf("got %v, want ErrZeroSequenceNo", err)
		}
	})
	t.Run("duplicate-key credential JSON", func(t *testing.T) {
		dup := []byte(`{"issuer":"did:dplaax:a","issuer":"did:dplaax:b"}`)
		wire := mustWire(&pipeline.Envelope{Credential: dup, SequenceNo: 1})
		if _, err := codec.UnmarshalEnvelope(wire); err == nil {
			t.Error("duplicate-key credential JSON must be rejected (StrictDecoder)")
		}
	})
	t.Run("trailing-data credential JSON", func(t *testing.T) {
		trailing := append(append([]byte{}, validCred...), []byte(`{"more":1}`)...)
		wire := mustWire(&pipeline.Envelope{Credential: trailing, SequenceNo: 1})
		if _, err := codec.UnmarshalEnvelope(wire); err == nil {
			t.Error("trailing data after the credential document must be rejected (StrictDecoder)")
		}
	})
}
