// Package envelopecodec is the wire codec for pipeline envelopes — the
// reference implementation of contract.EnvelopeCodec over the
// dplaax.pipeline.v1 wire form.
//
// The codec is stateless and subscription-agnostic: it maps wire absence of
// the payload to a nil Payload (by-reference delivery) and never decides
// whether absence is legitimate — that is the responsibility of the layer
// that knows the subscription's agreed delivery mode (runtime loop / export
// seam). The round-trip invariant for the credential is canonical-form
// equality (content hash), never lexical byte preservation.
package envelopecodec

import (
	"errors"
	"fmt"

	"github.com/provin-line/oss/gen/go/dplaax/pipeline/v1"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/vc"
	"google.golang.org/protobuf/proto"
)

// Typed sentinel errors; callers map them with errors.Is.
var (
	ErrNilEnvelope       = errors.New("envelopecodec: nil envelope")
	ErrNilCredential     = errors.New("envelopecodec: nil credential")
	ErrMissingCredential = errors.New("envelopecodec: envelope carries no credential")
	// ErrEmptyPayload — an inline payload is never empty (profile norm):
	// empty and absent are indistinguishable on the proto3 wire, so an
	// empty produced payload is a process bug, rejected at marshal time.
	ErrEmptyPayload = errors.New("envelopecodec: empty inline payload")
	// ErrZeroSequenceNo — sequence numbers are publisher-assigned and
	// 1-based; zero is indistinguishable from unset on the proto3 wire and
	// fails closed in both directions.
	ErrZeroSequenceNo = errors.New("envelopecodec: sequence_no is zero")
)

// Codec implements contract.EnvelopeCodec over dplaax.pipeline.v1.
type Codec struct{}

// New returns the dplaax.pipeline.v1 envelope codec.
func New() *Codec { return &Codec{} }

// MarshalEnvelope encodes the envelope into its proto wire form. The
// credential is embedded as its JCS-canonical JSON document.
func (c *Codec) MarshalEnvelope(e *contract.Envelope) ([]byte, error) {
	if e == nil {
		return nil, ErrNilEnvelope
	}
	if e.Credential == nil {
		return nil, ErrNilCredential
	}
	if e.Payload != nil && len(e.Payload) == 0 {
		return nil, ErrEmptyPayload
	}
	if e.SequenceNo == 0 {
		return nil, ErrZeroSequenceNo
	}
	// Call MarshalJSON directly: routing through json.Marshal would
	// HTML-escape <, >, & and break JCS canonical form (RFC 8785) on the
	// wire.
	cred, err := e.Credential.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("envelopecodec: marshal credential: %w", err)
	}
	wire, err := proto.Marshal(&pipeline.Envelope{
		Credential: cred,
		Payload:    e.Payload,
		SequenceNo: e.SequenceNo,
	})
	if err != nil {
		return nil, fmt.Errorf("envelopecodec: marshal envelope: %w", err)
	}
	return wire, nil
}

// UnmarshalEnvelope decodes the proto wire form. The embedded credential
// document goes through the strict decode path (vc.UnmarshalJSON); wire
// absence of the payload maps to nil (by-reference delivery).
func (c *Codec) UnmarshalEnvelope(data []byte) (*contract.Envelope, error) {
	var pb pipeline.Envelope
	if err := proto.Unmarshal(data, &pb); err != nil {
		return nil, fmt.Errorf("envelopecodec: unmarshal envelope: %w", err)
	}
	if len(pb.Credential) == 0 {
		return nil, ErrMissingCredential
	}
	if pb.SequenceNo == 0 {
		return nil, ErrZeroSequenceNo
	}
	// Call UnmarshalJSON directly so the canon StrictDecoder is the sole
	// decode gate — json.Unmarshal would put encoding/json's own scanner
	// in front of it.
	cred := new(vc.PipelinePassCredential)
	if err := cred.UnmarshalJSON(pb.Credential); err != nil {
		return nil, fmt.Errorf("envelopecodec: decode credential: %w", err)
	}
	var payload []byte
	if len(pb.Payload) > 0 {
		payload = pb.Payload
	}
	return &contract.Envelope{
		Credential: cred,
		Payload:    payload,
		SequenceNo: pb.SequenceNo,
	}, nil
}
