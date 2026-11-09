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
//
// What a subscriber hands UnmarshalEnvelope has no bound that holds
// regardless of the messaging backend, so the codec bounds what it decodes by
// its Limits, node-level and the same for every subscription: the whole
// message before it is read as protobuf, then the credential before it is
// read as JSON, and the inline payload. A refusal is an error naming the two
// sizes only.
package envelopecodec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

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
	// ErrInvalidLimits — New takes only positive Limits whose bound of a
	// whole message fits an int.
	ErrInvalidLimits = errors.New("envelopecodec: invalid limits")
	// ErrMessageTooLarge — the message is longer than the bound of a whole
	// message: MaxCredentialSize, MaxInlinePayloadSize and the framing of
	// the envelope's fields.
	ErrMessageTooLarge = errors.New("envelopecodec: message too large")
	// ErrCredentialTooLarge — the credential is longer than
	// MaxCredentialSize.
	ErrCredentialTooLarge = errors.New("envelopecodec: credential too large")
	// ErrInlinePayloadTooLarge — the inline payload is longer than
	// MaxInlinePayloadSize.
	ErrInlinePayloadTooLarge = errors.New("envelopecodec: inline payload too large")
)

// Limits bounds what UnmarshalEnvelope decodes. Both are required and
// positive.
type Limits struct {
	// MaxCredentialSize bounds the bytes of the credential, the JSON document
	// the envelope carries.
	MaxCredentialSize int
	// MaxInlinePayloadSize bounds the bytes of an inline payload.
	MaxInlinePayloadSize int
}

// framing is what the bound of a whole message allows besides the credential
// and the inline payload: the reference encoding writes the envelope's three
// fields (credential, payload, sequence_no), each as a tag of one byte and a
// varint of at most binary.MaxVarintLen64 bytes (the field's length, or the
// sequence number itself). A field, or a field written more than once, beyond
// those is admitted only within this allowance.
const framing = 3 * (1 + binary.MaxVarintLen64)

// Codec implements contract.EnvelopeCodec over dplaax.pipeline.v1. It holds
// only its limits and is safe for concurrent use. The zero Codec marshals,
// and refuses every message it is given to unmarshal.
type Codec struct {
	limits Limits
	// maxMessage is the bound of a whole message: both limits and framing.
	maxMessage int
}

// New returns the dplaax.pipeline.v1 envelope codec, bounding what it
// decodes by l. It refuses l with ErrInvalidLimits when either limit is not
// positive, or when the bound of a whole message would not fit an int.
func New(l Limits) (*Codec, error) {
	if l.MaxCredentialSize <= 0 || l.MaxInlinePayloadSize <= 0 {
		return nil, fmt.Errorf("%w: credential %d and inline payload %d must be positive", ErrInvalidLimits, l.MaxCredentialSize, l.MaxInlinePayloadSize)
	}
	if l.MaxCredentialSize > math.MaxInt-framing-l.MaxInlinePayloadSize {
		return nil, fmt.Errorf("%w: credential %d and inline payload %d, with %d bytes of framing, pass the largest int", ErrInvalidLimits, l.MaxCredentialSize, l.MaxInlinePayloadSize, framing)
	}
	return &Codec{limits: l, maxMessage: l.MaxCredentialSize + l.MaxInlinePayloadSize + framing}, nil
}

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
//
// It refuses data longer than the bound of a whole message before reading it
// (ErrMessageTooLarge), then a credential longer than MaxCredentialSize
// before decoding it (ErrCredentialTooLarge) and an inline payload longer
// than MaxInlinePayloadSize (ErrInlinePayloadTooLarge). Protobuf keeps the
// last of a field written more than once: the two limits bound the fields as
// decoded, and the bound of the whole message every occurrence together.
func (c *Codec) UnmarshalEnvelope(data []byte) (*contract.Envelope, error) {
	if len(data) > c.maxMessage {
		return nil, fmt.Errorf("%w: %d bytes, beyond the bound of %d", ErrMessageTooLarge, len(data), c.maxMessage)
	}
	var pb pipeline.Envelope
	if err := proto.Unmarshal(data, &pb); err != nil {
		return nil, fmt.Errorf("envelopecodec: unmarshal envelope: %w", err)
	}
	if len(pb.Credential) == 0 {
		return nil, ErrMissingCredential
	}
	if len(pb.Credential) > c.limits.MaxCredentialSize {
		return nil, fmt.Errorf("%w: %d bytes, beyond the bound of %d", ErrCredentialTooLarge, len(pb.Credential), c.limits.MaxCredentialSize)
	}
	if len(pb.Payload) > c.limits.MaxInlinePayloadSize {
		return nil, fmt.Errorf("%w: %d bytes, beyond the bound of %d", ErrInlinePayloadTooLarge, len(pb.Payload), c.limits.MaxInlinePayloadSize)
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
