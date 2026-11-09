package envelopecodec_test

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/provin-line/oss/gen/go/dplaax/pipeline/v1"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// framing is what the bound of a whole message allows besides the credential
// and the inline payload: the reference encoding's three fields, each a tag
// of one byte and a varint of at most ten.
const framing = 33

func TestNewRefusesInvalidLimits(t *testing.T) {
	cases := []struct {
		name   string
		limits envelopecodec.Limits
	}{
		{"zero", envelopecodec.Limits{}},
		{"zero credential", envelopecodec.Limits{MaxCredentialSize: 0, MaxInlinePayloadSize: 1}},
		{"zero inline payload", envelopecodec.Limits{MaxCredentialSize: 1, MaxInlinePayloadSize: 0}},
		{"negative credential", envelopecodec.Limits{MaxCredentialSize: -1, MaxInlinePayloadSize: 1}},
		{"negative inline payload", envelopecodec.Limits{MaxCredentialSize: 1, MaxInlinePayloadSize: -1}},
		{"sum overflows int", envelopecodec.Limits{MaxCredentialSize: math.MaxInt - framing, MaxInlinePayloadSize: 1}},
		{"both at the largest int", envelopecodec.Limits{MaxCredentialSize: math.MaxInt, MaxInlinePayloadSize: math.MaxInt}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := envelopecodec.New(tc.limits)
			if !errors.Is(err, envelopecodec.ErrInvalidLimits) {
				t.Fatalf("New(%+v): got %v, want ErrInvalidLimits", tc.limits, err)
			}
			if c != nil {
				t.Errorf("New(%+v) returned a codec with its error", tc.limits)
			}
		})
	}
}

func TestNewAcceptsTheLargestLimits(t *testing.T) {
	l := envelopecodec.Limits{MaxCredentialSize: math.MaxInt - framing - 1, MaxInlinePayloadSize: 1}
	if _, err := envelopecodec.New(l); err != nil {
		t.Fatalf("New(%+v): %v", l, err)
	}
}

func mustWire(t *testing.T, pb *pipeline.Envelope) []byte {
	t.Helper()
	b, err := proto.Marshal(pb)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	return b
}

// boundedCodec returns a codec whose credential bound is exactly the test
// credential's size and whose inline payload bound is 16 bytes, and that
// credential.
func boundedCodec(t *testing.T, credentialSlack int) (*envelopecodec.Codec, []byte) {
	t.Helper()
	cred, err := json.Marshal(newTestCredential(t))
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	c, err := envelopecodec.New(envelopecodec.Limits{MaxCredentialSize: len(cred) + credentialSlack, MaxInlinePayloadSize: 16})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, cred
}

func TestUnmarshalAcceptsWhatFitsTheLimits(t *testing.T) {
	c, cred := boundedCodec(t, 0)
	wire := mustWire(t, &pipeline.Envelope{Credential: cred, Payload: []byte(strings.Repeat("p", 16)), SequenceNo: math.MaxUint64})
	out, err := c.UnmarshalEnvelope(wire)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope: %v", err)
	}
	if len(out.Payload) != 16 {
		t.Errorf("payload: got %d bytes, want 16", len(out.Payload))
	}
}

// checkRefusal checks err is want and that its text names the two sizes and
// nothing of the message.
func checkRefusal(t *testing.T, err, want error, size, bound int, content string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
	text := err.Error()
	for _, n := range []int{size, bound} {
		if !strings.Contains(text, strconv.Itoa(n)) {
			t.Errorf("error %q does not name %d", text, n)
		}
	}
	if content != "" && strings.Contains(text, content) {
		t.Errorf("error %q quotes the message", text)
	}
}

func TestUnmarshalRefusesACredentialPastItsBound(t *testing.T) {
	c, cred := boundedCodec(t, -1)
	wire := mustWire(t, &pipeline.Envelope{Credential: cred, Payload: []byte("p"), SequenceNo: 1})
	_, err := c.UnmarshalEnvelope(wire)
	checkRefusal(t, err, envelopecodec.ErrCredentialTooLarge, len(cred), len(cred)-1, "pipe-1")
}

// The credential's bound is checked before it is read as JSON: bytes that are
// not JSON at all are refused by their size.
func TestUnmarshalRefusesACredentialPastItsBoundBeforeDecodingIt(t *testing.T) {
	c, cred := boundedCodec(t, 0)
	notJSON := strings.Repeat("\xff", len(cred)+1)
	wire := mustWire(t, &pipeline.Envelope{Credential: []byte(notJSON), Payload: []byte("p"), SequenceNo: 1})
	_, err := c.UnmarshalEnvelope(wire)
	checkRefusal(t, err, envelopecodec.ErrCredentialTooLarge, len(cred)+1, len(cred), "")
}

func TestUnmarshalRefusesAnInlinePayloadPastItsBound(t *testing.T) {
	c, cred := boundedCodec(t, 0)
	payload := strings.Repeat("Z", 17)
	wire := mustWire(t, &pipeline.Envelope{Credential: cred, Payload: []byte(payload), SequenceNo: 1})
	_, err := c.UnmarshalEnvelope(wire)
	checkRefusal(t, err, envelopecodec.ErrInlinePayloadTooLarge, 17, 16, "ZZZ")
}

// The bound of a whole message is checked before the bytes are read as
// protobuf: bytes that are not an envelope at all are refused by their
// size.
func TestUnmarshalRefusesAMessagePastItsBoundBeforeDecoding(t *testing.T) {
	c, cred := boundedCodec(t, 0)
	bound := len(cred) + 16 + framing
	data := []byte(strings.Repeat("\xff", bound+1))
	_, err := c.UnmarshalEnvelope(data)
	checkRefusal(t, err, envelopecodec.ErrMessageTooLarge, bound+1, bound, "")
}

// A message at the bound is not refused for its size: here a valid
// envelope padded with an unknown field up to the bound.
func TestUnmarshalAcceptsAMessageAtItsBound(t *testing.T) {
	c, cred := boundedCodec(t, 0)
	bound := len(cred) + 16 + framing
	base := mustWire(t, &pipeline.Envelope{Credential: cred, Payload: []byte("p"), SequenceNo: 1})
	pad := func(n int) []byte {
		// An unknown field 15 of wire type bytes: its tag (1 byte), its
		// length (1 byte, under 128) and n-2 bytes of content.
		b := protowire.AppendTag(nil, 15, protowire.BytesType)
		return protowire.AppendBytes(b, make([]byte, n-2))
	}
	at := append(append([]byte{}, base...), pad(bound-len(base))...)
	if len(at) != bound {
		t.Fatalf("padded to %d bytes, want %d", len(at), bound)
	}
	if _, err := c.UnmarshalEnvelope(at); err != nil {
		t.Fatalf("a message at the bound: %v", err)
	}
	past := append(append([]byte{}, base...), pad(bound-len(base)+1)...)
	_, err := c.UnmarshalEnvelope(past)
	checkRefusal(t, err, envelopecodec.ErrMessageTooLarge, bound+1, bound, "")
}

// Protobuf keeps the last of a field written more than once; the bounds
// apply to the fields as decoded, and the bound of the whole message to
// every occurrence together.
func TestUnmarshalBoundsTheDecodedFields(t *testing.T) {
	c, cred := boundedCodec(t, 0)
	field := func(payload string) []byte {
		b := protowire.AppendTag(nil, 2, protowire.BytesType)
		return protowire.AppendString(b, payload)
	}
	base := mustWire(t, &pipeline.Envelope{Credential: cred, SequenceNo: 1})

	t.Run("a larger payload written first", func(t *testing.T) {
		wire := append(append(append([]byte{}, base...), field(strings.Repeat("Z", 17))...), field("p")...)
		out, err := c.UnmarshalEnvelope(wire)
		if err != nil {
			t.Fatalf("UnmarshalEnvelope: %v", err)
		}
		if string(out.Payload) != "p" {
			t.Errorf("payload: got %q, want the last one written", out.Payload)
		}
	})
	t.Run("a larger payload written last", func(t *testing.T) {
		wire := append(append(append([]byte{}, base...), field("p")...), field(strings.Repeat("Z", 17))...)
		_, err := c.UnmarshalEnvelope(wire)
		checkRefusal(t, err, envelopecodec.ErrInlinePayloadTooLarge, 17, 16, "ZZZ")
	})

	credential := func(b []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), b)
	}
	small, _ := boundedCodec(t, -len(cred)+8)
	t.Run("a larger credential written first", func(t *testing.T) {
		wire := append(append(mustWire(t, &pipeline.Envelope{Payload: []byte("p"), SequenceNo: 1}), credential([]byte(strings.Repeat("Z", 9)))...), credential([]byte("{}"))...)
		_, err := small.UnmarshalEnvelope(wire)
		if errors.Is(err, envelopecodec.ErrCredentialTooLarge) || errors.Is(err, envelopecodec.ErrMessageTooLarge) {
			t.Fatalf("the last credential written fits: %v", err)
		}
	})
	t.Run("a larger credential written last", func(t *testing.T) {
		wire := append(append(mustWire(t, &pipeline.Envelope{Payload: []byte("p"), SequenceNo: 1}), credential([]byte("{}"))...), credential([]byte(strings.Repeat("Z", 9)))...)
		_, err := small.UnmarshalEnvelope(wire)
		checkRefusal(t, err, envelopecodec.ErrCredentialTooLarge, 9, 8, "ZZZ")
	})
}

// The bound of a whole message allows for the envelope's fields as the
// reference encoding writes them. These pin the fields it allows for: a field
// added to the envelope makes them fail until the allowance is reviewed.
func TestEnvelopeFieldsTheMessageBoundAllowsFor(t *testing.T) {
	fields := (&pipeline.Envelope{}).ProtoReflect().Descriptor().Fields()
	want := []struct {
		number protoreflect.FieldNumber
		name   protoreflect.Name
		kind   protoreflect.Kind
	}{
		{1, "credential", protoreflect.BytesKind},
		{2, "payload", protoreflect.BytesKind},
		{3, "sequence_no", protoreflect.Uint64Kind},
	}
	if fields.Len() != len(want) {
		t.Fatalf("the envelope has %d fields; the message bound allows for %d", fields.Len(), len(want))
	}
	for i, w := range want {
		f := fields.Get(i)
		if f.Number() != w.number || f.Name() != w.name || f.Kind() != w.kind || f.Cardinality() != protoreflect.Optional {
			t.Errorf("field %d: got %d %s %v %v, want %d %s %v singular", i, f.Number(), f.Name(), f.Kind(), f.Cardinality(), w.number, w.name, w.kind)
		}
	}
}

// The same three fields, read from the envelope's .proto source, so a field
// added there fails this before the Go code is generated again.
func TestEnvelopeProtoSourceHasTheFieldsTheMessageBoundAllowsFor(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "api", "protobuf", "dplaax", "pipeline", "v1", "envelope.proto"))
	if err != nil {
		t.Fatalf("read envelope.proto: %v", err)
	}
	body := regexp.MustCompile(`(?s)\nmessage Envelope \{(.*?)\n\}`).FindSubmatch(src)
	if body == nil {
		t.Fatal("envelope.proto: no message Envelope")
	}
	field := regexp.MustCompile(`(?m)^\s*([A-Za-z][\w.]*(?:\s+[A-Za-z][\w.]*)*)\s+(\w+)\s*=\s*(\d+)\s*;`)
	var got []string
	for _, line := range strings.Split(string(body[1]), "\n") {
		if code, _, _ := strings.Cut(line, "//"); strings.TrimSpace(code) != "" {
			m := field.FindStringSubmatch(code)
			if m == nil {
				t.Errorf("envelope.proto: a line the message bound does not know: %q", strings.TrimSpace(code))
				continue
			}
			got = append(got, m[1]+" "+m[2]+" = "+m[3])
		}
	}
	want := []string{"bytes credential = 1", "bytes payload = 2", "uint64 sequence_no = 3"}
	if strings.Join(got, "; ") != strings.Join(want, "; ") {
		t.Errorf("envelope.proto declares %q; the message bound allows for %q", got, want)
	}
}

// The reference encoding of the largest envelope the limits admit fits the
// bound of a whole message, for lengths whose varints take one to four
// bytes.
func TestTheLargestEnvelopeFitsTheMessageBound(t *testing.T) {
	for _, l := range []envelopecodec.Limits{
		{MaxCredentialSize: 1, MaxInlinePayloadSize: 1},
		{MaxCredentialSize: 127, MaxInlinePayloadSize: 128},
		{MaxCredentialSize: 16384, MaxInlinePayloadSize: 1 << 20},
		{MaxCredentialSize: 1 << 21, MaxInlinePayloadSize: 1 << 22},
	} {
		c, err := envelopecodec.New(l)
		if err != nil {
			t.Fatalf("New(%+v): %v", l, err)
		}
		wire := mustWire(t, &pipeline.Envelope{
			Credential: make([]byte, l.MaxCredentialSize),
			Payload:    make([]byte, l.MaxInlinePayloadSize),
			SequenceNo: math.MaxUint64,
		})
		_, err = c.UnmarshalEnvelope(wire)
		for _, bound := range []error{envelopecodec.ErrMessageTooLarge, envelopecodec.ErrCredentialTooLarge, envelopecodec.ErrInlinePayloadTooLarge} {
			if errors.Is(err, bound) {
				t.Errorf("limits %+v: the largest envelope (%d bytes) is refused: %v", l, len(wire), err)
			}
		}
		if err == nil {
			t.Errorf("limits %+v: a credential of NUL bytes decoded as JSON", l)
		}
	}
}

// The zero Codec admits no message.
func TestZeroCodecRefusesEveryMessage(t *testing.T) {
	var c envelopecodec.Codec
	_, cred := boundedCodec(t, 0)
	wire := mustWire(t, &pipeline.Envelope{Credential: cred, Payload: []byte("p"), SequenceNo: 1})
	if _, err := c.UnmarshalEnvelope(wire); !errors.Is(err, envelopecodec.ErrMessageTooLarge) {
		t.Fatalf("got %v, want ErrMessageTooLarge", err)
	}
}
