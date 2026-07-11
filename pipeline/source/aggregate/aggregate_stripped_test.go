package aggregate

import (
	"context"
	"testing"

	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
)

// Config.StrippedPublisher threads through to the emitter's dual-emit
// capability: a window fold additionally publishes the stripped
// (Payload: nil) form, under the same sequence number as the primary.
func TestProcess_StrippedPublisher_DualEmits(t *testing.T) {
	stripped := &recordPublisher{}
	h := newHarness(t, func(cfg *Config) { cfg.StrippedPublisher = stripped })
	h.feed(ingressEnvelope(t, "did:example:a", []byte(`{"v":1}`)))

	if !h.p.foldOnce(context.Background()) {
		t.Fatal("foldOnce returned false, want emitted")
	}
	if len(h.pub.calls) != 1 {
		t.Fatalf("primary publishes = %d, want 1", len(h.pub.calls))
	}
	if len(stripped.calls) != 1 {
		t.Fatalf("stripped publishes = %d, want 1", len(stripped.calls))
	}
	env, err := envelopecodec.New().UnmarshalEnvelope(stripped.calls[0])
	if err != nil {
		t.Fatalf("decode stripped envelope: %v", err)
	}
	if env.Payload != nil {
		t.Errorf("stripped envelope Payload = %v, want nil", env.Payload)
	}
	primary, err := envelopecodec.New().UnmarshalEnvelope(h.pub.calls[0])
	if err != nil {
		t.Fatalf("decode primary envelope: %v", err)
	}
	if primary.SequenceNo != env.SequenceNo {
		t.Errorf("sequence mismatch: primary=%d stripped=%d", primary.SequenceNo, env.SequenceNo)
	}
}

// Without a StrippedPublisher, the aggregate's emit behavior is unchanged.
func TestProcess_NoStrippedPublisher_Unchanged(t *testing.T) {
	h := newHarness(t, nil)
	h.feed(ingressEnvelope(t, "did:example:a", []byte(`{"v":1}`)))
	if !h.p.foldOnce(context.Background()) {
		t.Fatal("foldOnce returned false, want emitted")
	}
	if len(h.pub.calls) != 1 {
		t.Fatalf("primary publishes = %d, want 1", len(h.pub.calls))
	}
}
