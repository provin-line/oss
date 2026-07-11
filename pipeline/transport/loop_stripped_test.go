package transport_test

import (
	"testing"
	"time"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/transport"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
)

// LoopConfig.StrippedPublisher threads through to the Emitter's dual-emit
// capability: a producing loop with one configured publishes the stripped
// (Payload: nil) form to it, alongside the primary publish.
func TestLoop_StrippedPublisher_DualEmits(t *testing.T) {
	sub := newSyncSubscriber([]byte(`{"in":1}`))
	payload := []byte(`{"out":1}`)
	proc := &fakeProcessor{results: []*contract.Result{passedResult(t, payload)}, errs: []error{nil}}
	pub := &fakePublisher{}
	stripped := &fakePublisher{}

	loop, err := transport.NewLoop(transport.LoopConfig{
		Behavior:          contract.ChainPreserving,
		Strategy:          contract.VerificationAdjacent,
		Processor:         proc,
		Subscriber:        sub,
		Publisher:         pub,
		Codec:             envelopecodec.New(),
		Emission:          &fakeTlog{},
		StrippedPublisher: stripped,
	})
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}
	cancel, done := runLoop(t, loop, sub)
	sub.deliver()

	deadline := time.After(5 * time.Second)
	for pub.callCount() == 0 {
		select {
		case <-deadline:
			t.Fatal("primary publish never observed")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if stripped.callCount() != 1 {
		t.Fatalf("stripped publishes = %d, want 1", stripped.callCount())
	}
	env, err := envelopecodec.New().UnmarshalEnvelope(stripped.calls[0])
	if err != nil {
		t.Fatalf("decode stripped envelope: %v", err)
	}
	if env.Payload != nil {
		t.Errorf("stripped envelope Payload = %v, want nil", env.Payload)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("loop did not drain after cancel")
	}
}

// Without StrippedPublisher, a Loop's behavior is byte-for-byte unchanged
// (single publish only).
func TestLoop_NoStrippedPublisher_Unchanged(t *testing.T) {
	sub := newSyncSubscriber([]byte(`{"in":1}`))
	payload := []byte(`{"out":1}`)
	proc := &fakeProcessor{results: []*contract.Result{passedResult(t, payload)}, errs: []error{nil}}
	pub := &fakePublisher{}

	loop, err := transport.NewLoop(transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  proc,
		Subscriber: sub,
		Publisher:  pub,
		Codec:      envelopecodec.New(),
		Emission:   &fakeTlog{},
	})
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}
	cancel, done := runLoop(t, loop, sub)
	sub.deliver()

	deadline := time.After(5 * time.Second)
	for pub.callCount() == 0 {
		select {
		case <-deadline:
			t.Fatal("primary publish never observed")
		case <-time.After(10 * time.Millisecond):
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("loop did not drain after cancel")
	}
}
