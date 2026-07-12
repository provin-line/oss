package transport_test

import (
	"testing"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/transport"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
)

// The control-plane by-reference health gate reads a loop's stripped-publish
// health through StrippedPublishHealthy. Before Run (and for non-producing
// loops) it is nil-safe healthy; after a delivered message whose stripped
// publish fails, it reports unhealthy.
func TestLoop_StrippedPublishHealthAccessors(t *testing.T) {
	sub := newSyncSubscriber([]byte("raw input"))
	loop, err := transport.NewLoop(transport.LoopConfig{
		Behavior:          contract.ChainPreserving,
		Strategy:          contract.VerificationAdjacent,
		Processor:         &fakeProcessor{results: []*contract.Result{passedResult(t, []byte(`{"k":"v"}`))}, errs: []error{nil}},
		Subscriber:        sub,
		Publisher:         &fakePublisher{},
		Codec:             envelopecodec.New(),
		Emission:          &fakeTlog{},
		StrippedPublisher: &failingPublisher{}, // every stripped publish fails
	})
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	// Before Run the emitter does not exist yet: nil-safe healthy.
	if !loop.StrippedPublishHealthy() {
		t.Error("before Run: want healthy")
	}
	if n := loop.StrippedPublishFailures(); n != 0 {
		t.Errorf("before Run: count = %d, want 0", n)
	}

	cancel, done := runLoop(t, loop, sub)
	sub.deliver() // synchronous: the emit (and its failing stripped publish) completes
	cancel()
	if runErr := <-done; runErr != nil {
		t.Fatalf("Run: %v", runErr)
	}

	if loop.StrippedPublishHealthy() {
		t.Error("after a failing stripped publish: want unhealthy")
	}
	if n := loop.StrippedPublishFailures(); n != 1 {
		t.Errorf("after a failing stripped publish: count = %d, want 1", n)
	}
}
