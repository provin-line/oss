package transport_test

import (
	"context"
	"errors"
	"testing"

	"github.com/provin-line/oss/pipeline/transport"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
)

// A stripped-publisher-equipped Emitter dual-publishes: the primary form
// (with payload) and the stripped form (Payload: nil), both carrying the SAME
// sequence number.
func TestEmitter_Stripped_DualPublishSameSeq(t *testing.T) {
	pub := &fakePublisher{}
	stripped := &fakePublisher{}
	e, err := transport.NewEmitter(context.Background(), pub, envelopecodec.New(), &fakeTlog{}, nil, transport.WithStrippedPublisher(stripped))
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	payload := []byte(`{"a":1}`)
	cred := newTestCredential(t, payload)
	if err := e.Emit(context.Background(), cred, payload); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	if pub.callCount() != 1 {
		t.Fatalf("primary publishes = %d, want 1", pub.callCount())
	}
	if stripped.callCount() != 1 {
		t.Fatalf("stripped publishes = %d, want 1", stripped.callCount())
	}
	if got := seqOf(t, pub.calls[0]); got != 1 {
		t.Errorf("primary SequenceNo = %d, want 1", got)
	}
	if got := seqOf(t, stripped.calls[0]); got != 1 {
		t.Errorf("stripped SequenceNo = %d, want 1 (same as primary)", got)
	}

	// The stripped envelope round-trips to a nil Payload via the real codec.
	env, err := envelopecodec.New().UnmarshalEnvelope(stripped.calls[0])
	if err != nil {
		t.Fatalf("UnmarshalEnvelope(stripped): %v", err)
	}
	if env.Payload != nil {
		t.Errorf("stripped envelope Payload = %v, want nil", env.Payload)
	}
	if env.Credential == nil {
		t.Error("stripped envelope carries no credential")
	}

	// The primary form is unaffected: it still carries the payload.
	primaryEnv, err := envelopecodec.New().UnmarshalEnvelope(pub.calls[0])
	if err != nil {
		t.Fatalf("UnmarshalEnvelope(primary): %v", err)
	}
	if string(primaryEnv.Payload) != string(payload) {
		t.Errorf("primary Payload = %q, want %q", primaryEnv.Payload, payload)
	}
}

// stripped fake publisher that always fails, to exercise the partial-failure
// semantics.
type failingPublisher struct {
	calls int
}

func (f *failingPublisher) Publish([]byte) error { f.calls++; return errors.New("stripped: boom") }
func (f *failingPublisher) Healthy() bool        { return true }
func (f *failingPublisher) Close() error         { return nil }

// A stripped-publish failure does NOT fail Emit: the primary already
// delivered, so Emit succeeds (seq advances, emission log appends once), and
// the failure is recorded on the monotonic counter — not silently dropped.
func TestEmitter_Stripped_FailureDoesNotFailEmit(t *testing.T) {
	pub := &fakePublisher{}
	stripped := &failingPublisher{}
	tl := &fakeTlog{}
	e, err := transport.NewEmitter(context.Background(), pub, envelopecodec.New(), tl, nil, transport.WithStrippedPublisher(stripped))
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	payload := []byte(`{"a":1}`)
	cred := newTestCredential(t, payload)

	if err := e.Emit(context.Background(), cred, payload); err != nil {
		t.Fatalf("Emit with a failing stripped publisher: want nil (primary delivered), got %v", err)
	}
	if pub.callCount() != 1 {
		t.Errorf("primary publishes = %d, want 1", pub.callCount())
	}
	if tl.appendedCount() != 1 {
		t.Errorf("emission log appends = %d, want 1 (exactly once, form-independent)", tl.appendedCount())
	}
	if stripped.calls != 1 {
		t.Errorf("stripped publish attempts = %d, want 1", stripped.calls)
	}
	if got := e.StrippedPublishFailures(); got != 1 {
		t.Errorf("StrippedPublishFailures() = %d, want 1", got)
	}
	if _, ok := e.LastStrippedPublishFailure(); !ok {
		t.Error("LastStrippedPublishFailure() ok = false, want true after a failure")
	}

	// Seq advanced: the NEXT Emit uses sequence 2, on the primary publisher.
	if err := e.Emit(context.Background(), cred, payload); err != nil {
		t.Fatalf("second Emit: %v", err)
	}
	if got := seqOf(t, pub.calls[1]); got != 2 {
		t.Errorf("second SequenceNo = %d, want 2 (seq advanced despite stripped failure)", got)
	}
	if got := e.StrippedPublishFailures(); got != 2 {
		t.Errorf("StrippedPublishFailures() after second failure = %d, want 2 (monotonic)", got)
	}
}

// Without a stripped publisher, Emit is byte-for-byte the pre-dual-emit
// behavior: one publish, and the accessors report zero/none.
func TestEmitter_NoStrippedPublisher_Unchanged(t *testing.T) {
	pub := &fakePublisher{}
	e, err := transport.NewEmitter(context.Background(), pub, envelopecodec.New(), &fakeTlog{}, nil)
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	payload := []byte(`{"a":1}`)
	if err := e.Emit(context.Background(), newTestCredential(t, payload), payload); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if pub.callCount() != 1 {
		t.Errorf("publishes = %d, want 1", pub.callCount())
	}
	if got := e.StrippedPublishFailures(); got != 0 {
		t.Errorf("StrippedPublishFailures() = %d, want 0", got)
	}
	if _, ok := e.LastStrippedPublishFailure(); ok {
		t.Error("LastStrippedPublishFailure() ok = true, want false (never attempted)")
	}
}

// A PRIMARY publish failure is byte-for-byte the existing discipline even
// with a stripped publisher configured: the stripped publisher must not be
// touched, and the sequence must not advance.
func TestEmitter_Stripped_PrimaryFailureSkipsStripped(t *testing.T) {
	pub := &fakePublisher{failFirst: 1}
	stripped := &fakePublisher{}
	e, err := transport.NewEmitter(context.Background(), pub, envelopecodec.New(), &fakeTlog{}, nil, transport.WithStrippedPublisher(stripped))
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	payload := []byte(`{"a":1}`)
	cred := newTestCredential(t, payload)

	if err := e.Emit(context.Background(), cred, payload); err == nil {
		t.Fatal("Emit: want publish error")
	}
	if stripped.callCount() != 0 {
		t.Errorf("stripped publishes = %d, want 0 (primary failed before stripped is attempted)", stripped.callCount())
	}
	// The sequence was not advanced: the retry reuses 1, and stripped fires now.
	if err := e.Emit(context.Background(), cred, payload); err != nil {
		t.Fatalf("second Emit: %v", err)
	}
	if got := seqOf(t, pub.calls[0]); got != 1 {
		t.Errorf("reused SequenceNo = %d, want 1", got)
	}
	if stripped.callCount() != 1 {
		t.Errorf("stripped publishes after recovery = %d, want 1", stripped.callCount())
	}
}

// toggleFailPublisher fails its first failFirst publishes, then succeeds — to
// exercise stripped-publish health recovery.
type toggleFailPublisher struct {
	calls     int
	failFirst int
}

func (p *toggleFailPublisher) Publish([]byte) error {
	p.calls++
	if p.calls <= p.failFirst {
		return errors.New("stripped: boom")
	}
	return nil
}
func (p *toggleFailPublisher) Healthy() bool { return true }
func (p *toggleFailPublisher) Close() error  { return nil }

// Stripped-publish health tracks the LAST outcome, not a time window: a failure
// marks it unhealthy, and only a subsequent SUCCESSFUL stripped publish clears
// it — so a broken-then-quiet publisher never falsely recovers on elapsed time.
func TestEmitter_StrippedPublishHealth_TracksLastOutcome(t *testing.T) {
	stripped := &toggleFailPublisher{failFirst: 1}
	e, err := transport.NewEmitter(context.Background(), &fakePublisher{}, envelopecodec.New(), &fakeTlog{}, nil, transport.WithStrippedPublisher(stripped))
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	if !e.StrippedPublishHealthy() {
		t.Error("before any emit: want healthy (optimistic default)")
	}
	payload := []byte(`{"a":1}`)
	// First emit: the stripped publish fails (Emit itself still succeeds — the
	// primary already delivered) → unhealthy.
	if err := e.Emit(context.Background(), newTestCredential(t, payload), payload); err != nil {
		t.Fatalf("Emit 1: %v", err)
	}
	if e.StrippedPublishHealthy() {
		t.Error("after a failing stripped publish: want unhealthy")
	}
	// Second emit: the stripped publish succeeds → healthy again (proven recovery).
	if err := e.Emit(context.Background(), newTestCredential(t, payload), payload); err != nil {
		t.Fatalf("Emit 2: %v", err)
	}
	if !e.StrippedPublishHealthy() {
		t.Error("after a successful stripped publish: want healthy (recovery proven)")
	}
}
