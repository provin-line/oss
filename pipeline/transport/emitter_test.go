package transport_test

import (
	"context"
	"testing"

	"github.com/provin-line/oss/pipeline/transport"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
)

// seqOf decodes a published wire envelope and returns its SequenceNo.
func seqOf(t *testing.T, wire []byte) uint64 {
	t.Helper()
	env, err := envelopecodec.New().UnmarshalEnvelope(wire)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope: %v", err)
	}
	return env.SequenceNo
}

// A successful Emit publishes, appends, and advances the sequence (1 then 2).
func TestEmitter_Emit_PublishesAppendsAdvances(t *testing.T) {
	pub := &fakePublisher{}
	tl := &fakeTlog{}
	e := transport.NewEmitter(pub, envelopecodec.New(), tl, nil)

	cred := newTestCredential(t, []byte(`{"a":1}`))
	if err := e.Emit(context.Background(), cred, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("Emit #1: %v", err)
	}
	if err := e.Emit(context.Background(), cred, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("Emit #2: %v", err)
	}
	if pub.callCount() != 2 {
		t.Fatalf("publishes = %d, want 2", pub.callCount())
	}
	if tl.appendedCount() != 2 {
		t.Fatalf("appends = %d, want 2", tl.appendedCount())
	}
	if got := seqOf(t, pub.calls[0]); got != 1 {
		t.Errorf("first envelope SequenceNo = %d, want 1", got)
	}
	if got := seqOf(t, pub.calls[1]); got != 2 {
		t.Errorf("second envelope SequenceNo = %d, want 2", got)
	}
}

// Nil credential / nil payload are caller contract violations: error, no publish.
func TestEmitter_Emit_NilGuards(t *testing.T) {
	pub := &fakePublisher{}
	e := transport.NewEmitter(pub, envelopecodec.New(), &fakeTlog{}, nil)

	if err := e.Emit(context.Background(), nil, []byte(`{}`)); err == nil {
		t.Error("nil credential: want error")
	}
	cred := newTestCredential(t, []byte(`{}`))
	if err := e.Emit(context.Background(), cred, nil); err == nil {
		t.Error("nil payload: want error")
	}
	if pub.callCount() != 0 {
		t.Errorf("publishes = %d, want 0 (nil guards must not publish)", pub.callCount())
	}
}

// A publish failure returns an error and does NOT advance the sequence — the next
// attempt reuses the same number (no gap).
func TestEmitter_Emit_PublishFailure_ReusesSequence(t *testing.T) {
	pub := &fakePublisher{failFirst: 1}
	tl := &fakeTlog{}
	e := transport.NewEmitter(pub, envelopecodec.New(), tl, nil)
	cred := newTestCredential(t, []byte(`{"a":1}`))

	if err := e.Emit(context.Background(), cred, []byte(`{"a":1}`)); err == nil {
		t.Fatal("first Emit: want publish error")
	}
	if tl.appendedCount() != 0 {
		t.Errorf("appends = %d, want 0 (no append on failed publish)", tl.appendedCount())
	}
	// Second Emit publishes; the sequence was NOT advanced by the failure.
	if err := e.Emit(context.Background(), cred, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("second Emit: %v", err)
	}
	if got := seqOf(t, pub.calls[0]); got != 1 {
		t.Errorf("reused SequenceNo = %d, want 1 (no gap from a failed publish)", got)
	}
}

// An append failure AFTER a successful publish returns nil (the event was
// delivered) and the sequence still advances (the audit-defense gap is accepted).
func TestEmitter_Emit_AppendFailureAfterPublish_ReturnsNil(t *testing.T) {
	pub := &fakePublisher{}
	tl := &fakeTlog{failErr: context.DeadlineExceeded}
	e := transport.NewEmitter(pub, envelopecodec.New(), tl, nil)
	cred := newTestCredential(t, []byte(`{"a":1}`))

	if err := e.Emit(context.Background(), cred, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("append-failure Emit: want nil (event delivered), got %v", err)
	}
	if pub.callCount() != 1 {
		t.Fatalf("publishes = %d, want 1", pub.callCount())
	}
	// Sequence advanced despite the append failure: the next publish is 2.
	tl.failErr = nil
	if err := e.Emit(context.Background(), cred, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("second Emit: %v", err)
	}
	if got := seqOf(t, pub.calls[1]); got != 2 {
		t.Errorf("post-append-failure SequenceNo = %d, want 2 (sequence advanced)", got)
	}
}
