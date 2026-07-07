package transport_test

import (
	"context"
	"testing"

	"github.com/provin-line/oss/pipeline/transport"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	"github.com/provin-line/oss/tlog/filelog"
	"github.com/provin-line/oss/tlog/memlog"
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
	e, err := transport.NewEmitter(context.Background(), pub, envelopecodec.New(), tl, nil)
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}

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
	e, err := transport.NewEmitter(context.Background(), pub, envelopecodec.New(), &fakeTlog{}, nil)
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}

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
	e, err := transport.NewEmitter(context.Background(), pub, envelopecodec.New(), tl, nil)
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
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
	e, err := transport.NewEmitter(context.Background(), pub, envelopecodec.New(), tl, nil)
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
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

// A restart must not fork the sequence space: an Emitter constructed over a
// log that already holds emission records resumes AFTER the last recorded
// sequence — the durable log is the carrier of the discipline (tlog spec,
// FCoT ✗2 / Codex High-1).
func TestNewEmitter_ResumesSequenceFromLogTail(t *testing.T) {
	tl := memlog.New()
	for _, rec := range []string{
		`{"credentialHash":"sha256:aa","sequenceNo":"6"}`,
		`{"credentialHash":"sha256:bb","sequenceNo":"7"}`,
	} {
		if _, err := tl.Append(context.Background(), []byte(rec)); err != nil {
			t.Fatal(err)
		}
	}
	pub := &fakePublisher{}
	e, err := transport.NewEmitter(context.Background(), pub, envelopecodec.New(), tl, nil)
	if err != nil {
		t.Fatalf("NewEmitter over a seeded log: %v", err)
	}
	cred := newTestCredential(t, []byte(`{"a":1}`))
	if err := e.Emit(context.Background(), cred, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if got := seqOf(t, pub.calls[0]); got != 8 {
		t.Errorf("post-restart SequenceNo = %d, want 8 (resume after the recorded 7)", got)
	}
}

// A damaged tail record fails construction — the same doctrine that fails a
// broken chain at open extends to the sequence seed.
func TestNewEmitter_DamagedTailFailsConstruction(t *testing.T) {
	tl := memlog.New()
	if _, err := tl.Append(context.Background(), []byte(`not an emission record`)); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.NewEmitter(context.Background(), &fakePublisher{}, envelopecodec.New(), tl, nil); err == nil {
		t.Fatal("NewEmitter over a damaged tail: want error")
	}
}

// A tail at the top of the sequence space fails closed instead of wrapping
// to the invalid sequence 0.
func TestNewEmitter_SequenceExhaustionFailsClosed(t *testing.T) {
	tl := memlog.New()
	if _, err := tl.Append(context.Background(), []byte(`{"credentialHash":"sha256:aa","sequenceNo":"18446744073709551615"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.NewEmitter(context.Background(), &fakePublisher{}, envelopecodec.New(), tl, nil); err == nil {
		t.Fatal("MaxUint64 tail: want fail-closed error, got wrap-around")
	}
}

// The restart composition the slice exists for: an emitter over a DURABLE
// log, reopened, resumes the sequence — end to end over filelog, not a
// seeded fake.
func TestNewEmitter_ResumesOverReopenedFilelog(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l1, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	pub1 := &fakePublisher{}
	e1, err := transport.NewEmitter(ctx, pub1, envelopecodec.New(), l1, nil)
	if err != nil {
		t.Fatal(err)
	}
	cred := newTestCredential(t, []byte(`{"a":1}`))
	for i := 0; i < 2; i++ {
		if err := e1.Emit(ctx, cred, []byte(`{"a":1}`)); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	if err := l1.Close(); err != nil {
		t.Fatal(err)
	}

	// "Restart": reopen the same directory, build a fresh emitter.
	l2, err := filelog.New(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	pub2 := &fakePublisher{}
	e2, err := transport.NewEmitter(ctx, pub2, envelopecodec.New(), l2, nil)
	if err != nil {
		t.Fatalf("NewEmitter after restart: %v", err)
	}
	if err := e2.Emit(ctx, cred, []byte(`{"a":2}`)); err != nil {
		t.Fatalf("post-restart Emit: %v", err)
	}
	if got := seqOf(t, pub2.calls[0]); got != 3 {
		t.Fatalf("post-restart SequenceNo = %d, want 3 — the durable log must carry the discipline across restarts", got)
	}
}
