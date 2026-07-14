package transport_test

import (
	"context"
	"errors"
	"math"
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

// Emit outcomes are counted monotonically per emitter: every error return is
// one failure, every nil return (primary delivered) one success — the P1-2
// metrics wiring point, polled from a separate goroutine like
// StrippedPublishFailures.
func TestEmitter_EmitCounters_OutcomePerReturn(t *testing.T) {
	pub := &fakePublisher{failFirst: 1}
	e, err := transport.NewEmitter(context.Background(), pub, envelopecodec.New(), &fakeTlog{}, nil)
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	cred := newTestCredential(t, []byte(`{"a":1}`))

	// Caller contract violation (nil credential) is a failure.
	if err := e.Emit(context.Background(), nil, []byte(`{}`)); err == nil {
		t.Fatal("nil credential: want error")
	}
	// Publish failure is a failure; the retry with the reused sequence succeeds.
	if err := e.Emit(context.Background(), cred, []byte(`{"a":1}`)); err == nil {
		t.Fatal("first publish: want error")
	}
	if err := e.Emit(context.Background(), cred, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("retry Emit: %v", err)
	}
	if got := e.EmitSuccesses(); got != 1 {
		t.Errorf("EmitSuccesses = %d, want 1", got)
	}
	if got := e.EmitFailures(); got != 2 {
		t.Errorf("EmitFailures = %d, want 2 (nil guard + publish failure)", got)
	}
}

// An append failure after a successful publish is a SUCCESS for the emit
// counter — the event was delivered (same boundary as Emit's nil return).
func TestEmitter_EmitCounters_AppendFailureCountsSuccess(t *testing.T) {
	tl := &fakeTlog{failErr: context.DeadlineExceeded}
	e, err := transport.NewEmitter(context.Background(), &fakePublisher{}, envelopecodec.New(), tl, nil)
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	cred := newTestCredential(t, []byte(`{"a":1}`))
	if err := e.Emit(context.Background(), cred, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if got, want := e.EmitSuccesses(), uint64(1); got != want {
		t.Errorf("EmitSuccesses = %d, want %d", got, want)
	}
	if got := e.EmitFailures(); got != 0 {
		t.Errorf("EmitFailures = %d, want 0", got)
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

// The crash window the durable high-water closes: a sequence was recorded as
// intent and published, but the process crashed before appending it. On
// restart the log tail lags the high-water; recovery must resume PAST the
// high-water, never re-issuing the published number to a new event.
func TestNewEmitter_NoReuseAcrossLossWindow(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l1, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	e1, err := transport.NewEmitter(ctx, &fakePublisher{}, envelopecodec.New(), l1, nil)
	if err != nil {
		t.Fatal(err)
	}
	cred := newTestCredential(t, []byte(`{"a":1}`))
	for i := 0; i < 3; i++ { // clean emissions 1,2,3 (log tail == high-water == 3)
		if err := e1.Emit(ctx, cred, []byte(`{"a":1}`)); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	// Simulate "published 4, intent recorded, crashed before append": the
	// high-water leads the committed tail (3) by one.
	if err := l1.RecordIntent(ctx, 4); err != nil {
		t.Fatal(err)
	}
	if err := l1.Close(); err != nil {
		t.Fatal(err)
	}

	l2, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	pub2 := &fakePublisher{}
	e2, err := transport.NewEmitter(ctx, pub2, envelopecodec.New(), l2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e2.Emit(ctx, cred, []byte(`{"a":2}`)); err != nil {
		t.Fatalf("post-restart Emit: %v", err)
	}
	if got := seqOf(t, pub2.calls[0]); got != 5 {
		t.Fatalf("post-restart SequenceNo = %d, want 5 — must skip the high-water 4, not reuse it", got)
	}
}

// The first-event crash window (Codex High-1): an EMPTY log with a high-water
// of 1 must not resume at 1 — the empty-log early return would have reused it.
func TestNewEmitter_EmptyLogHighWaterRecovers(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l1, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := l1.RecordIntent(ctx, 1); err != nil { // intent for 1, but never appended
		t.Fatal(err)
	}
	if err := l1.Close(); err != nil {
		t.Fatal(err)
	}
	l2, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	pub := &fakePublisher{}
	e, err := transport.NewEmitter(ctx, pub, envelopecodec.New(), l2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Emit(ctx, newTestCredential(t, []byte(`{"a":1}`)), []byte(`{"a":1}`)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if got := seqOf(t, pub.calls[0]); got != 2 {
		t.Fatalf("empty-log recovery SequenceNo = %d, want 2 — must not reuse the high-water 1", got)
	}
}

// A high-water at the top of the space fails closed instead of wrapping to 0.
func TestNewEmitter_HighWaterExhaustionFailsClosed(t *testing.T) {
	ctx := context.Background()
	l, err := filelog.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.RecordIntent(ctx, math.MaxUint64); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.NewEmitter(ctx, &fakePublisher{}, envelopecodec.New(), l, nil); err == nil {
		t.Fatal("MaxUint64 high-water: want fail-closed error, got wrap-around")
	}
}

// failingIntentTlog is a tlog.Log that also provides the intent capability,
// with a RecordIntent that fails — to prove Emit fails CLOSED before publish.
type failingIntentTlog struct {
	*fakeTlog
	recordErr error
}

func (f *failingIntentTlog) RecordIntent(context.Context, uint64) error    { return f.recordErr }
func (f *failingIntentTlog) HighestIntent(context.Context) (uint64, error) { return 0, nil }

// A RecordIntent failure aborts Emit BEFORE any publish: no durable intent ⇒
// no delivery, and the sequence is not advanced.
func TestEmitter_RecordIntentFailsClosedBeforePublish(t *testing.T) {
	ctx := context.Background()
	tl := &failingIntentTlog{fakeTlog: &fakeTlog{}, recordErr: errors.New("intent boom")}
	pub := &fakePublisher{}
	e, err := transport.NewEmitter(ctx, pub, envelopecodec.New(), tl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Emit(ctx, newTestCredential(t, []byte(`{"a":1}`)), []byte(`{"a":1}`)); err == nil {
		t.Fatal("Emit over a failing RecordIntent: want error")
	}
	if pub.callCount() != 0 {
		t.Fatalf("publishes = %d, want 0 — intent must be durable before any publish", pub.callCount())
	}
	if tl.appendedCount() != 0 {
		t.Fatalf("appends = %d, want 0", tl.appendedCount())
	}
}
