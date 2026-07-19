package tlogship_test

// Unit tests for Shipper against a fake MirrorClient and a REAL filelog.Log
// (task-6 brief: the shipper receives the live tlog.Log handle — a fake log
// would not exercise the real CheckpointAt-backed cap-bounded batching this
// package now depends on, nor filelog's real "CheckpointAt only ever
// covers records it actually holds" behavior).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/pipeline/transport/tlogship"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/tlog/filelog"
	"github.com/provin-line/oss/tlog/memlog"
)

// memKS is a minimal in-memory keystore.Signer for arming a filelog
// CheckpointSigner in tests (mirrors filelog_test.go's own memKS — this
// package cannot import that internal test type across packages).
type memKS struct{ keys map[string][]byte }

func newMemKS() *memKS { return &memKS{keys: map[string][]byte{}} }

func (m *memKS) SaveKeyPair(did string, keys map[keystore.KeyID]*crypto.KeyPair) error {
	for id, kp := range keys {
		m.keys[did+"#"+string(id)] = kp.PrivateKey
	}
	return nil
}

func (m *memKS) Sign(did string, keyID string, data []byte) ([]byte, error) {
	priv, ok := m.keys[did+"#"+keyID]
	if !ok {
		return nil, fmt.Errorf("memKS: no key %s#%s", did, keyID)
	}
	return ed25519.Sign(priv, data)
}

const (
	testLogID    = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pa"
	testSignerID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pa:process:proc1"
)

// newSignedLog returns a real filelog.Log in a fresh temp dir, armed with a
// CheckpointSigner — the "live tlog.Log handle" a shipper consumes, and the
// only tlog.Log implementation that also provides CheckpointAt (memlog
// never signs; merklelog is out of the tlog-custody v0 mirror scope).
func newSignedLog(t *testing.T) tlog.Log {
	t.Helper()
	ks := newMemKS()
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := ks.SaveKeyPair(testSignerID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatalf("save: %v", err)
	}
	l, err := filelog.New(t.TempDir(), filelog.WithCheckpointSigner(filelog.CheckpointSigner{
		Signer: ks, SignerDID: testSignerID, KeyID: string(keystore.KeyIDSigning),
		VerificationMethod: testSignerID + "#signing", LogID: testLogID,
	}))
	if err != nil {
		t.Fatalf("filelog.New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func appendN(t *testing.T, l tlog.Log, payloads ...string) {
	t.Helper()
	for _, p := range payloads {
		if _, err := l.Append(context.Background(), []byte(p)); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
}

// fakeClient is an in-memory MirrorClient spy: it records every
// MirrorLogSegment call and tracks its own "durable acked size" exactly
// like a real registry would, so tests can assert both WHAT was shipped and
// the resulting resume state. failNextMirror/failNextState inject
// registry-down errors for a bounded number of subsequent calls.
type fakeClient struct {
	mu    sync.Mutex
	acked uint64

	segments []shippedSegment

	failMirror    int // remaining MirrorLogSegment calls to fail, starting from the very next call
	failAtCall    int // absolute 1-indexed MirrorLogSegment call number to fail EXACTLY once (0 = disabled); for a mid-drain failure partway through a multi-segment tick
	failState     int // remaining GetMirrorState calls to fail
	mirrorCalls   int
	stateCalls    int
	stateOverride *uint64 // when set, GetMirrorState returns this instead of acked (for the mirror-ahead-of-local test)
}

type shippedSegment struct {
	logID     string
	fromIndex uint64
	payloads  [][]byte
	cp        *tlog.Checkpoint
}

var errFakeRegistryDown = errors.New("fakeClient: registry unavailable")

func (f *fakeClient) GetMirrorState(_ context.Context, _ string) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stateCalls++
	if f.failState > 0 {
		f.failState--
		return 0, errFakeRegistryDown
	}
	if f.stateOverride != nil {
		return *f.stateOverride, nil
	}
	return f.acked, nil
}

func (f *fakeClient) MirrorLogSegment(_ context.Context, logID string, fromIndex uint64, payloads [][]byte, cp *tlog.Checkpoint) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mirrorCalls++
	if f.failMirror > 0 {
		f.failMirror--
		return 0, errFakeRegistryDown
	}
	if f.failAtCall != 0 && f.mirrorCalls == f.failAtCall {
		f.failAtCall = 0 // one-time: subsequent calls (including a retry of this same segment) succeed
		return 0, errFakeRegistryDown
	}
	f.segments = append(f.segments, shippedSegment{logID: logID, fromIndex: fromIndex, payloads: payloads, cp: cp})
	f.acked = fromIndex + uint64(len(payloads))
	return f.acked, nil
}

func (f *fakeClient) snapshot() (acked uint64, segments []shippedSegment, mirrorCalls, stateCalls int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.acked, append([]shippedSegment(nil), f.segments...), f.mirrorCalls, f.stateCalls
}

// discardLogger silences the shipper's operational log output for tests
// that deliberately drive it through repeated failures/warnings (registry
// down, backlog-over-caps) — the behavior is asserted via fakeClient's
// counters, not log lines.
var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

func testConfig(interval time.Duration) tlogship.Config {
	return tlogship.Config{MaxBatchRecords: 256, MaxBatchBytes: 4 << 20, FlushInterval: interval, Logger: discardLogger}
}

// --- New validation ---

func TestNew_MissingLog(t *testing.T) {
	if _, err := tlogship.New(nil, testLogID, &fakeClient{}, testConfig(time.Second)); !errors.Is(err, tlogship.ErrMissingLog) {
		t.Fatalf("err = %v, want ErrMissingLog", err)
	}
}

func TestNew_MissingLogID(t *testing.T) {
	l := newSignedLog(t)
	if _, err := tlogship.New(l, "", &fakeClient{}, testConfig(time.Second)); !errors.Is(err, tlogship.ErrMissingLogID) {
		t.Fatalf("err = %v, want ErrMissingLogID", err)
	}
}

func TestNew_MissingClient(t *testing.T) {
	l := newSignedLog(t)
	if _, err := tlogship.New(l, testLogID, nil, testConfig(time.Second)); !errors.Is(err, tlogship.ErrMissingClient) {
		t.Fatalf("err = %v, want ErrMissingClient", err)
	}
}

func TestNew_BadConfig(t *testing.T) {
	l := newSignedLog(t)
	cfg := testConfig(time.Second)
	cfg.MaxBatchRecords = 0
	if _, err := tlogship.New(l, testLogID, &fakeClient{}, cfg); !errors.Is(err, tlogship.ErrBadConfig) {
		t.Fatalf("err = %v, want ErrBadConfig", err)
	}
}

// TestNew_LogLacksCheckpointAt proves a log that does not provide the
// CheckpointAt capability (memlog: it never signs at all) is rejected at
// CONSTRUCTION, not on the first tick — the tlog-custody v0 mirror scope
// is filelog-only.
func TestNew_LogLacksCheckpointAt(t *testing.T) {
	l := memlog.New()
	if _, err := tlogship.New(l, testLogID, &fakeClient{}, testConfig(time.Second)); !errors.Is(err, tlogship.ErrLogLacksCheckpointAt) {
		t.Fatalf("err = %v, want ErrLogLacksCheckpointAt", err)
	}
}

// --- Drain: the single-tick flush semantics (resume, shipping, caps,
// caught-up no-op, mirror-ahead error) are all exercised through Drain,
// since Drain is just "one tick, retried until success or ctx done" and a
// generous ctx makes it succeed in exactly one attempt for these cases.

// TestDrain_ShipsFromAckedToHead proves a fresh shipper (acked=0) ships
// every local record up through the current checkpoint in one segment.
func TestDrain_ShipsFromAckedToHead(t *testing.T) {
	l := newSignedLog(t)
	appendN(t, l, "r0", "r1", "r2")
	fc := &fakeClient{}
	sh, err := tlogship.New(l, testLogID, fc, testConfig(time.Hour))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sh.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	acked, segments, mirrorCalls, _ := fc.snapshot()
	if acked != 3 {
		t.Fatalf("acked = %d, want 3", acked)
	}
	if mirrorCalls != 1 {
		t.Fatalf("mirrorCalls = %d, want exactly 1 (one segment covering the whole backlog)", mirrorCalls)
	}
	if len(segments) != 1 || segments[0].fromIndex != 0 || len(segments[0].payloads) != 3 {
		t.Fatalf("segments = %+v, want one segment [0,3)", segments)
	}
	if segments[0].cp == nil || segments[0].cp.Size != 3 {
		t.Fatalf("shipped checkpoint = %+v, want Size=3 (exactly covering the segment end)", segments[0].cp)
	}
}

// TestDrain_ResumesFromAckedSize proves a shipper that finds the registry
// already partway caught up (simulating resume-after-restart: the registry
// remembers what a PRIOR shipper instance already shipped) only ships the
// NEW tail, never re-sending already-acked records.
func TestDrain_ResumesFromAckedSize(t *testing.T) {
	l := newSignedLog(t)
	appendN(t, l, "r0", "r1", "r2", "r3", "r4")
	fc := &fakeClient{acked: 2} // a prior shipper already got the registry to 2
	sh, err := tlogship.New(l, testLogID, fc, testConfig(time.Hour))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sh.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	acked, segments, _, _ := fc.snapshot()
	if acked != 5 {
		t.Fatalf("acked = %d, want 5", acked)
	}
	if len(segments) != 1 || segments[0].fromIndex != 2 || len(segments[0].payloads) != 3 {
		t.Fatalf("segments = %+v, want one segment [2,5)", segments)
	}
}

// TestDrain_CaughtUp_ShipsNothing proves a shipper that is already fully
// caught up sends no RPC at all.
func TestDrain_CaughtUp_ShipsNothing(t *testing.T) {
	l := newSignedLog(t)
	appendN(t, l, "r0", "r1")
	fc := &fakeClient{acked: 2}
	sh, err := tlogship.New(l, testLogID, fc, testConfig(time.Hour))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sh.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	_, _, mirrorCalls, _ := fc.snapshot()
	if mirrorCalls != 0 {
		t.Fatalf("mirrorCalls = %d, want 0 (already caught up)", mirrorCalls)
	}
}

// TestDrain_CapHonoring_WithinCaps_ShipsOneBoundedSegment proves the common
// case the caps are designed for: a backlog that FITS inside
// MaxBatchRecords/MaxBatchBytes ships in one segment that never exceeds
// them.
func TestDrain_CapHonoring_WithinCaps_ShipsOneBoundedSegment(t *testing.T) {
	l := newSignedLog(t)
	appendN(t, l, "r0", "r1", "r2")
	fc := &fakeClient{}
	cfg := testConfig(time.Hour)
	cfg.MaxBatchRecords = 3 // exactly the backlog size
	sh, err := tlogship.New(l, testLogID, fc, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sh.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	acked, _, _, _ := fc.snapshot()
	if acked != 3 {
		t.Fatalf("acked = %d, want 3", acked)
	}
}

// TestDrain_BacklogLargerThanCaps_DrainsFullyInBoundedSegments proves the
// controller-decided fix for the old admission-gate wedge: a backlog of
// 5×MaxBatchRecords drains FULLY within one Drain call, split into
// successive segments each bounded by MaxBatchRecords, each shipped with a
// checkpoint that EXACTLY covers that segment's own end (CheckpointAt, not
// the log's current head) — never a single oversized call, and never
// stuck.
func TestDrain_BacklogLargerThanCaps_DrainsFullyInBoundedSegments(t *testing.T) {
	l := newSignedLog(t)
	const maxRecords = 3
	total := maxRecords*5 + 1 // deliberately not an exact multiple: last batch is a remainder
	payloads := make([]string, total)
	for i := range payloads {
		payloads[i] = fmt.Sprintf("r%d", i)
	}
	appendN(t, l, payloads...)

	fc := &fakeClient{}
	cfg := testConfig(10 * time.Millisecond)
	cfg.MaxBatchRecords = maxRecords
	sh, err := tlogship.New(l, testLogID, fc, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sh.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}

	acked, segments, mirrorCalls, _ := fc.snapshot()
	if acked != uint64(total) {
		t.Fatalf("acked = %d, want %d (fully drained)", acked, total)
	}
	wantSegments := (total + maxRecords - 1) / maxRecords // ceil(total/maxRecords)
	if mirrorCalls != wantSegments {
		t.Fatalf("mirrorCalls = %d, want %d bounded segments", mirrorCalls, wantSegments)
	}
	var from uint64
	for i, seg := range segments {
		if len(seg.payloads) > maxRecords {
			t.Fatalf("segment %d has %d records, want <= %d (MaxBatchRecords)", i, len(seg.payloads), maxRecords)
		}
		if seg.fromIndex != from {
			t.Fatalf("segment %d fromIndex = %d, want %d (contiguous, no gaps/overlaps)", i, seg.fromIndex, from)
		}
		end := seg.fromIndex + uint64(len(seg.payloads))
		if seg.cp == nil || seg.cp.Size != end {
			t.Fatalf("segment %d checkpoint = %+v, want Size=%d (exactly covering THIS segment's own end, via CheckpointAt)", i, seg.cp, end)
		}
		from = end
	}
	if from != uint64(total) {
		t.Fatalf("segments cover up to %d, want the full backlog %d", from, total)
	}
}

// TestDrain_SingleRecordExceedsMaxBytes_ErrorsWithoutStalling proves the
// one genuinely unshippable case remaining after cap-bounded batching: a
// SINGLE record's payload alone larger than MaxBatchBytes can never fit
// even a batch of one — tick reports ErrRecordExceedsMaxBatchBytes rather
// than silently skipping it or looping forever, and ships nothing for it.
func TestDrain_SingleRecordExceedsMaxBytes_ErrorsWithoutStalling(t *testing.T) {
	l := newSignedLog(t)
	appendN(t, l, "0123456789") // 10 bytes — the poison record
	fc := &fakeClient{}
	cfg := testConfig(20 * time.Millisecond)
	cfg.MaxBatchBytes = 5 // < 10 bytes: no batch containing this record can ever fit
	sh, err := tlogship.New(l, testLogID, fc, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err = sh.Drain(ctx)
	if err == nil {
		t.Fatal("Drain: want an error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Drain err = %v, want it to wrap context.DeadlineExceeded (never resolves by retrying)", err)
	}
	_, _, mirrorCalls, _ := fc.snapshot()
	if mirrorCalls != 0 {
		t.Fatalf("mirrorCalls = %d, want 0 — the oversized record must never be sent", mirrorCalls)
	}
}

// TestDrain_MidDrainRegistryDown_ResumesNextTick proves the "never blocks,
// resumes from the fresh cursor" contract for a MULTI-segment drain
// specifically: a backlog needing 3 segments where the SECOND
// MirrorLogSegment call fails (registry blips mid-drain) stops that tick's
// loop immediately (the first segment's shipment stands; the third is not
// attempted yet) — Drain's own retry, one interval later, re-reads
// GetMirrorState fresh and finishes the remaining segments.
func TestDrain_MidDrainRegistryDown_ResumesNextTick(t *testing.T) {
	l := newSignedLog(t)
	const maxRecords = 2
	appendN(t, l, "r0", "r1", "r2", "r3", "r4", "r5") // 3 segments of 2
	fc := &fakeClient{failAtCall: 2}                  // the SECOND MirrorLogSegment call fails, once
	cfg := testConfig(10 * time.Millisecond)
	cfg.MaxBatchRecords = maxRecords
	sh, err := tlogship.New(l, testLogID, fc, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := sh.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	acked, segments, mirrorCalls, stateCalls := fc.snapshot()
	if acked != 6 {
		t.Fatalf("acked = %d, want 6 (fully drained despite the mid-drain blip)", acked)
	}
	if len(segments) != 3 {
		t.Fatalf("segments shipped = %d, want 3 (the failed attempt shipped nothing)", len(segments))
	}
	if mirrorCalls != 4 { // 2 successful + 1 failed + 1 successful retry of the same segment
		t.Fatalf("mirrorCalls = %d, want 4 (2 ok, 1 failed, 1 retried ok)", mirrorCalls)
	}
	if stateCalls < 2 {
		t.Fatalf("GetMirrorState calls = %d, want >= 2 (the retry re-reads the cursor fresh)", stateCalls)
	}
	// The registry's cursor after the blip (acked=2, only the first segment
	// landed) must be exactly what the SECOND Drain attempt resumes from —
	// segment[1] (the successful retry) must start at 2, not re-ship [0,2).
	if segments[1].fromIndex != 2 {
		t.Fatalf("segment[1].fromIndex = %d, want 2 (resumed from the fresh cursor, not from a stale local cache)", segments[1].fromIndex)
	}
}

// TestDrain_MirrorAheadOfLocal_Errors proves the defensive fail-closed
// check: a registry reporting MORE acked records than the local log
// currently holds is a hard error, not silently ignored.
func TestDrain_MirrorAheadOfLocal_Errors(t *testing.T) {
	l := newSignedLog(t)
	appendN(t, l, "r0")
	ahead := uint64(99)
	fc := &fakeClient{stateOverride: &ahead}
	cfg := testConfig(20 * time.Millisecond)
	sh, err := tlogship.New(l, testLogID, fc, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := sh.Drain(ctx); err == nil {
		t.Fatal("Drain: want an error (mirror ahead of local), got nil")
	}
}

// TestDrain_RetriesUntilSuccess proves a transient registry-down condition
// (the first two flush attempts fail) resolves once the registry recovers,
// all within Drain's own retry loop — no caller-side retry needed.
func TestDrain_RetriesUntilSuccess(t *testing.T) {
	l := newSignedLog(t)
	appendN(t, l, "r0", "r1")
	fc := &fakeClient{failMirror: 2}
	cfg := testConfig(10 * time.Millisecond)
	sh, err := tlogship.New(l, testLogID, fc, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := sh.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	acked, _, mirrorCalls, _ := fc.snapshot()
	if acked != 2 {
		t.Fatalf("acked = %d, want 2", acked)
	}
	if mirrorCalls < 3 {
		t.Fatalf("mirrorCalls = %d, want >= 3 (2 failures + 1 success)", mirrorCalls)
	}
}

// --- Run: the ticking-goroutine behavior. ---

// TestRun_TicksRepeatedlyAndStopsOnCancel proves Run keeps flushing on the
// configured interval and returns promptly (nil) once ctx is cancelled.
func TestRun_TicksRepeatedlyAndStopsOnCancel(t *testing.T) {
	l := newSignedLog(t)
	appendN(t, l, "r0")
	fc := &fakeClient{}
	sh, err := tlogship.New(l, testLogID, fc, testConfig(10*time.Millisecond))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- sh.Run(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancellation")
	}
	_, _, mirrorCalls, stateCalls := fc.snapshot()
	if stateCalls < 2 {
		t.Fatalf("GetMirrorState calls = %d, want several ticks over 120ms at a 10ms interval", stateCalls)
	}
	if mirrorCalls != 1 {
		t.Fatalf("mirrorCalls = %d, want exactly 1 (shipped once, then caught up on every later tick)", mirrorCalls)
	}
}

// TestRun_RegistryDown_RetriesWithoutBlocking proves the never-blocks
// contract: a client that fails EVERY call (registry permanently down for
// the test's duration) never stops Run's ticking — GetMirrorState keeps
// being called every interval — and Run still returns cleanly the moment
// ctx is cancelled, exactly as if the registry were healthy.
func TestRun_RegistryDown_RetriesWithoutBlocking(t *testing.T) {
	l := newSignedLog(t)
	appendN(t, l, "r0", "r1")
	fc := &fakeClient{failState: 1 << 30} // effectively "always fails"
	sh, err := tlogship.New(l, testLogID, fc, testConfig(10*time.Millisecond))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- sh.Run(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancellation — a down registry must never block shutdown")
	}
	_, _, mirrorCalls, stateCalls := fc.snapshot()
	if stateCalls < 2 {
		t.Fatalf("GetMirrorState calls = %d, want several retried ticks despite every call failing", stateCalls)
	}
	if mirrorCalls != 0 {
		t.Fatalf("mirrorCalls = %d, want 0 — GetMirrorState never succeeded, so nothing should ever have been shipped", mirrorCalls)
	}
}
