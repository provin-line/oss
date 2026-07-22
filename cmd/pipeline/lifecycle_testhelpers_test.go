package main

// Shared test doubles for this task's (PR3b Task 7) shipper-wiring and
// ordered-shutdown tests: a real filelog.Log builder (mirrors
// pipeline/transport/tlogship's own shipper_test.go newSignedLog helper,
// reproduced here since that helper is unexported to a different test
// package), a spy tlogship.MirrorClient that also records whether the
// context it was called with was already cancelled (the D8 fresh-context
// property), and a fake dataPlane for driving run's shutdown sequence
// without a real NATS broker.

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	ksfilestore "github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/tlog/filelog"
)

// errSpyRegistryDown is spyMirrorClient's injected "registry unreachable"
// failure (see its failAlways field).
var errSpyRegistryDown = errors.New("spyMirrorClient: registry unavailable")

// genEd25519Key generates and saves a fresh signing keypair for did under
// keystore.KeyIDSigning in ks — the key filelog.WithCheckpointSigner (via
// newTestFilelog) and, for identities also used as a wireauth signer,
// wireauth.Sign (via keystore.KeyIDAuth — see genAuthKey) need present.
func genEd25519Key(t *testing.T, ks *ksfilestore.Store, did string, keyID keystore.KeyID) {
	t.Helper()
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate key for %s: %v", did, err)
	}
	if err := ks.SaveKeyPair(did, map[keystore.KeyID]*crypto.KeyPair{keyID: kp}); err != nil {
		t.Fatalf("save key for %s: %v", did, err)
	}
}

// newTestFilelog returns a real filelog.Log in a fresh temp dir, armed with
// a CheckpointSigner for signerDID/logID — the "live tlog.Log handle" a
// shipper consumes. ks must already hold a keystore.KeyIDSigning key for
// signerDID (genEd25519Key).
func newTestFilelog(t *testing.T, ks *ksfilestore.Store, signerDID, logID string) tlog.Log {
	t.Helper()
	l, err := filelog.New(t.TempDir(), filelog.WithCheckpointSigner(filelog.CheckpointSigner{
		Signer: ks, SignerDID: signerDID, KeyID: string(keystore.KeyIDSigning),
		VerificationMethod: signerDID + "#signing", LogID: logID,
	}))
	if err != nil {
		t.Fatalf("filelog.New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// spiedMirrorCall is one recorded MirrorClient call: which op, which logID,
// and whether ctx was ALREADY done at call time — the D8 fresh-context
// property every caller of this spy checks.
type spiedMirrorCall struct {
	op        string // "GetMirrorState" or "MirrorLogSegment"
	logID     string
	ctxDone   bool
	fromIndex uint64
	n         int
}

// spyMirrorClient is an in-memory tlogship.MirrorClient spy: it tracks its
// own durable acked size like a real registry would (so Drain/Run behave
// realistically) and records every call, including whether the caller's ctx
// was already cancelled — the property this task's lifecycle test exists to
// disprove for the final shutdown-time flush. failAlways, when set, makes
// every MirrorLogSegment call return an error (registry permanently down),
// for the drain-timeout test.
type spyMirrorClient struct {
	mu         sync.Mutex
	acked      uint64
	calls      []spiedMirrorCall
	failAlways bool
}

func (s *spyMirrorClient) GetMirrorState(ctx context.Context, logID string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, spiedMirrorCall{op: "GetMirrorState", logID: logID, ctxDone: ctxDone(ctx)})
	return s.acked, nil
}

func (s *spyMirrorClient) MirrorLogSegment(ctx context.Context, logID string, fromIndex uint64, payloads [][]byte, _ *tlog.Checkpoint) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, spiedMirrorCall{op: "MirrorLogSegment", logID: logID, ctxDone: ctxDone(ctx), fromIndex: fromIndex, n: len(payloads)})
	if s.failAlways {
		return 0, errSpyRegistryDown
	}
	s.acked = fromIndex + uint64(len(payloads))
	return s.acked, nil
}

func ctxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// snapshot returns the current acked size and a copy of every recorded call.
func (s *spyMirrorClient) snapshot() (uint64, []spiedMirrorCall) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acked, append([]spiedMirrorCall(nil), s.calls...)
}

// anyCallSawCanceledCtx reports whether ANY recorded call (across the
// shipper's whole lifetime — periodic ticks AND the final shutdown-time
// flush) observed an already-cancelled context.
func (s *spyMirrorClient) anyCallSawCanceledCtx() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.calls {
		if c.ctxDone {
			return true
		}
	}
	return false
}

// fakeDataPlane drives run's dataPlane seam without a real
// pipeline/runtime.Runtime (no NATS broker needed) — runFn/closeFn let each
// test control exactly when Run returns and what Close does, so the
// ordering test can record precisely when step 2 (loops drained) and step 5
// (closed) happen relative to the HTTP drain and the shipper flush.
type fakeDataPlane struct {
	runFn   func(ctx context.Context) error
	closeFn func() error
}

func (f *fakeDataPlane) Run(ctx context.Context) error { return f.runFn(ctx) }
func (f *fakeDataPlane) Close() error                  { return f.closeFn() }

// eventLog is a concurrency-safe ordered record of named events, for
// asserting the D8 shutdown sequence's relative order.
type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (e *eventLog) add(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, name)
}

func (e *eventLog) snapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.events...)
}
