package filelog_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/tlog/filelog"
	"github.com/provin-line/oss/tlog/internal/logcontract"
)

func newLog(t *testing.T) tlog.Log {
	t.Helper()
	l, err := filelog.New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l
}

func TestLogContract(t *testing.T) {
	logcontract.Suite(t, newLog)
	logcontract.ChainSuite(t, newLog)
}

// The whole point of the file log: records outlive the process. A reopened
// log serves the old records and CONTINUES the chain — the third append
// after reopen produces exactly the pinned vector's third hash.
func TestReopen_ReplaysAndContinuesChain(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l1, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range logcontract.Vector[:2] {
		if _, err := l1.Append(ctx, []byte(v.Payload)); err != nil {
			t.Fatal(err)
		}
	}
	// Single-opener: the "dead" process must release its handle before the
	// restart reopens (the flock guard now enforces this).
	if err := l1.Close(); err != nil {
		t.Fatal(err)
	}

	l2, err := filelog.New(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if n, err := l2.Size(ctx); err != nil || n != 2 {
		t.Fatalf("reopened Size = %d (err %v), want 2", n, err)
	}
	if rec, err := l2.Get(ctx, 1); err != nil || rec.Hash != logcontract.Vector[1].Hash {
		t.Fatalf("reopened Get(1) = %+v (err %v), want vector hash", rec, err)
	}
	rec, err := l2.Append(ctx, []byte(logcontract.Vector[2].Payload))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Index != 2 || rec.Hash != logcontract.Vector[2].Hash {
		t.Fatalf("post-reopen append = %+v, want index 2 with the vector chain hash — the chain must CONTINUE, not restart", rec)
	}
}

// A damaged line fails open-time: a log that cannot prove its own chain
// must not serve (evidence doctrine).
func TestOpen_DamagedEntryFailsClosed(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := l.Append(ctx, []byte{byte('a' + i)}); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "log.ndjson")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	// Tamper the MIDDLE record's payload: its own hash stays, the chain breaks.
	var env map[string]any
	// decoder-hygiene-exempt: test-side tamper helper on fixture bytes.
	if err := json.Unmarshal([]byte(lines[1]), &env); err != nil {
		t.Fatal(err)
	}
	env["payload"] = "dGFtcGVyZWQ" // base64 "tampered"
	// canonicalizer-hygiene-exempt: deliberate tamper fixture.
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	lines[1] = string(tampered)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Release the single-opener lock first: otherwise the reopen below would
	// fail with ErrLocked — a DIFFERENT error than the chain-damage this test
	// means to prove — and the `err == nil` assertion would pass for the WRONG
	// reason. Close makes the reopen genuinely exercise replay-over-tamper.
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := filelog.New(dir); err == nil || errors.Is(err, filelog.ErrLocked) {
		t.Fatalf("open over a tampered chain: want a chain-damage error, got %v", err)
	}
}

func TestOpen_GarbageLineFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "log.ndjson"), []byte("{not json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := filelog.New(dir); err == nil {
		t.Fatal("open over garbage: want error")
	}
}

func TestCheckpoint_UnsignedIsTypedError(t *testing.T) {
	l, err := filelog.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Checkpoint(context.Background()); !errors.Is(err, filelog.ErrUnsignedLog) {
		t.Fatalf("unarmed Checkpoint: err=%v, want ErrUnsignedLog", err)
	}
}

// --- signed checkpoints ------------------------------------------------------

type memKS struct{ keys map[string][]byte }

func (m *memKS) SaveKeyPair(did string, keys map[keystore.KeyID]*crypto.KeyPair) error {
	for id, kp := range keys {
		m.keys[did+"#"+string(id)] = kp.PrivateKey
	}
	return nil
}
func (m *memKS) GetPrivateKey(did string, keyID keystore.KeyID) ([]byte, error) {
	k, ok := m.keys[did+"#"+string(keyID)]
	if !ok {
		return nil, fmt.Errorf("key not found: %w", keystore.ErrNotFound)
	}
	return k, nil
}
func (m *memKS) Sign(did string, keyID string, data []byte) ([]byte, error) {
	priv, err := m.GetPrivateKey(did, keystore.KeyID(keyID))
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, data)
}
func (m *memKS) DeleteKeys(string) error { return nil }

func TestCheckpoint_SignedViewVerifies(t *testing.T) {
	ctx := context.Background()
	const (
		logID     = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pipe"
		signerDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pipe:process:s1"
		vm        = signerDID + "#signing"
	)
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	ks := &memKS{keys: map[string][]byte{}}
	if err := ks.SaveKeyPair(signerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatal(err)
	}

	l, err := filelog.New(t.TempDir(), filelog.WithCheckpointSigner(filelog.CheckpointSigner{
		Signer:             ks,
		SignerDID:          signerDID,
		KeyID:              string(keystore.KeyIDSigning),
		VerificationMethod: vm,
		LogID:              logID,
	}))
	if err != nil {
		t.Fatal(err)
	}
	var head string
	for _, p := range []string{"r1", "r2"} {
		rec, err := l.Append(ctx, []byte(p))
		if err != nil {
			t.Fatal(err)
		}
		head = rec.Hash
	}

	cp, err := l.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if cp.Size != 2 || cp.Head != head || cp.SignedBy != vm {
		t.Fatalf("checkpoint = %+v, want size 2 / head %s / signedBy %s", cp, head, vm)
	}
	if time.Since(cp.Timestamp) > time.Minute || cp.Timestamp.Location() != time.UTC {
		t.Errorf("timestamp %v: want recent UTC", cp.Timestamp)
	}

	// A verifier reconstructs the domain-separated view from public fields
	// and checks the signature — logId INSIDE the signature means a
	// checkpoint can never be presented as another log's.
	view, err := jcs.Canonicalize(map[string]any{
		"v":         1,
		"purpose":   "dplaax-tlog-checkpoint",
		"logId":     logID,
		"head":      cp.Head,
		"signedBy":  cp.SignedBy,
		"size":      "2",
		"timestamp": cp.Timestamp.Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	ok, err := (ed25519.Verifier{}).Verify(kp.PublicKey, view, cp.Signature)
	if err != nil || !ok {
		t.Fatalf("signature does not verify over the reconstructed view (ok=%v err=%v)", ok, err)
	}
	// And NOT over a view claiming a different log.
	otherView, err := jcs.Canonicalize(map[string]any{
		"v":         1,
		"purpose":   "dplaax-tlog-checkpoint",
		"logId":     "did:dplaax:poc.dplaax.dev:org:acme:pipeline:other",
		"head":      cp.Head,
		"signedBy":  cp.SignedBy,
		"size":      "2",
		"timestamp": cp.Timestamp.Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := (ed25519.Verifier{}).Verify(kp.PublicKey, otherView, cp.Signature); ok {
		t.Fatal("signature verified for a DIFFERENT log id — the binding is broken")
	}
}

// A crash mid-append leaves an unterminated final fragment. Every COMPLETE
// line was fsynced, so the torn tail is provably an uncommitted append:
// reopen truncates it loudly and the log keeps working — it must not refuse
// to boot forever. Interior damage stays fail-closed (see
// TestOpen_DamagedEntryFailsClosed).
func TestOpen_TornTailTruncatedAndLogContinues(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range logcontract.Vector[:2] {
		if _, err := l.Append(ctx, []byte(v.Payload)); err != nil {
			t.Fatal(err)
		}
	}
	// Release the single-opener lock before the "crash" write + reopen.
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "log.ndjson")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"v":1,"index":2,"pay`); err != nil { // no newline: torn
		t.Fatal(err)
	}
	f.Close()

	l2, err := filelog.New(dir)
	if err != nil {
		t.Fatalf("reopen over a torn tail must succeed: %v", err)
	}
	if n, _ := l2.Size(ctx); n != 2 {
		t.Fatalf("size after torn-tail truncate = %d, want 2", n)
	}
	rec, err := l2.Append(ctx, []byte(logcontract.Vector[2].Payload))
	if err != nil || rec.Hash != logcontract.Vector[2].Hash {
		t.Fatalf("append after truncate = %+v (err %v), want the vector chain to continue", rec, err)
	}
}

// Close releases the handle; a closed log refuses appends, and an append
// whose write fails poisons only when rollback is impossible.
func TestClose_AppendsRefused(t *testing.T) {
	ctx := context.Background()
	l, err := filelog.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(ctx, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close must be a no-op: %v", err)
	}
	if _, err := l.Append(ctx, []byte("b")); err == nil {
		t.Fatal("append on a closed log: want error")
	}
	// Reads still serve the committed memory state.
	if n, err := l.Size(ctx); err != nil || n != 1 {
		t.Fatalf("Size after close = %d (err %v), want 1", n, err)
	}
}

// Emission records are evidence: local permissions must not hand out what
// the tlog/read authorization surface protects.
func TestNew_PrivatePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(context.Background(), []byte("a")); err != nil {
		t.Fatal(err)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm()&0o077 != 0 {
		t.Errorf("dir mode = %v, want no group/other bits", di.Mode().Perm())
	}
	fi, err := os.Stat(filepath.Join(dir, "log.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("file mode = %v, want no group/other bits", fi.Mode().Perm())
	}
}

// The unsigned condition is detectable at the CONTRACT level: a caller
// holding only tlog.Log must not need to import the implementation.
func TestCheckpoint_UnsignedIsContractSentinel(t *testing.T) {
	l, err := filelog.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Checkpoint(context.Background()); !errors.Is(err, tlog.ErrUnsignedLog) {
		t.Fatalf("err=%v, want errors.Is(tlog.ErrUnsignedLog)", err)
	}
}

// --- single-opener guard -----------------------------------------------------

// Two live openers on one directory would interleave two chains and brick the
// next open. The exclusive advisory lock makes the second opener fail with a
// typed ErrLocked, having touched no bytes.
func TestNew_SecondOpenerRejected(t *testing.T) {
	dir := t.TempDir()
	l1, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Close()
	if _, err := filelog.New(dir); !errors.Is(err, filelog.ErrLocked) {
		t.Fatalf("second opener err = %v, want ErrLocked", err)
	}
}

// Close releases the lock: after the first opener closes, a reopen (a process
// restart) succeeds and the chain is intact.
func TestNew_LockReleasedOnClose(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l1, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l1.Append(ctx, []byte(logcontract.Vector[0].Payload)); err != nil {
		t.Fatal(err)
	}
	if err := l1.Close(); err != nil {
		t.Fatal(err)
	}
	l2, err := filelog.New(dir)
	if err != nil {
		t.Fatalf("reopen after Close must succeed: %v", err)
	}
	defer l2.Close()
	if rec, err := l2.Get(ctx, 0); err != nil || rec.Hash != logcontract.Vector[0].Hash {
		t.Fatalf("reopened Get(0) = %+v (err %v), want the vector hash", rec, err)
	}
}

// --- durable emission-sequence high-water (intent) ---------------------------

// The high-water is durable across reopen and monotonic (never regresses),
// and a missing intent file reads as 0.
func TestRecordIntent_DurableAndMonotonic(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if hw, err := l.HighestIntent(ctx); err != nil || hw != 0 {
		t.Fatalf("fresh HighestIntent = %d (err %v), want 0", hw, err)
	}
	if err := l.RecordIntent(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if hw, _ := l.HighestIntent(ctx); hw != 5 {
		t.Fatalf("HighestIntent = %d, want 5", hw)
	}
	// Monotonic: a lower value is a no-op.
	if err := l.RecordIntent(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if hw, _ := l.HighestIntent(ctx); hw != 5 {
		t.Fatalf("HighestIntent after lower RecordIntent = %d, want 5 (monotonic)", hw)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	// Durable across reopen.
	l2, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if hw, err := l2.HighestIntent(ctx); err != nil || hw != 5 {
		t.Fatalf("reopened HighestIntent = %d (err %v), want 5 (durable)", hw, err)
	}
}

// A present-but-unparseable intent file degrades to 0 (the explicit
// availability exception) instead of bricking New; recovery then falls back to
// the chain tail, never below it.
func TestNew_IntentUnparseableDegradesToBaseline(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.RecordIntent(ctx, 9); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	// Corrupt the intent file to non-numeric garbage.
	if err := os.WriteFile(filepath.Join(dir, "intent"), []byte("not-a-number"), 0o600); err != nil {
		t.Fatal(err)
	}
	l2, err := filelog.New(dir)
	if err != nil {
		t.Fatalf("unparseable intent must degrade, not brick New: %v", err)
	}
	defer l2.Close()
	if hw, err := l2.HighestIntent(ctx); err != nil || hw != 0 {
		t.Fatalf("degraded HighestIntent = %d (err %v), want 0", hw, err)
	}
}

// A REAL read I/O error on the intent file (not "absent", not "unparseable")
// fails New: a sick disk must be loud, not silently trusted. Injected by
// making `intent` a directory — os.ReadFile then fails with a non-ErrNotExist
// error.
func TestNew_IntentReadErrorFailsOpen(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "intent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := filelog.New(dir); err == nil {
		t.Fatal("New over an unreadable intent file: want error")
	}
}

// A leftover intent.tmp (crash between tmp write and rename) is ignored: the
// atomic-rename contract means only the `intent` file carries the high-water.
func TestNew_StaleIntentTmpIgnored(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.RecordIntent(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "intent.tmp"), []byte("garbage 999"), 0o600); err != nil {
		t.Fatal(err)
	}
	l2, err := filelog.New(dir)
	if err != nil {
		t.Fatalf("reopen over a stale intent.tmp must succeed: %v", err)
	}
	defer l2.Close()
	if hw, err := l2.HighestIntent(ctx); err != nil || hw != 7 {
		t.Fatalf("HighestIntent = %d (err %v), want 7 — intent.tmp must never be read", hw, err)
	}
}

// A RecordIntent whose durable persist FAILS must not advance the in-memory
// high-water: otherwise the emitter's retry would short-circuit as a no-op and
// publish with no durable intent behind it. After the fault clears, the retry
// re-persists (is not a no-op). Fault injected by making the dir unwritable so
// the temp file cannot be created.
func TestRecordIntent_FailedPersistNotNoOpOnRetry(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod-based fault injection is a no-op as root")
	}
	ctx := context.Background()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := os.Chmod(dir, 0o500); err != nil { // read+exec, no write: temp create fails
		t.Fatal(err)
	}
	if err := l.RecordIntent(ctx, 5); err == nil {
		t.Fatal("RecordIntent into an unwritable dir: want persist error")
	}
	if hw, _ := l.HighestIntent(ctx); hw != 0 {
		t.Fatalf("high-water = %d after a FAILED persist, want 0 (cache must not advance)", hw)
	}
	// Clear the fault; the retry must re-persist, NOT no-op on the stale cache.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := l.RecordIntent(ctx, 5); err != nil {
		t.Fatalf("retry after cleared fault: %v", err)
	}
	if hw, _ := l.HighestIntent(ctx); hw != 5 {
		t.Fatalf("high-water = %d after successful retry, want 5", hw)
	}
}

// P0-1: a filelog checkpoint carries the armed log identity as Origin.
func TestCheckpointCarriesOrigin(t *testing.T) {
	ctx := context.Background()
	const logID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:o"
	const signerDID = logID + ":process:s1"
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	ks := &memKS{keys: map[string][]byte{}}
	if err := ks.SaveKeyPair(signerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatal(err)
	}
	l, err := filelog.New(t.TempDir(), filelog.WithCheckpointSigner(filelog.CheckpointSigner{
		Signer: ks, SignerDID: signerDID,
		KeyID: string(keystore.KeyIDSigning), VerificationMethod: signerDID + "#signing", LogID: logID,
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.Append(ctx, []byte("r")); err != nil {
		t.Fatal(err)
	}
	cp, err := l.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Origin != logID {
		t.Errorf("Origin = %q, want %q", cp.Origin, logID)
	}
}
