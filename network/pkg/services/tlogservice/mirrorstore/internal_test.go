package mirrorstore

// White-box tests: crash-ordering and poisoning need to reach state Open's
// public surface deliberately hides (the hashed per-log directory name,
// and the ability to write journal lines without ever committing a
// checkpoint) — the same reason tlog/merklelog/poison_test.go's fault
// injection lives in `package merklelog` rather than `merklelog_test`.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/tlog"
)

func testCP(origin string, size uint64, head string) *tlog.Checkpoint {
	return &tlog.Checkpoint{
		Origin:    origin,
		Size:      size,
		Head:      head,
		Timestamp: time.Now().UTC().Truncate(time.Second),
		SignedBy:  "did:dplaax:example:process:shipper#signing",
		Signature: []byte("test-signature"),
	}
}

func testChainOf(payloads ...[]byte) string {
	head := ""
	for _, p := range payloads {
		head = ChainHash(head, p)
	}
	return head
}

// TestCrashOrdering_UnackedRecordsTruncatedOnReopen simulates the exact
// on-disk state a crash leaves between AppendVerified's two write steps:
// new records fsynced to the journal, but the checkpoint file NOT yet
// replaced (see append.go's doc). Reopen must truncate the journal back to
// the last durable checkpoint's size — those records were never acked.
func TestCrashOrdering_UnackedRecordsTruncatedOnReopen(t *testing.T) {
	logID := "did:dplaax:example:pipeline:crash"
	root := t.TempDir()

	st, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	batch1 := [][]byte{[]byte("c0"), []byte("c1"), []byte("c2")}
	head1 := testChainOf(batch1...)
	if _, err := st.AppendVerified(logID, batch1, testCP(logID, 3, head1)); err != nil {
		t.Fatalf("batch1: %v", err)
	}

	// Simulate a crash mid-way through a SECOND AppendVerified call: the
	// records fsync succeeded, the checkpoint replace never ran.
	dir := filepath.Join(root, dirName(logID))
	extra := [][]byte{[]byte("c3"), []byte("c4")}
	if _, err := appendJournal(dir, 3, head1, extra); err != nil {
		t.Fatalf("simulate crashed append: %v", err)
	}

	st2, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	acked, err := st2.AckedSize(logID)
	if err != nil {
		t.Fatalf("AckedSize after reopen: %v", err)
	}
	if acked != 3 {
		t.Fatalf("acked after reopen = %d, want 3 (unacked tail truncated)", acked)
	}
	if _, err := st2.Get(logID, 3); err == nil {
		t.Fatal("Get(3) after truncation: want error, got nil")
	}
	cp, err := st2.Checkpoint(logID)
	if err != nil {
		t.Fatalf("Checkpoint after reopen: %v", err)
	}
	if cp.Size != 3 || cp.Head != head1 {
		t.Fatalf("checkpoint after reopen = %+v, want size 3 head %q", cp, head1)
	}

	// The store must remain WRITABLE: resume from the truncated tail.
	acked2, err := st2.AppendVerified(logID, extra, testCP(logID, 5, testChainOf(append(append([][]byte{}, batch1...), extra...)...)))
	if err != nil {
		t.Fatalf("resume append after truncation: %v", err)
	}
	if acked2 != 5 {
		t.Fatalf("acked after resume = %d, want 5", acked2)
	}
}

// TestCrashOrdering_NeverCheckpointedLogTruncatesToEmpty covers the
// boundary case: a crash on the FIRST-EVER append for a log, before any
// checkpoint was ever written. Nothing was acked, so reopen must discard
// every record.
func TestCrashOrdering_NeverCheckpointedLogTruncatesToEmpty(t *testing.T) {
	logID := "did:dplaax:example:pipeline:crash-fresh"
	root := t.TempDir()

	dir := filepath.Join(root, dirName(logID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := appendJournal(dir, 0, "", [][]byte{[]byte("f0"), []byte("f1")}); err != nil {
		t.Fatalf("simulate crashed first append: %v", err)
	}
	// No checkpoint.json was ever written for this log.

	st, err := Open(root)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	acked, err := st.AckedSize(logID)
	if err != nil {
		t.Fatalf("AckedSize: %v", err)
	}
	if acked != 0 {
		t.Fatalf("acked = %d, want 0 (nothing was ever acked)", acked)
	}
	if _, err := st.Checkpoint(logID); err == nil {
		t.Fatal("Checkpoint: want ErrNotFound-wrapped error, got nil")
	}
}

// TestDamagedJournal_PoisonsOnlyThatLog corrupts one log's journal (its
// recorded chain at the checkpoint's size no longer matches the
// checkpoint's Head) and verifies Open marks ONLY that log poisoned —
// every call for it errors — while a second, healthy log under the same
// root is unaffected.
func TestDamagedJournal_PoisonsOnlyThatLog(t *testing.T) {
	damagedID := "did:dplaax:example:pipeline:damaged"
	healthyID := "did:dplaax:example:pipeline:healthy"
	root := t.TempDir()

	st, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	dp := [][]byte{[]byte("d0"), []byte("d1")}
	if _, err := st.AppendVerified(damagedID, dp, testCP(damagedID, 2, testChainOf(dp...))); err != nil {
		t.Fatalf("append damaged: %v", err)
	}
	hp := [][]byte{[]byte("h0")}
	if _, err := st.AppendVerified(healthyID, hp, testCP(healthyID, 1, testChainOf(hp...))); err != nil {
		t.Fatalf("append healthy: %v", err)
	}

	// Tamper the damaged log's journal: flip the recorded hash of the
	// second line so it no longer matches the checkpoint's head, without
	// going through any store API (raw disk corruption, e.g. bit rot or an
	// operator mistake).
	path := filepath.Join(root, dirName(damagedID), recordsFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), testChainOf(dp[0], dp[1]), strings.Repeat("0", 64), 1)
	if tampered == string(raw) {
		t.Fatal("tamper fixture did not change the file — test is not exercising damage")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	st2, err := Open(root)
	if err != nil {
		t.Fatalf("open after tamper: %v", err)
	}
	if _, err := st2.AckedSize(damagedID); err == nil {
		t.Fatal("AckedSize(damaged): want error (poisoned), got nil")
	}
	if _, err := st2.Checkpoint(damagedID); err == nil {
		t.Fatal("Checkpoint(damaged): want error (poisoned), got nil")
	}
	if _, err := st2.Get(damagedID, 0); err == nil {
		t.Fatal("Get(damaged, 0): want error (poisoned), got nil")
	}
	if _, err := st2.AppendVerified(damagedID, [][]byte{[]byte("d2")}, testCP(damagedID, 3, "irrelevant")); err == nil {
		t.Fatal("AppendVerified(damaged): want error (poisoned), got nil")
	}

	// The healthy log must be completely unaffected.
	if n, err := st2.AckedSize(healthyID); err != nil || n != 1 {
		t.Fatalf("AckedSize(healthy) = %d, %v; want 1, nil", n, err)
	}
	if rec, err := st2.Get(healthyID, 0); err != nil || string(rec.Payload) != "h0" {
		t.Fatalf("Get(healthy, 0) = %+v, %v; want payload h0", rec, err)
	}
}

// TestDamagedJournal_ShorterThanCheckpointPoisons covers the OTHER damage
// shape explicitly named by the brief: a journal that is SHORTER than what
// the persisted checkpoint claims (records genuinely lost, not merely
// unacked).
func TestDamagedJournal_ShorterThanCheckpointPoisons(t *testing.T) {
	logID := "did:dplaax:example:pipeline:short"
	root := t.TempDir()

	st, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	payloads := [][]byte{[]byte("s0"), []byte("s1"), []byte("s2")}
	if _, err := st.AppendVerified(logID, payloads, testCP(logID, 3, testChainOf(payloads...))); err != nil {
		t.Fatalf("append: %v", err)
	}

	// Simulate lost records: truncate the journal to just the first line,
	// leaving the checkpoint (which claims size 3) untouched.
	dir := filepath.Join(root, dirName(logID))
	_, offsets, _, _, err := replayJournal(filepath.Join(dir, recordsFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := truncateJournal(dir, offsets[0]); err != nil {
		t.Fatal(err)
	}

	st2, err := Open(root)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := st2.AckedSize(logID); err == nil {
		t.Fatal("AckedSize: want error (poisoned — journal shorter than checkpoint), got nil")
	}
}

// TestDamagedJournal_InteriorBreakWithNoCheckpointPoisons covers the edge
// case where the "journal shorter than checkpoint" fallback CANNOT catch
// the damage on its own: a log whose journal has an interior hash-chain
// break (replayJournal fails, returning zero records) but that has NEVER
// been checkpointed. checkpointSize(0) > len(records)(0) is false and the
// genesis expectedHead("") trivially equals the absent checkpoint's head
// (""), so without openLogDir's explicit replayJournal-error branch this
// would silently read as an empty, healthy log — masking real interior
// corruption. (Verified by deliberately removing that branch: this test
// then reports the log healthy instead of poisoned.)
func TestDamagedJournal_InteriorBreakWithNoCheckpointPoisons(t *testing.T) {
	logID := "did:dplaax:example:pipeline:interior-break"
	root := t.TempDir()
	dir := filepath.Join(root, dirName(logID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Line 0 is genuinely valid; line 1's hash does not chain from it.
	bad := `{"v":1,"index":0,"payload":"YTA=","hash":"` + ChainHash("", []byte("a0")) + `"}
{"v":1,"index":1,"payload":"YTE=","hash":"deadbeef"}
`
	if err := os.WriteFile(filepath.Join(dir, recordsFile), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	// No checkpoint.json is written — this log was never acked.

	st, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AckedSize(logID); err == nil {
		t.Fatal("AckedSize: want error (poisoned — interior chain break), got nil")
	}
	if _, err := st.Get(logID, 0); err == nil {
		t.Fatal("Get(0): want error (poisoned), got nil")
	}
}

// TestAppendVerified_CheckpointWriteFailureDoesNotAdvanceOrCorrupt covers
// the review finding on append.go: a records-fsync that succeeds followed
// by a checkpoint write that FAILS must not advance the live process's
// view (AckedSize/Get/Checkpoint) past what is durably checkpointed, and
// must not corrupt the on-disk journal for a subsequent retry.
//
// Fault-injection seam: after an initial successful append, the log
// directory is made unwritable (0o500 — read+search, no write). Writing to
// the ALREADY-EXISTING records.ndjson only needs write permission on that
// file (unaffected), so appendJournal still succeeds; but
// writeCheckpointFile's atomic replace must CREATE a new temp file in the
// directory, which needs directory write permission and so fails. This
// reproduces the exact byte-for-byte disk state a crash between the two
// writes would leave, without needing a production-code test hook.
func TestAppendVerified_CheckpointWriteFailureDoesNotAdvanceOrCorrupt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory write-permission semantics differ on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses permission checks")
	}
	logID := "did:dplaax:example:pipeline:ckpt-fail"
	root := t.TempDir()

	st, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	batch1 := [][]byte{[]byte("k0")}
	head1 := testChainOf(batch1...)
	cp1 := testCP(logID, 1, head1)
	if _, err := st.AppendVerified(logID, batch1, cp1); err != nil {
		t.Fatalf("initial append: %v", err)
	}

	dir := filepath.Join(root, dirName(logID))
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	// t.TempDir()'s own cleanup needs to remove files under dir — restore
	// write permission unconditionally so cleanup does not fail.
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	batch2 := [][]byte{[]byte("k1")}
	head2 := ChainHash(head1, batch2[0])
	cp2 := testCP(logID, 2, head2)
	if _, err := st.AppendVerified(logID, batch2, cp2); err == nil {
		t.Fatal("append with an unwritable checkpoint dir: want error, got nil")
	}

	// The live process must NOT have advanced past the last durable
	// checkpoint, even though the records were fsynced to the journal.
	if n, err := st.AckedSize(logID); err != nil || n != 1 {
		t.Fatalf("AckedSize after failed checkpoint write = %d, %v; want 1, nil (must not advance)", n, err)
	}
	if _, err := st.Get(logID, 1); err == nil {
		t.Fatal("Get(1) after failed checkpoint write: want error, got nil")
	}
	got, err := st.Checkpoint(logID)
	if err != nil {
		t.Fatalf("Checkpoint after failed write: %v", err)
	}
	if got.Size != 1 || got.Head != head1 {
		t.Fatalf("Checkpoint after failed write = %+v, want size 1 head %q (unchanged)", got, head1)
	}

	// Restore write permission and retry the IDENTICAL segment — the
	// rollback truncate must have kept records.ndjson density-correct, so
	// this must succeed cleanly (no duplicate-index damage from the
	// aborted attempt's orphaned bytes).
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	acked, err := st.AppendVerified(logID, batch2, cp2)
	if err != nil {
		t.Fatalf("retry after restoring permission: %v", err)
	}
	if acked != 2 {
		t.Fatalf("acked after retry = %d, want 2", acked)
	}
	if rec, err := st.Get(logID, 1); err != nil || rec.Hash != head2 {
		t.Fatalf("Get(1) after retry = %+v (err %v), want hash %q", rec, err, head2)
	}

	// A fresh Open over the same root must also see the retried state —
	// the rollback did not leave any orphaned bytes for replay to trip on.
	st2, err := Open(root)
	if err != nil {
		t.Fatalf("reopen after retry: %v", err)
	}
	if n, err := st2.AckedSize(logID); err != nil || n != 2 {
		t.Fatalf("reopened AckedSize = %d, %v; want 2, nil", n, err)
	}
}
