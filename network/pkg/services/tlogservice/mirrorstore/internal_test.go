package mirrorstore

// White-box tests: crash-ordering and poisoning need to reach state Open's
// public surface deliberately hides (the hashed per-log directory name,
// and the ability to write journal lines without ever committing a
// checkpoint) — the same reason tlog/merklelog/poison_test.go's fault
// injection lives in `package merklelog` rather than `merklelog_test`.

import (
	"fmt"
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

// TestAppendVerified_JournalAppendFailureRollsBack (P1-C) covers the review
// finding on the appendJournal error path: a partial os.File.Write / Sync
// failure leaves uncheckpointed bytes on disk; the write path must roll the
// journal back to its pre-append size (or poison), never return leaving the
// excess so a later retry re-appends duplicate indexes and poisons on reopen.
//
// Fault-injection seam: appendJournalFn is swapped for one that writes a
// partial (newline-less) line to records.ndjson — exactly the byte state a
// crash mid-Write leaves — then returns an error, WITHOUT chmod'ing anything,
// so the rollback truncate that follows can still open the writable file.
func TestAppendVerified_JournalAppendFailureRollsBack(t *testing.T) {
	logID := "did:dplaax:example:pipeline:append-fail"
	root := t.TempDir()
	st, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	batch1 := [][]byte{[]byte("j0")}
	head1 := testChainOf(batch1...)
	if _, err := st.AppendVerified(logID, batch1, testCP(logID, 1, head1)); err != nil {
		t.Fatalf("seed append: %v", err)
	}
	dir := filepath.Join(root, dirName(logID))
	preSize, err := journalSize(dir)
	if err != nil {
		t.Fatal(err)
	}

	orig := appendJournalFn
	appendJournalFn = func(d string, _ uint64, _ string, _ [][]byte) ([]*tlog.Record, error) {
		f, oerr := os.OpenFile(filepath.Join(d, recordsFile), os.O_APPEND|os.O_WRONLY, 0o600)
		if oerr != nil {
			return nil, oerr
		}
		// A partial, unterminated line — uncheckpointed bytes beyond preSize.
		_, _ = f.WriteString(`{"v":1,"index":1,"payload":"anoop","hash":"partial-no-newline`)
		_ = f.Sync()
		_ = f.Close()
		return nil, fmt.Errorf("injected journal append failure")
	}
	batch2 := [][]byte{[]byte("j1")}
	head2 := ChainHash(head1, batch2[0])
	cp2 := testCP(logID, 2, head2)
	_, aerr := st.AppendVerified(logID, batch2, cp2)
	appendJournalFn = orig
	if aerr == nil {
		t.Fatal("append with injected journal failure: want error, got nil")
	}

	// The journal must be rolled back to preSize (partial bytes removed).
	if sz, _ := journalSize(dir); sz != preSize {
		t.Fatalf("journal size after failed append = %d, want preSize %d (rolled back)", sz, preSize)
	}
	if n, err := st.AckedSize(logID); err != nil || n != 1 {
		t.Fatalf("AckedSize after failed append = %d, %v; want 1, nil (must not advance)", n, err)
	}

	// A retry of the IDENTICAL segment with the real appendJournal must succeed
	// cleanly (no orphaned duplicate-index bytes).
	acked, err := st.AppendVerified(logID, batch2, cp2)
	if err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}
	if acked != 2 {
		t.Fatalf("acked after retry = %d, want 2", acked)
	}

	// Reopen must NOT find the log poisoned — the journal is density-correct.
	st2, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if n, err := st2.AckedSize(logID); err != nil || n != 2 {
		t.Fatalf("reopened AckedSize = %d, %v; want 2, nil (not poisoned)", n, err)
	}
}

// TestReopen_CheckpointOriginMismatchPoisons (F4) covers the reopen finding: a
// log directory whose persisted checkpoint's Origin does NOT hash to that
// directory's name (a copied/swapped/corrupted dir) must be poisoned on Open,
// never served — otherwise a request for log B (whose dir the data now sits
// under) is answered with log A's checkpoint + records.
func TestReopen_CheckpointOriginMismatchPoisons(t *testing.T) {
	root := t.TempDir()
	st, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	logA := "did:dplaax:example:pipeline:origin-a"
	logB := "did:dplaax:example:pipeline:origin-b"
	p := [][]byte{[]byte("o0")}
	if _, err := st.AppendVerified(logA, p, testCP(logA, 1, testChainOf(p...))); err != nil {
		t.Fatalf("seed logA: %v", err)
	}
	// Swap: move logA's directory to logB's dir name. The dir named
	// dirName(logB) now holds a checkpoint whose Origin is logA.
	if err := os.Rename(filepath.Join(root, dirName(logA)), filepath.Join(root, dirName(logB))); err != nil {
		t.Fatal(err)
	}

	st2, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	// logB's dir must be poisoned (its checkpoint Origin hashes to logA's dir).
	if _, err := st2.AckedSize(logB); err == nil {
		t.Fatal("AckedSize(logB) over a swapped dir: want poisoned error, got nil (would serve logA's data under logB)")
	}
	if _, err := st2.Get(logB, 0); err == nil {
		t.Fatal("Get(logB,0) over a swapped dir: want poisoned error, got nil")
	}
	if _, err := st2.Checkpoint(logB); err == nil {
		t.Fatal("Checkpoint(logB) over a swapped dir: want poisoned error, got nil")
	}
	// logA's own dir is gone, so it is simply unknown (size 0) — never served.
	if n, err := st2.AckedSize(logA); err != nil || n != 0 {
		t.Fatalf("AckedSize(logA) after its dir moved = %d, %v; want 0, nil", n, err)
	}
}

// TestAppendVerified_PreWriteAppendFailureIsRetryableNotPoison (R1) covers the
// re-review regression the P1-C rollback introduced: a PRE-write appendJournal
// failure (EMFILE / permission / open failure — nothing written, the journal
// stays at preSize) must NOT poison the log. The unconditional truncate the
// first P1-C cut performed could itself fail for the same transient reason and
// then poison a perfectly healthy log for the process lifetime. A pre-write
// failure is a clean, retryable error; a subsequent good append must succeed.
//
// Fault-injection: records.ndjson is made read-only so that IF the code wrongly
// attempts a rollback truncate, that truncate FAILS (the exact condition that
// poisoned the log pre-fix); appendJournalFn is injected to fail without
// writing, leaving the journal at preSize.
func TestAppendVerified_PreWriteAppendFailureIsRetryableNotPoison(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file write-permission semantics differ on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses permission checks")
	}
	logID := "did:dplaax:example:pipeline:prewrite-fail"
	root := t.TempDir()
	st, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	batch1 := [][]byte{[]byte("q0")}
	head1 := testChainOf(batch1...)
	if _, err := st.AppendVerified(logID, batch1, testCP(logID, 1, head1)); err != nil {
		t.Fatalf("seed append: %v", err)
	}
	dir := filepath.Join(root, dirName(logID))
	preSize, err := journalSize(dir)
	if err != nil {
		t.Fatal(err)
	}
	recPath := filepath.Join(dir, recordsFile)
	if err := os.Chmod(recPath, 0o400); err != nil { // rollback truncate would fail
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(recPath, 0o600) })

	orig := appendJournalFn
	appendJournalFn = func(string, uint64, string, [][]byte) ([]*tlog.Record, error) {
		return nil, fmt.Errorf("injected pre-write open failure (EMFILE)") // writes nothing
	}
	batch2 := [][]byte{[]byte("q1")}
	head2 := ChainHash(head1, batch2[0])
	cp2 := testCP(logID, 2, head2)
	_, aerr := st.AppendVerified(logID, batch2, cp2)
	appendJournalFn = orig
	if aerr == nil {
		t.Fatal("append with injected pre-write failure: want error, got nil")
	}

	// The journal is unchanged and the log must NOT be poisoned.
	if sz, _ := journalSize(dir); sz != preSize {
		t.Fatalf("journal size after pre-write failure = %d, want unchanged preSize %d", sz, preSize)
	}
	if n, err := st.AckedSize(logID); err != nil || n != 1 {
		t.Fatalf("AckedSize after pre-write failure = %d, %v; want 1, nil (NOT poisoned — a pre-write failure is retryable)", n, err)
	}

	// Restore write permission and retry the identical segment — it must succeed
	// (the log was never poisoned).
	if err := os.Chmod(recPath, 0o600); err != nil {
		t.Fatal(err)
	}
	acked, err := st.AppendVerified(logID, batch2, cp2)
	if err != nil {
		t.Fatalf("retry after pre-write failure: %v", err)
	}
	if acked != 2 {
		t.Fatalf("acked after retry = %d, want 2", acked)
	}
}

// TestAppendVerified_PostRenameFsyncFailurePoisonsNotTruncates (P2-F) covers
// the review finding on writeCheckpointFile's ambiguous-durability case: when
// writeAtomic renames checkpoint.json to the new size SUCCESSFULLY but its
// trailing dir-fsync then fails, the checkpoint file ALREADY names the new
// size. Blind-truncating the journal back to the old size (the pre-fix path)
// leaves the checkpoint AHEAD of the records → poisoned-inconsistent on
// restart. The fix POISONS the log this session and does NOT truncate, so a
// fresh reopen finds records and checkpoint consistent at the new size.
//
// Fault-injection seam: afterRenameDirSync is swapped for one that fails,
// after the os.Rename inside writeAtomic has already committed.
func TestAppendVerified_PostRenameFsyncFailurePoisonsNotTruncates(t *testing.T) {
	logID := "did:dplaax:example:pipeline:postrename"
	root := t.TempDir()
	st, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	batch1 := [][]byte{[]byte("p0")}
	head1 := testChainOf(batch1...)
	if _, err := st.AppendVerified(logID, batch1, testCP(logID, 1, head1)); err != nil {
		t.Fatalf("seed append: %v", err)
	}

	orig := afterRenameDirSync
	afterRenameDirSync = func(string) error { return fmt.Errorf("injected post-rename dir-fsync failure") }
	batch2 := [][]byte{[]byte("p1")}
	head2 := ChainHash(head1, batch2[0])
	cp2 := testCP(logID, 2, head2)
	_, werr := st.AppendVerified(logID, batch2, cp2)
	afterRenameDirSync = orig
	if werr == nil {
		t.Fatal("append with post-rename fsync failure: want error, got nil")
	}

	// The live process must POISON this log (durability uncertain), NOT
	// silently truncate back to size 1.
	if _, err := st.AckedSize(logID); err == nil {
		t.Fatal("AckedSize after post-rename failure: want poisoned error, got nil (log was silently truncated)")
	}

	// checkpoint.json (renamed to 2) and the journal (untruncated at 2) are
	// consistent on disk, so a FRESH reopen finds a healthy log at 2 — never
	// checkpoint-ahead-of-records (which the pre-fix truncate produced).
	st2, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if n, err := st2.AckedSize(logID); err != nil || n != 2 {
		t.Fatalf("reopened AckedSize = %d, %v; want 2, nil (no checkpoint-ahead-of-records)", n, err)
	}
	cp, err := st2.Checkpoint(logID)
	if err != nil || cp.Size != 2 || cp.Head != head2 {
		t.Fatalf("reopened checkpoint = %+v (err %v), want size 2 head %q", cp, err, head2)
	}
}
