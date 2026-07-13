package filelog_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/tlog/filelog"
)

// On-disk layout the rotation contract pins (mirrors the unexported constants).
const (
	tLogFile      = "log.ndjson"
	tArchiveDir   = "archive"
	tManifestFile = "manifest.json"
	tRotateMarker = ".rotate-intent"
	tSegmentHW    = ".segment-hw"
)

func seg(n int) string { return fmt.Sprintf("seg-%06d", n) }

// seedLog appends payloads to a throwaway log and returns its raw log.ndjson
// bytes plus the final chain head — the material fault-injection tests plant on
// disk to simulate an interrupted rotation.
func seedLog(t *testing.T, payloads ...string) (raw []byte, head string) {
	t.Helper()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatalf("seed New: %v", err)
	}
	for _, p := range payloads {
		rec, err := l.Append(context.Background(), []byte(p))
		if err != nil {
			t.Fatalf("seed append: %v", err)
		}
		head = rec.Hash
	}
	if err := l.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}
	raw, err = os.ReadFile(filepath.Join(dir, tLogFile))
	if err != nil {
		t.Fatalf("seed read: %v", err)
	}
	return raw, head
}

// verifyArchiveReplays opens an archive segment dir as a filelog and asserts it
// independently replays to wantN records ending in wantHead.
func verifyArchiveReplays(t *testing.T, segPath string, wantN uint64, wantHead string) {
	t.Helper()
	l, err := filelog.New(segPath)
	if err != nil {
		t.Fatalf("archive replay New(%s): %v", segPath, err)
	}
	defer l.Close()
	n, err := l.Size(context.Background())
	if err != nil || n != wantN {
		t.Fatalf("archive size = %d (err %v), want %d", n, err, wantN)
	}
	if n > 0 && wantHead != "" {
		rec, err := l.Get(context.Background(), n-1)
		if err != nil || rec.Hash != wantHead {
			t.Fatalf("archive head = %+v (err %v), want %s", rec, err, wantHead)
		}
	}
}

func TestRotate_Basic(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	var head, genesis string
	for i, p := range []string{"a", "b", "c"} {
		rec, err := l.Append(ctx, []byte(p))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			genesis = rec.Hash
		}
		head = rec.Hash
	}

	rs, err := l.Rotate(ctx)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rs.Size != 3 || rs.Head != head || rs.Genesis != genesis || rs.Segment != 1 {
		t.Errorf("RotatedSegment = %+v, want size 3 / head %s / genesis %s / seg 1", rs, head, genesis)
	}
	if rs.Checkpoint != nil {
		t.Errorf("unsigned log: Checkpoint should be nil, got %+v", rs.Checkpoint)
	}
	// Live log is now empty.
	if n, _ := l.Size(ctx); n != 0 {
		t.Errorf("live Size after rotate = %d, want 0", n)
	}
	// Archived segment replays independently.
	verifyArchiveReplays(t, filepath.Join(dir, tArchiveDir, seg(1)), 3, head)
	// Manifest is readable and consistent.
	mb, err := os.ReadFile(filepath.Join(dir, tArchiveDir, seg(1), tManifestFile))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m struct {
		Size uint64 `json:"size"`
		Head string `json:"head"`
	}
	if err := json.Unmarshal(mb, &m); err != nil {
		t.Fatalf("manifest json: %v", err)
	}
	if m.Size != 3 || m.Head != head {
		t.Errorf("manifest = %+v, want size 3 / head %s", m, head)
	}
	// Marker cleared.
	if _, err := os.Stat(filepath.Join(dir, tRotateMarker)); !os.IsNotExist(err) {
		t.Errorf("rotation marker still present after success (err %v)", err)
	}
	_ = l.Close()
}

// The archived bytes are byte-identical to the live log before rotation — the
// append-only contract holds (records mutated/deleted nowhere).
func TestRotate_ArchiveByteIdentical(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"x", "y"} {
		if _, err := l.Append(ctx, []byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.ReadFile(filepath.Join(dir, tLogFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Rotate(ctx); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	archived, err := os.ReadFile(filepath.Join(dir, tArchiveDir, seg(1), tLogFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(archived) != string(before) {
		t.Errorf("archived segment differs from pre-rotation live log")
	}
	_ = l.Close()
}

// After rotation the live log begins a fresh genesis chain (index restarts at 0)
// and survives a reopen.
func TestRotate_FreshChainIndependent(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"a", "b"} {
		if _, err := l.Append(ctx, []byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.Rotate(ctx); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	rec, err := l.Append(ctx, []byte("fresh"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Index != 0 {
		t.Errorf("post-rotate append index = %d, want 0 (fresh genesis)", rec.Index)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopen: the fresh chain replays cleanly, archive coexists.
	l2, err := filelog.New(dir)
	if err != nil {
		t.Fatalf("reopen after rotate: %v", err)
	}
	defer l2.Close()
	if n, _ := l2.Size(ctx); n != 1 {
		t.Errorf("reopened live Size = %d, want 1", n)
	}
	verifyArchiveReplays(t, filepath.Join(dir, tArchiveDir, seg(1)), 2, "")
}

func TestRotate_PreservesIntent(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(ctx, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := l.RecordIntent(ctx, 42); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Rotate(ctx); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if hw, err := l.HighestIntent(ctx); err != nil || hw != 42 {
		t.Errorf("HighestIntent after rotate = %d (err %v), want 42 (emission high-water must not regress)", hw, err)
	}
	_ = l.Close()
}

func TestRotate_EmptyLogRejected(t *testing.T) {
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.Rotate(context.Background()); err == nil {
		t.Error("Rotate on an empty log: want error, got nil")
	}
}

func TestRotate_SignedSeal(t *testing.T) {
	ctx := context.Background()
	const (
		logID     = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pipe"
		signerDID = logID + ":process:s1"
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
	dir := t.TempDir()
	l, err := filelog.New(dir, filelog.WithCheckpointSigner(filelog.CheckpointSigner{
		Signer: ks, SignerDID: signerDID,
		KeyID: string(keystore.KeyIDSigning), VerificationMethod: vm, LogID: logID,
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
	// If Rotate re-entered the mu-locking Checkpoint it would deadlock here.
	rs, err := l.Rotate(ctx)
	if err != nil {
		t.Fatalf("Rotate (signed): %v", err)
	}
	if rs.Checkpoint == nil {
		t.Fatal("signed log: Rotate must carry a Checkpoint")
	}
	cp := rs.Checkpoint
	view, err := jcs.Canonicalize(map[string]any{
		"v": 1, "purpose": "dplaax-tlog-checkpoint", "logId": logID,
		"head": cp.Head, "signedBy": cp.SignedBy, "size": "2",
		"timestamp": cp.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cp.Head != head {
		t.Errorf("checkpoint head = %s, want %s", cp.Head, head)
	}
	ok, err := (ed25519.Verifier{}).Verify(kp.PublicKey, view, cp.Signature)
	if err != nil || !ok {
		t.Fatalf("checkpoint signature does not verify (ok=%v err=%v)", ok, err)
	}
	_ = l.Close()
}

func TestRotate_MultipleSegmentsMonotonic(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	// First segment.
	h1, _ := l.Append(ctx, []byte("s1a"))
	rs1, err := l.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Second segment.
	h2, _ := l.Append(ctx, []byte("s2a"))
	rs2, err := l.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rs1.Segment != 1 || rs2.Segment != 2 {
		t.Errorf("segments = %d,%d, want 1,2 (monotonic)", rs1.Segment, rs2.Segment)
	}
	verifyArchiveReplays(t, filepath.Join(dir, tArchiveDir, seg(1)), 1, h1.Hash)
	verifyArchiveReplays(t, filepath.Join(dir, tArchiveDir, seg(2)), 1, h2.Hash)
	_ = l.Close()
}

// Truncate-in-place keeps the log file's inode, so the single-opener flock holds
// throughout rotation: a second opener is still rejected afterward.
func TestRotate_FlockHeldThroughout(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.Append(ctx, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := filelog.New(dir); err == nil {
		t.Error("second opener after rotate: want ErrLocked, got nil (flock dropped)")
	}
}

// --- crash reconciliation (fault injection at New) ---------------------------

// plantCommittedRotation writes an interrupted-rotation state: a committed
// archive segment seg-1 plus the marker; the live log holds `liveRaw` (which the
// caller sets to the full S records for the truncate-pending case, or empty for
// the already-truncated case).
func plantCommittedRotation(t *testing.T, dir string, archived []byte, head string, size int, liveRaw []byte) {
	t.Helper()
	segPath := filepath.Join(dir, tArchiveDir, seg(1))
	if err := os.MkdirAll(segPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(segPath, tLogFile), archived, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, tLogFile), liveRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	marker := []byte(`{"segment":1,"size":` + strconv.Itoa(size) + `,"head":"` + head + `"}`)
	if err := os.WriteFile(filepath.Join(dir, tRotateMarker), marker, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReconcile_CommittedTruncatePending(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	raw, head := seedLog(t, "a", "b")
	// Crash after archive commit, before truncate: live still has the 2 records.
	plantCommittedRotation(t, dir, raw, head, 2, raw)

	l, err := filelog.New(dir)
	if err != nil {
		t.Fatalf("New should reconcile, got: %v", err)
	}
	defer l.Close()
	if n, _ := l.Size(ctx); n != 0 {
		t.Errorf("live Size after reconcile = %d, want 0 (truncate completed)", n)
	}
	if _, err := os.Stat(filepath.Join(dir, tRotateMarker)); !os.IsNotExist(err) {
		t.Errorf("marker not cleared after reconcile")
	}
	verifyArchiveReplays(t, filepath.Join(dir, tArchiveDir, seg(1)), 2, head)
}

func TestReconcile_CommittedTruncateAlreadyDone(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	raw, head := seedLog(t, "a", "b")
	// Crash after truncate, before marker removal: live already empty.
	plantCommittedRotation(t, dir, raw, head, 2, nil)

	l, err := filelog.New(dir)
	if err != nil {
		t.Fatalf("New should reconcile, got: %v", err)
	}
	defer l.Close()
	if n, _ := l.Size(ctx); n != 0 {
		t.Errorf("live Size = %d, want 0", n)
	}
	if _, err := os.Stat(filepath.Join(dir, tRotateMarker)); !os.IsNotExist(err) {
		t.Errorf("marker not cleared")
	}
}

func TestReconcile_UncommittedRollsBack(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	raw, head := seedLog(t, "a", "b")
	// Crash before segment commit: no archive/seg-1, only a staging remnant. Live
	// still holds both records and must remain authoritative.
	if err := os.WriteFile(filepath.Join(dir, tLogFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, tArchiveDir, "."+seg(1)+".tmp")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, tLogFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, tRotateMarker),
		[]byte(`{"segment":1,"size":2,"head":"`+head+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	l, err := filelog.New(dir)
	if err != nil {
		t.Fatalf("New should roll back, got: %v", err)
	}
	defer l.Close()
	if n, _ := l.Size(ctx); n != 2 {
		t.Errorf("live Size after rollback = %d, want 2 (live authoritative)", n)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf("staging remnant not removed on rollback")
	}
	if _, err := os.Stat(filepath.Join(dir, tRotateMarker)); !os.IsNotExist(err) {
		t.Errorf("marker not cleared on rollback")
	}
}

func TestReconcile_MismatchFailsLoud(t *testing.T) {
	dir := t.TempDir()
	raw, head := seedLog(t, "a", "b")
	other, _ := seedLog(t, "different", "records", "here")
	// Committed segment exists but disagrees with the marker (3 records vs 2).
	plantCommittedRotation(t, dir, other, head, 2, raw)

	if _, err := filelog.New(dir); err == nil {
		t.Error("mismatching archive segment: want New to fail loud, got nil")
	}
}

func TestReconcile_MalformedMarkerFailsClosed(t *testing.T) {
	dir := t.TempDir()
	raw, _ := seedLog(t, "a")
	if err := os.WriteFile(filepath.Join(dir, tLogFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Zero segment is invalid — reconciliation must fail closed, not proceed.
	if err := os.WriteFile(filepath.Join(dir, tRotateMarker),
		[]byte(`{"segment":0,"size":1,"head":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := filelog.New(dir); err == nil {
		t.Error("malformed marker: want New to fail closed, got nil")
	}
}

func TestRotate_UnreconciledMarkerFailsLoud(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.Append(ctx, []byte("a")); err != nil {
		t.Fatal(err)
	}
	// A marker appearing on a live log (New already reconciled) is an anomaly:
	// Rotate must refuse rather than guess.
	if err := os.WriteFile(filepath.Join(dir, tRotateMarker),
		[]byte(`{"segment":9,"size":1,"head":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Rotate(ctx); err == nil {
		t.Error("Rotate with an unreconciled marker present: want error, got nil")
	}
}

// Numbering must survive the documented cold-storage workflow: after operators
// move archive/ away, the next rotation must not reuse seg-000001 (the segment
// high-water lives in the log dir, not under archive/).
func TestRotate_NumberingSurvivesArchiveMove(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.Append(ctx, []byte("s1")); err != nil {
		t.Fatal(err)
	}
	rs1, err := l.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rs1.Segment != 1 {
		t.Fatalf("first segment = %d, want 1", rs1.Segment)
	}
	// Operator moves the whole archive to cold storage.
	cold := filepath.Join(t.TempDir(), "cold")
	if err := os.Rename(filepath.Join(dir, tArchiveDir), cold); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(ctx, []byte("s2")); err != nil {
		t.Fatal(err)
	}
	rs2, err := l.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rs2.Segment != 2 {
		t.Errorf("segment after archive move = %d, want 2 (numbering must not reset)", rs2.Segment)
	}
}

// A leftover .seg-N.tmp staging dir from a prior crash is neither counted as a
// committed segment nor allowed to block a fresh rotation.
func TestRotate_TmpRemnantIgnored(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.Append(ctx, []byte("s1")); err != nil {
		t.Fatal(err)
	}
	remnant := filepath.Join(dir, tArchiveDir, "."+seg(1)+".tmp")
	if err := os.MkdirAll(remnant, 0o700); err != nil {
		t.Fatal(err)
	}
	rs, err := l.Rotate(ctx)
	if err != nil {
		t.Fatalf("Rotate with tmp remnant: %v", err)
	}
	if rs.Segment != 1 {
		t.Errorf("segment = %d, want 1 (.tmp remnant must not count)", rs.Segment)
	}
	if _, err := os.Stat(remnant); !os.IsNotExist(err) {
		t.Errorf("tmp remnant not cleared: %v", err)
	}
	verifyArchiveReplays(t, filepath.Join(dir, tArchiveDir, seg(1)), 1, rs.Head)
}

// A corrupt segment high-water fails the rotation loudly rather than degrading
// to 0 (which would reissue a live segment number).
func TestRotate_CorruptSegmentHWFailsLoud(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.Append(ctx, []byte("s1")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, tSegmentHW), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Rotate(ctx); err == nil {
		t.Error("corrupt segment high-water: want Rotate to fail loud, got nil")
	}
}

// The rollback branch of reconcile refuses to accept a short live log when the
// marker names an uncommitted segment of size S (defense-in-depth for a lost
// archive link): it fails loud rather than silently returning a truncated log.
func TestReconcile_UncommittedShortLiveFailsLoud(t *testing.T) {
	dir := t.TempDir()
	_, head := seedLog(t, "a", "b")
	// Marker claims size 2, segment NOT committed, but the live log is empty — an
	// impossible state under normal operation (a lost committed segment).
	if err := os.WriteFile(filepath.Join(dir, tLogFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, tRotateMarker),
		[]byte(`{"segment":1,"size":2,"head":"`+head+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := filelog.New(dir); err == nil {
		t.Error("uncommitted segment with a short live log: want New to fail loud, got nil")
	}
}
