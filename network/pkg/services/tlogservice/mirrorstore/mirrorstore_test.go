package mirrorstore_test

import (
	"errors"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/services/tlogservice/mirrorstore"
	"github.com/provin-line/oss/tlog"
)

// mkCP builds a test checkpoint. mirrorstore does not verify signatures
// (that is the handler's job — D-T2 rules 1-3), so a fixed non-empty
// SignedBy/Signature is enough to satisfy the store's "actually signed"
// structural check.
func mkCP(origin string, size uint64, head string) *tlog.Checkpoint {
	return &tlog.Checkpoint{
		Origin:    origin,
		Size:      size,
		Head:      head,
		Timestamp: time.Now().UTC().Truncate(time.Second),
		SignedBy:  "did:dplaax:example:process:shipper#signing",
		Signature: []byte("test-signature"),
	}
}

func chainOf(payloads ...[]byte) string {
	head := ""
	for _, p := range payloads {
		head = mirrorstore.ChainHash(head, p)
	}
	return head
}

func assertCheckpointEqual(t *testing.T, got, want *tlog.Checkpoint) {
	t.Helper()
	if got == nil || want == nil {
		t.Fatalf("checkpoint = %v, want %v", got, want)
	}
	if got.Origin != want.Origin || got.Size != want.Size || got.Head != want.Head ||
		got.SignedBy != want.SignedBy || string(got.Signature) != string(want.Signature) {
		t.Fatalf("checkpoint = %+v, want %+v", got, want)
	}
	if !got.Timestamp.Equal(want.Timestamp) {
		t.Fatalf("checkpoint timestamp = %v, want %v", got.Timestamp, want.Timestamp)
	}
}

func TestUnknownLog_ZeroAndNotFound(t *testing.T) {
	st, err := mirrorstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if n, err := st.AckedSize("did:dplaax:example:pipeline:none"); err != nil || n != 0 {
		t.Fatalf("AckedSize(unknown) = %d, %v; want 0, nil", n, err)
	}
	if n, err := st.Size("did:dplaax:example:pipeline:none"); err != nil || n != 0 {
		t.Fatalf("Size(unknown) = %d, %v; want 0, nil", n, err)
	}
	if _, err := st.Checkpoint("did:dplaax:example:pipeline:none"); !errors.Is(err, mirrorstore.ErrNotFound) {
		t.Fatalf("Checkpoint(unknown) err = %v, want ErrNotFound", err)
	}
	if _, err := st.Get("did:dplaax:example:pipeline:none", 0); err == nil {
		t.Fatal("Get(unknown, 0): want error, got nil")
	}
}

func TestAppendVerified_RoundTrip(t *testing.T) {
	logID := "did:dplaax:example:pipeline:alpha"
	st, err := mirrorstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	payloads := [][]byte{[]byte("r0"), []byte("r1"), []byte("r2")}
	head := chainOf(payloads...)
	cp := mkCP(logID, 3, head)

	acked, err := st.AppendVerified(logID, payloads, cp)
	if err != nil {
		t.Fatalf("AppendVerified: %v", err)
	}
	if acked != 3 {
		t.Fatalf("acked = %d, want 3", acked)
	}
	if n, err := st.AckedSize(logID); err != nil || n != 3 {
		t.Fatalf("AckedSize = %d, %v; want 3, nil", n, err)
	}
	if n, err := st.Size(logID); err != nil || n != 3 {
		t.Fatalf("Size = %d, %v; want 3, nil", n, err)
	}
	got, err := st.Checkpoint(logID)
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	assertCheckpointEqual(t, got, cp)

	prevHash := ""
	for i, p := range payloads {
		rec, err := st.Get(logID, uint64(i))
		if err != nil {
			t.Fatalf("Get(%d): %v", i, err)
		}
		if rec.Index != uint64(i) || string(rec.Payload) != string(p) {
			t.Fatalf("Get(%d) = %+v, want index %d payload %q", i, rec, i, p)
		}
		if want := mirrorstore.ChainHash(prevHash, p); rec.Hash != want {
			t.Fatalf("Get(%d).Hash = %q, want %q", i, rec.Hash, want)
		}
		prevHash = rec.Hash
	}
	if _, err := st.Get(logID, 3); err == nil {
		t.Fatal("Get(3): want out-of-range error, got nil")
	}
}

func TestReopen_PersistsAndContinuesChain(t *testing.T) {
	logID := "did:dplaax:example:pipeline:beta"
	root := t.TempDir()

	st1, err := mirrorstore.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	batch1 := [][]byte{[]byte("a0"), []byte("a1")}
	head1 := chainOf(batch1...)
	// ONE checkpoint value, reused for both the append call and the later
	// assertion — mkCP stamps time.Now(), so two separate calls straddling
	// a one-second boundary would make the timestamps differ and falsify
	// the equality check below.
	cp1Sent := mkCP(logID, 2, head1)
	if _, err := st1.AppendVerified(logID, batch1, cp1Sent); err != nil {
		t.Fatalf("AppendVerified batch1: %v", err)
	}

	st2, err := mirrorstore.Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if n, err := st2.AckedSize(logID); err != nil || n != 2 {
		t.Fatalf("reopened AckedSize = %d, %v; want 2, nil", n, err)
	}
	if rec, err := st2.Get(logID, 1); err != nil || rec.Hash != head1 {
		t.Fatalf("reopened Get(1) = %+v (err %v), want hash %q", rec, err, head1)
	}
	cp1, err := st2.Checkpoint(logID)
	if err != nil {
		t.Fatalf("reopened Checkpoint: %v", err)
	}
	assertCheckpointEqual(t, cp1, cp1Sent)

	// The chain must CONTINUE from the reopened tail, not restart.
	batch2 := [][]byte{[]byte("a2")}
	head2 := mirrorstore.ChainHash(head1, batch2[0])
	acked, err := st2.AppendVerified(logID, batch2, mkCP(logID, 3, head2))
	if err != nil {
		t.Fatalf("AppendVerified batch2: %v", err)
	}
	if acked != 3 {
		t.Fatalf("acked after batch2 = %d, want 3", acked)
	}
	if rec, err := st2.Get(logID, 2); err != nil || rec.Hash != head2 {
		t.Fatalf("Get(2) = %+v (err %v), want hash %q", rec, err, head2)
	}
}

func TestAppendVerified_IdempotentNoOp(t *testing.T) {
	logID := "did:dplaax:example:pipeline:gamma"
	st, err := mirrorstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	payloads := [][]byte{[]byte("x0"), []byte("x1")}
	head := chainOf(payloads...)
	cp := mkCP(logID, 2, head)
	if _, err := st.AppendVerified(logID, payloads, cp); err != nil {
		t.Fatalf("first append: %v", err)
	}

	// Exact resend of the same checkpoint, zero new records: idempotent no-op.
	acked, err := st.AppendVerified(logID, nil, cp)
	if err != nil {
		t.Fatalf("idempotent resend: %v", err)
	}
	if acked != 2 {
		t.Fatalf("acked after resend = %d, want 2", acked)
	}
	if n, _ := st.AckedSize(logID); n != 2 {
		t.Fatalf("AckedSize after resend = %d, want 2 (no duplication)", n)
	}
	if _, err := st.Get(logID, 2); err == nil {
		t.Fatal("Get(2) after idempotent resend: want error (no growth), got nil")
	}
}

func TestAppendVerified_MonotonicityIgnoresOlderValidCheckpoint(t *testing.T) {
	logID := "did:dplaax:example:pipeline:delta"
	st, err := mirrorstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	batch1 := [][]byte{[]byte("y0"), []byte("y1"), []byte("y2")}
	head1 := chainOf(batch1...)
	if _, err := st.AppendVerified(logID, batch1, mkCP(logID, 3, head1)); err != nil {
		t.Fatalf("batch1: %v", err)
	}
	batch2 := [][]byte{[]byte("y3"), []byte("y4")}
	head2 := mirrorstore.ChainHash(head1, batch2[0])
	head2 = mirrorstore.ChainHash(head2, batch2[1])
	newCP := mkCP(logID, 5, head2)
	if _, err := st.AppendVerified(logID, batch2, newCP); err != nil {
		t.Fatalf("batch2: %v", err)
	}

	// A VALID but OLDER checkpoint (correct head for its own smaller size)
	// arrives late: ignored, never regresses the head.
	staleButValid := mkCP(logID, 3, head1)
	acked, err := st.AppendVerified(logID, nil, staleButValid)
	if err != nil {
		t.Fatalf("stale-but-valid checkpoint: want no-op success, got err %v", err)
	}
	if acked != 5 {
		t.Fatalf("acked after stale-but-valid checkpoint = %d, want 5 (unregressed)", acked)
	}
	got, err := st.Checkpoint(logID)
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	assertCheckpointEqual(t, got, newCP)

	// A checkpoint claiming an OLDER size but with a WRONG head is a
	// genuine conflict, not a benign stale replay: reject loudly.
	conflicting := mkCP(logID, 3, "0000000000000000000000000000000000000000000000000000000000000000")
	if _, err := st.AppendVerified(logID, nil, conflicting); err == nil {
		t.Fatal("conflicting stale checkpoint: want error, got nil")
	}
	// The head must still be unregressed and unaffected by the rejected call.
	if n, _ := st.AckedSize(logID); n != 5 {
		t.Fatalf("AckedSize after rejected conflicting checkpoint = %d, want 5", n)
	}
}

func TestAppendVerified_SizeMismatch(t *testing.T) {
	logID := "did:dplaax:example:pipeline:epsilon"
	st, err := mirrorstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	payloads := [][]byte{[]byte("z0")}
	head := chainOf(payloads...)

	// Ahead-checkpoint: claims more records than the segment carries.
	if _, err := st.AppendVerified(logID, payloads, mkCP(logID, 5, head)); err == nil {
		t.Fatal("ahead checkpoint: want error, got nil")
	}
	// Gap: claims fewer than acked(0) + len(records).
	if _, err := st.AppendVerified(logID, payloads, mkCP(logID, 0, head)); err == nil {
		t.Fatal("gap checkpoint: want error, got nil")
	}
}

func TestAppendVerified_ChainMismatch(t *testing.T) {
	logID := "did:dplaax:example:pipeline:zeta"
	st, err := mirrorstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	payloads := [][]byte{[]byte("w0"), []byte("w1")}
	wrongHead := mirrorstore.ChainHash("", []byte("not-the-right-payload"))
	if _, err := st.AppendVerified(logID, payloads, mkCP(logID, 2, wrongHead)); err == nil {
		t.Fatal("wrong chain head: want error, got nil")
	}
	if n, _ := st.AckedSize(logID); n != 0 {
		t.Fatalf("AckedSize after rejected append = %d, want 0 (nothing partially committed)", n)
	}
}

func TestAppendVerified_OriginMismatch(t *testing.T) {
	logID := "did:dplaax:example:pipeline:eta"
	st, err := mirrorstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	payloads := [][]byte{[]byte("v0")}
	cp := mkCP("did:dplaax:example:pipeline:someone-else", 1, chainOf(payloads...))
	if _, err := st.AppendVerified(logID, payloads, cp); err == nil {
		t.Fatal("origin mismatch: want error, got nil")
	}
}

func TestAppendVerified_UnsignedCheckpointRejected(t *testing.T) {
	logID := "did:dplaax:example:pipeline:theta"
	st, err := mirrorstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	payloads := [][]byte{[]byte("u0")}
	cp := mkCP(logID, 1, chainOf(payloads...))
	cp.Signature = nil
	if _, err := st.AppendVerified(logID, payloads, cp); err == nil {
		t.Fatal("unsigned checkpoint: want error, got nil")
	}
	cp2 := mkCP(logID, 1, chainOf(payloads...))
	cp2.SignedBy = ""
	if _, err := st.AppendVerified(logID, payloads, cp2); err == nil {
		t.Fatal("empty SignedBy: want error, got nil")
	}
}

func TestAppendVerified_NilCheckpointRejected(t *testing.T) {
	logID := "did:dplaax:example:pipeline:iota"
	st, err := mirrorstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AppendVerified(logID, [][]byte{[]byte("t0")}, nil); err == nil {
		t.Fatal("nil checkpoint: want error, got nil")
	}
}

func TestMultipleLogsAreIndependent(t *testing.T) {
	root := t.TempDir()
	st, err := mirrorstore.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	logA := "did:dplaax:example:pipeline:multi-a"
	logB := "did:dplaax:example:pipeline:multi-b"
	pa := [][]byte{[]byte("a0")}
	pb := [][]byte{[]byte("b0"), []byte("b1")}
	if _, err := st.AppendVerified(logA, pa, mkCP(logA, 1, chainOf(pa...))); err != nil {
		t.Fatalf("append A: %v", err)
	}
	if _, err := st.AppendVerified(logB, pb, mkCP(logB, 2, chainOf(pb...))); err != nil {
		t.Fatalf("append B: %v", err)
	}
	if n, _ := st.AckedSize(logA); n != 1 {
		t.Fatalf("AckedSize(A) = %d, want 1", n)
	}
	if n, _ := st.AckedSize(logB); n != 2 {
		t.Fatalf("AckedSize(B) = %d, want 2", n)
	}
}
