package memlog_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"

	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/tlog/memlog"
)

// chainHash mirrors the documented commitment: sha256 over (prev.Hash ‖ payload),
// the genesis record chaining from the empty hash (tlog.Record.Hash contract).
func chainHash(prev string, payload []byte) string {
	h := sha256.Sum256(append([]byte(prev), payload...))
	return hex.EncodeToString(h[:])
}

func TestLog_ImplementsTlogLog(t *testing.T) {
	var _ tlog.Log = memlog.New()
}

func TestAppend_IndexAndChainHash(t *testing.T) {
	ctx := context.Background()
	l := memlog.New()

	p0 := []byte("first")
	p1 := []byte("second")

	r0, err := l.Append(ctx, p0)
	if err != nil {
		t.Fatalf("append 0: %v", err)
	}
	if r0.Index != 0 {
		t.Fatalf("index 0: got %d", r0.Index)
	}
	want0 := chainHash("", p0)
	if r0.Hash != want0 {
		t.Fatalf("genesis hash: got %s want %s", r0.Hash, want0)
	}

	r1, err := l.Append(ctx, p1)
	if err != nil {
		t.Fatalf("append 1: %v", err)
	}
	if r1.Index != 1 {
		t.Fatalf("index 1: got %d", r1.Index)
	}
	want1 := chainHash(want0, p1)
	if r1.Hash != want1 {
		t.Fatalf("chain hash: got %s want %s", r1.Hash, want1)
	}
}

func TestGet_RoundTripAndOutOfRange(t *testing.T) {
	ctx := context.Background()
	l := memlog.New()

	if _, err := l.Get(ctx, 0); err == nil {
		t.Fatal("get on empty log: want error, got nil")
	}

	payload := []byte("payload")
	if _, err := l.Append(ctx, payload); err != nil {
		t.Fatalf("append: %v", err)
	}

	got, err := l.Get(ctx, 0)
	if err != nil {
		t.Fatalf("get 0: %v", err)
	}
	if string(got.Payload) != "payload" {
		t.Fatalf("payload: got %q", got.Payload)
	}

	if _, err := l.Get(ctx, 5); err == nil {
		t.Fatal("get out of range: want error, got nil")
	}
}

// TestReturnedRecordsAreImmutable asserts the tlog.Log immutability contract: a
// caller mutating a record returned by Append or Get must NOT corrupt the committed
// record (independently flagged by Claude + Codex review → convergent must-fix).
func TestReturnedRecordsAreImmutable(t *testing.T) {
	ctx := context.Background()
	l := memlog.New()

	r, err := l.Append(ctx, []byte("original"))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	wantHash := r.Hash
	// Mutate the Append return.
	r.Payload[0] = 'X'
	r.Hash = "tampered"
	r.Index = 999

	got, err := l.Get(ctx, 0)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got.Payload) != "original" {
		t.Fatalf("payload corrupted via Append return: got %q", got.Payload)
	}
	if got.Hash != wantHash {
		t.Fatalf("hash corrupted via Append return: got %q want %q", got.Hash, wantHash)
	}
	if got.Index != 0 {
		t.Fatalf("index corrupted via Append return: got %d want 0", got.Index)
	}

	// Mutate the Get return; a second Get must be unaffected.
	got.Payload[0] = 'Y'
	got.Hash = "tampered2"
	again, err := l.Get(ctx, 0)
	if err != nil {
		t.Fatalf("get again: %v", err)
	}
	if string(again.Payload) != "original" || again.Hash != wantHash {
		t.Fatalf("record corrupted via Get return: payload=%q hash=%q", again.Payload, again.Hash)
	}
}

func TestSize(t *testing.T) {
	ctx := context.Background()
	l := memlog.New()

	n, err := l.Size(ctx)
	if err != nil {
		t.Fatalf("size: %v", err)
	}
	if n != 0 {
		t.Fatalf("empty size: got %d want 0", n)
	}

	for i := 0; i < 3; i++ {
		if _, err := l.Append(ctx, []byte{byte(i)}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	n, err = l.Size(ctx)
	if err != nil {
		t.Fatalf("size: %v", err)
	}
	if n != 3 {
		t.Fatalf("size: got %d want 3", n)
	}
}

func TestCheckpoint_ReturnsErrUnsignedLog(t *testing.T) {
	ctx := context.Background()
	l := memlog.New()
	if _, err := l.Append(ctx, []byte("x")); err != nil {
		t.Fatalf("append: %v", err)
	}

	_, err := l.Checkpoint(ctx)
	if !errors.Is(err, memlog.ErrUnsignedLog) {
		t.Fatalf("checkpoint: want ErrUnsignedLog, got %v", err)
	}
}

// TestTamperEvidence demonstrates the chain property: a payload change at index k
// diverges the commitment at k and every index after it — any retroactive
// modification is detectable by chain replay (tlog.Record.Hash contract).
func TestTamperEvidence(t *testing.T) {
	ctx := context.Background()
	build := func(third []byte) []string {
		l := memlog.New()
		hashes := make([]string, 0, 3)
		for _, p := range [][]byte{[]byte("a"), []byte("b"), third} {
			r, err := l.Append(ctx, p)
			if err != nil {
				t.Fatalf("append: %v", err)
			}
			hashes = append(hashes, r.Hash)
		}
		return hashes
	}

	clean := build([]byte("c"))
	tampered := build([]byte("c-TAMPERED"))

	if clean[0] != tampered[0] || clean[1] != tampered[1] {
		t.Fatal("prefix before the tampered index must be identical")
	}
	if clean[2] == tampered[2] {
		t.Fatal("tampered index must diverge")
	}
}

// TestConcurrentAppend asserts Append is safe under concurrency: N parallel
// appends yield a contiguous 0..N-1 index set with no gaps or duplicates.
func TestConcurrentAppend(t *testing.T) {
	ctx := context.Background()
	l := memlog.New()

	const n = 64
	var wg sync.WaitGroup
	seen := make([]int64, n)
	idxCh := make(chan uint64, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := l.Append(ctx, []byte{byte(i)})
			if err != nil {
				t.Errorf("append: %v", err)
				return
			}
			idxCh <- r.Index
		}(i)
	}
	wg.Wait()
	close(idxCh)

	for idx := range idxCh {
		if idx >= n {
			t.Fatalf("index out of expected range: %d", idx)
		}
		seen[idx]++
	}
	for i, c := range seen {
		if c != 1 {
			t.Fatalf("index %d appeared %d times (want exactly 1)", i, c)
		}
	}

	size, err := l.Size(ctx)
	if err != nil {
		t.Fatalf("size: %v", err)
	}
	if size != n {
		t.Fatalf("size: got %d want %d", size, n)
	}
}
