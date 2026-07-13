// Package logcontract is the shared behavioral suite for tlog.Log
// implementations, split by what a family shares:
//
//   - Suite is the implementation-neutral contract every Log passes (dense
//     zero-based indexes, round-trips, record immutability, out-of-range
//     errors, size, concurrent-append density);
//   - ChainSuite additionally pins the hash-chain commitment formula
//     byte-exactly — the memlog/filelog family runs it; a tree log's
//     Record.Hash is the RFC 6962 leaf hash instead (merklelog pins that
//     with its own known-answer vectors).
//
// Implementation-specific behavior (restart replay, damage handling, signed
// checkpoints, proofs) stays in each package's own tests.
package logcontract

import (
	"context"
	"sync"
	"testing"

	"github.com/provin-line/oss/tlog"
)

// Vector pins the chain-hash formula BYTE-EXACTLY so external replay
// verification has exact bytes: hash = sha256( []byte(prevHashHex) ‖
// payload ), the genesis record using the EMPTY STRING as prevHashHex (not
// 32 zero bytes). Payloads "alpha", "beta", "" in order.
var Vector = []struct {
	Payload string
	Hash    string
}{
	{"alpha", "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8"},
	{"beta", "808831aee7e048720b620493c47e4cb1cd833f27e52d5f84e8adcb59827324ab"},
	{"", "1142f0a442cc8435feed59a3a49871b111aa551a77ccc142f5acec72913414d9"},
}

// ChainSuite pins the hash-chain commitment formula byte-exactly. Only the
// hash-chain family (memlog, filelog) runs it.
func ChainSuite(t *testing.T, newLog func(t *testing.T) tlog.Log) {
	t.Helper()
	ctx := context.Background()

	t.Run("chain vector", func(t *testing.T) {
		l := newLog(t)
		for i, v := range Vector {
			rec, err := l.Append(ctx, []byte(v.Payload))
			if err != nil {
				t.Fatalf("Append[%d]: %v", i, err)
			}
			if rec.Index != uint64(i) {
				t.Errorf("record %d: Index = %d", i, rec.Index)
			}
			if rec.Hash != v.Hash {
				t.Errorf("record %d: Hash = %s, want %s (the pinned chain formula)", i, rec.Hash, v.Hash)
			}
		}
	})
}

// Suite runs the implementation-neutral tlog.Log contract against a fresh
// implementation.
func Suite(t *testing.T, newLog func(t *testing.T) tlog.Log) {
	t.Helper()
	ctx := context.Background()

	t.Run("get round-trip and out-of-range", func(t *testing.T) {
		l := newLog(t)
		want, err := l.Append(ctx, []byte("payload-a"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := l.Get(ctx, 0)
		if err != nil {
			t.Fatalf("Get(0): %v", err)
		}
		if got.Index != want.Index || got.Hash != want.Hash || string(got.Payload) != "payload-a" {
			t.Errorf("Get(0) = %+v, want %+v", got, want)
		}
		if _, err := l.Get(ctx, 1); err == nil {
			t.Error("Get past the end: want error")
		}
	})

	t.Run("records are immutable", func(t *testing.T) {
		l := newLog(t)
		payload := []byte("mutable-caller-slice")
		rec, err := l.Append(ctx, payload)
		if err != nil {
			t.Fatal(err)
		}
		payload[0] = 'X'     // caller mutates its own slice after Append
		rec.Payload[0] = 'Y' // caller mutates the returned record
		reread, err := l.Get(ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		if string(reread.Payload) != "mutable-caller-slice" {
			t.Errorf("committed payload was mutated through a caller slice: %q", reread.Payload)
		}
	})

	t.Run("size", func(t *testing.T) {
		l := newLog(t)
		if n, err := l.Size(ctx); err != nil || n != 0 {
			t.Fatalf("empty Size = %d (err %v)", n, err)
		}
		for i := 0; i < 3; i++ {
			if _, err := l.Append(ctx, []byte{byte(i)}); err != nil {
				t.Fatal(err)
			}
		}
		if n, err := l.Size(ctx); err != nil || n != 3 {
			t.Fatalf("Size = %d (err %v), want 3", n, err)
		}
	})

	t.Run("concurrent append is dense", func(t *testing.T) {
		l := newLog(t)
		const writers = 8
		var wg sync.WaitGroup
		seen := make(chan uint64, writers)
		for i := 0; i < writers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				rec, err := l.Append(ctx, []byte{byte(i)})
				if err != nil {
					t.Errorf("Append: %v", err)
					return
				}
				seen <- rec.Index
			}(i)
		}
		wg.Wait()
		close(seen)
		indexes := map[uint64]bool{}
		for idx := range seen {
			if indexes[idx] {
				t.Errorf("index %d assigned twice", idx)
			}
			indexes[idx] = true
		}
		if len(indexes) != writers {
			t.Fatalf("%d distinct indexes, want %d", len(indexes), writers)
		}
		for i := uint64(0); i < writers; i++ {
			if !indexes[i] {
				t.Errorf("index %d missing — indexes must be dense", i)
			}
		}
	})
}
