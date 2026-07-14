package wireauth_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

// Concurrent hammer: many goroutines racing Use for the same (signer, nonce)
// must yield exactly one success; distinct signers reusing a nonce never
// collide. Run under -race, this turns the mutex's "correct by inspection" into
// verified behavior for the one stateful component on the internet-facing path.
func TestMemoryNonceStore_ConcurrentUse(t *testing.T) {
	store := wireauth.NewMemoryNonceStore()
	const goroutines = 64

	t.Run("same signer+nonce: exactly one success", func(t *testing.T) {
		var success, replay int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				switch err := store.Use("did:sig", "n"); {
				case err == nil:
					atomic.AddInt64(&success, 1)
				case errors.Is(err, wireauth.ErrReplay):
					atomic.AddInt64(&replay, 1)
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if success != 1 || replay != goroutines-1 {
			t.Errorf("success=%d replay=%d, want 1 and %d", success, replay, goroutines-1)
		}
	})

	t.Run("distinct signers, same nonce: all succeed", func(t *testing.T) {
		s2 := wireauth.NewMemoryNonceStore()
		var success int64
		var wg sync.WaitGroup
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				if err := s2.Use(string(rune('A'+id%goroutines))+":signer", "shared"); err == nil {
					atomic.AddInt64(&success, 1)
				}
			}(i)
		}
		wg.Wait()
		if success != goroutines {
			t.Errorf("success=%d, want %d (distinct signers must not collide)", success, goroutines)
		}
	})
}

// The store must not retain nonces forever: entries older than the retention
// (the acceptance window's own reach, past which a proof can never be
// re-presented) are swept, and their signer bucket collapses when emptied —
// otherwise a self-credentialed peer OOMs the node with unique nonces.
func TestMemoryNonceStore_EvictsPastRetention(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	const retention = 65 * time.Second // DefaultAcceptanceWindow(): 60s past + 5s future
	store := wireauth.NewMemoryNonceStore(
		wireauth.WithNonceRetention(retention),
		wireauth.WithNonceClock(func() time.Time { return clock() }),
	)

	if err := store.Use("did:sig", "old"); err != nil {
		t.Fatalf("first Use: %v", err)
	}
	// Within retention (strict): the entry is retained, so a replay is caught.
	now = now.Add(retention)
	if err := store.Use("did:sig", "mid"); err != nil {
		t.Fatalf("Use at boundary: %v", err)
	}
	if err := store.Use("did:sig", "old"); !errors.Is(err, wireauth.ErrReplay) {
		t.Fatalf(`replay of "old" at age==retention: want ErrReplay, got %v`, err)
	}
	// Past retention (strict >): "old" (age 2*retention) and "mid" are swept, so
	// re-presenting them is NOT a replay — and the swept signer bucket is gone.
	now = now.Add(retention + time.Second)
	if err := store.Use("did:sig", "old"); err != nil {
		t.Errorf(`"old" past retention: want accepted (swept), got %v`, err)
	}
	if n := wireauth.NonceEntryCount(store); n > 2 {
		t.Errorf("entry count = %d after sweep, want the stale bucket collapsed (<=2)", n)
	}
}

// DefaultAcceptanceWindow's retention is exactly MaxPast+MaxFuture — the single
// authoritative value the composition root uses for both the verifier window
// and the nonce store, so they cannot drift.
func TestDefaultAcceptanceWindow_Retention(t *testing.T) {
	w := wireauth.DefaultAcceptanceWindow()
	if got, want := w.NonceRetention(), w.MaxPast+w.MaxFuture; got != want {
		t.Errorf("NonceRetention() = %v, want MaxPast+MaxFuture = %v", got, want)
	}
	if w.MaxPast != 60*time.Second || w.MaxFuture != 5*time.Second {
		t.Errorf("DefaultAcceptanceWindow = %+v, want {60s, 5s}", w)
	}
}
