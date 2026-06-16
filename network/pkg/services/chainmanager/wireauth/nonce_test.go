package wireauth_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

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
