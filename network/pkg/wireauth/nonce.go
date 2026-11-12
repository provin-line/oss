package wireauth

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// NonceStore records which nonces a signer has already spent, for replay
// defense. Use is the atomic check-and-set: it records (signerDID, nonce) and
// returns ErrReplay if that pair was already present. Keying per signer is
// deliberate (D-w10) — a nonce is meaningful relative to its signer, so two
// distinct signers reusing the same nonce must not collide.
//
// expiresAt is when the proof that spends the nonce stops being acceptable.
// A store takes no pair after its expiry: Use then returns ErrExpired and
// records nothing, decided together with the check-and-set, by the store's
// own clock. That is what lets a store forget a pair after its expiry.
// ctx is the request's, for a store that does I/O. Any error other than ErrReplay and ErrExpired is the store's own
// failure; the verifier refuses the proof with it, as it cannot tell whether
// the nonce was spent.
type NonceStore interface {
	Use(ctx context.Context, signerDID, nonce string, expiresAt time.Time) error
}

// NonceOption configures a memory NonceStore at construction.
type NonceOption func(*memNonceStore)

// WithNonceRetention sets the least time a recorded nonce is kept after its
// insertion, and how often the store sweeps (at most once per retention). A
// nonce is kept until its expiry whatever the retention, and the store takes
// no nonce after its expiry, so the retention bounds memory, not safety. The
// default is DefaultAcceptanceWindow().NonceRetention().
func WithNonceRetention(d time.Duration) NonceOption {
	return func(s *memNonceStore) {
		if d > 0 {
			s.retention = d
		}
	}
}

// WithNonceClock overrides the store's clock (test seam; default time.Now).
func WithNonceClock(now func() time.Time) NonceOption {
	return func(s *memNonceStore) {
		if now != nil {
			s.now = now
		}
	}
}

// memNonceStore is the in-memory NonceStore — the accepted PoC posture (a
// restart drops all records; the verifier's restart epoch barrier closes the
// replay window that opens). A persistent store is a documented follow-up.
//
// It self-prunes so it cannot grow without bound within a single run: each
// recorded nonce carries the time until which it is kept, the later of its
// insertion plus retention and its expiresAt, and entries past that are
// swept. The
// sweep is global (all signers) and throttled to at most once per retention
// interval, so a flood of unique nonces from many signers is amortized O(1)
// per Use rather than an O(n) scan on every call.
type memNonceStore struct {
	mu   sync.Mutex
	seen map[string]map[string]time.Time // signerDID -> nonce -> kept until

	retention time.Duration
	now       func() time.Time
	lastSweep time.Time
}

// NewMemoryNonceStore returns an in-memory NonceStore. Without options it uses
// the default acceptance-window retention and the real clock; see
// WithNonceRetention / WithNonceClock.
func NewMemoryNonceStore(opts ...NonceOption) NonceStore {
	s := &memNonceStore{
		seen:      make(map[string]map[string]time.Time),
		retention: DefaultAcceptanceWindow().NonceRetention(),
		now:       time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Use ignores ctx: the memory store does no I/O.
func (s *memNonceStore) Use(_ context.Context, signerDID, nonce string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if now.After(expiresAt) {
		return fmt.Errorf("%w: its nonce reached the store after the proof's expiry %s", ErrExpired, expiresAt.UTC().Format(time.RFC3339))
	}
	s.sweepLocked(now)

	bySigner := s.seen[signerDID]
	if bySigner == nil {
		bySigner = make(map[string]time.Time)
		s.seen[signerDID] = bySigner
	}
	if _, ok := bySigner[nonce]; ok {
		return ErrReplay
	}
	keep := now.Add(s.retention)
	if expiresAt.After(keep) {
		keep = expiresAt
	}
	bySigner[nonce] = keep
	return nil
}

// sweepLocked removes entries STRICTLY past the time they are kept until and
// drops any signer bucket left empty. It runs at most once per retention
// interval, keeping Use amortized cheap. Strict ">" mirrors the verifier's
// strict window comparison: an entry at exactly its keep time is still within
// reach and must be kept.
func (s *memNonceStore) sweepLocked(now time.Time) {
	if !s.lastSweep.IsZero() && now.Sub(s.lastSweep) < s.retention {
		return
	}
	s.lastSweep = now
	for signer, byNonce := range s.seen {
		for nonce, keep := range byNonce {
			if now.After(keep) {
				delete(byNonce, nonce)
			}
		}
		if len(byNonce) == 0 {
			delete(s.seen, signer)
		}
	}
}
