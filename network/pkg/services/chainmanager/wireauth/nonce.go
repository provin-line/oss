package wireauth

import (
	"sync"
	"time"
)

// NonceStore records which nonces a signer has already spent, for replay
// defense. Use is the atomic check-and-set: it records (signerDID, nonce) and
// returns ErrReplay if that pair was already present. Keying per signer is
// deliberate (D-w10) — a nonce is meaningful relative to its signer, so two
// distinct signers reusing the same nonce must not collide.
type NonceStore interface {
	Use(signerDID, nonce string) error
}

// NonceOption configures a memory NonceStore at construction.
type NonceOption func(*memNonceStore)

// WithNonceRetention sets how long a recorded nonce is kept before it is
// eligible for eviction. It MUST be at least the verifier's acceptance-window
// reach (MaxPast + MaxFuture): a proof can be presented until issuedAt+MaxPast,
// and issuedAt may be as late as now+MaxFuture, so an entry younger than the
// window could still be replayed and must be retained. The default is
// DefaultAcceptanceWindow().NonceRetention(); a deployment using a custom
// window must pass the matching retention here so the two cannot drift.
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
// recorded nonce carries its insertion time, and entries older than retention
// (past which the acceptance window can never re-admit a proof) are swept.
// The sweep is global (all signers) and throttled to at most once per
// retention interval, so a flood of unique nonces from many signers is
// amortized O(1) per Use rather than an O(n) scan on every call.
type memNonceStore struct {
	mu   sync.Mutex
	seen map[string]map[string]time.Time // signerDID -> nonce -> inserted-at

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

func (s *memNonceStore) Use(signerDID, nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	s.sweepLocked(now)

	bySigner := s.seen[signerDID]
	if bySigner == nil {
		bySigner = make(map[string]time.Time)
		s.seen[signerDID] = bySigner
	}
	if _, ok := bySigner[nonce]; ok {
		return ErrReplay
	}
	bySigner[nonce] = now
	return nil
}

// sweepLocked removes entries whose age STRICTLY exceeds retention and drops any
// signer bucket left empty. It runs at most once per retention interval (a proof
// cannot survive a full retention anyway), keeping Use amortized cheap. Strict
// ">" mirrors the verifier's strict window comparison: an entry at exactly
// age==retention is still within reach and must be kept.
func (s *memNonceStore) sweepLocked(now time.Time) {
	if !s.lastSweep.IsZero() && now.Sub(s.lastSweep) < s.retention {
		return
	}
	s.lastSweep = now
	cutoff := now.Add(-s.retention)
	for signer, byNonce := range s.seen {
		for nonce, inserted := range byNonce {
			if inserted.Before(cutoff) { // age > retention (strict)
				delete(byNonce, nonce)
			}
		}
		if len(byNonce) == 0 {
			delete(s.seen, signer)
		}
	}
}
