package wireauth

import "sync"

// NonceStore records which nonces a signer has already spent, for replay
// defense. Use is the atomic check-and-set: it records (signerDID, nonce) and
// returns ErrReplay if that pair was already present. Keying per signer is
// deliberate (D-w10) — a nonce is meaningful relative to its signer, so two
// distinct signers reusing the same nonce must not collide.
type NonceStore interface {
	Use(signerDID, nonce string) error
}

// memNonceStore is the in-memory NonceStore — the accepted PoC posture (a
// restart drops all records; the verifier's restart epoch barrier closes the
// replay window that opens). A persistent store is a documented follow-up.
type memNonceStore struct {
	mu   sync.Mutex
	seen map[string]map[string]struct{}
}

// NewMemoryNonceStore returns an empty in-memory NonceStore.
func NewMemoryNonceStore() NonceStore {
	return &memNonceStore{seen: make(map[string]map[string]struct{})}
}

func (s *memNonceStore) Use(signerDID, nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	bySigner := s.seen[signerDID]
	if bySigner == nil {
		bySigner = make(map[string]struct{})
		s.seen[signerDID] = bySigner
	}
	if _, ok := bySigner[nonce]; ok {
		return ErrReplay
	}
	bySigner[nonce] = struct{}{}
	return nil
}
