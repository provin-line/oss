package wireauth

// NonceEntryCount reports the total number of (signer, nonce) records currently
// held by an in-memory NonceStore — a test seam for asserting that eviction
// bounds growth. It returns 0 for any other NonceStore implementation.
func NonceEntryCount(s NonceStore) int {
	m, ok := s.(*memNonceStore)
	if !ok {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, byNonce := range m.seen {
		n += len(byNonce)
	}
	return n
}
