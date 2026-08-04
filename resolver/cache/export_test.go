package cache

import "time"

// SetNowForTest substitutes the clock so a test can cross TTL boundaries
// without sleeping. Test-only.
func SetNowForTest(r *Resolver, now func() time.Time) {
	r.now = now
}

// HitParseSlotsForTest exposes the hit-parse bound so a test can pin it to the
// production resolver's admission capacity. Test-only.
func HitParseSlotsForTest(r *Resolver) int {
	return cap(r.parseSem)
}
