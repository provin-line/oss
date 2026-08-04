package cache

import "time"

// SetNowForTest substitutes the clock so a test can cross TTL boundaries
// without sleeping. Test-only.
func SetNowForTest(r *Resolver, now func() time.Time) {
	r.now = now
}
