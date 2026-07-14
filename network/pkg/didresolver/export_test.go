package didresolver

import "time"

// SetResolutionConcurrencyForTest resizes the resolution semaphore so a test can
// saturate it without launching maxConcurrentResolutions goroutines. Test-only.
func SetResolutionConcurrencyForTest(r *Resolver, n int) {
	r.sem = make(chan struct{}, n)
}

// SetResolutionTimeoutForTest shortens the per-resolve deadline so a stalling
// server can be observed to time out quickly. Test-only.
func SetResolutionTimeoutForTest(r *Resolver, d time.Duration) {
	r.timeout = d
}
