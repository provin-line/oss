package httpserve

import "time"

// SetBodyStallTimeout sets the body stall timeout for one test.
func SetBodyStallTimeout(d time.Duration) (restore func()) {
	old := bodyStallTimeout
	bodyStallTimeout = d
	return func() { bodyStallTimeout = old }
}
