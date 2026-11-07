package httpserve

import "time"

// SetBodyStallTimeout sets the body stall timeout for one test.
func SetBodyStallTimeout(d time.Duration) (restore func()) {
	old := bodyStallTimeout
	bodyStallTimeout = d
	return func() { bodyStallTimeout = old }
}

// SetBodyReadTimeout sets the whole-body read limit for one test.
func SetBodyReadTimeout(d time.Duration) (restore func()) {
	old := bodyReadTimeout
	bodyReadTimeout = d
	return func() { bodyReadTimeout = old }
}
