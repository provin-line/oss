package handler

import (
	"errors"
	"fmt"
	"time"
)

// errMalformedIssuedAt marks an AuthProof.issued_at that is not a canonical
// RFC 3339 UTC second-precision string. The handler maps it to InvalidArgument.
var errMalformedIssuedAt = errors.New("chainmanager: malformed issued_at")

// parseIssuedAt strictly decodes the wire issued_at string (slice-11 D-p5). It
// accepts ONLY the canonical RFC 3339 UTC second-precision form (the exact form
// wireauth signs over: issuedAt.UTC().Format(time.RFC3339)) and rejects anything
// else — fractional seconds, a non-Z offset (including +00:00), or any
// non-canonical string — BEFORE the proof reaches wireauth.Verify, so the
// transport value can never diverge from the signed second-precision string.
func parseIssuedAt(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %q: %v", errMalformedIssuedAt, s, err)
	}
	// Canonical iff re-rendering the parsed instant in UTC reproduces the input:
	// this rejects sub-second precision (Format drops it) and any non-Z offset
	// (Format emits Z), in one comparison.
	if s != t.UTC().Format(time.RFC3339) {
		return time.Time{}, fmt.Errorf("%w: %q is not canonical UTC second-precision RFC 3339", errMalformedIssuedAt, s)
	}
	return t.UTC(), nil
}
