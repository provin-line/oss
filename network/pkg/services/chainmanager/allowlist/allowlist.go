// Package allowlist matches a candidate DID against a trust pattern — the
// admission decision behind a pipeline's allow-list. It is a distinct
// responsibility from persistence (store): next-B's UpdateAllowList validation
// and the last-slice connection-flow admission both consume it.
//
// A pattern is a dplaax DID glob, segment-aware over the ":"-delimited identifier
// (D-c5): literal segments match exactly, "*" matches exactly one interior
// segment, and a trailing "*" matches zero-or-more remaining segments (so
// "did:dplaax:*:org:acme:*" matches the acme owner DID and everything beneath
// it). The did:dplaax method prefix must be literal. path.Match is deliberately
// not used: it treats ":" as an ordinary character, so its "*" would span
// segments.
//
// Matching is fail-closed on both sides. A malformed pattern is ErrInvalidPattern
// (never a silent allow). A candidate that does not parse as a dplaax DID returns
// (false, nil) — a syntactically invalid identifier is never trusted, not even
// against a broad wildcard like "did:dplaax:*". Default-distrust over a rule set
// (an empty set matches nothing) is the caller's concern: it iterates patterns
// and a zero-length iteration yields no match.
package allowlist

import (
	"errors"
	"strings"

	"github.com/provin-line/oss/did/dplaax"
)

// ErrInvalidPattern is returned for a structurally invalid allow-list pattern: a
// non-wildcard literal that is not a dplaax safe-segment (e.g. a "*" combined with
// other characters, an empty segment, a slash, an all-dots segment), a wildcard or
// non-literal in the did:dplaax method prefix, or a fixed (non-trailing-"*")
// pattern whose length does not match any dplaax DID arity (so no DID could ever
// match it — a dead rule).
var ErrInvalidPattern = errors.New("allowlist: invalid pattern")

// methodPrefix is the two literal leading segments every dplaax DID — and every
// valid pattern — must carry.
var methodPrefix = [...]string{"did", "dplaax"}

// Match reports whether candidateDID is admitted by pattern. A malformed pattern
// returns ErrInvalidPattern; a candidate that is not a parseable dplaax DID
// returns (false, nil) — fail-closed.
func Match(pattern, candidateDID string) (bool, error) {
	pSegs, err := parsePattern(pattern)
	if err != nil {
		return false, err
	}
	// Fail-closed candidate validation: an identifier that does not parse as a
	// dplaax DID is never trusted, even by a broad wildcard.
	if _, err := dplaax.Parse(candidateDID); err != nil {
		return false, nil
	}
	cSegs := strings.Split(candidateDID, ":")
	return matchSegments(pSegs, cSegs), nil
}

// ValidatePattern reports whether pattern is a structurally valid allow-list
// pattern, without a candidate to match against — the write-boundary counterpart
// to Match (e.g. for the operator's UpdateAllowList). It returns ErrInvalidPattern
// for exactly the structural faults Match rejects (it shares parsePattern), so the
// write-time validator and the match-time check can never disagree on validity,
// and nil for a usable pattern.
func ValidatePattern(pattern string) error {
	_, err := parsePattern(pattern)
	return err
}

// parsePattern splits and validates a pattern into its segments. The method
// prefix must be the literal "did:dplaax"; every remaining segment must be either
// a bare "*" or a dplaax safe-segment literal; and a fixed pattern (one with no
// trailing "*") must have a length that matches a dplaax DID arity, so it can
// actually name a DID.
func parsePattern(pattern string) ([]string, error) {
	segs := strings.Split(pattern, ":")
	// Need the method prefix plus at least one segment to match against.
	if len(segs) < len(methodPrefix)+1 {
		return nil, ErrInvalidPattern
	}
	for i, want := range methodPrefix {
		if segs[i] != want {
			return nil, ErrInvalidPattern
		}
	}
	for _, seg := range segs[len(methodPrefix):] {
		if seg == "*" {
			continue
		}
		// A non-wildcard literal must be a dplaax safe-segment: anything else
		// (empty, a "*" mid-segment, a slash, an all-dots segment) can never appear
		// in a real candidate, so it would be a silently dead rule. IsSafeSegment
		// subsumes the empty and contains-"*" checks.
		if !dplaax.IsSafeSegment(seg) {
			return nil, ErrInvalidPattern
		}
	}
	// A pattern with no trailing "*" matches only candidates of exactly its own
	// length, so it must align to a valid dplaax DID arity — otherwise no DID can
	// ever match it and storing it as a rule would silently deny the intended
	// subscriber (a dead rule). A trailing "*" is open-ended (it absorbs the
	// remainder), so any length >= the method prefix + one segment is fine.
	if segs[len(segs)-1] != "*" && !validDIDArity(len(segs)-len(methodPrefix)) {
		return nil, ErrInvalidPattern
	}
	return segs, nil
}

// validDIDArity reports whether n post-method segments form one of the dplaax
// DID shapes: owner (registry/accountType/accountID = 3), pipeline (+pipeline/id
// = 5), or process (+process/id = 7).
func validDIDArity(n int) bool {
	return n == 3 || n == 5 || n == 7
}

// matchSegments walks pattern and candidate segments in lockstep. A trailing "*"
// consumes the remaining candidate segments (zero or more); an interior "*"
// consumes exactly one; a literal must equal the candidate segment. The match
// succeeds only when both sequences are fully consumed.
func matchSegments(pSegs, cSegs []string) bool {
	j := 0
	for i, p := range pSegs {
		if p == "*" && i == len(pSegs)-1 {
			return true // trailing "*": matches cSegs[j:], zero or more
		}
		if j >= len(cSegs) {
			return false // pattern still has literal/single-* segments, candidate exhausted
		}
		if p == "*" || p == cSegs[j] {
			j++
			continue
		}
		return false
	}
	return j == len(cSegs)
}
