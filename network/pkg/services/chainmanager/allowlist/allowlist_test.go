package allowlist

import (
	"errors"
	"testing"
)

// Match is segment-aware over the ":"-delimited dplaax DID (D-c5): literal
// segments match exactly, "*" matches exactly one interior segment, a trailing
// "*" matches zero-or-more remaining segments, and the did:dplaax method prefix
// must be literal. It is fail-closed on both sides — a malformed pattern is an
// error, and a candidate that does not parse as a dplaax DID never matches, even
// a broad wildcard.

func TestMatch_Bool(t *testing.T) {
	cases := []struct {
		name      string
		pattern   string
		candidate string
		want      bool
	}{
		{"exact match", "did:dplaax:reg:org:acme", "did:dplaax:reg:org:acme", true},
		{"exact non-match", "did:dplaax:reg:org:acme", "did:dplaax:reg:org:other", false},

		{"interior star one segment", "did:dplaax:*:org:acme", "did:dplaax:reg:org:acme", true},
		{"interior star does not span colon", "did:dplaax:*:org:acme", "did:dplaax:reg:sub:org:acme", false},

		{"trailing star zero remainder", "did:dplaax:*:org:acme:*", "did:dplaax:reg:org:acme", true},
		{"trailing star two remainder", "did:dplaax:*:org:acme:*", "did:dplaax:reg:org:acme:pipeline:p1", true},
		{"trailing star bare prefix", "did:dplaax:*", "did:dplaax:reg:org:acme", true},
		{"trailing star one remainder", "did:dplaax:reg:org:acme:*", "did:dplaax:reg:org:acme:pipeline", true},
		{"trailing star matches owner and below", "did:dplaax:reg:org:acme:*", "did:dplaax:reg:org:acme", true},

		// Pipeline arity (7 segments): a fixed pattern matches only same-arity
		// candidates; wildcards may stand in the pipeline/process structural
		// positions.
		{"pipeline-arity all wildcards", "did:dplaax:*:*:*:*:*", "did:dplaax:reg:org:acme:pipeline:p1", true},
		{"pipeline-arity exact", "did:dplaax:reg:org:acme:pipeline:p1", "did:dplaax:reg:org:acme:pipeline:p1", true},
		{"process-arity exact", "did:dplaax:reg:org:acme:pipeline:p1:process:x", "did:dplaax:reg:org:acme:pipeline:p1:process:x", true},

		{"no trailing star, candidate longer", "did:dplaax:reg:org:acme", "did:dplaax:reg:org:acme:pipeline:p1", false},

		// Fail-closed: a candidate that does not parse as a dplaax DID never
		// matches, not even a broad wildcard.
		{"malformed candidate vs broad wildcard", "did:dplaax:*", "not-a-did", false},
		{"empty candidate vs broad wildcard", "did:dplaax:*", "", false},
		{"non-dplaax candidate vs broad wildcard", "did:dplaax:*", "did:web:reg:org:acme", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Match(c.pattern, c.candidate)
			if err != nil {
				t.Fatalf("Match(%q, %q) returned error: %v", c.pattern, c.candidate, err)
			}
			if got != c.want {
				t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.candidate, got, c.want)
			}
		})
	}
}

func TestMatch_InvalidPattern(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
	}{
		{"star mid-segment", "did:dplaax:reg:org:ac*me"},
		{"empty segment", "did:dplaax::org:acme"},
		{"wildcard method", "did:*:reg:org:acme"},
		{"wildcard did prefix", "*:dplaax:reg:org:acme"},
		{"wrong method literal", "did:web:reg:org:acme"},
		{"too short, prefix only", "did:dplaax"},
		{"empty pattern", ""},
		{"trailing colon empty segment", "did:dplaax:reg:"},

		// Dead fixed (non-trailing-*) patterns: a pattern with no trailing
		// wildcard must have a valid DID arity (owner=5 / pipeline=7 / process=9
		// segments), else no dplaax DID can ever match it and storing it as a rule
		// would silently deny the intended subscriber (Codex P2). The minimum DID
		// is the 5-segment owner.
		{"fixed too short, registry only", "did:dplaax:reg"},
		{"fixed too short, no accountID", "did:dplaax:reg:org"},
		{"fixed between owner and pipeline arity", "did:dplaax:reg:org:acme:pipeline"},
		{"fixed interior wildcards, dead arity", "did:dplaax:*:*:*:extra"},
		{"fixed between pipeline and process arity", "did:dplaax:reg:org:acme:pipeline:p1:process"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// A malformed pattern is an error regardless of the candidate; the
			// candidate here is a valid dplaax DID so only the pattern is at fault.
			got, err := Match(c.pattern, "did:dplaax:reg:org:acme")
			if !errors.Is(err, ErrInvalidPattern) {
				t.Fatalf("Match(%q, ...) error = %v, want ErrInvalidPattern", c.pattern, err)
			}
			if got {
				t.Errorf("Match(%q, ...) = true on a malformed pattern, want false", c.pattern)
			}
		})
	}
}
