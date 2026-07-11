package chainmanager

import (
	"errors"
	"testing"
)

// A realistic dotted-registry DID (poc.dplaax.dev), as used throughout the
// e2e capstones — the case D-2's prefix scheme exists to keep collision-free.
const dottedPipelineDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pipe"

func TestSubjectForMode_Inline(t *testing.T) {
	got, err := subjectForMode(dottedPipelineDID, "inline")
	if err != nil {
		t.Fatalf("subjectForMode: %v", err)
	}
	if got != dottedPipelineDID {
		t.Errorf("inline subject = %q, want the plain publisher DID %q", got, dottedPipelineDID)
	}
}

func TestSubjectForMode_ByReference(t *testing.T) {
	got, err := subjectForMode(dottedPipelineDID, "by-reference")
	if err != nil {
		t.Fatalf("subjectForMode: %v", err)
	}
	want := "byref." + dottedPipelineDID
	if got != want {
		t.Errorf("by-reference subject = %q, want %q", got, want)
	}
}

// The prefix scheme must never collide with a plain-mode subject for any
// dotted DID — a suffix scheme could (a DID ending in a ".byref" segment),
// prefix cannot (the first token is either "byref" or "did:...").
func TestSubjectForMode_PrefixNeverCollidesWithPlain(t *testing.T) {
	inline, err := subjectForMode(dottedPipelineDID, "inline")
	if err != nil {
		t.Fatalf("subjectForMode inline: %v", err)
	}
	byref, err := subjectForMode(dottedPipelineDID, "by-reference")
	if err != nil {
		t.Fatalf("subjectForMode by-reference: %v", err)
	}
	if inline == byref {
		t.Fatalf("inline and by-reference subjects collide: %q", inline)
	}
}

func TestSubjectForMode_UnsafeSubject(t *testing.T) {
	cases := map[string]string{
		"whitespace":   "did:dplaax:reg:org:acme pipeline",
		"tab":          "did:dplaax:reg:org:acme\tpipeline",
		"wildcard *":   "did:dplaax:reg:org:acme:*",
		"wildcard >":   "did:dplaax:reg:org:acme:>",
		"leading dot":  ".did:dplaax:reg:org:acme",
		"double dot":   "did:dplaax:reg..org:acme",
		"trailing dot": "did:dplaax:reg:org:acme.",
		"empty":        "",
	}
	for name, did := range cases {
		t.Run(name, func(t *testing.T) {
			for _, mode := range []string{"inline", "by-reference"} {
				if _, err := subjectForMode(did, mode); !errors.Is(err, ErrUnsafeSubject) {
					t.Errorf("mode=%q subjectForMode(%q) err = %v, want ErrUnsafeSubject", mode, did, err)
				}
			}
		})
	}
}

func TestSubjectForMode_SafeDottedDIDNotRejected(t *testing.T) {
	// A well-formed dotted registry DID must NOT trip the unsafe-subject
	// validator (dots alone are fine; only EMPTY dot-tokens are rejected).
	if _, err := subjectForMode(dottedPipelineDID, "inline"); err != nil {
		t.Errorf("well-formed dotted DID rejected: %v", err)
	}
}
