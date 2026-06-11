package did_test

import (
	"testing"

	"github.com/provin-line/oss/did"
)

func TestMethodOf(t *testing.T) {
	valid := []struct {
		in   string
		want string
	}{
		{"did:dplaax:poc.dplaax.io:org:acme", "dplaax"},
		{"did:dplaax:poc.dplaax.io:org:acme:pipeline:p:process:x", "dplaax"},
		{"did:web:example.com", "web"},
		{"did:webvh:QmHash:example.com", "webvh"},
		{"did:key:z6Mk", "key"},
		{"did:1abc:x", "1abc"},            // digit-first method name is legal (1*method-char)
		{"did:example:abc%41", "example"}, // pct-encoded idchar in msid is legal
		{"did:example::abc", "example"},   // internal empty segment is legal (*( *idchar ":" ) 1*idchar)
	}
	for _, tt := range valid {
		got, err := did.MethodOf(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("MethodOf(%q) = (%q, %v), want (%q, nil)", tt.in, got, err, tt.want)
		}
	}

	// W3C DID Core §3.1: method-name = 1*method-char, method-char = %x61-7A / DIGIT.
	// Everything else fails closed.
	invalid := []struct {
		in   string
		name string
	}{
		{"", "empty"},
		{"did:", "no method"},
		{"did:dplaax", "no method-specific id"},
		{"did:dplaax:", "empty method-specific id"},
		{"did:DPLAAX:x", "uppercase method (DID Core restricts to [a-z0-9])"},
		{"did:dpl-aax:x", "hyphen in method name"},
		{"DID:dplaax:x", "uppercase scheme"},
		{"urn:dplaax:x", "not a did scheme"},
		{"did::x", "empty method name"},
		{"did:dplaax:x:", "trailing colon (method-specific-id must end with an idchar)"},
		{"did:dplaax::", "msid of a lone colon"},
	}
	for _, tt := range invalid {
		if _, err := did.MethodOf(tt.in); err == nil {
			t.Errorf("MethodOf(%q) = nil error, want rejection: %s", tt.in, tt.name)
		}
	}
}
