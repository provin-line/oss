package vc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/provin-line/oss/canon/jcs"
)

// The stored-address paths (body hash, wire form, source-root leaves) canonicalize
// under RFC 8785, so the id they already advertise — jcs-rfc8785 — names what they
// actually do. Before this switch, source_root_canonical said "jcs-rfc8785" while
// the leaves were hashed with the int64-verbatim deviation: the same-name-different-
// bytes hazard P0-4 called Critical, latent only because real bodies carry no numbers.

func TestSourceRootCanonicalIDMatchesTheCanonicalizer(t *testing.T) {
	if SourceRootCanonicalJCS != jcs.NameRFC8785 {
		t.Fatalf("source_root_canonical = %q but the canonicalizer is %q — the wire id must name the bytes it produces",
			SourceRootCanonicalJCS, jcs.NameRFC8785)
	}
}

func TestBodyHashUsesRFC8785(t *testing.T) {
	// A body carrying an unsafe integer is the only case where the two paths
	// diverge, so it is the only case that proves which one is wired in.
	body := map[string]any{"id": "urn:x", "n": json.Number("9007199254740993")}
	cred := &PipelinePassCredential{body: body}

	got, err := cred.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	want, err := jcs.HashRFC8785(body)
	if err != nil {
		t.Fatalf("HashRFC8785: %v", err)
	}
	if got != want {
		legacy, _ := jcs.Hash(body)
		t.Errorf("Hash() = %s\n want %s (RFC 8785)\n legacy would be %s", got, want, legacy)
	}
}

func TestMarshalJSONUsesRFC8785(t *testing.T) {
	body := map[string]any{"id": "urn:x", "n": json.Number("9007199254740993")}
	cred := &PipelinePassCredential{body: body}

	got, err := cred.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if strings.Contains(string(got), "9007199254740993") {
		t.Errorf("MarshalJSON preserved the legacy int64-verbatim spelling: %s", got)
	}
	if !strings.Contains(string(got), "9007199254740992") {
		t.Errorf("MarshalJSON did not round through binary64 as RFC 8785 requires: %s", got)
	}
}

func TestNumericFreeBodiesAreByteIdenticalAcrossTheSwitch(t *testing.T) {
	// The migration's safety property: real bodies carry no numbers, so the
	// switch does not move their content addresses. The number inventory
	// (docs/evidence/forkw-1-number-inventory-2026-07-15.md) is what establishes
	// that stored artifacts are in this class.
	body := map[string]any{
		"id":       "urn:uuid:1",
		"issuer":   "did:dplaax:owner:process",
		"subject":  map[string]any{"outputHash": "sha256:abc", "claim": "provin:convert"},
		"literals": []any{nil, true, false, "text"},
	}
	legacy, err := jcs.Hash(body)
	if err != nil {
		t.Fatal(err)
	}
	strict, err := jcs.HashRFC8785(body)
	if err != nil {
		t.Fatal(err)
	}
	if legacy != strict {
		t.Errorf("numeric-free body moved: legacy=%s rfc8785=%s", legacy, strict)
	}
}
