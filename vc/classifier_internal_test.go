package vc

import (
	"encoding/json"
	"testing"

	"github.com/provin-line/oss/canon/jcs"
)

// What we ISSUE under eddsa-jcs-2022 must be canonicalized by the
// canonicalizer that suite names. This is unobservable from outside — the
// admission gate rejects the only inputs on which the two canonicalizers
// disagree, so every signable document produces identical bytes either way —
// which is exactly why it needs pinning here. An artifact that claims W3C
// conformance while being canonicalized under the int64-verbatim deviation is
// the same-name-different-bytes hazard, just latent.
func TestIssuanceSuiteUsesRFC8785(t *testing.T) {
	c, err := canonicalizerFor(CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("canonicalizerFor(%s): %v", CryptosuiteEdDSAJCS2022, err)
	}
	if got := c.Name(); got != jcs.NameRFC8785 {
		t.Errorf("issuance canonicalizer = %q, want %q — a W3C-shaped proof signed with the legacy deviation claims a conformance it does not have",
			got, jcs.NameRFC8785)
	}
}

// The legacy contract keeps its own canonicalizer, reached through the contract
// rather than the registry: the registry answers "what do we issue?", the
// contract answers "what was this signed under?". Collapsing the two would make
// old evidence unverifiable the moment issuance moved on.
func TestLegacyContractKeepsTheDeviation(t *testing.T) {
	c, err := ContractLegacyProvinEdDSAJCSInt64.canonicalizer()
	if err != nil {
		t.Fatalf("legacy contract canonicalizer: %v", err)
	}
	got, err := c(map[string]any{"n": json.Number("9007199254740993")})
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if string(got) != `{"n":9007199254740993}` {
		t.Errorf("legacy contract lost the int64-verbatim deviation: %s", got)
	}
}
