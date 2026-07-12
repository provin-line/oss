package orgverify

import (
	"context"
	"testing"

	"github.com/provin-line/oss/resolver/local"
)

func TestInspect_PopulatesAllObservations(t *testing.T) {
	didStr := "did:dplaax:poc.dplaax.dev:org:acme.com"
	pub := mustKey(t)
	doc := newOwnerDoc(t, didStr, pub)
	fp := fingerprintFor(t, didStr, pub)
	dns := &stubResolver{records: []string{
		"v=dplaax1; did=" + didStr + "; key=" + fp,
	}}
	docs := local.New()
	docs.Add(doc)

	out, err := Inspect(context.Background(), didStr, Options{DNSResolver: dns, DIDResolver: docs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.OrgID != "acme.com" {
		t.Errorf("OrgID=%q, want acme.com", out.OrgID)
	}
	if out.OwnerDID != didStr {
		t.Errorf("OwnerDID=%q", out.OwnerDID)
	}
	if out.KeyFingerprint != fp {
		t.Errorf("KeyFingerprint=%q, want %q", out.KeyFingerprint, fp)
	}
	if len(out.DNSRecords) != 1 {
		t.Errorf("DNSRecords len=%d, want 1", len(out.DNSRecords))
	}
	if out.DocumentRetrieved == nil {
		t.Error("DocumentRetrieved is nil")
	}
}

// Inspect never computes a verdict — even when the underlying state would be
// a negative Verify() outcome (here: no DID Document at all), Inspect
// succeeds and records the failure as an observation, not an error.
func TestInspect_DocFetchFailure_IsObservationNotError(t *testing.T) {
	didStr := "did:dplaax:poc.dplaax.dev:org:acme.com"
	out, err := Inspect(context.Background(), didStr, Options{
		DNSResolver: &stubResolver{records: []string{}},
		DIDResolver: local.New(), // empty: resolution fails
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.DocumentError == "" {
		t.Error("expected DocumentError to be populated")
	}
	if out.DocumentRetrieved != nil {
		t.Error("DocumentRetrieved should be nil on fetch failure")
	}
}

func TestInspect_NotFQDN_SkipsDNSLookup(t *testing.T) {
	didStr := "did:dplaax:poc.dplaax.dev:org:acme"
	out, err := Inspect(context.Background(), didStr, Options{
		DNSResolver: &stubResolver{records: []string{"should not be reached"}},
		DIDResolver: local.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.IsFQDN {
		t.Error("IsFQDN=true, want false for a single-label orgId")
	}
	if out.DNSName != "" {
		t.Errorf("DNSName=%q, want empty (lookup skipped)", out.DNSName)
	}
}

func TestInspect_RequiresDIDResolver(t *testing.T) {
	_, err := Inspect(context.Background(), "did:dplaax:poc.dplaax.dev:org:acme.com", Options{})
	if err == nil {
		t.Fatal("expected error when Options.DIDResolver is nil")
	}
}
