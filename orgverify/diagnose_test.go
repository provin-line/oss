package orgverify

import (
	"strings"
	"testing"
)

func TestDiagnose_Verified(t *testing.T) {
	steps := Diagnose(&Result{Level: EndorsementVerified})
	if len(steps) != 0 {
		t.Errorf("Verified should produce no steps, got %d", len(steps))
	}
}

func TestDiagnose_Nil(t *testing.T) {
	if steps := Diagnose(nil); len(steps) != 0 {
		t.Errorf("nil Result should produce no steps, got %d", len(steps))
	}
}

func TestDiagnose_Missing_DIDNotEndorsed(t *testing.T) {
	r := &Result{
		Level: EndorsementMissing, Reason: ReasonDIDNotEndorsed,
		OwnerDID: "did:dplaax:poc.dplaax.dev:org:acme.com",
		OrgID:    "acme.com", KeyFingerprint: "sha256:" + strings.Repeat("a", 64),
	}
	steps := Diagnose(r)
	if len(steps) == 0 {
		t.Fatalf("expected steps, got 0")
	}
	joined := strings.Join(stepStrings(steps), "\n")
	if !strings.Contains(joined, "_dplaax-org.acme.com") {
		t.Errorf("expected DNS name in remediation, got: %s", joined)
	}
	if !strings.Contains(joined, "v=dplaax1") {
		t.Errorf("expected TXT template in remediation, got: %s", joined)
	}
}

func TestDiagnose_Invalid_KeyMismatch(t *testing.T) {
	r := &Result{
		Level: EndorsementInvalid, Reason: ReasonKeyMismatch,
		OwnerDID: "did:dplaax:poc.dplaax.dev:org:acme.com",
		OrgID:    "acme.com", KeyFingerprint: "sha256:" + strings.Repeat("a", 64),
	}
	steps := Diagnose(r)
	if len(steps) == 0 {
		t.Fatal("expected steps")
	}
	joined := strings.Join(stepStrings(steps), "\n")
	if !strings.Contains(joined, "rotated") && !strings.Contains(joined, "rotation") {
		t.Errorf("expected mention of rotation, got: %s", joined)
	}
}

func TestDiagnose_Invalid_MalformedRecord(t *testing.T) {
	r := &Result{
		Level: EndorsementInvalid, Reason: ReasonMalformedRecord,
		OwnerDID: "did:dplaax:poc.dplaax.dev:org:acme.com",
		OrgID:    "acme.com",
	}
	steps := Diagnose(r)
	if len(steps) == 0 {
		t.Fatal("expected steps")
	}
	joined := strings.Join(stepStrings(steps), "\n")
	if !strings.Contains(joined, "generate-txt") {
		t.Errorf("expected remediation to point at generate-txt, got: %s", joined)
	}
}

func TestDiagnose_Unreachable_Transient(t *testing.T) {
	r := &Result{
		Level: EndorsementUnreachable, Reason: ReasonDNSUnreachable,
		Detail: "DNS lookup failed for _dplaax-org.acme.com: dns: timeout",
	}
	steps := Diagnose(r)
	if len(steps) == 0 {
		t.Fatal("expected steps")
	}
	joined := strings.Join(stepStrings(steps), "\n")
	if !strings.Contains(joined, "Retry") {
		t.Errorf("expected retry guidance, got: %s", joined)
	}
}

func TestDiagnose_NA_NotFQDN(t *testing.T) {
	r := &Result{
		Level: EndorsementNA, Reason: ReasonOrgIDNotFQDN,
		OwnerDID: "did:dplaax:poc.dplaax.dev:org:acme",
	}
	steps := Diagnose(r)
	if len(steps) == 0 {
		t.Fatal("expected steps")
	}
	joined := strings.Join(stepStrings(steps), "\n")
	if !strings.Contains(joined, "FQDN") {
		t.Errorf("expected FQDN guidance, got: %s", joined)
	}
}

func stepStrings(steps []RemediationStep) []string {
	out := make([]string, len(steps))
	for i, s := range steps {
		out[i] = s.Action + ": " + s.Detail
	}
	return out
}
