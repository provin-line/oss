package orgverify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/resolver/local"
)

func newOwnerDoc(t *testing.T, didStr string, pub []byte) *did.DIDDocument {
	t.Helper()
	return docWithSigningKey(didStr, pub)
}

func fingerprintFor(t *testing.T, didStr string, pub []byte) string {
	t.Helper()
	fp, err := FingerprintFromDIDDocument(newOwnerDoc(t, didStr, pub))
	if err != nil {
		t.Fatalf("fingerprint setup failed: %v", err)
	}
	return fp
}

func TestVerify_Verified(t *testing.T) {
	didStr := "did:dplaax:poc.dplaax.dev:org:acme.com"
	pub := mustKey(t)
	fp := fingerprintFor(t, didStr, pub)
	dns := &stubResolver{records: []string{
		"v=dplaax1; did=" + didStr + "; key=" + fp,
	}}
	docs := local.New()
	docs.Add(newOwnerDoc(t, didStr, pub))

	r, err := Verify(context.Background(), didStr, Options{
		DNSResolver: dns,
		DIDResolver: docs,
		Now:         func() time.Time { return time.Unix(0, 0) },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Level != EndorsementVerified {
		t.Errorf("Level=%s, want %s", r.Level, EndorsementVerified)
	}
	if r.Reason != ReasonOK {
		t.Errorf("Reason=%s, want %s", r.Reason, ReasonOK)
	}
}

// A registry mounting a DID under the same orgId as a legitimate owner (an
// impostor claiming the DNS-endorsed name) is Missing — DNS endorses the
// LEGITIMATE did, not the impostor's — never silently accepted.
func TestVerify_Squatting_Missing(t *testing.T) {
	attackerDID := "did:dplaax:registry.attacker.example:org:acme.com"
	legitDID := "did:dplaax:poc.dplaax.dev:org:acme.com"
	legitPub := mustKey(t)
	legitFP := fingerprintFor(t, legitDID, legitPub)
	dns := &stubResolver{records: []string{
		"v=dplaax1; did=" + legitDID + "; key=" + legitFP,
	}}
	docs := local.New()
	docs.Add(newOwnerDoc(t, attackerDID, mustKey(t)))

	r, err := Verify(context.Background(), attackerDID, Options{DNSResolver: dns, DIDResolver: docs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Level != EndorsementMissing {
		t.Errorf("Level=%s, want %s", r.Level, EndorsementMissing)
	}
	if r.Reason != ReasonDIDNotEndorsed {
		t.Errorf("Reason=%s", r.Reason)
	}
}

func TestVerify_KeyMismatch_Invalid(t *testing.T) {
	didStr := "did:dplaax:poc.dplaax.dev:org:acme.com"
	dnsFP := fingerprintFor(t, didStr, mustKey(t))
	dns := &stubResolver{records: []string{"v=dplaax1; did=" + didStr + "; key=" + dnsFP}}
	docs := local.New()
	docs.Add(newOwnerDoc(t, didStr, mustKey(t)))

	r, err := Verify(context.Background(), didStr, Options{DNSResolver: dns, DIDResolver: docs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Level != EndorsementInvalid {
		t.Errorf("Level=%s, want %s", r.Level, EndorsementInvalid)
	}
	if r.Reason != ReasonKeyMismatch {
		t.Errorf("Reason=%s", r.Reason)
	}
}

func TestVerify_NoDNSRecords_Missing(t *testing.T) {
	didStr := "did:dplaax:poc.dplaax.dev:org:acme.com"
	dns := &stubResolver{err: &dnsError{cause: ErrDNSNoRecords, message: "NXDOMAIN"}}
	docs := local.New()
	docs.Add(newOwnerDoc(t, didStr, mustKey(t)))

	r, err := Verify(context.Background(), didStr, Options{DNSResolver: dns, DIDResolver: docs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Level != EndorsementMissing {
		t.Errorf("Level=%s, want %s", r.Level, EndorsementMissing)
	}
	if r.Reason != ReasonNoDNSRecords {
		t.Errorf("Reason=%s", r.Reason)
	}
}

func TestVerify_DNSUnreachable_Unreachable(t *testing.T) {
	didStr := "did:dplaax:poc.dplaax.dev:org:acme.com"
	dns := &stubResolver{err: &dnsError{cause: ErrDNSTimeout, message: "timeout"}}
	docs := local.New()
	docs.Add(newOwnerDoc(t, didStr, mustKey(t)))

	r, err := Verify(context.Background(), didStr, Options{DNSResolver: dns, DIDResolver: docs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Level != EndorsementUnreachable {
		t.Errorf("Level=%s, want %s", r.Level, EndorsementUnreachable)
	}
	if r.Reason != ReasonDNSUnreachable {
		t.Errorf("Reason=%s", r.Reason)
	}
}

func TestVerify_DocFetchFailed_Unreachable(t *testing.T) {
	didStr := "did:dplaax:poc.dplaax.dev:org:acme.com"
	dns := &stubResolver{records: []string{}}
	docs := local.New() // empty: resolving didStr fails with resolver.ErrNotFound

	r, err := Verify(context.Background(), didStr, Options{DNSResolver: dns, DIDResolver: docs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Level != EndorsementUnreachable {
		t.Errorf("Level=%s, want %s", r.Level, EndorsementUnreachable)
	}
	if r.Reason != ReasonDocFetchFailed {
		t.Errorf("Reason=%s", r.Reason)
	}
}

func TestVerify_NotFQDN_NA(t *testing.T) {
	didStr := "did:dplaax:poc.dplaax.dev:org:acme"
	r, err := Verify(context.Background(), didStr, Options{
		DNSResolver: &stubResolver{}, DIDResolver: local.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Level != EndorsementNA {
		t.Errorf("Level=%s, want %s", r.Level, EndorsementNA)
	}
	if r.Reason != ReasonOrgIDNotFQDN {
		t.Errorf("Reason=%s", r.Reason)
	}
}

func TestVerify_PipelineDIDNormalizesToOwner(t *testing.T) {
	pipelineDID := "did:dplaax:poc.dplaax.dev:org:acme.com:pipeline:lot"
	ownerDID := "did:dplaax:poc.dplaax.dev:org:acme.com"
	pub := mustKey(t)
	fp := fingerprintFor(t, ownerDID, pub)
	dns := &stubResolver{records: []string{"v=dplaax1; did=" + ownerDID + "; key=" + fp}}
	docs := local.New()
	docs.Add(newOwnerDoc(t, ownerDID, pub))

	r, err := Verify(context.Background(), pipelineDID, Options{DNSResolver: dns, DIDResolver: docs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Level != EndorsementVerified {
		t.Errorf("Level=%s, want %s", r.Level, EndorsementVerified)
	}
	if r.OwnerDID != ownerDID {
		t.Errorf("OwnerDID=%s, want %s", r.OwnerDID, ownerDID)
	}
}

func TestVerify_UnknownHierarchyPattern_Error(t *testing.T) {
	// The parser is permissive and accepts any safe segment shape, but
	// ValidateDID must reject unknown hierarchy patterns so garbage DIDs do
	// not silently coerce to their owner.
	garbageDID := "did:dplaax:poc.dplaax.dev:org:acme.com:foo:bar"
	_, err := Verify(context.Background(), garbageDID, Options{
		DNSResolver: &stubResolver{}, DIDResolver: local.New(),
	})
	if err == nil {
		t.Fatal("expected error for unknown hierarchy pattern")
	}
}

// Multi-record adjudication branch (1): every record naming our DID agrees
// with the DID Document -> Verified even with >1 record.
func TestVerify_MultipleAgreeingRecords_Verified(t *testing.T) {
	didStr := "did:dplaax:poc.dplaax.dev:org:acme.com"
	pub := mustKey(t)
	fp := fingerprintFor(t, didStr, pub)
	dns := &stubResolver{records: []string{
		"v=dplaax1; did=" + didStr + "; key=" + fp,
		"v=dplaax1; did=" + didStr + "; key=" + fp,
	}}
	docs := local.New()
	docs.Add(newOwnerDoc(t, didStr, pub))

	r, err := Verify(context.Background(), didStr, Options{DNSResolver: dns, DIDResolver: docs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Level != EndorsementVerified {
		t.Errorf("Level=%s, want %s", r.Level, EndorsementVerified)
	}
}

// Multi-record adjudication branch (1): records naming our DID disagree with
// each other -> Invalid (key_conflict), even though one of them matches the
// DID Document's key.
func TestVerify_ConflictingTXT_Invalid(t *testing.T) {
	didStr := "did:dplaax:poc.dplaax.dev:org:acme.com"
	pubA := mustKey(t)
	fp1 := fingerprintFor(t, didStr, pubA)
	fp2 := fingerprintFor(t, didStr, mustKey(t))
	dns := &stubResolver{records: []string{
		"v=dplaax1; did=" + didStr + "; key=" + fp1,
		"v=dplaax1; did=" + didStr + "; key=" + fp2,
	}}
	docs := local.New()
	docs.Add(newOwnerDoc(t, didStr, pubA))

	r, err := Verify(context.Background(), didStr, Options{DNSResolver: dns, DIDResolver: docs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Level != EndorsementInvalid {
		t.Errorf("Level=%s, want %s (conflict)", r.Level, EndorsementInvalid)
	}
	if r.Reason != ReasonKeyConflict {
		t.Errorf("Reason=%s", r.Reason)
	}
}

// Multi-record adjudication branch (2): a record parses but names a
// DIFFERENT DID (so zero records match ours) while a SEPARATE malformed
// record contains "did=<ourDID>" -> Invalid (malformed_record).
func TestVerify_MalformedRecordForOurDID_Invalid(t *testing.T) {
	didStr := "did:dplaax:poc.dplaax.dev:org:acme.com"
	otherDID := "did:dplaax:poc.dplaax.dev:org:other.example"
	docs := local.New()
	docs.Add(newOwnerDoc(t, didStr, mustKey(t)))
	dns := &stubResolver{records: []string{
		"v=dplaax1; did=" + otherDID + "; key=sha256:" + strings.Repeat("a", 64),
		"v=dplaax1; did=" + didStr + "; key=sha256:" + strings.Repeat("A", 64), // uppercase hex: malformed
	}}

	r, err := Verify(context.Background(), didStr, Options{DNSResolver: dns, DIDResolver: docs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Level != EndorsementInvalid {
		t.Errorf("Level=%s, want %s (malformed)", r.Level, EndorsementInvalid)
	}
	if r.Reason != ReasonMalformedRecord {
		t.Errorf("Reason=%s", r.Reason)
	}
}

// Multi-record adjudication branch (2): zero records match our DID and no
// malformed record mentions it either -> Missing, not Invalid — unrelated
// DNS noise at the same name must not manufacture a false verdict.
func TestVerify_UnrelatedRecordsOnly_Missing(t *testing.T) {
	didStr := "did:dplaax:poc.dplaax.dev:org:acme.com"
	otherDID := "did:dplaax:poc.dplaax.dev:org:other.example"
	docs := local.New()
	docs.Add(newOwnerDoc(t, didStr, mustKey(t)))
	dns := &stubResolver{records: []string{
		"v=dplaax1; did=" + otherDID + "; key=sha256:" + strings.Repeat("a", 64),
		"not a valid record at all",
	}}

	r, err := Verify(context.Background(), didStr, Options{DNSResolver: dns, DIDResolver: docs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Level != EndorsementMissing {
		t.Errorf("Level=%s, want %s", r.Level, EndorsementMissing)
	}
	if r.Reason != ReasonDIDNotEndorsed {
		t.Errorf("Reason=%s", r.Reason)
	}
}

func TestVerify_MalformedTXT_Invalid(t *testing.T) {
	didStr := "did:dplaax:poc.dplaax.dev:org:acme.com"
	dns := &stubResolver{records: []string{
		"v=dplaax1; did=" + didStr + "; key=sha256:" + strings.Repeat("A", 64),
	}}
	docs := local.New()
	docs.Add(newOwnerDoc(t, didStr, mustKey(t)))

	r, err := Verify(context.Background(), didStr, Options{DNSResolver: dns, DIDResolver: docs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Level != EndorsementInvalid {
		t.Errorf("Level=%s, want %s (malformed)", r.Level, EndorsementInvalid)
	}
	if r.Reason != ReasonMalformedRecord {
		t.Errorf("Reason=%s", r.Reason)
	}
}

func TestVerify_RequiresDIDResolver(t *testing.T) {
	_, err := Verify(context.Background(), "did:dplaax:poc.dplaax.dev:org:acme.com", Options{})
	if err == nil {
		t.Fatal("expected error when Options.DIDResolver is nil")
	}
}

// The port's ONE deliberate adjudication divergence from the predecessor,
// pinned so a refactor cannot silently reintroduce the old ordering: spec
// §7.5 gives branch (1) precedence — when at least one PARSEABLE record
// matches the owner DID with the right fingerprint (and none mismatch), the
// verdict is Verified even if a MALFORMED record containing did=<ourDID>
// sits beside it. (The predecessor checked malformed-attribution first and
// would have returned Invalid here.) Malformed-record attribution only
// decides when NO parseable matching record exists — branch (2).
func TestVerify_ValidRecordBesideMalformedMention_Verified(t *testing.T) {
	didStr := "did:dplaax:poc.dplaax.dev:org:acme.com"
	pub := mustKey(t)
	fp := fingerprintFor(t, didStr, pub)
	dns := &stubResolver{records: []string{
		"v=dplaax1; did=" + didStr + "; key=" + fp,
		// Malformed (duplicate known key) AND mentioning our DID — branch
		// (2)'s needle, which branch (1) must outrank.
		"v=dplaax1; v=dplaax1; did=" + didStr + "; key=" + fp,
	}}
	docs := local.New()
	docs.Add(newOwnerDoc(t, didStr, pub))

	r, err := Verify(context.Background(), didStr, Options{
		DNSResolver: dns,
		DIDResolver: docs,
		Now:         func() time.Time { return time.Unix(0, 0) },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Level != EndorsementVerified {
		t.Errorf("Level=%s, want %s (branch-1 precedence over malformed attribution)", r.Level, EndorsementVerified)
	}
}
