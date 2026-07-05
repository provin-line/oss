package vc_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/vc"
)

func sourceCred(t *testing.T, issuer, outputHash string) *vc.PipelinePassCredential {
	t.Helper()
	subj := subjectFields()
	subj.TransformationClaim = vc.ClaimConvert
	subj.OutputHash = outputHash
	return newCred(t, vc.CredentialFields{
		Issuer:    issuer,
		ValidFrom: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		Subject:   subj,
	})
}

func threeSources(t *testing.T) []*vc.PipelinePassCredential {
	t.Helper()
	return []*vc.PipelinePassCredential{
		sourceCred(t, "did:dplaax:poc.dplaax.dev:org:mineA:pipeline:m:process:s",
			"sha256:"+strings.Repeat("5", 64)),
		sourceCred(t, "did:dplaax:poc.dplaax.dev:org:mineA:pipeline:m:process:s",
			"sha256:"+strings.Repeat("6", 64)),
		sourceCred(t, "did:dplaax:poc.dplaax.dev:org:mineB:pipeline:m:process:s",
			"sha256:"+strings.Repeat("7", 64)),
	}
}

// Independent RFC 6962 reimplementation: leaves SHA-256(0x00||entry) sorted
// by SHA-256(entry) ascending; internal nodes SHA-256(0x01||l||r) with the
// left subtree spanning the largest power of two smaller than n.
func independentRoot(t *testing.T, sources []*vc.PipelinePassCredential) string {
	t.Helper()
	type leaf struct {
		content [32]byte
		hash    [32]byte
	}
	leaves := make([]leaf, len(sources))
	for i, s := range sources {
		wire, err := s.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON: %v", err)
		}
		leaves[i].content = sha256.Sum256(wire)
		leaves[i].hash = sha256.Sum256(append([]byte{0x00}, wire...))
	}
	sort.Slice(leaves, func(i, j int) bool {
		return string(leaves[i].content[:]) < string(leaves[j].content[:])
	})
	hashes := make([][32]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = l.hash
	}
	var mth func(h [][32]byte) [32]byte
	mth = func(h [][32]byte) [32]byte {
		switch len(h) {
		case 0:
			return sha256.Sum256(nil)
		case 1:
			return h[0]
		}
		k := 1
		for k*2 < len(h) {
			k *= 2
		}
		l, r := mth(h[:k]), mth(h[k:])
		buf := append([]byte{0x01}, l[:]...)
		buf = append(buf, r[:]...)
		return sha256.Sum256(buf)
	}
	root := mth(hashes)
	return "f1220" + hex.EncodeToString(root[:])
}

func TestComputeSourceRootMatchesRFC6962(t *testing.T) {
	for n := 1; n <= 3; n++ {
		sources := threeSources(t)[:n]
		got, err := vc.ComputeSourceRoot(sources, vc.SourceRootCanonicalJCS)
		if err != nil {
			t.Fatalf("ComputeSourceRoot(n=%d): %v", n, err)
		}
		if want := independentRoot(t, sources); got != want {
			t.Errorf("n=%d: root = %s, want %s", n, got, want)
		}
	}
}

func TestComputeSourceRootOrderIndependent(t *testing.T) {
	s := threeSources(t)
	r1, err := vc.ComputeSourceRoot(s, vc.SourceRootCanonicalJCS)
	if err != nil {
		t.Fatalf("ComputeSourceRoot: %v", err)
	}
	shuffled := []*vc.PipelinePassCredential{s[2], s[0], s[1]}
	r2, err := vc.ComputeSourceRoot(shuffled, vc.SourceRootCanonicalJCS)
	if err != nil {
		t.Fatalf("ComputeSourceRoot(shuffled): %v", err)
	}
	if r1 != r2 {
		t.Errorf("root depends on input order: %s != %s", r1, r2)
	}
	if !strings.HasPrefix(r1, "f1220") || len(r1) != len("f1220")+64 {
		t.Errorf("root format: %q", r1)
	}
}

func TestComputeSourceRootEmptySet(t *testing.T) {
	got, err := vc.ComputeSourceRoot(nil, vc.SourceRootCanonicalJCS)
	if err != nil {
		t.Fatalf("ComputeSourceRoot(nil): %v", err)
	}
	// RFC 6962 §2.1: MTH of the empty list is SHA-256 of the empty string.
	want := "f1220e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("empty root = %s, want %s", got, want)
	}
}

func TestComputeSourceRootRejects(t *testing.T) {
	s := threeSources(t)
	if _, err := vc.ComputeSourceRoot(s, "bogus-canonical"); err == nil {
		t.Error("unknown canonical: want error, got nil")
	}
	dup := []*vc.PipelinePassCredential{s[0], s[0]}
	if _, err := vc.ComputeSourceRoot(dup, vc.SourceRootCanonicalJCS); err == nil {
		t.Error("duplicate source: want error, got nil")
	}
}

func TestNewSourceCommitment(t *testing.T) {
	s := threeSources(t)
	oc, err := vc.NewSourceCommitment(s, vc.SourceRootCanonicalJCS)
	if err != nil {
		t.Fatalf("NewSourceCommitment: %v", err)
	}
	wantIssuers := []string{
		"did:dplaax:poc.dplaax.dev:org:mineA:pipeline:m:process:s",
		"did:dplaax:poc.dplaax.dev:org:mineB:pipeline:m:process:s",
	}
	if len(oc.DerivedFrom) != 2 || oc.DerivedFrom[0] != wantIssuers[0] || oc.DerivedFrom[1] != wantIssuers[1] {
		t.Errorf("DerivedFrom = %v, want %v (unique, sorted)", oc.DerivedFrom, wantIssuers)
	}
	wantRoot, _ := vc.ComputeSourceRoot(s, vc.SourceRootCanonicalJCS)
	if oc.SourceRoot != wantRoot {
		t.Errorf("SourceRoot = %s, want %s", oc.SourceRoot, wantRoot)
	}
	if oc.SourceRootCanonical != vc.SourceRootCanonicalJCS {
		t.Errorf("SourceRootCanonical = %s", oc.SourceRootCanonical)
	}
}

func aggregateCred(t *testing.T, commitment *vc.SourceCommitment) *vc.PipelinePassCredential {
	t.Helper()
	subj := subjectFields()
	subj.TransformationClaim = vc.ClaimAggregate
	subj.InputHash = ""
	return newCred(t, vc.CredentialFields{
		Issuer:           "did:dplaax:poc.dplaax.dev:org:factory:pipeline:agg:process:a1",
		ValidFrom:        time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC),
		Subject:          subj,
		SourceCommitment: commitment,
	})
}

func newTestVerifier() *vc.Verifier {
	return vc.NewVerifier(nil, nil)
}

func TestVerifySourceCommitmentVerified(t *testing.T) {
	s := threeSources(t)
	oc, err := vc.NewSourceCommitment(s, vc.SourceRootCanonicalJCS)
	if err != nil {
		t.Fatalf("NewSourceCommitment: %v", err)
	}
	cred := aggregateCred(t, oc)
	got, err := newTestVerifier().VerifySourceCommitment(context.Background(), cred, s)
	if err != nil {
		t.Fatalf("VerifySourceCommitment: %v", err)
	}
	if got != vc.ConfidenceVerified {
		t.Errorf("verdict = %v, want verified", got)
	}
}

func TestVerifySourceCommitmentNilInputs(t *testing.T) {
	// Misuse guard: nil inputs must return a defined error, never panic —
	// sources arrive from gather loops whose slots can legitimately still be
	// nil when a caller wires the gathering wrong (17k hardened the
	// construction side in ComputeSourceRoot; this pins the verify side).
	s := threeSources(t)
	oc, err := vc.NewSourceCommitment(s, vc.SourceRootCanonicalJCS)
	if err != nil {
		t.Fatalf("NewSourceCommitment: %v", err)
	}
	cred := aggregateCred(t, oc)

	if _, err := newTestVerifier().VerifySourceCommitment(context.Background(), nil, s); err == nil {
		t.Error("nil credential: want error, got nil")
	}
	withNil := append(append([]*vc.PipelinePassCredential{}, s...), nil)
	got, err := newTestVerifier().VerifySourceCommitment(context.Background(), cred, withNil)
	if err == nil {
		t.Error("nil source element: want error, got nil")
	}
	if got != vc.ConfidenceFailed {
		t.Errorf("nil source element: verdict = %v, want failed", got)
	}
}

func TestVerifySourceCommitmentTamperedRoot(t *testing.T) {
	s := threeSources(t)
	oc, _ := vc.NewSourceCommitment(s, vc.SourceRootCanonicalJCS)
	oc.SourceRoot = "f1220" + strings.Repeat("00", 32)
	cred := aggregateCred(t, oc)
	got, err := newTestVerifier().VerifySourceCommitment(context.Background(), cred, s)
	if err != nil {
		t.Fatalf("VerifySourceCommitment: %v", err)
	}
	if got != vc.ConfidenceFailed {
		t.Errorf("verdict = %v, want failed", got)
	}
}

func TestVerifySourceCommitmentIncompleteSources(t *testing.T) {
	s := threeSources(t)
	oc, _ := vc.NewSourceCommitment(s, vc.SourceRootCanonicalJCS)
	cred := aggregateCred(t, oc)
	// mineB's credential not yet resolved: issuer subset -> indeterminate.
	got, err := newTestVerifier().VerifySourceCommitment(context.Background(), cred, s[:2])
	if err != nil {
		t.Fatalf("VerifySourceCommitment: %v", err)
	}
	if got != vc.ConfidenceIndeterminate {
		t.Errorf("verdict = %v, want indeterminate", got)
	}
}

func TestVerifySourceCommitmentForeignSource(t *testing.T) {
	s := threeSources(t)
	oc, _ := vc.NewSourceCommitment(s[:2], vc.SourceRootCanonicalJCS) // claims mineA only
	cred := aggregateCred(t, oc)
	got, err := newTestVerifier().VerifySourceCommitment(context.Background(), cred, s) // mineB extra
	if err != nil {
		t.Fatalf("VerifySourceCommitment: %v", err)
	}
	if got != vc.ConfidenceFailed {
		t.Errorf("verdict = %v, want failed (issuer outside derived_from)", got)
	}
}

func TestVerifySourceCommitmentUnknownCanonical(t *testing.T) {
	s := threeSources(t)
	oc, _ := vc.NewSourceCommitment(s, vc.SourceRootCanonicalJCS)
	oc.SourceRootCanonical = "bogus-canonical"
	cred := aggregateCred(t, oc)
	got, err := newTestVerifier().VerifySourceCommitment(context.Background(), cred, s)
	if err != nil {
		t.Fatalf("VerifySourceCommitment: %v", err)
	}
	if got != vc.ConfidenceFailed {
		t.Errorf("verdict = %v, want failed (unknown canonical fails closed)", got)
	}
}

func TestVerifySourceCommitmentMisuse(t *testing.T) {
	v := newTestVerifier()
	// No commitment at all.
	plain := aggregateCred(t, nil)
	if _, err := v.VerifySourceCommitment(context.Background(), plain, nil); err == nil {
		t.Error("no commitment: want error, got nil")
	}
}

func TestVerifySourceCommitmentChainPreserving(t *testing.T) {
	// The commitment is orthogonal to previousCredential: a chain-preserving
	// credential committing to its full consumed source set — the triggering
	// predecessor included (all-consumed semantics) — verifies like any other.
	s := threeSources(t)
	oc, _ := vc.NewSourceCommitment(s, vc.SourceRootCanonicalJCS)
	prevHash, err := s[0].Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	subj := subjectFields()
	cred := newCred(t, vc.CredentialFields{
		Issuer:             "did:dplaax:poc.dplaax.dev:org:x:pipeline:p:process:f",
		ValidFrom:          time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC),
		Subject:            subj,
		PreviousCredential: prevHash,
		SourceCommitment:   oc,
	})
	got, err := newTestVerifier().VerifySourceCommitment(context.Background(), cred, s)
	if err != nil {
		t.Fatalf("VerifySourceCommitment: %v", err)
	}
	if got != vc.ConfidenceVerified {
		t.Errorf("verdict = %v, want verified (chain-preserving carries a commitment)", got)
	}
}

func TestVerifySourceCommitmentPredecessorOmitted(t *testing.T) {
	// All-consumed violation: a chain-preserving credential whose commitment
	// (and gathered set) omit the triggering predecessor must fail even
	// though the equality property holds over the claimed set — the verifier
	// holds the predecessor's content hash and requires a matching source.
	s := threeSources(t)
	oc, _ := vc.NewSourceCommitment(s, vc.SourceRootCanonicalJCS)
	subj := subjectFields()
	cred := newCred(t, vc.CredentialFields{
		Issuer:             "did:dplaax:poc.dplaax.dev:org:x:pipeline:p:process:f",
		ValidFrom:          time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC),
		Subject:            subj,
		PreviousCredential: "sha256:" + strings.Repeat("9", 64), // not among s
		SourceCommitment:   oc,
	})
	got, err := newTestVerifier().VerifySourceCommitment(context.Background(), cred, s)
	if err != nil {
		t.Fatalf("VerifySourceCommitment: %v", err)
	}
	if got != vc.ConfidenceFailed {
		t.Errorf("verdict = %v, want failed (predecessor omitted from commitment)", got)
	}
}

func TestVerifySourceCommitmentEmptyClaim(t *testing.T) {
	oc, err := vc.NewSourceCommitment(nil, vc.SourceRootCanonicalJCS)
	if err != nil {
		t.Fatalf("NewSourceCommitment(nil): %v", err)
	}
	cred := aggregateCred(t, oc)
	got, err := newTestVerifier().VerifySourceCommitment(context.Background(), cred, nil)
	if err != nil {
		t.Fatalf("VerifySourceCommitment: %v", err)
	}
	if got != vc.ConfidenceVerified {
		t.Errorf("verdict = %v, want verified (signed claim of zero sources)", got)
	}
}

func TestVerifySourceCommitmentDuplicateClaimFailsClosed(t *testing.T) {
	s := threeSources(t)
	oc, _ := vc.NewSourceCommitment(s, vc.SourceRootCanonicalJCS)
	cred := aggregateCred(t, oc)
	// Inject a duplicated derived_from entry at the wire level (New
	// normalizes to a unique set, so craft the wire form directly).
	wire, _ := cred.MarshalJSON()
	dup := strings.Replace(string(wire), `"derived_from":["`,
		`"derived_from":["`+oc.DerivedFrom[0]+`","`, 1)
	var tampered vc.PipelinePassCredential
	if err := tampered.UnmarshalJSON([]byte(dup)); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if len(tampered.SourceCommitment().DerivedFrom) != len(oc.DerivedFrom)+1 {
		t.Fatalf("test setup: duplicate not injected: %v", tampered.SourceCommitment().DerivedFrom)
	}
	got, err := newTestVerifier().VerifySourceCommitment(context.Background(), &tampered, s)
	if err != nil {
		t.Fatalf("VerifySourceCommitment: %v", err)
	}
	if got != vc.ConfidenceFailed {
		t.Errorf("verdict = %v, want failed (duplicate-carrying claim is malformed)", got)
	}
}
