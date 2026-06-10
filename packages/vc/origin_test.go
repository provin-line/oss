package vc_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/packages/vc"
)

func sourceCred(t *testing.T, issuer, outputHash string) *vc.PipelinePassCredential {
	t.Helper()
	subj := subjectFields()
	subj.TransformationType = vc.TransformationConvert
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
		sourceCred(t, "did:dplaax:poc.dplaax.io:org:mineA:pipeline:m:process:s",
			"sha256:"+strings.Repeat("5", 64)),
		sourceCred(t, "did:dplaax:poc.dplaax.io:org:mineA:pipeline:m:process:s",
			"sha256:"+strings.Repeat("6", 64)),
		sourceCred(t, "did:dplaax:poc.dplaax.io:org:mineB:pipeline:m:process:s",
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

func TestNewOriginCommitment(t *testing.T) {
	s := threeSources(t)
	oc, err := vc.NewOriginCommitment(s, vc.SourceRootCanonicalJCS)
	if err != nil {
		t.Fatalf("NewOriginCommitment: %v", err)
	}
	wantIssuers := []string{
		"did:dplaax:poc.dplaax.io:org:mineA:pipeline:m:process:s",
		"did:dplaax:poc.dplaax.io:org:mineB:pipeline:m:process:s",
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

func aggregateCred(t *testing.T, origin *vc.OriginCommitment) *vc.PipelinePassCredential {
	t.Helper()
	subj := subjectFields()
	subj.TransformationType = vc.TransformationAggregate
	subj.InputHash = ""
	return newCred(t, vc.CredentialFields{
		Issuer:    "did:dplaax:poc.dplaax.io:org:factory:pipeline:agg:process:a1",
		ValidFrom: time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC),
		Subject:   subj,
		Origin:    origin,
	})
}

func newTestVerifier() *vc.Verifier {
	return vc.NewVerifier(nil, nil)
}

func TestVerifyOriginCommitmentVerified(t *testing.T) {
	s := threeSources(t)
	oc, err := vc.NewOriginCommitment(s, vc.SourceRootCanonicalJCS)
	if err != nil {
		t.Fatalf("NewOriginCommitment: %v", err)
	}
	cred := aggregateCred(t, oc)
	got, err := newTestVerifier().VerifyOriginCommitment(context.Background(), cred, s)
	if err != nil {
		t.Fatalf("VerifyOriginCommitment: %v", err)
	}
	if got != vc.ConfidenceVerified {
		t.Errorf("verdict = %v, want verified", got)
	}
}

func TestVerifyOriginCommitmentTamperedRoot(t *testing.T) {
	s := threeSources(t)
	oc, _ := vc.NewOriginCommitment(s, vc.SourceRootCanonicalJCS)
	oc.SourceRoot = "f1220" + strings.Repeat("00", 32)
	cred := aggregateCred(t, oc)
	got, err := newTestVerifier().VerifyOriginCommitment(context.Background(), cred, s)
	if err != nil {
		t.Fatalf("VerifyOriginCommitment: %v", err)
	}
	if got != vc.ConfidenceFailed {
		t.Errorf("verdict = %v, want failed", got)
	}
}

func TestVerifyOriginCommitmentIncompleteSources(t *testing.T) {
	s := threeSources(t)
	oc, _ := vc.NewOriginCommitment(s, vc.SourceRootCanonicalJCS)
	cred := aggregateCred(t, oc)
	// mineB's credential not yet resolved: issuer subset -> indeterminate.
	got, err := newTestVerifier().VerifyOriginCommitment(context.Background(), cred, s[:2])
	if err != nil {
		t.Fatalf("VerifyOriginCommitment: %v", err)
	}
	if got != vc.ConfidenceIndeterminate {
		t.Errorf("verdict = %v, want indeterminate", got)
	}
}

func TestVerifyOriginCommitmentForeignSource(t *testing.T) {
	s := threeSources(t)
	oc, _ := vc.NewOriginCommitment(s[:2], vc.SourceRootCanonicalJCS) // claims mineA only
	cred := aggregateCred(t, oc)
	got, err := newTestVerifier().VerifyOriginCommitment(context.Background(), cred, s) // mineB extra
	if err != nil {
		t.Fatalf("VerifyOriginCommitment: %v", err)
	}
	if got != vc.ConfidenceFailed {
		t.Errorf("verdict = %v, want failed (issuer outside derived_from)", got)
	}
}

func TestVerifyOriginCommitmentUnknownCanonical(t *testing.T) {
	s := threeSources(t)
	oc, _ := vc.NewOriginCommitment(s, vc.SourceRootCanonicalJCS)
	oc.SourceRootCanonical = "bogus-canonical"
	cred := aggregateCred(t, oc)
	got, err := newTestVerifier().VerifyOriginCommitment(context.Background(), cred, s)
	if err != nil {
		t.Fatalf("VerifyOriginCommitment: %v", err)
	}
	if got != vc.ConfidenceFailed {
		t.Errorf("verdict = %v, want failed (unknown canonical fails closed)", got)
	}
}

func TestVerifyOriginCommitmentMisuse(t *testing.T) {
	v := newTestVerifier()
	// No commitment at all.
	plain := aggregateCred(t, nil)
	if _, err := v.VerifyOriginCommitment(context.Background(), plain, nil); err == nil {
		t.Error("no commitment: want error, got nil")
	}
	// Chain-preserving credential carrying a commitment (non-conformant;
	// New does not validate, so this is constructible).
	s := threeSources(t)
	oc, _ := vc.NewOriginCommitment(s, vc.SourceRootCanonicalJCS)
	subj := subjectFields()
	bad := newCred(t, vc.CredentialFields{
		Issuer:             "did:dplaax:poc.dplaax.io:org:x:pipeline:p:process:f",
		ValidFrom:          time.Now(),
		Subject:            subj,
		PreviousCredential: "sha256:" + strings.Repeat("9", 64),
		Origin:             oc,
	})
	if _, err := v.VerifyOriginCommitment(context.Background(), bad, s); err == nil {
		t.Error("chain-preserving credential: want error, got nil")
	}
}

func TestVerifyOriginCommitmentEmptyClaim(t *testing.T) {
	oc, err := vc.NewOriginCommitment(nil, vc.SourceRootCanonicalJCS)
	if err != nil {
		t.Fatalf("NewOriginCommitment(nil): %v", err)
	}
	cred := aggregateCred(t, oc)
	got, err := newTestVerifier().VerifyOriginCommitment(context.Background(), cred, nil)
	if err != nil {
		t.Fatalf("VerifyOriginCommitment: %v", err)
	}
	if got != vc.ConfidenceVerified {
		t.Errorf("verdict = %v, want verified (signed claim of zero sources)", got)
	}
}
