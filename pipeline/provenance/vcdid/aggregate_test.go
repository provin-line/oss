package vcdid_test

import (
	"context"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/pipeline/provenance/vcdid"
	"github.com/provin-line/oss/vc"
)

// aggSigner builds a real aggregate signer: transformationClaim provin:aggregate
// with the audit-reachable canonical configured (D-17k-4/5). The aggregate path is
// always commitment-bearing, so SourceRootCanonical is required at construction even
// though AuditReachable (the chained flag) is unset.
func aggSigner(t *testing.T) *vcdid.Signer {
	t.Helper()
	b, _ := fixture(t)
	return newSigner(t, b, func(c *vcdid.Config) {
		c.TransformationClaim = vc.ClaimAggregate
		c.SourceRootCanonical = vc.SourceRootCanonicalJCS
	})
}

// signedSource builds a real signed FirstDrop under its own issuer DID (own
// keystore/builder) so a consumed set spans multiple distinct issuers — the
// credential AS RECEIVED (signed wire form) the commitment must be computed over.
func signedSource(t *testing.T, issuer, hash string) *vc.PipelinePassCredential {
	t.Helper()
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	ks := newMemKeyStore()
	if err := ks.SaveKeyPair(issuer, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatalf("SaveKeyPair: %v", err)
	}
	s, err := vcdid.NewSigner(vcdid.Config{
		Builder: vc.NewBuilder(ks), IssuerDID: issuer, KeyID: keyID,
		VerificationMethod: issuer + "#signing", PipelineID: "src", ProcessID: "p",
		TransformationClaim: vc.ClaimConvert,
	})
	if err != nil {
		t.Fatalf("NewSigner(%s): %v", issuer, err)
	}
	cred, err := s.SignFirstDrop(context.Background(), []byte(`{"v":1}`), "sha256:"+hash, "sha256:"+hash)
	if err != nil {
		t.Fatalf("source SignFirstDrop: %v", err)
	}
	return cred
}

const (
	srcAIssuer = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:a:process:a1"
	srcBIssuer = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:b:process:b1"
)

// TestSigner_SignAggregateFirstDrop_CommitsAndVerifies is the slice-17k capstone: a
// real aggregate signer folds a consumed set of two signed sources (distinct issuers)
// into a FirstDrop whose source commitment a verifier recomputes to Verified, with
// InputHash and previousCredential structurally absent and claim provin:aggregate.
func TestSigner_SignAggregateFirstDrop_CommitsAndVerifies(t *testing.T) {
	s := aggSigner(t)
	srcA := signedSource(t, srcAIssuer, "a")
	srcB := signedSource(t, srcBIssuer, "b")
	sources := []*vc.PipelinePassCredential{srcA, srcB}

	cred, err := s.SignAggregateFirstDrop(context.Background(), []byte(`{"agg":true}`), "sha256:out", sources)
	if err != nil {
		t.Fatalf("SignAggregateFirstDrop: %v", err)
	}

	// Claim is provin:aggregate.
	subj, _ := cred.Subject()
	if subj.TransformationClaim != vc.ClaimAggregate {
		t.Errorf("claim=%q, want %q", subj.TransformationClaim, vc.ClaimAggregate)
	}
	if subj.OutputHash != "sha256:out" {
		t.Errorf("outputHash=%q, want sha256:out", subj.OutputHash)
	}

	// InputHash and previousCredential are absent in the WIRE BODY — the typed
	// accessors collapse absent and empty to "", so check the raw keys (D-17k-2,
	// spec-review L3).
	csub, ok := cred.Body()["credentialSubject"].(map[string]any)
	if !ok {
		t.Fatal("credentialSubject missing")
	}
	if _, present := csub["inputHash"]; present {
		t.Error("aggregate FirstDrop wire body carries inputHash (must be absent)")
	}
	// previousCredential is written inside credentialSubject (credential.go), so
	// check there, not the body top level (review #1 — the top-level key is always
	// absent and would make this assertion vacuous).
	if _, present := csub["previousCredential"]; present {
		t.Error("aggregate FirstDrop credentialSubject carries previousCredential (must be absent)")
	}
	if cred.PreviousCredential() != "" {
		t.Errorf("PreviousCredential()=%q, want empty (chain origin)", cred.PreviousCredential())
	}

	// The commitment round-trips Verified against the sources as received, and
	// DerivedFrom is exactly the unique issuer set.
	sc := cred.SourceCommitment()
	if sc == nil {
		t.Fatal("aggregate FirstDrop carries no source commitment")
	}
	state, err := vc.NewVerifier(nil, nil).VerifySourceCommitment(context.Background(), cred, sources)
	if err != nil {
		t.Fatalf("VerifySourceCommitment: %v", err)
	}
	if state != vc.ConfidenceVerified {
		t.Errorf("VerifySourceCommitment=%v, want Verified", state)
	}
	// DerivedFrom is the unique issuer set, lexicographically ascending (the pinned
	// byte-deterministic order). srcAIssuer < srcBIssuer, so assert exact order.
	if len(sc.DerivedFrom) != 2 || sc.DerivedFrom[0] != srcAIssuer || sc.DerivedFrom[1] != srcBIssuer {
		t.Errorf("DerivedFrom=%v, want [%q %q]", sc.DerivedFrom, srcAIssuer, srcBIssuer)
	}
}

// N=1 (batch-of-1) is still a valid aggregate FirstDrop: a single-element commitment.
func TestSigner_SignAggregateFirstDrop_BatchOfOne(t *testing.T) {
	s := aggSigner(t)
	sources := []*vc.PipelinePassCredential{signedSource(t, srcAIssuer, "a")}
	cred, err := s.SignAggregateFirstDrop(context.Background(), []byte(`{"agg":true}`), "sha256:out", sources)
	if err != nil {
		t.Fatalf("SignAggregateFirstDrop(N=1): %v", err)
	}
	state, err := vc.NewVerifier(nil, nil).VerifySourceCommitment(context.Background(), cred, sources)
	if err != nil || state != vc.ConfidenceVerified {
		t.Errorf("N=1 commitment: state=%v err=%v, want Verified/nil", state, err)
	}
}

// A duplicate-content source is caller misuse — surfaced as an error, never silently
// deduped (D-17k-7).
func TestSigner_SignAggregateFirstDrop_DuplicateSource(t *testing.T) {
	s := aggSigner(t)
	src := signedSource(t, srcAIssuer, "a")
	if _, err := s.SignAggregateFirstDrop(context.Background(), []byte(`{}`), "sha256:out",
		[]*vc.PipelinePassCredential{src, src}); err == nil {
		t.Error("duplicate-content source: want error, got nil")
	}
}

// A nil source element fails closed (an error, not a panic) — spec-review M2.
func TestSigner_SignAggregateFirstDrop_NilSource(t *testing.T) {
	s := aggSigner(t)
	if _, err := s.SignAggregateFirstDrop(context.Background(), []byte(`{}`), "sha256:out",
		[]*vc.PipelinePassCredential{signedSource(t, srcAIssuer, "a"), nil}); err == nil {
		t.Error("nil source element: want error, got nil")
	}
}

// An empty consumed set yields a valid empty-DerivedFrom commitment (legal on a chain
// origin); whether to emit on an empty window is the runtime's policy, not the signer's
// (D-17k-8).
func TestSigner_SignAggregateFirstDrop_EmptySet(t *testing.T) {
	s := aggSigner(t)
	cred, err := s.SignAggregateFirstDrop(context.Background(), []byte(`{"agg":true}`), "sha256:out", nil)
	if err != nil {
		t.Fatalf("SignAggregateFirstDrop(empty): %v", err)
	}
	sc := cred.SourceCommitment()
	if sc == nil || len(sc.DerivedFrom) != 0 {
		t.Errorf("empty set: want a commitment with empty DerivedFrom, got %+v", sc)
	}
}

// A signer whose configured claim is NOT provin:aggregate cannot mint the aggregate
// shape, even with SourceRootCanonical set (spec-review M1 / D-17k-4).
func TestSigner_SignAggregateFirstDrop_WrongClaimRejected(t *testing.T) {
	b, _ := fixture(t)
	s := newSigner(t, b, func(c *vcdid.Config) {
		c.TransformationClaim = vc.ClaimConvert
		c.SourceRootCanonical = vc.SourceRootCanonicalJCS
	})
	if _, err := s.SignAggregateFirstDrop(context.Background(), []byte(`{}`), "sha256:out",
		[]*vc.PipelinePassCredential{signedSource(t, srcAIssuer, "a")}); err == nil {
		t.Error("non-aggregate claim signer: SignAggregateFirstDrop must be rejected")
	}
}

// An aggregate-configured signer must mint ONLY through SignAggregateFirstDrop: the
// legacy SignFirstDrop / SignChainPreserving paths fail closed, so an aggregate signer
// cannot emit a malformed provin:aggregate credential (inputHash present / no
// commitment, or a previousCredential link). Binds claim↔method both ways (review P2-b).
func TestSigner_AggregateSigner_RejectsLegacyPaths(t *testing.T) {
	s := aggSigner(t)
	if _, err := s.SignFirstDrop(context.Background(), []byte(`{}`), "sha256:in", "sha256:out"); err == nil {
		t.Error("aggregate signer SignFirstDrop: want rejection, got nil")
	}
	src := signedSource(t, srcAIssuer, "a")
	if _, err := s.SignChainPreserving(context.Background(), []byte(`{}`), "sha256:in", "sha256:out", src); err == nil {
		t.Error("aggregate signer SignChainPreserving: want rejection, got nil")
	}
}

// Constructing an aggregate-claim signer without SourceRootCanonical is a loud
// construction error (D-17k-5), decoupled from the chained AuditReachable flag.
func TestNewSigner_AggregateRequiresCanonical(t *testing.T) {
	b, _ := fixture(t)
	cfg := vcdid.Config{
		Builder: b, IssuerDID: issuerDID, KeyID: keyID, VerificationMethod: vmID,
		PipelineID: "p1", ProcessID: "proc1", TransformationClaim: vc.ClaimAggregate,
		// SourceRootCanonical deliberately empty, AuditReachable unset.
	}
	if _, err := vcdid.NewSigner(cfg); err == nil {
		t.Error("NewSigner(ClaimAggregate, no SourceRootCanonical): want error")
	}
}

// An aggregate signer configured with a fold-output schema reference emits it
// into the FirstDrop's credential subject, exactly like the source/chained
// producing sides (TestSigner_SignFirstDrop_EmitsSchema) — the aggregate's
// specially-shaped subject (commitment triple) still carries Schema.
func TestSigner_SignAggregateFirstDrop_EmitsSchema(t *testing.T) {
	b, _ := fixture(t)
	ref := vc.SchemaRef{
		ID:          "dplaax:schema/agg-report@2026-07-10-abcdef0123456789",
		Type:        "JsonSchema",
		ContentHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	s := newSigner(t, b, func(c *vcdid.Config) {
		c.TransformationClaim = vc.ClaimAggregate
		c.SourceRootCanonical = vc.SourceRootCanonicalJCS
		c.Schema = ref
	})
	sources := []*vc.PipelinePassCredential{
		signedSource(t, "did:dplaax:reg:org:alpha:pipeline:a:process:p1", "sha256:s1"),
	}
	cred, err := s.SignAggregateFirstDrop(context.Background(), []byte(`{"agg":true}`), "sha256:out", sources)
	if err != nil {
		t.Fatalf("SignAggregateFirstDrop: %v", err)
	}
	subj, err := cred.Subject()
	if err != nil {
		t.Fatalf("Subject: %v", err)
	}
	if subj.Schema != ref {
		t.Errorf("aggregate emitted schema = %+v, want %+v", subj.Schema, ref)
	}

	// And none when unset (aggSigner has no Schema configured).
	plain, err := aggSigner(t).SignAggregateFirstDrop(context.Background(), []byte(`{"agg":true}`), "sha256:out", sources)
	if err != nil {
		t.Fatalf("SignAggregateFirstDrop (no schema): %v", err)
	}
	ps, _ := plain.Subject()
	if ps.Schema != (vc.SchemaRef{}) {
		t.Errorf("no-schema aggregate emitted %+v, want zero", ps.Schema)
	}
}
