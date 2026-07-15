package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/pipeline/provenance/vcdid"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// cvSourceResolver adapts a local *vcresolver.Service to auditor.SourceResolver: it maps the
// store's authoritative ErrNotFound to auditor.ErrSourceNotFound (→ orphan), leaving other
// errors transient (→ unavailable). The real external-set fixture's resolver (slice-17q
// D-17q-6) — a legitimate availability seam over a real serving store; issuer-endpoint fan-out
// is the deferred production detail. This cross-layer integration lives in cmd/standalone (the
// composition root), not in network/, honoring the network/↔pipeline/ layer rule.
type cvSourceResolver struct{ svc *vcresolver.Service }

func (r cvSourceResolver) Resolve(ctx context.Context, hash string) (*vc.PipelinePassCredential, error) {
	cred, err := r.svc.ResolveVC(ctx, hash)
	if err != nil {
		if errors.Is(err, vcresolver.ErrNotFound) {
			return nil, errors.Join(auditor.ErrSourceNotFound, err)
		}
		return nil, err
	}
	return cred, nil
}

// TestConsumeVerify_Integration_RealDIDGraph is the slice-17q real external-set fixture: a real
// aggregate FirstDrop signed over two real, independently-signed source FirstDrops is
// independently verified at the CONSUME locus — sources fetched from a real serving store, the
// signed SourceRoot recomputed by the real vc.Verifier over the real DID graph → Verified; then
// orphan + partial branches over the same real machinery. The concrete caller that keeps the
// verifier from being an uncalled library (D-17q-6).
func TestConsumeVerify_Integration_RealDIDGraph(t *testing.T) {
	const (
		owner   = "did:dplaax:reg:org:acme"
		srcAIss = "did:dplaax:reg:org:acme:pipeline:cvsca:process:sa"
		srcBIss = "did:dplaax:reg:org:acme:pipeline:cvscb:process:sb"
		aggIss  = "did:dplaax:reg:org:acme:pipeline:cvagg:process:ag"
	)
	ctx := context.Background()
	ks := filestore.New(t.TempDir())
	res := local.New()
	for _, iss := range []string{srcAIss, srcBIss, aggIss} {
		kp, err := (ed25519.Generator{}).Generate()
		if err != nil {
			t.Fatalf("keygen %q: %v", iss, err)
		}
		if err := ks.SaveKeyPair(iss, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
			t.Fatalf("save key %q: %v", iss, err)
		}
		res.Add(capProcessDoc(iss, owner, kp.PublicKey))
	}
	res.Add(capOwnerDoc(owner))
	builder := vc.NewBuilder(ks)
	cvHash := func(b []byte) string {
		s := sha256.Sum256(b)
		return "sha256:" + hex.EncodeToString(s[:])
	}

	pool := memstore.NewPool()
	svc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), pool)
	signSource := func(iss, proc string, payload []byte) (*vc.PipelinePassCredential, string) {
		s, err := vcdid.NewSigner(vcdid.Config{
			Builder: builder, IssuerDID: iss, KeyID: string(keystore.KeyIDSigning),
			VerificationMethod: iss + "#signing", PipelineID: proc, ProcessID: proc,
			TransformationClaim: vc.ClaimConvert,
		})
		if err != nil {
			t.Fatalf("source signer %q: %v", iss, err)
		}
		h := cvHash(payload)
		cred, err := s.SignFirstDrop(ctx, payload, h, h)
		if err != nil {
			t.Fatalf("SignFirstDrop %q: %v", iss, err)
		}
		b, err := cred.MarshalJSON()
		if err != nil {
			t.Fatalf("marshal %q: %v", iss, err)
		}
		stored, err := svc.StoreVC(ctx, b, "", 0)
		if err != nil {
			t.Fatalf("store %q: %v", iss, err)
		}
		return cred, stored.BodyAddress
	}
	srcA, hA := signSource(srcAIss, "sa", []byte(`{"reading":1}`))
	srcB, hB := signSource(srcBIss, "sb", []byte(`{"reading":2}`))

	aggSigner, err := vcdid.NewSigner(vcdid.Config{
		Builder: builder, IssuerDID: aggIss, KeyID: string(keystore.KeyIDSigning),
		VerificationMethod: aggIss + "#signing", PipelineID: "cvagg", ProcessID: "ag",
		TransformationClaim: vc.ClaimAggregate, SourceRootCanonical: vc.SourceRootCanonicalJCS,
	})
	if err != nil {
		t.Fatalf("aggregate signer: %v", err)
	}
	aggPayload := []byte(`{"agg":true}`)
	aggCred, err := aggSigner.SignAggregateFirstDrop(ctx, aggPayload, cvHash(aggPayload),
		[]*vc.PipelinePassCredential{srcA, srcB})
	if err != nil {
		t.Fatalf("SignAggregateFirstDrop: %v", err)
	}

	cv, err := auditor.NewConsumeVerifier(vc.NewVerifier(res, ed25519.Verifier{}), cvSourceResolver{svc: svc})
	if err != nil {
		t.Fatalf("NewConsumeVerifier: %v", err)
	}

	// Verified: the relying party fetches both sources itself and recomputes the signed root.
	verdict, err := cv.Verify(ctx, aggCred, []string{hA, hB})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verdict.State != vc.ConfidenceVerified || verdict.Reason != auditor.ReasonVerified {
		t.Errorf("verdict = {%v,%q}, want {Verified,verified} (notation %q)", verdict.State, verdict.Reason, verdict.Notation)
	}

	// Orphan: a well-formed consumed hash not in the store → Indeterminate/orphan (no false verdict).
	missing := "sha256:9999999999999999999999999999999999999999999999999999999999999999"
	orphan, _ := cv.Verify(ctx, aggCred, []string{hA, missing})
	if orphan.State != vc.ConfidenceIndeterminate || orphan.Reason != auditor.ReasonOrphan {
		t.Errorf("orphan verdict = {%v,%q}, want {Indeterminate,orphan}", orphan.State, orphan.Reason)
	}

	// Wrong set (only one of two committed sources) → the verifier disproves it: never Verified.
	partial, _ := cv.Verify(ctx, aggCred, []string{hA})
	if partial.State == vc.ConfidenceVerified {
		t.Errorf("single-source verify = Verified, want NOT Verified (%q)", partial.Reason)
	}
	_ = hB
}
