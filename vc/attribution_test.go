package vc_test

import (
	"context"
	"testing"

	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// AttributeOwner resolves an issuer to its responsible Owner via the real
// controller-binding walk (audit.attribution.segment).
func TestAttributeOwner_ResolvesIssuerToOwner(t *testing.T) {
	_, _, r := buildChainFixture(t, procAOrigin, procBSameOrg)
	v := vc.NewVerifier(r, ed25519Verifier())

	owner, err := v.AttributeOwner(context.Background(), procAOrigin)
	if err != nil {
		t.Fatalf("AttributeOwner: %v", err)
	}
	if want := ownerOf(t, procAOrigin); owner != want {
		t.Errorf("owner = %q, want %q", owner, want)
	}
}

// Applied per segment and to the chain origin's issuer, the one primitive
// composes both audit rules: per-credential segment attribution and the
// origin-default target for everything preceding the cut
// (audit.attribution.origin-default).
func TestAttributeOwner_OriginDefaultComposition(t *testing.T) {
	origin, child, r := buildChainFixture(t, procAOrigin, procBOtherOrg)
	v := vc.NewVerifier(r, ed25519Verifier())

	for _, cred := range []*vc.PipelinePassCredential{origin, child} {
		owner, err := v.AttributeOwner(context.Background(), cred.Issuer())
		if err != nil {
			t.Fatalf("AttributeOwner(%s): %v", cred.Issuer(), err)
		}
		if want := ownerOf(t, cred.Issuer()); owner != want {
			t.Errorf("segment owner = %q, want %q", owner, want)
		}
	}
	preChain, err := v.AttributeOwner(context.Background(), origin.Issuer())
	if err != nil {
		t.Fatalf("AttributeOwner(origin): %v", err)
	}
	if want := ownerOf(t, procAOrigin); preChain != want {
		t.Errorf("pre-chain owner = %q, want %q", preChain, want)
	}
}

// An unresolvable issuer is an error — an owner is never fabricated
// (matching ClassifyChain's discipline over the shared walk).
func TestAttributeOwner_UnresolvableIssuer_Errors(t *testing.T) {
	v := vc.NewVerifier(local.New(), ed25519Verifier()) // empty resolver

	if _, err := v.AttributeOwner(context.Background(), procAOrigin); err == nil {
		t.Error("AttributeOwner with an unresolvable issuer: want error")
	}
}

// The walk starts at a Process DID; handing it an Owner DID (or any
// non-Process identifier) cannot be attributed and errors.
func TestAttributeOwner_NonProcessIssuer_Errors(t *testing.T) {
	_, _, r := buildChainFixture(t, procAOrigin, procBSameOrg)
	v := vc.NewVerifier(r, ed25519Verifier())

	if _, err := v.AttributeOwner(context.Background(), ownerOf(t, procAOrigin)); err == nil {
		t.Error("AttributeOwner on an Owner DID: want error (not a Process issuer)")
	}
}
