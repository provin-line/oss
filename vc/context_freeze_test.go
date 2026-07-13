package vc_test

import (
	"testing"

	"github.com/provin-line/oss/vc"
)

// TestIssuedContextFrozenAtV0 is the P0-2 freeze anchor: the @context array
// every credential is issued with is the v0 wire vocabulary and does not
// change. The expected URIs are pinned as LITERALS here (not via the vc
// package constants) on purpose — a regression that repoints a constant is
// caught by this test rather than silently tracked. The @context rides the
// signing scope as bytes, so changing either protocol/profile URI is a
// cross-implementation hash partition and a next-MAJOR break, not a patch.
func TestIssuedContextFrozenAtV0(t *testing.T) {
	cred, err := vc.New(vc.CredentialFields{
		Issuer: "did:dplaax:poc.dplaax.dev:org:x:pipeline:p:process:s",
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "p",
			ProcessID:           "s",
			TransformationClaim: vc.ClaimConvert,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, ok := cred.Body()["@context"].([]any)
	if !ok {
		t.Fatalf("@context is not an array: %T", cred.Body()["@context"])
	}
	want := []string{
		"https://www.w3.org/ns/credentials/v2",
		"https://dplaax.dev/vc/v1",
		"https://provin.dev/vc/v1",
	}
	if len(ctx) != len(want) {
		t.Fatalf("@context = %v, want %v", ctx, want)
	}
	for i, w := range want {
		if got, _ := ctx[i].(string); got != w {
			t.Errorf("@context[%d] = %q, want %q", i, got, w)
		}
	}
}
