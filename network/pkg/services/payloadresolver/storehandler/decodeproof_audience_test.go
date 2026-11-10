package storehandler

import (
	"testing"

	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
)

func TestDecodeProofCarriesAudience(t *testing.T) {
	proof, err := decodeProof(&chainpb.AuthProof{
		SignerDid: "did:dplaax:a.example:org:o1",
		Audience:  "r.example",
		Nonce:     "n1",
		IssuedAt:  "2026-01-02T03:04:05Z",
		Signature: []byte("sig"),
	})
	if err != nil {
		t.Fatalf("decodeProof: %v", err)
	}
	if proof.Audience != "r.example" {
		t.Errorf("Audience = %q, want %q", proof.Audience, "r.example")
	}
}
