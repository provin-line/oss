package inputcapture_test

import (
	"context"
	"testing"

	"github.com/provin-line/oss/appraisal/inputcapture"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/internal/jsondepth"
	"github.com/provin-line/oss/resolver/local"
)

// deep is a value nested depth arrays deep.
func deep(depth int) any {
	var v any = "x"
	for range depth {
		v = []any{v}
	}
	return v
}

// Over a resolver that keeps the resolver.Resolver contract, Resolve answers
// with a document or an error, a document it cannot hash too.
func TestDIDResolver_ReturnsADocumentOrAnError(t *testing.T) {
	const (
		present  = "did:dplaax:poc.dplaax.dev:org:acme"
		unhashed = "did:dplaax:poc.dplaax.dev:org:deep"
	)
	next := local.New()
	next.Add(did.New(did.DocumentFields{ID: present}))
	next.Add(did.New(did.DocumentFields{
		ID: unhashed,
		VerificationMethod: []did.VerificationMethod{{
			ID: unhashed + "#k", Type: "JsonWebKey2020", Controller: unhashed,
			PublicKeyJWK: map[string]any{"kty": "OKP", "deep": deep(jsondepth.Max + 1)},
		}},
	}))
	r := inputcapture.DIDResolver{Next: next}
	if _, err := r.Resolve(context.Background(), unhashed); err == nil {
		t.Fatal("a document nested too deep to hash: resolved, want the hash's error")
	}
	for _, d := range []string{present, unhashed, "did:dplaax:poc.dplaax.dev:org:absent"} {
		if doc, err := r.Resolve(context.Background(), d); doc == nil && err == nil {
			t.Errorf("Resolve(%q): neither a document nor an error", d)
		}
	}
}
