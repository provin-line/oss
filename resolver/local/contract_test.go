package local_test

import (
	"context"
	"testing"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/resolver/local"
)

// Resolve answers with a document or an error, never with neither
// (resolver.Resolver).
func TestResolve_ReturnsADocumentOrAnError(t *testing.T) {
	const present = "did:dplaax:poc.dplaax.dev:org:acme"
	r := local.New()
	r.Add(did.New(did.DocumentFields{ID: present}))
	for _, d := range []string{present, "did:dplaax:poc.dplaax.dev:org:absent", ""} {
		if doc, err := r.Resolve(context.Background(), d); doc == nil && err == nil {
			t.Errorf("Resolve(%q): neither a document nor an error", d)
		}
	}
}
