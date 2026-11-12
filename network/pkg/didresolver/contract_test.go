package didresolver_test

import (
	"context"
	"testing"

	"github.com/provin-line/oss/network/pkg/core"
)

// Resolve answers with a document or an error, never with neither
// (resolver.Resolver), whatever the registry answers.
func TestResolve_ReturnsADocumentOrAnError(t *testing.T) {
	for name, c := range map[string]struct {
		stub  *stub
		guard *core.URLGuard
		did   string
	}{
		"a document":                    {stub: &stub{}},
		"not found":                     {stub: &stub{notFound: true}},
		"a server error":                {stub: &stub{serverError: true}},
		"an oversized document":         {stub: &stub{oversized: true}},
		"another DID's document":        {stub: &stub{docID: "did:dplaax:poc.dplaax.dev:org:other"}},
		"a DID that does not parse":     {stub: &stub{}, did: "did:dplaax:"},
		"an endpoint the guard refuses": {stub: &stub{}, guard: core.NewURLGuard()},
	} {
		guard, d := c.guard, c.did
		if guard == nil {
			guard = loopbackGuard()
		}
		if d == "" {
			d = testDID
		}
		r := newResolver(t, c.stub, guard)
		if doc, err := r.Resolve(context.Background(), d); doc == nil && err == nil {
			t.Errorf("%s: neither a document nor an error", name)
		}
	}
}
