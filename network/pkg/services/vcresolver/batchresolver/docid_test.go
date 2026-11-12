package batchresolver

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/vc"
)

// otherIssuersDoc is another DID's document, advertising its own #vc-resolver
// endpoint ep under the bare fragment.
func otherIssuersDoc(id, ep string) *did.DIDDocument {
	return did.New(did.DocumentFields{
		ID: id,
		Service: []did.ServiceEndpoint{{
			ID: "#vc-resolver", Type: "VCResolver", ServiceEndpoint: ep,
		}},
	})
}

// An issuer whose resolved document is another DID's derives no endpoint: the
// entry is fetched from nowhere and, with its retry budget left, kept.
func TestDrainOnce_IssuerDocumentOfAnotherDID_DerivesNoEndpoint(t *testing.T) {
	pool, svc := newWiring()
	ctx := context.Background()
	p := credOf(t, "")
	h := credOf(t, hashOf(t, p))
	if _, err := svc.StoreVC(ctx, mustJSON(t, h), "", 0); err != nil { // empty hint
		t.Fatal(err)
	}
	const other = "https://other.example/vc"
	fetch := &fakeFetcher{fn: func(context.Context, string, string) (*vc.PipelinePassCredential, error) { return p, nil }}
	r, _ := New(pool, svc, fetch, fakeDID{doc: otherIssuersDoc("did:dplaax:poc.dplaax.dev:org:other:pipeline:p1:process:x", other)}, fakeGuard{}, okConfig())
	if err := r.drainOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fetch.calls) != 0 {
		t.Errorf("fetch calls = %v, want none", fetch.calls)
	}
	rem, _ := pool.ListNewest(10)
	if len(rem) != 1 || rem[0].RetryCount != 1 {
		t.Errorf("entry = %+v, want retained with RetryCount 1", rem)
	}
}

// deriveIssuerEndpoint names the document's DID and the issuer within a bound,
// however long the id.
func TestDeriveIssuerEndpoint_NamesAnotherDIDsDocumentWithinABound(t *testing.T) {
	pool, svc := newWiring()
	long := "did:dplaax:poc.dplaax.dev:org:" + strings.Repeat("x", 64<<10)
	r, _ := New(pool, svc, &fakeFetcher{}, fakeDID{doc: otherIssuersDoc(long, "https://other.example/vc")}, fakeGuard{}, okConfig())
	ep, err := r.deriveIssuerEndpoint(context.Background(), issuer)
	if ep != "" || err == nil || len(err.Error()) > 1024 || !strings.Contains(err.Error(), fmt.Sprintf("(%d bytes)", len(long))) {
		t.Errorf("deriveIssuerEndpoint = %q, %.200v (%d bytes), want no endpoint and an error naming the id's head and length", ep, err, len(fmt.Sprint(err)))
	}
}
