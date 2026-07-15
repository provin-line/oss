package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	vcpb "github.com/provin-line/oss/gen/go/dplaax/vc/v1"
	"github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	vcresolverclient "github.com/provin-line/oss/network/pkg/services/vcresolver/client"
	vcfilestore "github.com/provin-line/oss/network/pkg/services/vcresolver/filestore"
	vchandler "github.com/provin-line/oss/network/pkg/services/vcresolver/handler"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/vc"
)

// The end-to-end statement of what this slice bought, over real HTTP against
// the durable store: two signed forms of ONE body both survive, and each is
// fetchable byte-for-byte.
//
// Before this, the second publish overwrote the first — so a valid proof could
// be evicted by a later invalid one, and an invalid proof arriving first could
// keep the valid one out. There was no way to ask for a specific one, because
// only one existed.

// variantE2E is an embedded VCResolverService over the FILE backend (the
// substrate a node actually runs), reachable through the production client.
type variantE2E struct {
	client *vcresolverclient.Resolver
	raw    vcpbconnect.VCResolverServiceClient
}

func newVariantE2E(t *testing.T) variantE2E {
	t.Helper()
	backend, err := vcfilestore.NewBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	svc := vcresolver.New(vcresolver.NewVariantStore(backend), memstore.NewPool())
	_, h := vcpbconnect.NewVCResolverServiceHandler(vchandler.New(svc))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	raw := vcpbconnect.NewVCResolverServiceClient(srv.Client(), srv.URL)
	return variantE2E{client: vcresolverclient.New(raw), raw: raw}
}

// variantCred builds one signed form of a fixed body. Different proofValues are
// different variants of the SAME body — the shape a proof re-issue produces.
func variantCred(t *testing.T, proofValue string) *vc.PipelinePassCredential {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:s1",
		"credentialSubject": map[string]any{"pipelineId": "p1", "processId": "s1"},
		"proof": map[string]any{
			"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
			"verificationMethod": "did:dplaax:poc.dplaax.dev:org:acme#signing",
			"proofPurpose":       "assertionMethod", "created": "2026-07-01T00:00:01Z",
			"proofValue": proofValue,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var c vc.PipelinePassCredential
	if err := c.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	return &c
}

func TestE2E_TwoProofsOfOneBodyBothSurviveAndFetchExactly(t *testing.T) {
	ctx := context.Background()
	e := newVariantE2E(t)
	first, second := variantCred(t, "zFirstProof"), variantCred(t, "zSecondProof")

	storedFirst, err := e.client.StoreCredential(ctx, first, "")
	if err != nil {
		t.Fatalf("publish the first proof: %v", err)
	}
	storedSecond, err := e.client.StoreCredential(ctx, second, "")
	if err != nil {
		t.Fatalf("publish the second proof: %v", err)
	}

	if storedFirst.BodyAddress != storedSecond.BodyAddress {
		t.Fatalf("two proofs of one body got different addresses: %s vs %s", storedFirst.BodyAddress, storedSecond.BodyAddress)
	}
	if storedFirst.WireVariantID == storedSecond.WireVariantID {
		t.Fatal("two different proofs got one variant id")
	}

	// The first proof is still there, byte-for-byte, after the second landed.
	// This is the eviction that used to happen.
	for _, tc := range []struct {
		name    string
		cred    *vc.PipelinePassCredential
		variant string
	}{
		{"first", first, storedFirst.WireVariantID},
		{"second", second, storedSecond.WireVariantID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := e.raw.ResolveVariant(ctx, connect.NewRequest(&vcpb.ResolveVariantRequest{
				BodyAddress: storedFirst.BodyAddress, WireVariantId: tc.variant,
			}))
			if err != nil {
				t.Fatalf("ResolveVariant: %v", err)
			}
			want, err := tc.cred.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			if string(got.Msg.GetCredential()) != string(want) {
				t.Errorf("ResolveVariant returned\n%s\nwant\n%s", got.Msg.GetCredential(), want)
			}
		})
	}

	// Both are enumerable under the body...
	list, err := e.raw.ListVariants(ctx, connect.NewRequest(&vcpb.ListVariantsRequest{BodyAddress: storedFirst.BodyAddress}))
	if err != nil {
		t.Fatalf("ListVariants: %v", err)
	}
	if len(list.Msg.GetWireVariantIds()) != 2 {
		t.Errorf("the body holds %v, want both variants", list.Msg.GetWireVariantIds())
	}

	// ...and the body-only read still answers, with one of them, saying which.
	resolved, err := e.client.ResolveCredential(ctx, storedFirst.BodyAddress)
	if err != nil {
		t.Fatalf("ResolveCredential: %v", err)
	}
	if got, err := resolved.Hash(); err != nil || got != storedFirst.BodyAddress {
		t.Errorf("the projection served body %s (err %v), want %s", got, err, storedFirst.BodyAddress)
	}
	named, err := e.raw.ResolveVC(ctx, connect.NewRequest(&vcpb.ResolveVCRequest{Hash: storedFirst.BodyAddress}))
	if err != nil {
		t.Fatalf("ResolveVC: %v", err)
	}
	servedID := named.Msg.GetWireVariantId()
	if servedID != storedFirst.WireVariantID && servedID != storedSecond.WireVariantID {
		t.Errorf("the projection named %q, which is neither variant", servedID)
	}
	exact, err := e.raw.ResolveVariant(ctx, connect.NewRequest(&vcpb.ResolveVariantRequest{
		BodyAddress: storedFirst.BodyAddress, WireVariantId: servedID,
	}))
	if err != nil {
		t.Fatalf("ResolveVariant on the named variant: %v", err)
	}
	if string(exact.Msg.GetCredential()) != string(named.Msg.GetCredential()) {
		t.Error("the variant the projection named does not fetch the bytes it served")
	}
}

// TestE2E_RepublishingTheSameProofIsIdempotent: a retry — the same bytes again —
// must not be an error and must not duplicate. Publishers retry.
func TestE2E_RepublishingTheSameProofIsIdempotent(t *testing.T) {
	ctx := context.Background()
	e := newVariantE2E(t)
	cred := variantCred(t, "zRetried")

	first, err := e.client.StoreCredential(ctx, cred, "")
	if err != nil {
		t.Fatalf("first publish: %v", err)
	}
	again, err := e.client.StoreCredential(ctx, cred, "")
	if err != nil {
		t.Fatalf("re-publishing identical bytes must be idempotent: %v", err)
	}
	if first != again {
		t.Errorf("the retry got %+v, want %+v", again, first)
	}
	list, err := e.raw.ListVariants(ctx, connect.NewRequest(&vcpb.ListVariantsRequest{BodyAddress: first.BodyAddress}))
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Msg.GetWireVariantIds()) != 1 {
		t.Errorf("the retry duplicated the variant: %v", list.Msg.GetWireVariantIds())
	}
}
