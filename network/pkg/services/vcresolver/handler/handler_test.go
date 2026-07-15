package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"connectrpc.com/connect"

	vcpb "github.com/provin-line/oss/gen/go/dplaax/vc/v1"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/handler"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/vc"
)

func newHandler() *handler.Handler {
	return handler.New(vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), memstore.NewPool()))
}

func TestHandler_StoreVC_ErrorCodes(t *testing.T) {
	h := newHandler()
	// Malformed credential bytes → InvalidArgument.
	_, err := h.StoreVC(context.Background(), connect.NewRequest(&vcpb.StoreVCRequest{Credential: []byte("not json")}))
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Errorf("malformed credential: code = %v, want InvalidArgument (%v)", got, err)
	}
	// Non-string previousCredential → InvalidArgument (not silent chain-origin).
	bad, _ := json.Marshal(map[string]any{
		"issuer":            "did:dplaax:poc.dplaax.dev:org:acme",
		"credentialSubject": map[string]any{"previousCredential": 123},
	})
	_, err = h.StoreVC(context.Background(), connect.NewRequest(&vcpb.StoreVCRequest{Credential: bad}))
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Errorf("malformed previousCredential: code = %v, want InvalidArgument (%v)", got, err)
	}
}

// ResolveVC must serve the JCS-canonical bytes (PipelinePassCredential.MarshalJSON),
// not encoding/json.Marshal output, which re-escapes <, >, & — breaking the wire
// contract that a consumer can recompute the content address from the bytes it
// receives (issue #1). Mirror of client.TestStoreCredential_SendsCanonicalBytes.
func TestHandler_ResolveVC_ServesCanonicalBytes(t *testing.T) {
	h := newHandler()
	ctx := context.Background()

	// A credential body carrying <, >, & in a string value — JCS keeps them literal,
	// encoding/json.Marshal escapes them to < > &.
	b, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:dplaax:poc.dplaax.dev:org:acme",
		"credentialSubject": map[string]any{"pipelineId": "p1", "processId": "a<b>c&d"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var c vc.PipelinePassCredential
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	canonical, err := c.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	storeResp, err := h.StoreVC(ctx, connect.NewRequest(&vcpb.StoreVCRequest{Credential: canonical}))
	if err != nil {
		t.Fatalf("StoreVC: %v", err)
	}
	resolveResp, err := h.ResolveVC(ctx, connect.NewRequest(&vcpb.ResolveVCRequest{Hash: storeResp.Msg.GetHash()}))
	if err != nil {
		t.Fatalf("ResolveVC: %v", err)
	}

	if got := resolveResp.Msg.GetCredential(); !bytes.Equal(got, canonical) {
		t.Errorf("ResolveVC served non-canonical bytes:\n got = %s\nwant = %s", got, canonical)
	}
}

func TestHandler_ResolveVC_ErrorCodes(t *testing.T) {
	h := newHandler()
	// Malformed hash → InvalidArgument.
	_, err := h.ResolveVC(context.Background(), connect.NewRequest(&vcpb.ResolveVCRequest{Hash: "not-a-hash"}))
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Errorf("bad hash: code = %v, want InvalidArgument (%v)", got, err)
	}
	// Well-formed miss → NotFound.
	_, err = h.ResolveVC(context.Background(), connect.NewRequest(&vcpb.ResolveVCRequest{Hash: "sha256:" + strings.Repeat("a", 64)}))
	if got := connect.CodeOf(err); got != connect.CodeNotFound {
		t.Errorf("absent: code = %v, want NotFound (%v)", got, err)
	}
}

// wireCred builds minimal wire-form credential bytes with an optional
// previousCredential link (processID keeps hashes distinct).
func wireCred(t *testing.T, processID, prev string) []byte {
	t.Helper()
	subject := map[string]any{"pipelineId": "p1", "processId": processID}
	if prev != "" {
		subject["previousCredential"] = prev
	}
	// canonicalizer-hygiene-exempt: test fixture bytes, re-canonicalized by StoreVC.
	b, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:s1",
		"credentialSubject": subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func storeWire(t *testing.T, h *handler.Handler, b []byte) string {
	t.Helper()
	resp, err := h.StoreVC(context.Background(), connect.NewRequest(&vcpb.StoreVCRequest{Credential: b}))
	if err != nil {
		t.Fatalf("StoreVC: %v", err)
	}
	return resp.Msg.GetHash()
}

func TestHandler_ListSuccessors_PagingAndTokens(t *testing.T) {
	ctx := context.Background()
	h := newHandler()
	origin := storeWire(t, h, wireCred(t, "origin", ""))
	c1 := storeWire(t, h, wireCred(t, "childA", origin))
	c2 := storeWire(t, h, wireCred(t, "childB", origin))
	first, second := c1, c2
	if first > second {
		first, second = second, first
	}

	page1, err := h.ListSuccessors(ctx, connect.NewRequest(&vcpb.ListSuccessorsRequest{Hash: origin, PageSize: 1}))
	if err != nil {
		t.Fatalf("ListSuccessors: %v", err)
	}
	if got := page1.Msg.GetSuccessors(); len(got) != 1 || got[0] != first {
		t.Fatalf("page1 = %v, want [%s]", got, first)
	}
	tok := page1.Msg.GetNextPageToken()
	if tok == "" {
		t.Fatal("page1 must issue a continuation token")
	}
	page2, err := h.ListSuccessors(ctx, connect.NewRequest(&vcpb.ListSuccessorsRequest{Hash: origin, PageSize: 1, PageToken: tok}))
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if got := page2.Msg.GetSuccessors(); len(got) != 1 || got[0] != second {
		t.Fatalf("page2 = %v, want [%s]", got, second)
	}

	// A continuation replayed against a DIFFERENT hash must be rejected,
	// never silently resume the other hash's listing.
	if _, err := h.ListSuccessors(ctx, connect.NewRequest(&vcpb.ListSuccessorsRequest{Hash: c1, PageToken: tok})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("cross-hash token replay: code = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// Childless hash: empty page, no token, success.
	leaf, err := h.ListSuccessors(ctx, connect.NewRequest(&vcpb.ListSuccessorsRequest{Hash: c2}))
	if err != nil || len(leaf.Msg.GetSuccessors()) != 0 || leaf.Msg.GetNextPageToken() != "" {
		t.Fatalf("childless = %+v (err %v), want empty page without token", leaf.Msg, err)
	}
}

func TestHandler_ListSuccessors_InvalidInputs(t *testing.T) {
	ctx := context.Background()
	h := newHandler()
	origin := storeWire(t, h, wireCred(t, "origin", ""))
	for _, req := range []*vcpb.ListSuccessorsRequest{
		{Hash: "not-a-hash"},
		{Hash: origin, PageSize: -1},
		{Hash: origin, PageToken: "garbage!!!"},
	} {
		if _, err := h.ListSuccessors(ctx, connect.NewRequest(req)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("req %+v: code = %v, want InvalidArgument", req, connect.CodeOf(err))
		}
	}
}

// signedVariantWire builds one signed form of a fixed body; distinct
// proofValues are distinct variants of that one body.
func signedVariantWire(t *testing.T, proofValue string) []byte {
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
	canonical, err := c.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func storeVariant(t *testing.T, h *handler.Handler, wire []byte) *vcpb.StoreVCResponse {
	t.Helper()
	res, err := h.StoreVC(context.Background(), connect.NewRequest(&vcpb.StoreVCRequest{Credential: wire}))
	if err != nil {
		t.Fatalf("StoreVC: %v", err)
	}
	return res.Msg
}

// TestHandler_ExactFetchIsByteIdentical is the wire-level statement of what
// evidence means: what a peer sends comes back byte-for-byte, through the RPC
// boundary, under the id the server named for it. If this drifts, a verdict
// cannot be reproduced from what an auditor fetched.
func TestHandler_ExactFetchIsByteIdentical(t *testing.T) {
	ctx := context.Background()
	h := newHandler()
	a, b := signedVariantWire(t, "zA"), signedVariantWire(t, "zB")
	resA, resB := storeVariant(t, h, a), storeVariant(t, h, b)

	if resA.GetHash() != resB.GetHash() {
		t.Fatalf("two proofs over one body got different hashes: %s vs %s", resA.GetHash(), resB.GetHash())
	}
	if resA.GetWireVariantId() == resB.GetWireVariantId() {
		t.Fatal("two different proofs got the same variant id")
	}
	for _, tc := range []struct {
		variant string
		want    []byte
	}{{resA.GetWireVariantId(), a}, {resB.GetWireVariantId(), b}} {
		got, err := h.ResolveVariant(ctx, connect.NewRequest(&vcpb.ResolveVariantRequest{
			BodyAddress: resA.GetHash(), WireVariantId: tc.variant,
		}))
		if err != nil {
			t.Fatalf("ResolveVariant(%s): %v", tc.variant, err)
		}
		if !bytes.Equal(got.Msg.GetCredential(), tc.want) {
			t.Errorf("ResolveVariant(%s) =\n%s\nwant\n%s", tc.variant, got.Msg.GetCredential(), tc.want)
		}
	}
}

// TestHandler_ResolveVCNamesTheVariantItServed: the body-only read is
// provisional, so it says which variant it chose — that id is how a consumer
// pins the document it just saw.
func TestHandler_ResolveVCNamesTheVariantItServed(t *testing.T) {
	ctx := context.Background()
	h := newHandler()
	stored := storeVariant(t, h, signedVariantWire(t, "zA"))

	got, err := h.ResolveVC(ctx, connect.NewRequest(&vcpb.ResolveVCRequest{Hash: stored.GetHash()}))
	if err != nil {
		t.Fatalf("ResolveVC: %v", err)
	}
	if got.Msg.GetWireVariantId() != stored.GetWireVariantId() {
		t.Errorf("ResolveVC named variant %q, want %q", got.Msg.GetWireVariantId(), stored.GetWireVariantId())
	}
	// ...and that id fetches exactly the bytes it just served.
	exact, err := h.ResolveVariant(ctx, connect.NewRequest(&vcpb.ResolveVariantRequest{
		BodyAddress: stored.GetHash(), WireVariantId: got.Msg.GetWireVariantId(),
	}))
	if err != nil {
		t.Fatalf("ResolveVariant: %v", err)
	}
	if !bytes.Equal(exact.Msg.GetCredential(), got.Msg.GetCredential()) {
		t.Error("the variant ResolveVC named does not fetch the bytes it served")
	}
}

func TestHandler_ResolveVariant_ErrorCodes(t *testing.T) {
	ctx := context.Background()
	h := newHandler()
	stored := storeVariant(t, h, signedVariantWire(t, "zA"))
	absentVariant := vc.WireVariantIDFromHex(strings.Repeat("0", 64))
	absentBody := "sha256:" + strings.Repeat("0", 64)

	tests := []struct {
		name          string
		body, variant string
		want          connect.Code
	}{
		{"unheld variant of a held body", stored.GetHash(), absentVariant, connect.CodeNotFound},
		{"unheld body", absentBody, stored.GetWireVariantId(), connect.CodeNotFound},
		{"malformed body", "not-a-hash", stored.GetWireVariantId(), connect.CodeInvalidArgument},
		{"malformed variant", stored.GetHash(), "not-a-variant", connect.CodeInvalidArgument},
		{"a content address where a variant id belongs", stored.GetHash(), stored.GetHash(), connect.CodeInvalidArgument},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.ResolveVariant(ctx, connect.NewRequest(&vcpb.ResolveVariantRequest{
				BodyAddress: tc.body, WireVariantId: tc.variant,
			}))
			if got := connect.CodeOf(err); got != tc.want {
				t.Errorf("code = %v, want %v (err %v)", got, tc.want, err)
			}
		})
	}
}

// TestHandler_ListVariants_TokenIsBoundToItsBody: a continuation replayed
// against another body must be refused, never silently answered — a token is
// not a licence to list something else.
func TestHandler_ListVariants_TokenIsBoundToItsBody(t *testing.T) {
	ctx := context.Background()
	h := newHandler()
	stored := storeVariant(t, h, signedVariantWire(t, "zA"))
	storeVariant(t, h, signedVariantWire(t, "zB"))

	first, err := h.ListVariants(ctx, connect.NewRequest(&vcpb.ListVariantsRequest{
		BodyAddress: stored.GetHash(), PageSize: 1,
	}))
	if err != nil {
		t.Fatalf("ListVariants: %v", err)
	}
	if len(first.Msg.GetWireVariantIds()) != 1 || first.Msg.GetNextPageToken() == "" {
		t.Fatalf("first page = %v token=%q, want one id and a continuation", first.Msg.GetWireVariantIds(), first.Msg.GetNextPageToken())
	}
	second, err := h.ListVariants(ctx, connect.NewRequest(&vcpb.ListVariantsRequest{
		BodyAddress: stored.GetHash(), PageSize: 1, PageToken: first.Msg.GetNextPageToken(),
	}))
	if err != nil {
		t.Fatalf("ListVariants (page 2): %v", err)
	}
	if len(second.Msg.GetWireVariantIds()) != 1 {
		t.Fatalf("second page = %v, want one id", second.Msg.GetWireVariantIds())
	}
	if second.Msg.GetWireVariantIds()[0] == first.Msg.GetWireVariantIds()[0] {
		t.Error("the cursor is not exclusive: page 2 repeats page 1")
	}
	if second.Msg.GetNextPageToken() != "" {
		t.Error("the listing is exhausted but still offers a continuation")
	}

	// The same token against a different body: refused.
	otherBody := "sha256:" + strings.Repeat("1", 64)
	_, err = h.ListVariants(ctx, connect.NewRequest(&vcpb.ListVariantsRequest{
		BodyAddress: otherBody, PageSize: 1, PageToken: first.Msg.GetNextPageToken(),
	}))
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Errorf("token replayed against another body: code = %v, want InvalidArgument", got)
	}
}

// TestHandler_ListVariants_UnknownBodyIsAnEmptyPage: holding no variants is a
// normal answer scoped to this node, not a claim that none exist.
func TestHandler_ListVariants_UnknownBodyIsAnEmptyPage(t *testing.T) {
	h := newHandler()
	got, err := h.ListVariants(context.Background(), connect.NewRequest(&vcpb.ListVariantsRequest{
		BodyAddress: "sha256:" + strings.Repeat("0", 64),
	}))
	if err != nil {
		t.Fatalf("ListVariants(unknown body) = %v, want an empty page", err)
	}
	if len(got.Msg.GetWireVariantIds()) != 0 || got.Msg.GetNextPageToken() != "" {
		t.Errorf("unknown body = %v token=%q, want empty", got.Msg.GetWireVariantIds(), got.Msg.GetNextPageToken())
	}
	if _, err := h.ListVariants(context.Background(), connect.NewRequest(&vcpb.ListVariantsRequest{
		BodyAddress: "sha256:" + strings.Repeat("0", 64), PageSize: -1,
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("negative page size: code = %v, want InvalidArgument", connect.CodeOf(err))
	}
}
