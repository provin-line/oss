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
	return handler.New(vcresolver.New(memstore.NewStore(), memstore.NewPool()))
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
