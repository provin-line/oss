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
