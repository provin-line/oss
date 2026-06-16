package handler_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"connectrpc.com/connect"

	vcpb "github.com/provin-line/oss/gen/go/dplaax/vc/v1"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/handler"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
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
