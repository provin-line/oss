package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	vcpb "github.com/provin-line/oss/gen/go/dplaax/vc/v1"
	"github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/client"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/handler"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/vc"
)

const issuer = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1"

// wireResolver stands up an in-process VCResolverService over an in-memory store
// and returns a client-side *client.Resolver that reaches it over a real Connect
// server.
func wireResolver(t *testing.T) *client.Resolver {
	t.Helper()
	svc := vcresolver.New(memstore.NewStore(), memstore.NewPool())
	_, h := vcpbconnect.NewVCResolverServiceHandler(handler.New(svc))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return client.New(vcpbconnect.NewVCResolverServiceClient(srv.Client(), srv.URL))
}

// cred builds a PipelinePassCredential, optionally linking a previousCredential.
func cred(t *testing.T, prev any) *vc.PipelinePassCredential {
	t.Helper()
	subject := map[string]any{"pipelineId": "p1", "processId": "proc1"}
	if prev != nil {
		subject["previousCredential"] = prev
	}
	b, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            issuer,
		"credentialSubject": subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	var c vc.PipelinePassCredential
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

// StoreCredential returns the server-recomputed content address, which must equal
// the credential's own Hash(); ResolveCredential then round-trips it back.
func TestStoreAndResolve_RoundTrip(t *testing.T) {
	r := wireResolver(t)
	ctx := context.Background()
	c := cred(t, nil)

	want, err := c.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	addr, err := r.StoreCredential(ctx, c, "")
	if err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}
	if addr != want {
		t.Fatalf("StoreCredential addr = %q, want %q", addr, want)
	}

	got, err := r.ResolveCredential(ctx, addr)
	if err != nil {
		t.Fatalf("ResolveCredential: %v", err)
	}
	gotHash, err := got.Hash()
	if err != nil {
		t.Fatalf("resolved Hash: %v", err)
	}
	if gotHash != want {
		t.Fatalf("resolved hash = %q, want %q", gotHash, want)
	}
	if got.Issuer() != issuer {
		t.Fatalf("resolved issuer = %q, want %q", got.Issuer(), issuer)
	}
}

// A well-formed but absent content address resolves to an error (chainwalk turns
// it into a chain hole → indeterminate).
func TestResolveCredential_Absent_IsError(t *testing.T) {
	r := wireResolver(t)
	absent := "sha256:" + strings.Repeat("b", 64)
	if _, err := r.ResolveCredential(context.Background(), absent); err == nil {
		t.Fatal("ResolveCredential(absent): want error, got nil")
	}
}

// A malformed (non-content-address) hash is an error, not a nil credential.
func TestResolveCredential_MalformedHash_IsError(t *testing.T) {
	r := wireResolver(t)
	if _, err := r.ResolveCredential(context.Background(), "not-a-hash"); err == nil {
		t.Fatal("ResolveCredential(malformed): want error, got nil")
	}
}

// A chained credential (linking a predecessor by content address) survives the
// store's strict previousCredential decode and round-trips.
func TestStoreAndResolve_LinkedCredential(t *testing.T) {
	r := wireResolver(t)
	ctx := context.Background()
	prevAddr := "sha256:" + strings.Repeat("a", 64)
	c := cred(t, prevAddr)

	addr, err := r.StoreCredential(ctx, c, "https://upstream.example/")
	if err != nil {
		t.Fatalf("StoreCredential(linked): %v", err)
	}
	got, err := r.ResolveCredential(ctx, addr)
	if err != nil {
		t.Fatalf("ResolveCredential(linked): %v", err)
	}
	if got.PreviousCredential() != prevAddr {
		t.Fatalf("resolved previousCredential = %q, want %q", got.PreviousCredential(), prevAddr)
	}
}

// capturingClient records the StoreVC request bytes so a test can assert exactly what
// reached the wire. ResolveVC is unused here.
type capturingClient struct{ stored []byte }

func (c *capturingClient) StoreVC(_ context.Context, req *connect.Request[vcpb.StoreVCRequest]) (*connect.Response[vcpb.StoreVCResponse], error) {
	c.stored = req.Msg.GetCredential()
	return connect.NewResponse(&vcpb.StoreVCResponse{Hash: "sha256:" + strings.Repeat("0", 64)}), nil
}

func (c *capturingClient) ResolveVC(_ context.Context, _ *connect.Request[vcpb.ResolveVCRequest]) (*connect.Response[vcpb.ResolveVCResponse], error) {
	return nil, errors.New("not used")
}

// StoreCredential must put the credential's JCS-canonical bytes on the wire — the same
// bytes MarshalJSON produces (as the envelope codec does). encoding/json.Marshal would
// re-escape <, >, & to <>&, breaking canonical-byte consumers; a field
// value with "&" pins that down.
func TestStoreCredential_SendsCanonicalBytes(t *testing.T) {
	b, _ := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            issuer,
		"credentialSubject": map[string]any{"pipelineId": "p1", "processId": "a&b<c>"},
	})
	var c vc.PipelinePassCredential
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	want, err := c.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	cap := &capturingClient{}
	r := client.New(cap)
	_, _ = r.StoreCredential(context.Background(), &c, "") // bogus hash returned => err ignored; we assert bytes

	if !bytes.Equal(cap.stored, want) {
		t.Fatalf("wire bytes are not canonical:\n got  %s\n want %s", cap.stored, want)
	}
}
