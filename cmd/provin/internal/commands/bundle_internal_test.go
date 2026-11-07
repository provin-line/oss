package commands

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	auditpb "github.com/provin-line/oss/gen/go/dplaax/audit/v1"
	"github.com/provin-line/oss/gen/go/dplaax/audit/v1/auditpbconnect"
	vcpb "github.com/provin-line/oss/gen/go/dplaax/vc/v1"
	"github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
	"github.com/provin-line/oss/network/pkg/core"
)

const issuerOfTest = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1"

// issuerServer answers as an issuer's endpoint: release, when not nil, makes
// every call wait until the test ends, ignoring the client's deadline.
type issuerServer struct {
	vcpbconnect.UnimplementedVCResolverServiceHandler
	auditpbconnect.UnimplementedAuditServiceHandler
	release chan struct{}
	size    int
}

func (s issuerServer) ResolveVC(context.Context, *connect.Request[vcpb.ResolveVCRequest]) (*connect.Response[vcpb.ResolveVCResponse], error) {
	if s.release != nil {
		<-s.release
		return nil, errors.New("released")
	}
	return connect.NewResponse(&vcpb.ResolveVCResponse{Credential: bytes.Repeat([]byte("x"), s.size)}), nil
}

func (s issuerServer) GetConsumedSources(context.Context, *connect.Request[auditpb.GetConsumedSourcesRequest]) (*connect.Response[auditpb.GetConsumedSourcesResponse], error) {
	<-s.release
	return nil, errors.New("released")
}

func issuerSource(t *testing.T, srv issuerServer) *wireConsumedSource {
	t.Helper()
	_, vh := vcpbconnect.NewVCResolverServiceHandler(srv)
	vcSrv := httptest.NewServer(vh)
	t.Cleanup(vcSrv.Close)
	_, ah := auditpbconnect.NewAuditServiceHandler(srv)
	auditSrv := httptest.NewServer(ah)
	t.Cleanup(auditSrv.Close)
	if srv.release != nil {
		t.Cleanup(func() { close(srv.release) }) // runs before the servers close
	}
	return &wireConsumedSource{
		token:       "tok",
		guard:       core.NewURLGuard(core.WithAllowLoopback(true)),
		vcResolver:  map[string]string{"poc.dplaax.dev": vcSrv.URL},
		auditBases:  map[string]string{"poc.dplaax.dev": auditSrv.URL},
		audit:       map[string]auditClient{},
		vcs:         map[string]vcpbconnect.VCResolverServiceClient{},
		callTimeout: 50 * time.Millisecond,
	}
}

// An issuer's endpoint is another organization's server: a response larger
// than the client reads is refused.
func TestFetchSourceCredential_RefusesAnOversizedResponse(t *testing.T) {
	s := issuerSource(t, issuerServer{size: issuerReadMaxBytes + 1})
	_, err := s.FetchSourceCredential(context.Background(), issuerOfTest, "sha256:"+strings.Repeat("a", 64))
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("oversized credential: err = %v, want resource_exhausted", err)
	}
}

// Every call to an issuer's endpoint ends within the call timeout, under a
// context that is never cancelled.
func TestWireConsumedSource_IssuerCallsEndWithinTheTimeout(t *testing.T) {
	s := issuerSource(t, issuerServer{release: make(chan struct{})})
	ctx := context.WithoutCancel(context.Background())
	for name, call := range map[string]func() error{
		"FetchSourceCredential": func() error {
			_, err := s.FetchSourceCredential(ctx, issuerOfTest, "sha256:"+strings.Repeat("a", 64))
			return err
		},
		"FetchConsumed": func() error {
			_, err := s.FetchConsumed(ctx, issuerOfTest, "sha256:"+strings.Repeat("b", 64))
			return err
		},
	} {
		done := make(chan error, 1)
		go func() { done <- call() }()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s: silent issuer: want error", name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: still waiting after 5s", name)
		}
	}
}

// A source built without a timeout of its own, as BundleExport builds it,
// bounds every call with issuerCallTimeout.
func TestWireConsumedSource_DefaultsToIssuerCallTimeout(t *testing.T) {
	ctx, cancel := (&wireConsumedSource{}).issuerCall(context.Background())
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > issuerCallTimeout || time.Until(deadline) < issuerCallTimeout-time.Second {
		t.Fatalf("deadline = %v (ok %v), want about %s from now", deadline, ok, issuerCallTimeout)
	}
}
