package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	auditpb "github.com/provin-line/oss/gen/go/dplaax/audit/v1"
	"github.com/provin-line/oss/gen/go/dplaax/audit/v1/auditpbconnect"
	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	tlogpb "github.com/provin-line/oss/gen/go/dplaax/tlog/v1"
	"github.com/provin-line/oss/gen/go/dplaax/tlog/v1/tlogpbconnect"
	ksfilestore "github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/tlog"
)

func TestOwnNodeAudienceDerivedFromSigner(t *testing.T) {
	if got := ownNodeAudience("", "did:dplaax:home.example:org:o1:pipeline:p1:process:s1"); got != "home.example" {
		t.Errorf("derived audience = %q, want home.example", got)
	}
	if got := ownNodeAudience("", "not a did"); got != "" {
		t.Errorf("audience for an unparsable signer = %q, want empty (the call then fails before sending)", got)
	}
}

func TestOverrideWinsOverDerivedAudience(t *testing.T) {
	if got := ownNodeAudience("node.example", "did:dplaax:home.example:org:o1:pipeline:p1"); got != "node.example" {
		t.Errorf("own-node audience with an override = %q, want node.example", got)
	}
	loops := []pipelineconfig.LoopConfig{{
		Role: pipelineconfig.RoleSink, IngressSubject: "did:dplaax:up.example:org:o2:pipeline:p2",
		Sink: pipelineconfig.SinkConfig{UpstreamEndpoint: "https://up.example/p", PayloadDelivery: "by-reference", UpstreamRegistry: "node.example"},
	}}
	got, err := upstreamAudiences(loops)
	if err != nil {
		t.Fatalf("upstreamAudiences: %v", err)
	}
	if got["https://up.example/p"] != "node.example" {
		t.Errorf("upstream audience with an override = %q, want node.example", got["https://up.example/p"])
	}
}

func TestUpstreamAudienceDerivedFromIngressSubject(t *testing.T) {
	loops := []pipelineconfig.LoopConfig{
		{
			Role: pipelineconfig.RoleSink, IngressSubject: "did:dplaax:a.example:org:o:pipeline:pa",
			Sink: pipelineconfig.SinkConfig{UpstreamEndpoint: "https://a.example/p", PayloadDelivery: "by-reference"},
		},
		{
			Role: pipelineconfig.RoleChained, IngressSubject: "did:dplaax:b.example:org:o:pipeline:pb",
			Chained: pipelineconfig.ChainedConfig{UpstreamEndpoint: "https://b.example/p", PayloadDelivery: "by-reference"},
		},
		{
			Role: pipelineconfig.RoleAggregate,
			Aggregate: pipelineconfig.AggregateConfig{Ingresses: []pipelineconfig.AggregateIngress{
				{Subject: "did:dplaax:c.example:org:o:pipeline:pc", UpstreamEndpoint: "https://c.example/p", PayloadDelivery: "by-reference"},
				{Subject: "did:dplaax:d.example:org:o:pipeline:pd", UpstreamEndpoint: "https://d.example/p", PayloadDelivery: "inline"},
			}},
		},
		{
			Role: pipelineconfig.RoleSink, IngressSubject: "did:dplaax:e.example:org:o:pipeline:pe",
			Sink: pipelineconfig.SinkConfig{UpstreamEndpoint: "https://e.example/p", PayloadDelivery: "inline"},
		},
	}
	got, err := upstreamAudiences(loops)
	if err != nil {
		t.Fatalf("upstreamAudiences: %v", err)
	}
	want := map[string]string{"https://a.example/p": "a.example", "https://b.example/p": "b.example", "https://c.example/p": "c.example"}
	if len(got) != len(want) {
		t.Errorf("audiences = %v, want %v (inline ingresses fetch nothing)", got, want)
	}
	for ep, aud := range want {
		if got[ep] != aud {
			t.Errorf("audience of %s = %q, want %q", ep, got[ep], aud)
		}
	}
}

func TestUpstreamAudienceConflictFailsBoot(t *testing.T) {
	loops := []pipelineconfig.LoopConfig{
		{
			Role: pipelineconfig.RoleSink, IngressSubject: "did:dplaax:a.example:org:o:pipeline:pa",
			Sink: pipelineconfig.SinkConfig{UpstreamEndpoint: "https://shared.example/p", PayloadDelivery: "by-reference"},
		},
		{
			Role: pipelineconfig.RoleChained, IngressSubject: "did:dplaax:b.example:org:o:pipeline:pb",
			Chained: pipelineconfig.ChainedConfig{UpstreamEndpoint: "https://shared.example/p", PayloadDelivery: "by-reference"},
		},
	}
	if _, err := upstreamAudiences(loops); err == nil || !strings.Contains(err.Error(), "https://shared.example/p") {
		t.Fatalf("one endpoint, two audiences: %v, want a boot error naming the endpoint", err)
	}
}

func TestResolvePayloadUnknownEndpointFailsClosed(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	ks := newAuthKeyStore(t, wireNodeDID)
	factory := newPayloadClientFactory(ks, "", "", "", srv.Client(), 0)
	r := wireRetryingPayloadResolver{client: factory.For(wireNodeDID), audiences: map[string]string{"https://configured.example": "configured.example"}}
	if _, err := r.ResolvePayload(context.Background(), srv.URL, "sha256:00"); err == nil {
		t.Fatal("an endpoint no by-reference ingress configures was fetched")
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("%d requests reached the unconfigured endpoint, want 0", n)
	}
}

// reportCapture records the audience of each ReportEmitHealth proof.
type reportCapture struct {
	chainpbconnect.UnimplementedChainServiceHandler
	audience string
}

func (c *reportCapture) ReportEmitHealth(_ context.Context, req *connect.Request[chainpb.ReportEmitHealthRequest]) (*connect.Response[chainpb.ReportEmitHealthResponse], error) {
	c.audience = req.Msg.GetAuthProof().GetAudience()
	return connect.NewResponse(&chainpb.ReportEmitHealthResponse{}), nil
}

// The own-node clients the factories build sign for the derived audience, or
// for the override when one is configured.
func TestFactoriesSignForTheOwnNodeAudience(t *testing.T) {
	const publisher = "did:dplaax:home.example:org:o1:pipeline:p1"
	for name, c := range map[string]struct{ override, want string }{
		"derived":  {"", "home.example"},
		"override": {"node.example", "node.example"},
	} {
		t.Run(name, func(t *testing.T) {
			capture := &reportCapture{}
			path, h := chainpbconnect.NewChainServiceHandler(capture)
			mux := http.NewServeMux()
			mux.Handle(path, h)
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)
			f := newReportClientFactory(newAuthKeyStore(t, publisher), srv.URL, c.override, "", srv.Client())
			if _, err := f.For(publisher).ReportEmitHealth(context.Background(), publisher, true); err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("ReportEmitHealth: %v", err)
			}
			if capture.audience != c.want {
				t.Errorf("proof audience = %q, want %q", capture.audience, c.want)
			}
		})
	}
}

// newAuthKeyStore returns a keystore holding an #auth key for did.
func newAuthKeyStore(t *testing.T, did string) *ksfilestore.Store {
	t.Helper()
	ks := ksfilestore.New(t.TempDir())
	provisionAuthKey(t, ks, did)
	return ks
}

// mustUpstreamAudiences is upstreamAudiences for a test's config.
func mustUpstreamAudiences(t *testing.T, c *pipelineconfig.Config) map[string]string {
	t.Helper()
	m, err := upstreamAudiences(c.Loops)
	if err != nil {
		t.Fatalf("upstreamAudiences: %v", err)
	}
	return m
}

// auditCapture and mirrorCapture record the audience of the proof each
// own-node client signs.
type auditCapture struct {
	auditpbconnect.UnimplementedAuditServiceHandler
	audience string
}

func (c *auditCapture) RegisterAuditHead(_ context.Context, req *connect.Request[auditpb.RegisterAuditHeadRequest]) (*connect.Response[auditpb.RegisterAuditHeadResponse], error) {
	c.audience = req.Msg.GetAuthProof().GetAudience()
	return connect.NewResponse(&auditpb.RegisterAuditHeadResponse{}), nil
}

type mirrorCapture struct {
	tlogpbconnect.UnimplementedTlogServiceHandler
	audience string
}

func (c *mirrorCapture) MirrorLogSegment(_ context.Context, req *connect.Request[tlogpb.MirrorLogSegmentRequest]) (*connect.Response[tlogpb.MirrorLogSegmentResponse], error) {
	c.audience = req.Msg.GetAuthProof().GetAudience()
	return connect.NewResponse(&tlogpb.MirrorLogSegmentResponse{}), nil
}

// Every own-node factory signs for the derived audience, or for
// vc-store-registry when it is set.
func TestOwnNodeFactoriesHonorTheOverride(t *testing.T) {
	const signer = "did:dplaax:home.example:org:o1:pipeline:p1:process:s1"
	cases := map[string]struct{ override, want string }{
		"derived":  {"", "home.example"},
		"override": {"node.example", "node.example"},
	}
	for name, c := range cases {
		t.Run("audit/"+name, func(t *testing.T) {
			capture := &auditCapture{}
			path, h := auditpbconnect.NewAuditServiceHandler(capture)
			mux := http.NewServeMux()
			mux.Handle(path, h)
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)
			f := newAuditClientFactory(newAuthKeyStore(t, signer), srv.URL, c.override, "", srv.Client())
			if err := f.For(signer).RegisterAuditHead(context.Background(), addr("a")); err != nil {
				t.Fatalf("RegisterAuditHead: %v", err)
			}
			if capture.audience != c.want {
				t.Errorf("proof audience = %q, want %q", capture.audience, c.want)
			}
		})
		t.Run("mirror/"+name, func(t *testing.T) {
			capture := &mirrorCapture{}
			path, h := tlogpbconnect.NewTlogServiceHandler(capture)
			mux := http.NewServeMux()
			mux.Handle(path, h)
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)
			f := newMirrorClientFactory(newAuthKeyStore(t, signer), srv.URL, c.override, "", srv.Client())
			cp := &tlog.Checkpoint{Origin: "did:dplaax:home.example:org:o1:pipeline:p1", Size: 1, Head: addr("b"), Timestamp: time.Now()}
			if _, err := f.For(signer).MirrorLogSegment(context.Background(), cp.Origin, 0, [][]byte{[]byte("r")}, cp); err != nil {
				t.Fatalf("MirrorLogSegment: %v", err)
			}
			if capture.audience != c.want {
				t.Errorf("proof audience = %q, want %q", capture.audience, c.want)
			}
		})
	}
	// The payload store's harness verifies for registry "reg", its owners'
	// registry: the derived audience goes through, and an override naming
	// another registry is refused there.
	t.Run("payload store", func(t *testing.T) {
		h := newPayloadRetainHarness(t, payloadOwnerA)
		derived := wirePayloadStore{factory: newPayloadClientFactory(h.ks, h.url, "", "", h.httpc, 0)}
		if _, err := derived.Store(context.Background(), []byte("derived"), payloadOwnerA); err != nil {
			t.Fatalf("Store with the derived audience: %v", err)
		}
		other := wirePayloadStore{factory: newPayloadClientFactory(h.ks, h.url, "other.example", "", h.httpc, 0)}
		_, err := other.Store(context.Background(), []byte("override"), payloadOwnerA)
		if connect.CodeOf(err) != connect.CodeUnauthenticated || !strings.Contains(err.Error(), "other.example") {
			t.Fatalf("Store with an override for another registry: %v, want Unauthenticated naming it", err)
		}
	})
}

func TestUpstreamOverrideForChainedAndAggregate(t *testing.T) {
	loops := []pipelineconfig.LoopConfig{
		{
			Role: pipelineconfig.RoleChained, IngressSubject: "did:dplaax:b.example:org:o:pipeline:pb",
			Chained: pipelineconfig.ChainedConfig{UpstreamEndpoint: "https://b.example/p", PayloadDelivery: "by-reference", UpstreamRegistry: "node-b.example"},
		},
		{
			Role: pipelineconfig.RoleAggregate,
			Aggregate: pipelineconfig.AggregateConfig{Ingresses: []pipelineconfig.AggregateIngress{
				{Subject: "did:dplaax:c.example:org:o:pipeline:pc", UpstreamEndpoint: "https://c.example/p", PayloadDelivery: "by-reference", UpstreamRegistry: "node-c.example"},
			}},
		},
	}
	got, err := upstreamAudiences(loops)
	if err != nil {
		t.Fatalf("upstreamAudiences: %v", err)
	}
	if got["https://b.example/p"] != "node-b.example" || got["https://c.example/p"] != "node-c.example" {
		t.Errorf("audiences with overrides = %v, want node-b.example and node-c.example", got)
	}
}
