package main

import (
	"context"
	"errors"
	"fmt"
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
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
	"github.com/provin-line/oss/pipeline/transport/tlogship"
	"github.com/provin-line/oss/tlog"
)

// must is c, failing the test with err.
func must[T any](c T, err error) func(testing.TB) T {
	return func(t testing.TB) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
}

func TestOwnNodeAudienceDerivedFromSigner(t *testing.T) {
	if got, err := ownNodeAudience("", "did:dplaax:home.example:org:o1:pipeline:p1:process:s1"); err != nil || got != "home.example" {
		t.Errorf("derived audience = %q, %v, want home.example", got, err)
	}
}

// A signer DID that does not parse has no node to derive an audience from;
// the error names it and the reason Parse gives, within a bound however long
// it is.
func TestOwnNodeAudienceOfAnUnparsableSignerIsAnError(t *testing.T) {
	if got, err := ownNodeAudience("", "not a did"); err == nil || !strings.Contains(err.Error(), `"not a did"`) {
		t.Errorf("audience for an unparsable signer = %q, %v, want an error naming it", got, err)
	}
	if _, err := ownNodeAudience("", "did:dplaax:home.example:org:o/1:pipeline:p1"); err == nil || !strings.Contains(err.Error(), "violates the safe-segment rule") {
		t.Errorf("an unsafe segment: %v, want the reason Parse gives", err)
	}
	long := "did:dplaax:" + strings.Repeat("x", 5000)
	if _, err := ownNodeAudience("", long); err == nil || len(err.Error()) > 400 || !strings.Contains(err.Error(), fmt.Sprintf("(%d bytes)", len(long))) {
		t.Errorf("a long unparsable signer: %v, want an error naming its head and length", err)
	}
}

// Each client factory refuses a signer DID that does not parse, rather than
// building a client that fails at its first call for want of an audience.
func TestClientFactoriesRefuseAnUnparsableSigner(t *testing.T) {
	for name, forDID := range map[string]func(string) error{
		"audit": func(d string) error {
			_, err := newAuditClientFactory(nil, "http://node.example", "", "", nil).For(d)
			return err
		},
		"mirror": func(d string) error {
			_, err := newMirrorClientFactory(nil, "http://node.example", "", "", nil).For(d)
			return err
		},
		"report": func(d string) error {
			_, err := newReportClientFactory(nil, "http://node.example", "", "", nil).For(d)
			return err
		},
		"payload": func(d string) error {
			_, err := newPayloadClientFactory(nil, "http://node.example", "", "", nil, 0).For(d)
			return err
		},
	} {
		if err := forDID("not a did"); err == nil || !strings.Contains(err.Error(), `"not a did"`) {
			t.Errorf("%s: %v, want an error naming the signer", name, err)
		}
		if err := forDID("did:dplaax:home.example:org:o1:pipeline:p1"); err != nil {
			t.Errorf("%s: a parsable signer: %v", name, err)
		}
	}
}

func TestOverrideWinsOverDerivedAudience(t *testing.T) {
	if got, err := ownNodeAudience("node.example", "did:dplaax:home.example:org:o1:pipeline:p1"); err != nil || got != "node.example" {
		t.Errorf("own-node audience with an override = %q, %v, want node.example", got, err)
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

// An upstream pipeline DID that does not parse is named within a bound,
// however long it is.
func TestUpstreamAudienceOfALongUnparsableSubjectIsBounded(t *testing.T) {
	loops := []pipelineconfig.LoopConfig{{
		Role: pipelineconfig.RoleSink, IngressSubject: "did:dplaax:a.example:org:" + strings.Repeat("x", 5000) + ":pipeline:p!",
		Sink: pipelineconfig.SinkConfig{UpstreamEndpoint: "https://up.example/p", PayloadDelivery: "by-reference"},
	}}
	if _, err := upstreamAudiences(loops); err == nil || len(err.Error()) > 500 || !strings.Contains(err.Error(), fmt.Sprintf("(%d bytes)", len(loops[0].IngressSubject))) {
		t.Errorf("a long unparsable upstream subject: %.200v (%d bytes), want an error naming its head and length", err, len(fmt.Sprint(err)))
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
	r := wireRetryingPayloadResolver{client: must(factory.For(wireNodeDID))(t), audiences: map[string]string{"https://configured.example": "configured.example"}}
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
			if _, err := must(f.For(publisher))(t).ReportEmitHealth(context.Background(), publisher, true); err != nil && !errors.Is(err, context.Canceled) {
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
			if err := must(f.For(signer))(t).RegisterAuditHead(context.Background(), addr("a")); err != nil {
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
			if _, err := must(f.For(signer))(t).MirrorLogSegment(context.Background(), cp.Origin, 0, [][]byte{[]byte("r")}, cp); err != nil {
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

// A factory caches no client for a signer DID it refused: asked again, it
// refuses again.
func TestClientFactoriesCacheNothingOnARefusal(t *testing.T) {
	f := newAuditClientFactory(nil, "http://node.example", "", "", nil)
	for range 2 {
		if _, err := f.For("not a did"); err == nil {
			t.Fatal("an unparsable signer was taken")
		}
	}
	if len(f.clients) != 0 {
		t.Errorf("%d clients cached after refusals", len(f.clients))
	}
}

// A seam's refusal stops the builders that call it.
func TestBuildersPassOnTheirSeamsRefusal(t *testing.T) {
	refused := errors.New("seam refused")
	custody := []pipelineruntime.CustodyLog{{LogID: "l1", Signer: pipelineruntime.IssuerConfig{DID: "did:dplaax:reg:org:acme:pipeline:a:process:p1"}}}
	if _, err := buildShippers(custody, func(string) (tlogship.MirrorClient, error) { return nil, refused }, pipelineconfig.TlogMirrorConfig{MaxBatchRecords: 1, MaxBatchBytes: 1 << 10, FlushInterval: time.Hour}); !errors.Is(err, refused) {
		t.Errorf("buildShippers: %v, want the seam's refusal", err)
	}
	specs := []emitHealthReporterSpec{{OutputSubject: "did:dplaax:reg:org:acme:pipeline:a", Healthy: func() bool { return true }}}
	if _, err := buildEmitHealthReporters(specs, func(string) (emitHealthReportClient, error) { return nil, refused }, time.Second); !errors.Is(err, refused) {
		t.Errorf("buildEmitHealthReporters: %v, want the seam's refusal", err)
	}
}
