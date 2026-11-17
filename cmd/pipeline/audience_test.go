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
	"github.com/provin-line/oss/tlog"
)

// The audience of the pipeline's own node is node-registry when it is set,
// whatever the signers' registries.
func TestOwnNodeAudience_NodeRegistryWins(t *testing.T) {
	got, err := ownNodeAudience("node.example", []string{"did:dplaax:a.example:org:o1", "did:dplaax:b.example:org:o1:pipeline:p1"})
	if err != nil || got != "node.example" {
		t.Errorf("own-node audience with node-registry = %q, %v, want node.example", got, err)
	}
}

// Without node-registry it is the registry every signer shares.
func TestOwnNodeAudience_TheRegistryOfEverySigner(t *testing.T) {
	got, err := ownNodeAudience("", []string{"did:dplaax:home.example:org:o1", "did:dplaax:home.example:org:o1:pipeline:p1:process:s1"})
	if err != nil || got != "home.example" {
		t.Errorf("own-node audience = %q, %v, want home.example", got, err)
	}
	if got, err := ownNodeAudience("", nil); err != nil || got != "" {
		t.Errorf("no signer = %q, %v, want none: the pipeline sends its node no proof", got, err)
	}
}

// Signers of two registries, without node-registry, are an error naming both
// and node-registry: the node accepts proofs for one audience only.
func TestOwnNodeAudience_SignersOfTwoRegistriesAreAnError(t *testing.T) {
	_, err := ownNodeAudience("", []string{"did:dplaax:a.example:org:o1", "did:dplaax:a.example:org:o1:pipeline:p1", "did:dplaax:b.example:org:o2:pipeline:p2"})
	if err == nil || !strings.Contains(err.Error(), "a.example") || !strings.Contains(err.Error(), "b.example") || !strings.Contains(err.Error(), "node-registry") {
		t.Errorf("signers of two registries: %v, want an error naming both and node-registry", err)
	}
}

// A signer DID that does not parse has no registry; the error names it within
// a bound, with the parser's reason.
func TestOwnNodeAudienceOfAnUnparsableSignerIsAnError(t *testing.T) {
	if _, err := ownNodeAudience("", []string{"not a did"}); err == nil || !strings.Contains(err.Error(), `"not a did"`) {
		t.Errorf("an unparsable signer: %v, want an error naming it", err)
	}
	if _, err := ownNodeAudience("", []string{"did:dplaax:home.example:org:o/1:pipeline:p1"}); err == nil || !strings.Contains(err.Error(), "violates the safe-segment rule") {
		t.Errorf("an unsafe segment: %v, want the reason Parse gives", err)
	}
	long := "did:dplaax:" + strings.Repeat("x", 5000)
	if _, err := ownNodeAudience("", []string{long}); err == nil || len(err.Error()) > 400 || !strings.Contains(err.Error(), fmt.Sprintf("(%d bytes)", len(long))) {
		t.Errorf("a long unparsable signer: %v, want an error naming its head and length", err)
	}
}

// The pipeline signs its own node's proofs as the node DID, as each producing
// loop's output subject and issuer, and as each sink's receipt issuer.
func TestOwnNodeSigners(t *testing.T) {
	loops := []pipelineconfig.LoopConfig{
		{Role: pipelineconfig.RoleSource, Source: pipelineconfig.SourceConfig{OutputSubject: "src-subject", Issuer: pipelineconfig.IssuerConfig{DID: "src-issuer"}}},
		{Role: pipelineconfig.RoleChained, Chained: pipelineconfig.ChainedConfig{OutputSubject: "chained-subject", Issuer: pipelineconfig.IssuerConfig{DID: "chained-issuer"}}},
		{Role: pipelineconfig.RoleAggregate, Aggregate: pipelineconfig.AggregateConfig{OutputSubject: "agg-subject", Issuer: pipelineconfig.IssuerConfig{DID: "agg-issuer"}}},
		{Role: pipelineconfig.RoleSink, Sink: pipelineconfig.SinkConfig{Receipt: pipelineconfig.SinkReceiptConfig{Issue: true, Issuer: pipelineconfig.IssuerConfig{DID: "receipt-issuer"}}}},
		{Role: pipelineconfig.RoleSink},
	}
	got := ownNodeSigners(loops, "node-did")
	want := []string{"node-did", "src-subject", "src-issuer", "chained-subject", "chained-issuer", "agg-subject", "agg-issuer", "receipt-issuer"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("ownNodeSigners = %q, want %q", got, want)
	}
}

func TestUpstreamAudienceOverride(t *testing.T) {
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
	factory := newPayloadClientFactory(ks, "", "", "", srv.Client(), 0, map[string]string{"https://configured.example": "configured.example"})
	r := wireRetryingPayloadResolver{client: factory.For(wireNodeDID)}
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

// The own-node clients a factory builds sign for the audience it was given,
// whatever their signer's registry.
func TestFactoriesSignForTheOwnNodeAudience(t *testing.T) {
	const publisher = "did:dplaax:home.example:org:o1:pipeline:p1"
	capture := &reportCapture{}
	path, h := chainpbconnect.NewChainServiceHandler(capture)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f := newReportClientFactory(newAuthKeyStore(t, publisher), srv.URL, "node.example", "", srv.Client())
	if _, err := f.For(publisher).ReportEmitHealth(context.Background(), publisher, true); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("ReportEmitHealth: %v", err)
	}
	if capture.audience != "node.example" {
		t.Errorf("proof audience = %q, want node.example", capture.audience)
	}
}

// newAuthKeyStore returns a keystore holding an #auth key for did.
func newAuthKeyStore(t *testing.T, did string) *ksfilestore.Store {
	t.Helper()
	ks := ksfilestore.New(t.TempDir())
	provisionAuthKey(t, ks, did)
	return ks
}

// mustOwnNodeAudience is the audience main decides for c's own node.
func mustOwnNodeAudience(t *testing.T, c *pipelineconfig.Config, nodeDID string) string {
	t.Helper()
	a, err := ownNodeAudience(c.NodeRegistry, ownNodeSigners(c.Loops, nodeDID))
	if err != nil {
		t.Fatalf("ownNodeAudience: %v", err)
	}
	return a
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

// Every own-node factory signs for the audience main decided, whether the
// signer's registry or node-registry.
func TestOwnNodeFactoriesSignForTheDecidedAudience(t *testing.T) {
	const signer = "did:dplaax:home.example:org:o1:pipeline:p1:process:s1"
	cases := map[string]struct{ audience, want string }{
		"the signer's registry": {"home.example", "home.example"},
		"node-registry":         {"node.example", "node.example"},
	}
	for name, c := range cases {
		t.Run("audit/"+name, func(t *testing.T) {
			capture := &auditCapture{}
			path, h := auditpbconnect.NewAuditServiceHandler(capture)
			mux := http.NewServeMux()
			mux.Handle(path, h)
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)
			f := newAuditClientFactory(newAuthKeyStore(t, signer), srv.URL, c.audience, "", srv.Client())
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
			f := newMirrorClientFactory(newAuthKeyStore(t, signer), srv.URL, c.audience, "", srv.Client())
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
	// registry: that audience goes through, and one naming another registry
	// is refused there.
	t.Run("payload store", func(t *testing.T) {
		h := newPayloadRetainHarness(t, payloadOwnerA)
		own := wirePayloadStore{factory: newPayloadClientFactory(h.ks, h.url, "reg", "", h.httpc, 0, nil)}
		if _, err := own.Store(context.Background(), []byte("own"), payloadOwnerA); err != nil {
			t.Fatalf("Store with the node's audience: %v", err)
		}
		other := wirePayloadStore{factory: newPayloadClientFactory(h.ks, h.url, "other.example", "", h.httpc, 0, nil)}
		_, err := other.Store(context.Background(), []byte("override"), payloadOwnerA)
		if connect.CodeOf(err) != connect.CodeUnauthenticated || !strings.Contains(err.Error(), "other.example") {
			t.Fatalf("Store with another registry's audience: %v, want Unauthenticated naming it", err)
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
