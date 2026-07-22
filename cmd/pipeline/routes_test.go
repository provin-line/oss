package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/o3co/protobuf.interceptors/endpoint"

	"github.com/provin-line/oss/network/pkg/auth"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
)

// TestRoutes_NoRegistryRPCMounted assembles the REAL cmd/pipeline HTTP
// handler (buildHandler, main.go) — not a reimplementation — and proves the
// architectural claim its own package doc makes: "no ConnectRPC services of
// its own". Every registry RPC path (enumerated from the generated Connect
// procedure constants under gen/go/dplaax/*/v1/*connect — the canonical
// source of truth for what a REAL registry node mounts) 404s here: a plain
// http.ServeMux with no pattern for the path returns 404 regardless of
// method, which is exactly what distinguishes "never mounted" from "mounted
// but rejecting" (401 unauthenticated / 403 forbidden / 405 wrong method
// would all imply something IS listening at that path).
func TestRoutes_NoRegistryRPCMounted(t *testing.T) {
	h := newTestPipelineHandler(t)

	// One representative RPC per service, covering every dplaax.*.v1 package
	// under api/protobuf/dplaax/ — including BOTH services under chain.v1
	// (ChainService, the L1 operator surface; ChainPeerService, the L2
	// wireauth surface) and BOTH under payload.v1 (PayloadService,
	// PayloadStoreService).
	procedures := []string{
		"/dplaax.audit.v1.AuditService/RegisterEvidence",
		"/dplaax.chain.v1.ChainService/Subscribe",
		"/dplaax.chain.v1.ChainPeerService/GetPublisherInfo",
		"/dplaax.did.v1.DIDService/ResolveDID",
		"/dplaax.payload.v1.PayloadService/ResolvePayload",
		"/dplaax.payload.v1.PayloadStoreService/RetainPayload",
		"/dplaax.schema.v1.SchemaService/GetSchema",
		"/dplaax.signer.v1.SignerService/Sign",
		"/dplaax.tlog.v1.TlogService/GetLogCheckpoint",
		"/dplaax.vc.v1.VCResolverService/ResolveVC",
	}
	for _, proc := range procedures {
		t.Run(proc, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, proc, strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("POST %s = %d, want 404 (not 401/403/405 — those would mean something IS mounted there)", proc, rec.Code)
			}
		})
	}
}

// TestRoutes_Healthz pins /healthz: public, always 200 while the process is
// up (main.go's package doc — liveness, not readiness).
func TestRoutes_Healthz(t *testing.T) {
	h := newTestPipelineHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /healthz = %d, want 200", rec.Code)
	}
}

// TestRoutes_PushIngressIsMounted proves the OTHER half of the architectural
// claim: this binary is not a black hole either — a configured push-ingress
// route (mountPushRoutes, wired through buildHandler's mountIngest exactly as
// main() wires it) really is reachable. An unauthenticated POST hits the L1
// PDP gate FIRST (push.go's pushRoutes) and gets 401 — proving the route IS
// mounted (a 404 here would mean the ingest wiring silently vanished), while
// the unauthenticated GET /health sub-route (deliberately public, gated only
// on loop readiness — see pushRoutes' doc) 503s because the fake loop below
// is never marked ready.
func TestRoutes_PushIngressIsMounted(t *testing.T) {
	h := newTestPipelineHandler(t)

	// POST without a bearer: the PDP gate fires before the readiness gate, so
	// this is 401, not 503 — pins that the route exists AND the auth gate
	// responds (a 404 here would mean nothing is mounted at /ingest/<name>/).
	req := httptest.NewRequest(http.MethodPost, "/ingest/"+testLoopName+"/push", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST %s (no bearer) = %d, want 401 (proves the push route is mounted and PDP-gated)", req.URL.Path, rec.Code)
	}

	// GET .../health: public, but readiness-gated — 503 since the fake
	// binding's Ready channel is never closed by this test.
	req = httptest.NewRequest(http.MethodGet, "/ingest/"+testLoopName+"/health", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("GET %s (not ready) = %d, want 503", req.URL.Path, rec.Code)
	}
}

// testLoopName is the fake push binding's name in newTestPipelineHandler.
const testLoopName = "src"

// newTestPipelineHandler assembles this binary's REAL HTTP surface via
// buildHandler (main.go) — the same function main() itself calls — with a
// minimal but real mountIngest: one push binding over a fake
// transport.Publisher (never actually dials NATS; this test exercises HTTP
// routing/gating only, not data-plane delivery — TestPushIngest_Boot's sibling
// in cmd/standalone and TestPipeline_ActualBoot already cover the wire path
// end-to-end). natsHealthy is nil, mirroring the zero-loop-runtime case
// buildHandler's own doc documents — /readyz is not exercised by any test in
// this file, so its absence has no effect here. authCfg is a zero-value
// &auth.AuthConfig{} (empty Backend, no backend case matches) and
// hasPushIngress is true (a push binding IS mounted below), but pdpCheck
// still returns ok=false for the empty Backend, so no PDP check is added
// regardless — readiness.go's own tests cover the PDP-gating logic directly.
func newTestPipelineHandler(t *testing.T) http.Handler {
	t.Helper()
	guard := core.NewURLGuard(core.WithAllowLoopback(true))
	pipeCfg := &pipelineconfig.Config{MaxPushBodySize: 1 << 20}
	verifier := endpoint.NewStaticEndpoint(nil) // no rules => every Verify fails; only the 401 (no bearer) path is asserted here
	ready := make(chan struct{})                // never closed: the push route stays readiness-gated (503), not the point of this test
	mountIngest := func(mux *http.ServeMux) error {
		binding := pipelineruntime.PushBinding{Name: testLoopName, Publisher: fakePublisher{}, Ready: ready}
		return mountPushRoutes(mux, []pipelineruntime.PushBinding{binding}, verifier, pipeCfg.MaxPushBodySize)
	}
	h, err := buildHandler(guard, pipeCfg, &auth.AuthConfig{}, mountIngest, nil, true)
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	return h
}

// fakePublisher is a no-op transport.Publisher — this file never runs a real
// data plane, so Publish is never actually invoked (every push route hit here
// is denied before reaching the adapter).
type fakePublisher struct{}

func (fakePublisher) Publish([]byte) error { return nil }
func (fakePublisher) Healthy() bool        { return true }
func (fakePublisher) Close() error         { return nil }
