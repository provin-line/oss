package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpoint"

	didpb "github.com/provin-line/oss/gen/go/dplaax/did/v1"
	"github.com/provin-line/oss/gen/go/dplaax/did/v1/didpbconnect"
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
// routing/gating only, not data-plane delivery — the httpingest e2e scenario
// (provin.e2e) and TestPipeline_ActualBoot already cover the wire path
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

// TestPushRoutes_PDPDenial403 pins pushRoutes' auth mapping directly (unit
// level, no HTTP handler assembly): a bearer the PDP denies is 403 (any
// Verify failure — the RPC interceptors elsewhere in this module likewise do
// not distinguish denial from outage), distinct from the 401 of a missing
// bearer. Also pins Retry-After on the readiness 503. Relocated from
// cmd/standalone/push_test.go (PR3c: cmd/standalone retired) — push.go here
// is a byte-for-byte copy of that binary's own push.go (see its package
// doc), and this is the only test either copy's pushRoutes ever had for its
// 403/Retry-After behavior specifically (TestRoutes_PushIngressIsMounted,
// above, only exercises the 401/503 paths through the full handler).
func TestPushRoutes_PDPDenial403(t *testing.T) {
	ready := make(chan struct{})
	close(ready)
	denyAll := endpoint.NewStaticEndpoint(nil) // no rules => every Verify fails
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
	h := pushRoutes(inner, denyAll, ready)

	req := httptest.NewRequest(http.MethodPost, "/push", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("PDP-denied push: got %d, want 403", rec.Code)
	}

	// Readiness 503 carries Retry-After (allowed but not ready).
	allow := endpoint.NewStaticEndpoint([]endpoint.StaticRule{{Resource: "ingest", Action: "push"}})
	h = pushRoutes(inner, allow, make(chan struct{}))
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/push", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer tok")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Errorf("not-ready push: got %d (Retry-After %q), want 503 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
}

type errVerifier struct{ err error }

func (v errVerifier) Verify(context.Context, string, string) error { return v.err }

// TestPushRoutes_PDPOutage503 pins that a PDP outage is reported as 503 with
// Retry-After (the sender may retry) while every other Verify failure stays 403.
func TestPushRoutes_PDPOutage503(t *testing.T) {
	ready := make(chan struct{})
	close(ready)
	reached := false
	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })
	post := func(v auth.Verifier) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/push", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		pushRoutes(inner, v, ready).ServeHTTP(rec, req)
		return rec
	}

	for name, err := range map[string]error{
		"bare":    interceptors.ErrBackendUnavailable,
		"wrapped": fmt.Errorf("pdp: %w", interceptors.ErrBackendUnavailable),
	} {
		rec := post(errVerifier{err})
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
			t.Errorf("%s: got %d (Retry-After %q), want 503 with Retry-After", name, rec.Code, rec.Header().Get("Retry-After"))
		}
	}
	for name, err := range map[string]error{
		"denied":   &interceptors.DeniedError{},
		"internal": errors.New("malformed decision"),
	} {
		if rec := post(errVerifier{err}); rec.Code != http.StatusForbidden {
			t.Errorf("%s: got %d, want 403", name, rec.Code)
		}
	}
	if reached {
		t.Error("handler reached although the PDP did not allow")
	}
}

// TestPDPOutage_RealO3coEndpoint drives the real o3co endpoint against a PDP
// that answers 503: the push receiver answers 503 with Retry-After and an
// L1-guarded RPC fails with Unavailable.
func TestPDPOutage_RealO3coEndpoint(t *testing.T) {
	pdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "overloaded", http.StatusServiceUnavailable)
	}))
	defer pdp.Close()
	verifier, err := auth.NewVerifier(&auth.AuthConfig{Backend: auth.BackendO3co, PolicyVerifierURL: pdp.URL})
	if err != nil {
		t.Fatal(err)
	}

	ready := make(chan struct{})
	close(ready)
	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("handler reached during a PDP outage") })
	req := httptest.NewRequest(http.MethodPost, "/push", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	pushRoutes(inner, verifier, ready).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Errorf("push: got %d (Retry-After %q), want 503 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}

	_, h := didpbconnect.NewDIDServiceHandler(
		didpbconnect.UnimplementedDIDServiceHandler{},
		connect.WithInterceptors(auth.Interceptors(verifier)...),
	)
	srv := httptest.NewServer(h)
	defer srv.Close()
	rpc := connect.NewRequest(&didpb.RegisterOwnerRequest{})
	rpc.Header().Set("Authorization", "Bearer tok")
	_, err = didpbconnect.NewDIDServiceClient(srv.Client(), srv.URL).RegisterOwner(context.Background(), rpc)
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("RPC: code = %v (%v), want Unavailable", connect.CodeOf(err), err)
	}
}
