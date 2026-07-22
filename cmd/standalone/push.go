package main

import (
	"fmt"
	"net/http"
	"strings"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/provin-line/oss/network/pkg/auth"

	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
	"github.com/provin-line/oss/pipeline/source/ingest/apipush"
)

// mountPushRoutes mounts one apipush adapter per binding under /ingest/<name>/.
// Zero bindings mount nothing (HTTP-only and NATS-only deployments unchanged).
// The bindings themselves (pipelineruntime.PushBinding) come from the data
// plane's loop builders (pipeline/runtime.Build); this file owns only the
// control-plane HTTP mounting that consumes them.
func mountPushRoutes(mux *http.ServeMux, bindings []pipelineruntime.PushBinding, verifier auth.Verifier, maxBodyBytes int) error {
	for _, b := range bindings {
		inner, err := apipush.New(apipush.Config{Publisher: b.Publisher, MaxBodyBytes: maxBodyBytes})
		if err != nil {
			return fmt.Errorf("standalone: loop %q: push adapter: %w", b.Name, err)
		}
		prefix := "/ingest/" + b.Name
		mux.Handle(prefix+"/", http.StripPrefix(prefix, pushRoutes(inner, verifier, b.Ready)))
	}
	return nil
}

// pushRoutes composes the per-loop route policy around the apipush adapter:
//
//   - /health is public (orchestrator probes carry no bearer, mirroring /healthz)
//     but readiness-gated — a green health before the loop can receive would
//     invite publishes that core NATS silently drops.
//   - every other path (the push route) is PDP-guarded FIRST — an
//     unauthenticated caller learns nothing about body gates or node state —
//     then readiness-gated, then handed to the adapter.
//
// The PDP check is the same L1 seam the RPC interceptors enforce: bearer from
// the Authorization header into the context, then auth.Verifier.Verify with
// resource "ingest", action "push" (proto policy-option naming convention).
// Missing/empty bearer → 401; any Verify failure → 403 (the RPC interceptor
// likewise does not distinguish PDP denial from PDP outage).
func pushRoutes(inner http.Handler, verifier auth.Verifier, ready <-chan struct{}) http.Handler {
	requireReady := func(w http.ResponseWriter) bool {
		select {
		case <-ready:
			return true
		default:
			w.Header().Set("Retry-After", "1")
			http.Error(w, "ingest loop not ready", http.StatusServiceUnavailable)
			return false
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			if !requireReady(w) {
				return
			}
			inner.ServeHTTP(w, r)
			return
		}
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		ctx := interceptors.WithBearerToken(r.Context(), token)
		if err := verifier.Verify(ctx, "ingest", "push"); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !requireReady(w) {
			return
		}
		inner.ServeHTTP(w, r.WithContext(ctx))
	})
}
