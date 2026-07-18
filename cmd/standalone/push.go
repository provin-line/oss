package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/provin-line/oss/network/pkg/auth"

	"github.com/provin-line/oss/pipeline/source/ingest/apipush"
	"github.com/provin-line/oss/pipeline/transport"
)

// pushBinding is one push-enabled source loop's HTTP ingest surface: the loop
// name (already validated as a URL-safe segment at config load), a Publisher on
// the loop's ingress subject over the shared data-plane connection, and the
// loop's subscription-readiness latch. buildDataPlane produces the bindings;
// BuildHandler mounts them at /ingest/<name>/.
type pushBinding struct {
	name      string
	publisher transport.Publisher
	ready     <-chan struct{}
}

// ingestMounts is the HTTP push surface main mounts onto BuildHandler's mux via
// the mountIngest closure (BuildHandler's old `ingest ingestMounts` parameter
// was replaced by that callback seam when BuildHandler moved to
// internal/netcompose — netcompose must stay free of this data-plane type, so
// this stays here). The zero value mounts nothing; maxBodySize must be
// positive when bindings exist (apipush.New fails closed otherwise).
//
// Currently unreferenced: main wires mountPushRoutes directly through the
// closure rather than constructing this value. Kept per the extraction plan
// (ingestMounts is data-plane-shaped and stays in cmd/standalone); a follow-up
// task removing cmd/standalone entirely may delete it.
type ingestMounts struct {
	bindings    []pushBinding
	maxBodySize int
}

// readySubscriber decorates a transport.Subscriber with a readiness latch that
// closes when Subscribe returns without error — the Subscriber contract confirms
// the subscription with the broker before returning, so the latch is exactly
// "the loop can now receive". The push route gates on it: core NATS silently
// drops a publish with no subscriber, so a 202 before the latch would be a lie.
type readySubscriber struct {
	transport.Subscriber
	once  sync.Once
	ready chan struct{}
}

func newReadySubscriber(s transport.Subscriber) *readySubscriber {
	return &readySubscriber{Subscriber: s, ready: make(chan struct{})}
}

// Subscribe implements transport.Subscriber, latching readiness on success.
func (r *readySubscriber) Subscribe(handler func(data []byte)) error {
	err := r.Subscriber.Subscribe(handler)
	if err == nil {
		r.once.Do(func() { close(r.ready) })
	}
	return err
}

// Ready returns the latch channel (closed once the subscription is confirmed).
func (r *readySubscriber) Ready() <-chan struct{} { return r.ready }

// mountPushRoutes mounts one apipush adapter per binding under /ingest/<name>/.
// Zero bindings mount nothing (HTTP-only and NATS-only deployments unchanged).
func mountPushRoutes(mux *http.ServeMux, bindings []pushBinding, verifier auth.Verifier, maxBodyBytes int) error {
	for _, b := range bindings {
		inner, err := apipush.New(apipush.Config{Publisher: b.publisher, MaxBodyBytes: maxBodyBytes})
		if err != nil {
			return fmt.Errorf("standalone: loop %q: push adapter: %w", b.name, err)
		}
		prefix := "/ingest/" + b.name
		mux.Handle(prefix+"/", http.StripPrefix(prefix, pushRoutes(inner, verifier, b.ready)))
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
