package main

// /readyz is a deliberately small, HONEST readiness surface (task brief:
// "a cheap probe to the registry base URL; keep it honest and simple") — NOT
// a port of internal/netcompose's readiness.go (this binary must not import
// netcompose): no per-check pluggable registry, no PDP probing (cmd/pipeline
// mounts no PDP-gated ConnectRPC services of its own to be ready FOR), just
// the two dependencies this binary actually has: the shared NATS connection
// every loop rides, and the one registry base URL every wire Dep (VC store,
// audit, schema, payload) is pointed at.
//
// A tiny TTL cache still guards against turning an unauthenticated /readyz
// flood into an outbound registry-probe amplifier (the same concern
// netcompose's own cache exists for) — kept minimal on purpose: one combined
// snapshot, no per-check bookkeeping.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// readinessCheck is one named dependency probe.
type readinessCheck struct {
	name  string
	check func(ctx context.Context) error
}

// perCheckTimeout bounds one probe so a hung dependency cannot stall the
// whole /readyz response past a supervisor's probe timeout.
const perCheckTimeout = 2 * time.Second

// readinessCacheTTL bounds how stale a served snapshot may be, and so bounds
// the outbound registry-probe rate regardless of inbound /readyz request
// rate. Mirrors netcompose.ReadinessCacheTTL's value for consistency across
// the module's binaries.
const readinessCacheTTL = 3 * time.Second

// natsCheck reports whether the data plane's shared broker connection can
// serve traffic.
func natsCheck(healthy func() bool) readinessCheck {
	return readinessCheck{
		name: "nats",
		check: func(context.Context) error {
			if !healthy() {
				return fmt.Errorf("broker connection cannot serve traffic")
			}
			return nil
		},
	}
}

// registryCheck probes the ONE registry base URL (pipeCfg.VCStoreEndpoint)
// for reachability: any HTTP response counts as reachable — this binary
// mounts no ConnectRPC path of its own at that base, so a plain GET almost
// certainly 404s; the point is only "a server answered", the same posture
// netcompose.PDPCheck documents for its own reachability probe.
func registryCheck(client *http.Client, baseURL string) readinessCheck {
	return readinessCheck{
		name: "registry",
		check: func(ctx context.Context) error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
			if err != nil {
				return fmt.Errorf("build registry probe request: %w", err)
			}
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("registry unreachable at %s: %w", hostOnly(baseURL), err)
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
			_ = resp.Body.Close()
			return nil
		},
	}
}

// hostOnly reduces a URL to scheme://host[:port] for logging — never the
// path or query, mirroring netcompose.HostOnly's own redaction posture.
func hostOnly(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<redacted>"
	}
	return u.Scheme + "://" + u.Host
}

// readySnapshot is the aggregate readiness result at one instant.
type readySnapshot struct {
	ready   bool
	results map[string]string
}

func runReadyChecks(ctx context.Context, checks []readinessCheck) readySnapshot {
	results := make(map[string]string, len(checks))
	ready := true
	for _, c := range checks {
		cctx, cancel := context.WithTimeout(ctx, perCheckTimeout)
		err := c.check(cctx)
		cancel()
		if err != nil {
			log.Printf("readyz: check %s failed: %v", c.name, err)
			ready = false
			results[c.name] = "failed"
			continue
		}
		results[c.name] = "ok"
	}
	return readySnapshot{ready: ready, results: results}
}

// cachedReadiness serves a snapshot refreshed at most once per readinessCacheTTL.
type cachedReadiness struct {
	checks []readinessCheck

	mu          sync.Mutex
	lastRefresh time.Time
	snapshot    readySnapshot
	fresh       bool
}

func newCachedReadiness(checks []readinessCheck) *cachedReadiness {
	return &cachedReadiness{checks: checks}
}

func (c *cachedReadiness) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		snap := c.get()
		status, code := "ok", http.StatusOK
		if !snap.ready {
			status, code = "degraded", http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "checks": snap.results})
	}
}

func (c *cachedReadiness) get() readySnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.fresh && now.Sub(c.lastRefresh) < readinessCacheTTL {
		return c.snapshot
	}
	// The aggregate budget scales with the check count — an outer cap equal to
	// ONE check's cap would starve the last check to near-zero the moment a
	// third probe is added (a false-negative /readyz while the deps are up).
	// Each check still bounds itself at perCheckTimeout inside runReadyChecks.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(len(c.checks))*perCheckTimeout)
	defer cancel()
	c.snapshot = runReadyChecks(ctx, c.checks)
	c.lastRefresh = now
	c.fresh = true
	return c.snapshot
}

func healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}
