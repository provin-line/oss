/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package netcompose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/provin-line/oss/network/pkg/auth"
)

// Readiness (/readyz) is dependency-aware, unlike liveness (/healthz, static):
// it reports whether the dependencies THIS node is configured with can serve —
// a node with zero loops has no nats check, a static-PDP node has no probe.
// Readiness failing means "do not route new work here"; liveness failing means
// "restart me". Keeping the two endpoints separate keeps those two supervisor
// actions separate.

// ReadinessCheck is one named dependency probe. Check returns nil when the
// dependency can serve. Names must be unique within one readyz handler (the
// results are keyed by name). The error is LOGGED server-side only — /readyz
// is mounted unauthenticated on the internet-facing mux, and check errors
// carry internal topology (PDP base URL, filesystem paths), so the public
// body reports pass/fail per check and nothing else.
type ReadinessCheck struct {
	Name  string
	Check func(ctx context.Context) error
}

// perCheckTimeout bounds every individual probe so one hung dependency cannot
// stall the whole readiness response past a supervisor's probe timeout.
const perCheckTimeout = 2 * time.Second

// ReadinessCacheTTL bounds how stale a served readiness snapshot may be, and so
// bounds the outbound PDP-probe rate to ~1/TTL regardless of inbound /readyz
// request rate. Kept well below a typical supervisor failure-detection window.
const ReadinessCacheTTL = 3 * time.Second

// readySnapshot is the aggregate readiness result at one instant.
type readySnapshot struct {
	ready   bool
	results map[string]struct {
		Status string `json:"status"`
	}
}

// runReadyChecks runs every check concurrently under one perCheckTimeout and
// aggregates the outcome. Check errors are logged server-side only (they carry
// internal topology and /readyz is public).
func runReadyChecks(ctx context.Context, checks []ReadinessCheck) readySnapshot {
	results := make(map[string]struct {
		Status string `json:"status"`
	}, len(checks))
	var mu sync.Mutex
	var wg sync.WaitGroup
	ready := true
	for _, c := range checks {
		wg.Add(1)
		go func(c ReadinessCheck) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, perCheckTimeout)
			err := c.Check(cctx)
			cancel()
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				log.Printf("readyz: check %s failed: %v", c.Name, err)
				ready = false
				results[c.Name] = struct {
					Status string `json:"status"`
				}{Status: "failed"}
				return
			}
			results[c.Name] = struct {
				Status string `json:"status"`
			}{Status: "ok"}
		}(c)
	}
	wg.Wait()
	return readySnapshot{ready: ready, results: results}
}

func writeSnapshot(w http.ResponseWriter, snap readySnapshot) {
	status, code := "ok", http.StatusOK
	if !snap.ready {
		status, code = "degraded", http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": status,
		"checks": snap.results,
	})
}

// cachedReadiness serves a readiness snapshot refreshed at most once per ttl,
// so a flood of unauthenticated /readyz requests cannot amplify into one
// outbound PDP probe (and one goroutine-per-dependency) per request. The
// refresh is coalesced under a mutex — concurrent stale requests share one
// refresh — and the FIRST request refreshes synchronously, so a never-yet-
// refreshed cache reports degraded/probe-derived state, never a zero snapshot
// that would falsely read as ready. The refresh uses its own bounded context,
// decoupled from any single caller's cancellation. No background goroutine, so
// no lifecycle to manage (BuildHandler receives no context). The type itself
// stays unexported (only ever named via inference from NewCachedReadiness's
// return); its Now field and Handler method are exported so an external test
// could reach across the package boundary to override the clock and obtain
// the /readyz http.HandlerFunc — cmd/standalone's readiness_test.go once did
// (cmd/pipeline now has its own independent, unexported cachedReadiness
// rather than importing this one).
type cachedReadiness struct {
	checks []ReadinessCheck
	ttl    time.Duration
	Now    func() time.Time

	mu          sync.Mutex
	lastRefresh time.Time
	snapshot    readySnapshot
	fresh       bool
}

// NewCachedReadiness builds a cache over checks, refreshed at most once per ttl.
func NewCachedReadiness(checks []ReadinessCheck, ttl time.Duration) *cachedReadiness {
	return &cachedReadiness{checks: checks, ttl: ttl, Now: time.Now}
}

// Handler returns the /readyz http.HandlerFunc backed by this cache.
func (c *cachedReadiness) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeSnapshot(w, c.get())
	}
}

func (c *cachedReadiness) get() readySnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.Now()
	if c.fresh && now.Sub(c.lastRefresh) < c.ttl {
		return c.snapshot
	}
	// Refresh under a fresh bounded context so one caller's cancellation cannot
	// poison the shared snapshot. Held under the lock so concurrent stale
	// requests coalesce onto this single refresh.
	ctx, cancel := context.WithTimeout(context.Background(), perCheckTimeout)
	defer cancel()
	c.snapshot = runReadyChecks(ctx, c.checks)
	c.lastRefresh = now
	c.fresh = true
	return c.snapshot
}

// EvidenceStoreCheck probes the durable evidence substrate: the directory must
// exist and be a directory. (Deeper write probes would churn the store on every
// poll; boot already fails closed if the dir is uncreatable.)
func EvidenceStoreCheck(dir string) ReadinessCheck {
	return ReadinessCheck{
		Name: "evidence-store",
		Check: func(context.Context) error {
			info, err := os.Stat(dir)
			if err != nil {
				return fmt.Errorf("evidence dir: %w", err)
			}
			if !info.IsDir() {
				return fmt.Errorf("evidence dir %s is not a directory", dir)
			}
			return nil
		},
	}
}

// NATSCheck reports whether the data plane's shared broker connection can
// serve traffic. healthy is transport-level (nats.Conn.IsConnected under the
// hood) — the same signal transport.Publisher.Healthy exposes per publisher.
func NATSCheck(healthy func() bool) ReadinessCheck {
	return ReadinessCheck{
		Name: "nats",
		Check: func(context.Context) error {
			if !healthy() {
				return fmt.Errorf("broker connection cannot serve traffic")
			}
			return nil
		},
	}
}

// HostOnly reduces a URL to scheme://host[:port] for logging — never the
// userinfo, path, or query. url.Redacted() is insufficient here: it masks a
// password but keeps the username and the query string. A URL that fails to
// parse is reported as "<redacted>" rather than echoed raw. Exported because
// readiness_test.go exercises it directly.
func HostOnly(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<redacted>"
	}
	return u.Scheme + "://" + u.Host
}

// PDPCheck probes the configured external PDP for REACHABILITY: an HTTP
// round-trip to its base URL that yields any HTTP response counts as reachable
// (a 404 from a PDP that mounts no root route still proves the dependency is
// there). Whether the PDP would authorize a given request is L1's per-RPC
// business, not readiness. Returns (check, true) for external backends and
// (zero, false) for in-process ones (static — nothing to probe).
//
// Precondition: cfg is post-LoadAuthConfig (validated/normalized) — the ""→
// o3co backend default is applied there, so an empty Backend never reaches
// this switch from production wiring.
func PDPCheck(cfg *auth.AuthConfig) (ReadinessCheck, bool) {
	var base string
	switch cfg.Backend {
	case auth.BackendO3co:
		base = cfg.PolicyVerifierURL
	case auth.BackendOPA:
		base = cfg.OPA.BaseURL
	case auth.BackendCedar:
		base = cfg.Cedar.BaseURL
	default:
		return ReadinessCheck{}, false
	}
	client := &http.Client{
		// Reachability needs only the FIRST response; following redirects
		// could walk off-host.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	} // per-request ctx carries the timeout
	return ReadinessCheck{
		Name: "pdp",
		Check: func(ctx context.Context) error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
			if err != nil {
				return fmt.Errorf("pdp probe: %w", err)
			}
			res, err := client.Do(req)
			if err != nil {
				// client.Do returns a *url.Error whose message embeds the FULL
				// request URL (path + query). Unwrap to its inner cause so the
				// log carries only scheme://host (see HostOnly) plus the reason.
				cause := err
				var ue *url.Error
				if errors.As(err, &ue) {
					cause = ue.Err
				}
				return fmt.Errorf("pdp unreachable at %s: %w", HostOnly(base), cause)
			}
			// Drain a bounded slice so the connection is pooled, not dropped.
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 512))
			_ = res.Body.Close()
			return nil
		},
	}, true
}
