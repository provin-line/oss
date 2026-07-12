/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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

// readinessCheck is one named dependency probe. Check returns nil when the
// dependency can serve. Names must be unique within one readyz handler (the
// results are keyed by name). The error is LOGGED server-side only — /readyz
// is mounted unauthenticated on the internet-facing mux, and check errors
// carry internal topology (PDP base URL, filesystem paths), so the public
// body reports pass/fail per check and nothing else.
type readinessCheck struct {
	Name  string
	Check func(ctx context.Context) error
}

// perCheckTimeout bounds every individual probe so one hung dependency cannot
// stall the whole readiness response past a supervisor's probe timeout.
const perCheckTimeout = 2 * time.Second

// readyz aggregates the given checks into a readiness handler: HTTP 200 with
// {"status":"ok"} when every check passes, HTTP 503 with {"status":"degraded"}
// otherwise. Checks run concurrently, so the whole response is bounded by one
// perCheckTimeout, not their sum (supervisor probe timeouts are short). The
// bound is best-effort: a probe that ignores its ctx (os.Stat on a dead
// network mount) can still hang its goroutine — the failure direction stays
// correct (the supervisor's own probe timeout reads as not-ready).
func readyz(checks []readinessCheck) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		type checkResult struct {
			Status string `json:"status"`
		}
		results := make(map[string]checkResult, len(checks))
		var mu sync.Mutex
		var wg sync.WaitGroup
		ready := true
		for _, c := range checks {
			wg.Add(1)
			go func(c readinessCheck) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(r.Context(), perCheckTimeout)
				err := c.Check(ctx)
				cancel()
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					// Server-side detail only: check errors carry internal
					// topology and this endpoint is public.
					log.Printf("readyz: check %s failed: %v", c.Name, err)
					ready = false
					results[c.Name] = checkResult{Status: "failed"}
					return
				}
				results[c.Name] = checkResult{Status: "ok"}
			}(c)
		}
		wg.Wait()
		status := "ok"
		code := http.StatusOK
		if !ready {
			status = "degraded"
			code = http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": status,
			"checks": results,
		})
	}
}

// evidenceStoreCheck probes the durable evidence substrate: the directory must
// exist and be a directory. (Deeper write probes would churn the store on every
// poll; boot already fails closed if the dir is uncreatable.)
func evidenceStoreCheck(dir string) readinessCheck {
	return readinessCheck{
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

// natsCheck reports whether the data plane's shared broker connection can
// serve traffic. healthy is transport-level (nats.Conn.IsConnected under the
// hood) — the same signal transport.Publisher.Healthy exposes per publisher.
func natsCheck(healthy func() bool) readinessCheck {
	return readinessCheck{
		Name: "nats",
		Check: func(context.Context) error {
			if !healthy() {
				return fmt.Errorf("broker connection cannot serve traffic")
			}
			return nil
		},
	}
}

// pdpCheck probes the configured external PDP for REACHABILITY: an HTTP
// round-trip to its base URL that yields any HTTP response counts as reachable
// (a 404 from a PDP that mounts no root route still proves the dependency is
// there). Whether the PDP would authorize a given request is L1's per-RPC
// business, not readiness. Returns (check, true) for external backends and
// (zero, false) for in-process ones (static — nothing to probe).
//
// Precondition: cfg is post-LoadAuthConfig (validated/normalized) — the ""→
// o3co backend default is applied there, so an empty Backend never reaches
// this switch from production wiring.
func pdpCheck(cfg *auth.AuthConfig) (readinessCheck, bool) {
	var base string
	switch cfg.Backend {
	case auth.BackendO3co:
		base = cfg.PolicyVerifierURL
	case auth.BackendOPA:
		base = cfg.OPA.BaseURL
	case auth.BackendCedar:
		base = cfg.Cedar.BaseURL
	default:
		return readinessCheck{}, false
	}
	client := &http.Client{
		// Reachability needs only the FIRST response; following redirects
		// could walk off-host.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	} // per-request ctx carries the timeout
	return readinessCheck{
		Name: "pdp",
		Check: func(ctx context.Context) error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
			if err != nil {
				return fmt.Errorf("pdp probe: %w", err)
			}
			res, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("pdp unreachable at %s: %w", base, err)
			}
			// Drain a bounded slice so the connection is pooled, not dropped.
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 512))
			_ = res.Body.Close()
			return nil
		},
	}, true
}
