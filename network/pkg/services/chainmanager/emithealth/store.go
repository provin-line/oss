// Package emithealth is a per-publisher, in-memory TTL store of
// ReportEmitHealth reports: a publisher's self-reported stripped-publish
// health, expiring after a configured TTL. It backs the publisher-scoped
// by-reference advertisement gate (chainmanager.WithPublisherHealth) on a
// report-mode network node (cmd/network) — the per-process analogue of
// cmd/standalone's in-process WithByReferenceHealth gate. TTL and the
// advertise-without-reports policy are configured via network/pkg/chainconfig
// (provin.network.chain.emit-health).
//
// Like wireauth's memNonceStore and netcompose's ByRefHealthGate, the store is
// pull-evaluated (State takes the caller's own "now", never reads a clock
// itself) and purely in-memory: a restart drops all reports, and the
// fail-degraded semantics (NeverReported and Expired both degrade unless
// advertise-without-reports is set) mean a restarted node simply requires
// publishers to re-report before it advertises by-reference for them again —
// never a false "healthy".
package emithealth

import (
	"sync"
	"time"
)

// HealthState is a publisher's reported health as of the instant State is
// evaluated.
type HealthState int

const (
	// NeverReported is a publisher this Store has never recorded a report
	// for. It is the zero value deliberately (AGENTS.md: zero values fail
	// closed) — an unrecognized publisher reads as "no report on file", never
	// as any positive health claim.
	NeverReported HealthState = iota
	// HealthyReported is a publisher whose most recently recorded report was
	// healthy and has not yet expired.
	HealthyReported
	// UnhealthyReported is a publisher whose most recently recorded report
	// was unhealthy and has not yet expired.
	UnhealthyReported
	// Expired is a publisher with a recorded report whose TTL has elapsed —
	// regardless of whether that last report was healthy or unhealthy, a
	// stale report is no longer trusted (fail-degraded).
	Expired
)

// report is one publisher's most recently recorded ReportEmitHealth call. A
// report is a point-in-time snapshot, not an aggregate — Report always
// replaces any prior entry for the same publisher.
type report struct {
	healthy bool
	at      time.Time
}

// Store is a per-publisher TTL store of ReportEmitHealth reports. The zero
// value is not usable; construct with New. Safe for concurrent use.
type Store struct {
	mu      sync.Mutex
	ttl     time.Duration
	reports map[string]report
}

// New returns a Store whose reports are considered fresh for ttl (see
// State's doc for the exact boundary semantics). ttl should be positive —
// network/pkg/chainconfig.LoadChainConfig enforces that at boot; New itself
// does not re-validate it.
func New(ttl time.Duration) *Store {
	return &Store{ttl: ttl, reports: make(map[string]report)}
}

// Report records publisherDID's self-reported health as of now, replacing
// any prior report for that publisher.
func (s *Store) Report(publisherDID string, healthy bool, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports[publisherDID] = report{healthy: healthy, at: now}
}

// State reports publisherDID's health as of now:
//
//   - NeverReported: Report has never been called for publisherDID.
//   - Expired: a report exists, but now.Sub(at) >= ttl. The boundary is
//     pinned INCLUSIVE of ttl itself — a report exactly ttl old is already
//     Expired, not still fresh — mirroring the response's ttl field as a
//     hard, not-inclusive freshness bound: a consumer that waits exactly ttl
//     before re-checking must never observe a report as still fresh.
//   - HealthyReported / UnhealthyReported: a report exists, has not expired
//     (now.Sub(at) < ttl), and its last recorded value was healthy /
//     unhealthy respectively.
func (s *Store) State(publisherDID string, now time.Time) HealthState {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reports[publisherDID]
	if !ok {
		return NeverReported
	}
	if now.Sub(r.at) >= s.ttl {
		return Expired
	}
	if r.healthy {
		return HealthyReported
	}
	return UnhealthyReported
}
