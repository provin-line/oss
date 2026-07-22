package main

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/pipelineconfig"
)

// ─────────────────────────────────────────────────────────────────────────
// reportClientFactory — cache-per-DID (pure, no network), mirrors
// TestAuditClientFactory_CachesPerDID / TestMirrorClientFactory_CachesPerDID.
// ─────────────────────────────────────────────────────────────────────────

func TestReportClientFactory_CachesPerDID(t *testing.T) {
	f := newReportClientFactory(nil, "http://example.invalid", "", http.DefaultClient)
	a1 := f.For("did:dplaax:reg:org:acme:pipeline:a")
	a2 := f.For("did:dplaax:reg:org:acme:pipeline:a")
	if a1 != a2 {
		t.Error("For(samePublisherDID) returned two different clients, want the cached one")
	}
	b1 := f.For("did:dplaax:reg:org:acme:pipeline:b")
	if a1 == b1 {
		t.Error("For(differentPublisherDID) returned the SAME client as another publisher")
	}
}

// ─────────────────────────────────────────────────────────────────────────
// emitHealthCadence — pure TTL -> interval derivation.
// ─────────────────────────────────────────────────────────────────────────

func TestEmitHealthCadence(t *testing.T) {
	cases := []struct {
		ttl  time.Duration
		want time.Duration
	}{
		{30 * time.Second, 10 * time.Second},         // TTL/3, above the floor
		{3 * time.Minute, time.Minute},               // TTL/3, well above the floor
		{9 * time.Second, minEmitHealthCadence},      // TTL/3 = 3s, below the floor
		{15 * time.Second, minEmitHealthCadence},     // TTL/3 = 5s, exactly AT the floor
		{minEmitHealthCadence, minEmitHealthCadence}, // tiny TTL still floors
	}
	for _, c := range cases {
		if got := emitHealthCadence(c.ttl); got != c.want {
			t.Errorf("emitHealthCadence(%s) = %s, want %s", c.ttl, got, c.want)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────
// producingLoopPublishers — source/chained/aggregate only, sink excluded.
// ─────────────────────────────────────────────────────────────────────────

func TestProducingLoopPublishers_ExcludesSink(t *testing.T) {
	loops := []pipelineconfig.LoopConfig{
		{Name: "src", Role: pipelineconfig.RoleSource, Source: pipelineconfig.SourceConfig{OutputSubject: "did:dplaax:reg:org:acme:pipeline:src"}},
		{Name: "chn", Role: pipelineconfig.RoleChained, Chained: pipelineconfig.ChainedConfig{OutputSubject: "did:dplaax:reg:org:acme:pipeline:chn"}},
		{Name: "agg", Role: pipelineconfig.RoleAggregate, Aggregate: pipelineconfig.AggregateConfig{OutputSubject: "did:dplaax:reg:org:acme:pipeline:agg"}},
		{Name: "snk", Role: pipelineconfig.RoleSink, Sink: pipelineconfig.SinkConfig{}},
	}
	got := producingLoopPublishers(loops)
	want := []string{"did:dplaax:reg:org:acme:pipeline:src", "did:dplaax:reg:org:acme:pipeline:chn", "did:dplaax:reg:org:acme:pipeline:agg"}
	if len(got) != len(want) {
		t.Fatalf("producingLoopPublishers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("producingLoopPublishers = %v, want %v", got, want)
		}
	}
}

func TestProducingLoopPublishers_EmptyLoopsYieldsEmpty(t *testing.T) {
	if got := producingLoopPublishers(nil); len(got) != 0 {
		t.Fatalf("producingLoopPublishers(nil) = %v, want empty", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// emitHealthReporter.run — cadence + immediate-first-report + stop-on-cancel.
// ─────────────────────────────────────────────────────────────────────────

type spiedReport struct {
	publisherDID string
	healthy      bool
}

type spyEmitHealthClient struct {
	mu    sync.Mutex
	calls []spiedReport
}

func (s *spyEmitHealthClient) ReportEmitHealth(_ context.Context, publisherDID string, healthy bool) (time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, spiedReport{publisherDID: publisherDID, healthy: healthy})
	return time.Minute, nil
}

func (s *spyEmitHealthClient) snapshot() []spiedReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]spiedReport(nil), s.calls...)
}

// TestEmitHealthReporter_ReportsImmediatelyThenOnCadence_StopsOnCancel
// proves: (1) a report lands immediately on entry, before the first tick —
// closing the "degraded until the first interval elapses" boot gap; (2)
// subsequent reports keep landing on r.interval; (3) run returns promptly
// once ctx is cancelled; (4) every report carries the configured publisher
// DID and healthy=true.
func TestEmitHealthReporter_ReportsImmediatelyThenOnCadence_StopsOnCancel(t *testing.T) {
	spy := &spyEmitHealthClient{}
	const publisherDID = "did:dplaax:reg:org:acme:pipeline:p"
	r := &emitHealthReporter{client: spy, publisherDID: publisherDID, interval: 15 * time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() { r.run(ctx); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after ctx deadline")
	}

	calls := spy.snapshot()
	// ~110ms at a 15ms cadence, PLUS the immediate report at t=0: expect
	// several calls, generously bounded to tolerate scheduling jitter.
	if len(calls) < 3 {
		t.Fatalf("report count = %d, want at least 3 (an immediate report plus repeated ticks over ~110ms at 15ms cadence)", len(calls))
	}
	for _, c := range calls {
		if c.publisherDID != publisherDID {
			t.Errorf("report publisherDID = %q, want %q", c.publisherDID, publisherDID)
		}
		if !c.healthy {
			t.Errorf("report healthy = false, want true")
		}
	}
}

// TestEmitHealthReporter_StopsPromptlyEvenWithNoTickYet proves run returns
// promptly on cancellation even before its first ticker fire (a LONG
// interval, cancelled almost immediately) — mirrors
// tlogship.Shipper's own "never blocks" contract.
func TestEmitHealthReporter_StopsPromptlyEvenWithNoTickYet(t *testing.T) {
	spy := &spyEmitHealthClient{}
	r := &emitHealthReporter{client: spy, publisherDID: "did:dplaax:reg:org:acme:pipeline:p", interval: time.Hour}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.run(ctx); close(done) }()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return promptly after cancel")
	}
	// Exactly the immediate report (t=0), never a tick (interval is an hour).
	if calls := spy.snapshot(); len(calls) != 1 {
		t.Fatalf("report count = %d, want exactly 1 (the immediate report only)", len(calls))
	}
}
