package main

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
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
// emitHealthCadence — pure TTL -> initial-interval derivation (unchanged by
// the P2 fix: this seeds ONLY the reporter's first interval; every
// subsequent one comes from cadenceFromReturnedTTL, below).
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
// cadenceFromReturnedTTL (P2 Codex) — the REGISTRY's returned TTL re-derives
// the reporter's cadence on every successful report, unlike emitHealthCadence
// (which only ever seeds the initial value from this binary's own local
// config).
// ─────────────────────────────────────────────────────────────────────────

func TestCadenceFromReturnedTTL(t *testing.T) {
	cases := []struct {
		name string
		ttl  time.Duration
		want time.Duration
	}{
		{"well above the floor: ttl/3 wins", 30 * time.Second, 10 * time.Second},
		{"generously above the floor", 3 * time.Minute, time.Minute},
		{"ttl/3 below the floor, but ttl/2 still clears it: floor applies", 12 * time.Second, minEmitHealthCadence}, // ttl/3=4s<5s floor; ttl/2=6s>=5s -> floor (5s) applies uncapped
		{"ttl/3 below the floor AND floor would exceed ttl/2: capped at ttl/2", 6 * time.Second, 3 * time.Second},   // ttl/3=2s<5s floor; ttl/2=3s<5s floor -> capped at 3s
		{"degenerate tiny ttl: absolute minimum wins", 100 * time.Millisecond, minAbsoluteEmitHealthCadence},
		{"non-positive ttl: caller keeps current cadence (0 signals no-op)", 0, 0},
		{"negative ttl: same no-op signal", -time.Second, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cadenceFromReturnedTTL(c.ttl); got != c.want {
				t.Errorf("cadenceFromReturnedTTL(%s) = %s, want %s", c.ttl, got, c.want)
			}
		})
	}
}

// TestCadenceFromReturnedTTL_AtTheFloorBoundary pins the exact ttl at which
// ttl/3 first clears minEmitHealthCadence (15s -> 5s), mirroring
// TestEmitHealthCadence's own boundary case.
func TestCadenceFromReturnedTTL_AtTheFloorBoundary(t *testing.T) {
	if got := cadenceFromReturnedTTL(15 * time.Second); got != minEmitHealthCadence {
		t.Errorf("cadenceFromReturnedTTL(15s) = %s, want %s (ttl/3 exactly at the floor)", got, minEmitHealthCadence)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// producingLoops — the (Name, OutputSubject) pairing preflightPayloadRetainKeys
// (wiring.go) and emitHealthReporterSpecsFor (below) both derive from.
// ─────────────────────────────────────────────────────────────────────────

func TestProducingLoops_ExcludesSink(t *testing.T) {
	loops := []pipelineconfig.LoopConfig{
		{Name: "src", Role: pipelineconfig.RoleSource, Source: pipelineconfig.SourceConfig{OutputSubject: "did:dplaax:reg:org:acme:pipeline:src"}},
		{Name: "chn", Role: pipelineconfig.RoleChained, Chained: pipelineconfig.ChainedConfig{OutputSubject: "did:dplaax:reg:org:acme:pipeline:chn"}},
		{Name: "agg", Role: pipelineconfig.RoleAggregate, Aggregate: pipelineconfig.AggregateConfig{OutputSubject: "did:dplaax:reg:org:acme:pipeline:agg"}},
		{Name: "snk", Role: pipelineconfig.RoleSink, Sink: pipelineconfig.SinkConfig{}},
	}
	got := producingLoops(loops)
	want := []producingLoopRef{
		{Name: "src", OutputSubject: "did:dplaax:reg:org:acme:pipeline:src"},
		{Name: "chn", OutputSubject: "did:dplaax:reg:org:acme:pipeline:chn"},
		{Name: "agg", OutputSubject: "did:dplaax:reg:org:acme:pipeline:agg"},
	}
	if len(got) != len(want) {
		t.Fatalf("producingLoops = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("producingLoops = %+v, want %+v", got, want)
		}
	}
}

func TestProducingLoops_EmptyLoopsYieldsEmpty(t *testing.T) {
	if got := producingLoops(nil); len(got) != 0 {
		t.Fatalf("producingLoops(nil) = %+v, want empty", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// emitHealthSourcesByName / emitHealthReporterSpecsFor (P1 fix) — binding a
// reporter to ITS OWN producer's stripped-publish health accessor, matched
// by loop name.
// ─────────────────────────────────────────────────────────────────────────

// fakeStrippedSource is a minimal runtime.StrippedCounter (LoopMetrics.Stripped's
// declared field type) that ALSO implements emitHealthSource, mirroring how
// *transport.Loop / *aggregate.Process structurally satisfy both — a plain
// bool pointer for StrippedPublishHealthy so a test can flip it between
// report() calls; StrippedPublishFailures is never exercised here.
type fakeStrippedSource struct{ healthy *bool }

func (f fakeStrippedSource) StrippedPublishHealthy() bool    { return *f.healthy }
func (f fakeStrippedSource) StrippedPublishFailures() uint64 { return 0 }

func TestEmitHealthSourcesByName_IndexesByLoopName(t *testing.T) {
	h := true
	metrics := []pipelineruntime.LoopMetrics{
		{Name: "src", Stripped: fakeStrippedSource{healthy: &h}},
		{Name: "snk"}, // sink: no Stripped accessor at all (nil)
	}
	sources := emitHealthSourcesByName(metrics)
	if len(sources) != 1 {
		t.Fatalf("emitHealthSourcesByName = %d entries, want 1 (sink has no Stripped accessor)", len(sources))
	}
	if _, ok := sources["src"]; !ok {
		t.Error(`emitHealthSourcesByName missing "src"`)
	}
	if _, ok := sources["snk"]; ok {
		t.Error(`emitHealthSourcesByName should not have an entry for "snk" (nil Stripped)`)
	}
}

func TestEmitHealthReporterSpecsFor_BindsEachProducerToItsOwnAccessor(t *testing.T) {
	loops := []pipelineconfig.LoopConfig{
		{Name: "src", Role: pipelineconfig.RoleSource, Source: pipelineconfig.SourceConfig{OutputSubject: "did:dplaax:reg:org:acme:pipeline:src"}},
		{Name: "agg", Role: pipelineconfig.RoleAggregate, Aggregate: pipelineconfig.AggregateConfig{OutputSubject: "did:dplaax:reg:org:acme:pipeline:agg"}},
	}
	srcHealthy := true
	aggHealthy := false
	metrics := []pipelineruntime.LoopMetrics{
		{Name: "src", Stripped: fakeStrippedSource{healthy: &srcHealthy}},
		{Name: "agg", Stripped: fakeStrippedSource{healthy: &aggHealthy}},
	}

	specs := emitHealthReporterSpecsFor(loops, metrics)
	if len(specs) != 2 {
		t.Fatalf("emitHealthReporterSpecsFor = %d specs, want 2", len(specs))
	}
	byOutput := map[string]emitHealthReporterSpec{}
	for _, s := range specs {
		byOutput[s.OutputSubject] = s
	}
	src, ok := byOutput["did:dplaax:reg:org:acme:pipeline:src"]
	if !ok {
		t.Fatal("missing spec for src's output subject")
	}
	if !src.Healthy() {
		t.Error("src's spec.Healthy() = false, want true (src's own accessor)")
	}
	agg, ok := byOutput["did:dplaax:reg:org:acme:pipeline:agg"]
	if !ok {
		t.Fatal("missing spec for agg's output subject")
	}
	if agg.Healthy() {
		t.Error("agg's spec.Healthy() = true, want false (agg's own accessor)")
	}

	// Flipping src's health must NOT affect agg's spec, and vice versa — each
	// reporter reads its OWN producer, never a shared/mismatched one.
	srcHealthy = false
	if src.Healthy() {
		t.Error("src's spec.Healthy() did not track its own accessor's live value")
	}
	if agg.Healthy() {
		t.Error("flipping src's health must not affect agg's spec")
	}
}

// TestEmitHealthReporterSpecsFor_NoMatchingSourceDefaultsHealthy proves the
// defensive fallback: a producing loop with no matching metrics entry (a
// should-be-impossible gap per D-6) reports healthy=true rather than
// panicking on a nil func.
func TestEmitHealthReporterSpecsFor_NoMatchingSourceDefaultsHealthy(t *testing.T) {
	loops := []pipelineconfig.LoopConfig{
		{Name: "src", Role: pipelineconfig.RoleSource, Source: pipelineconfig.SourceConfig{OutputSubject: "did:dplaax:reg:org:acme:pipeline:src"}},
	}
	specs := emitHealthReporterSpecsFor(loops, nil) // no metrics at all
	if len(specs) != 1 {
		t.Fatalf("emitHealthReporterSpecsFor = %d specs, want 1", len(specs))
	}
	if !specs[0].Healthy() {
		t.Error("spec with no matching source: Healthy() = false, want true (defensive default)")
	}
}

func TestEmitHealthReporterSpecsFor_EmptyLoopsYieldsEmpty(t *testing.T) {
	if got := emitHealthReporterSpecsFor(nil, nil); len(got) != 0 {
		t.Fatalf("emitHealthReporterSpecsFor(nil, nil) = %v, want empty", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// emitHealthReporter.run / .report — cadence + immediate-first-report +
// stop-on-cancel + the P1 (current health) and P2 (registry-returned TTL
// retunes cadence) fixes.
// ─────────────────────────────────────────────────────────────────────────

type spiedReport struct {
	publisherDID string
	healthy      bool
}

// spyEmitHealthClient is emitHealthReportClient's test double. ttl is
// returned on every successful call (defaulting to the zero value — "no
// usable TTL", the report/no-op-cadence-change signal — unless a test sets
// it); errNext, if non-nil, is returned (and cleared) on the VERY NEXT call
// only, letting a test inject exactly one failure.
type spyEmitHealthClient struct {
	mu      sync.Mutex
	calls   []spiedReport
	ttl     time.Duration
	errNext error
}

func (s *spyEmitHealthClient) ReportEmitHealth(_ context.Context, publisherDID string, healthy bool) (time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, spiedReport{publisherDID: publisherDID, healthy: healthy})
	if s.errNext != nil {
		err := s.errNext
		s.errNext = nil
		return 0, err
	}
	return s.ttl, nil
}

func (s *spyEmitHealthClient) snapshot() []spiedReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]spiedReport(nil), s.calls...)
}

// TestEmitHealthReporter_ReportsImmediatelyThenOnCadence_StopsOnCancel
// proves: (1) a report lands immediately on entry, before the first tick —
// closing the "degraded until the first interval elapses" boot gap; (2)
// subsequent reports keep landing on r.interval (the spy's ttl is left at
// its zero value, the "no usable TTL" no-op-cadence-change signal, so this
// test's cadence stays exactly r.interval throughout — the P2 retuning path
// is exercised by its own dedicated test below); (3) run returns promptly
// once ctx is cancelled; (4) every report carries the configured publisher
// DID and healthy=true (the default nil-healthy accessor).
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

// TestEmitHealthReporter_SendsCurrentHealthEveryTick is the P1 (converged)
// fix's core proof: a reporter whose producer turns unhealthy sends
// healthy=false on the NEXT report, not the hardcoded true every prior
// version sent regardless of the producer's actual state.
func TestEmitHealthReporter_SendsCurrentHealthEveryTick(t *testing.T) {
	spy := &spyEmitHealthClient{}
	var healthy atomic.Bool
	healthy.Store(true)
	r := &emitHealthReporter{
		client:       spy,
		publisherDID: "did:dplaax:reg:org:acme:pipeline:p",
		interval:     time.Hour, // never ticks on its own; this test drives report() directly
		healthy:      healthy.Load,
	}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	r.report(context.Background(), ticker)
	healthy.Store(false)
	r.report(context.Background(), ticker)
	healthy.Store(true)
	r.report(context.Background(), ticker)

	calls := spy.snapshot()
	if len(calls) != 3 {
		t.Fatalf("report count = %d, want 3", len(calls))
	}
	want := []bool{true, false, true}
	for i, w := range want {
		if calls[i].healthy != w {
			t.Errorf("call %d: healthy = %v, want %v", i, calls[i].healthy, w)
		}
	}
}

// TestEmitHealthReporter_NilHealthyDefaultsTrue proves the defensive default
// (currentlyHealthy's doc): a hand-built reporter with no healthy accessor
// reports true, never panics.
func TestEmitHealthReporter_NilHealthyDefaultsTrue(t *testing.T) {
	spy := &spyEmitHealthClient{}
	r := &emitHealthReporter{client: spy, publisherDID: "did:dplaax:reg:org:acme:pipeline:p", interval: time.Hour}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	r.report(context.Background(), ticker)

	calls := spy.snapshot()
	if len(calls) != 1 || !calls[0].healthy {
		t.Fatalf("report with nil healthy accessor = %+v, want exactly one healthy=true call", calls)
	}
}

// TestEmitHealthReporter_RetunesCadenceFromReturnedTTL is the P2 (Codex)
// fix's core proof: after a successful report, the reporter's cadence comes
// from the REGISTRY's returned TTL (via cadenceFromReturnedTTL), not the
// fixed interval it was constructed with.
func TestEmitHealthReporter_RetunesCadenceFromReturnedTTL(t *testing.T) {
	spy := &spyEmitHealthClient{ttl: 30 * time.Second} // ttl/3 = 10s
	r := &emitHealthReporter{client: spy, publisherDID: "did:dplaax:reg:org:acme:pipeline:p", interval: time.Minute}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	r.report(context.Background(), ticker)

	if r.interval != 10*time.Second {
		t.Errorf("interval after a report returning ttl=30s = %s, want 10s (ttl/3)", r.interval)
	}
}

// TestEmitHealthReporter_FailedReportLeavesCadenceUnchanged proves a failed
// report (registry unreachable, etc) does NOT retune cadence — the last
// known-good interval is the safest fallback for a registry that just
// proved unreachable.
func TestEmitHealthReporter_FailedReportLeavesCadenceUnchanged(t *testing.T) {
	spy := &spyEmitHealthClient{ttl: 30 * time.Second, errNext: context.DeadlineExceeded}
	r := &emitHealthReporter{client: spy, publisherDID: "did:dplaax:reg:org:acme:pipeline:p", interval: time.Minute}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	r.report(context.Background(), ticker)

	if r.interval != time.Minute {
		t.Errorf("interval after a FAILED report = %s, want unchanged (1m)", r.interval)
	}
}

// TestEmitHealthReporter_NonPositiveReturnedTTLLeavesCadenceUnchanged proves
// a successful report that returns a non-positive TTL (a misbehaving/older
// registry) is treated as "no usable TTL" — the cadence stays exactly as it
// was, never collapsing to the absolute minimum on bad input.
func TestEmitHealthReporter_NonPositiveReturnedTTLLeavesCadenceUnchanged(t *testing.T) {
	spy := &spyEmitHealthClient{ttl: 0}
	r := &emitHealthReporter{client: spy, publisherDID: "did:dplaax:reg:org:acme:pipeline:p", interval: 42 * time.Second}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	r.report(context.Background(), ticker)

	if r.interval != 42*time.Second {
		t.Errorf("interval after a report returning ttl=0 = %s, want unchanged (42s)", r.interval)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// buildEmitHealthReporters — wires each spec's OutputSubject + Healthy
// accessor into a reporter, signed/reported through the SAME identity.
// ─────────────────────────────────────────────────────────────────────────

func TestBuildEmitHealthReporters_WiresSpecsToReporters(t *testing.T) {
	seenDIDs := map[string]bool{}
	clientFor := func(publisherDID string) emitHealthReportClient {
		seenDIDs[publisherDID] = true
		return &spyEmitHealthClient{}
	}
	h1, h2 := true, false
	specs := []emitHealthReporterSpec{
		{OutputSubject: "did:dplaax:reg:org:acme:pipeline:a", Healthy: func() bool { return h1 }},
		{OutputSubject: "did:dplaax:reg:org:acme:pipeline:b", Healthy: func() bool { return h2 }},
	}
	reporters := buildEmitHealthReporters(specs, clientFor, 5*time.Second)
	if len(reporters) != 2 {
		t.Fatalf("buildEmitHealthReporters = %d reporters, want 2", len(reporters))
	}
	for _, want := range []string{"did:dplaax:reg:org:acme:pipeline:a", "did:dplaax:reg:org:acme:pipeline:b"} {
		if !seenDIDs[want] {
			t.Errorf("reportClientFor never called for %q", want)
		}
	}
	byDID := map[string]*emitHealthReporter{}
	for _, r := range reporters {
		byDID[r.publisherDID] = r
	}
	if !byDID["did:dplaax:reg:org:acme:pipeline:a"].currentlyHealthy() {
		t.Error("reporter a: currentlyHealthy() = false, want true (its own spec's accessor)")
	}
	if byDID["did:dplaax:reg:org:acme:pipeline:b"].currentlyHealthy() {
		t.Error("reporter b: currentlyHealthy() = true, want false (its own spec's accessor)")
	}
}
