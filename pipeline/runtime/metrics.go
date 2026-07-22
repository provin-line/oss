package runtime

// EmitCounters is the emit-outcome accessor pair every producing handle
// (transport.Loop, aggregate.Process) exposes. Method set mirrored verbatim
// from internal/netcompose/metrics.go's EmitCounters so those same concrete
// types satisfy both structurally — this package no longer imports
// internal/netcompose (network/ and pipeline/ never import each other,
// AGENTS.md rule 2); cmd/standalone converts a []LoopMetrics to
// []netcompose.LoopMetrics before handing it to the metrics bridge.
type EmitCounters interface {
	EmitSuccesses() uint64
	EmitFailures() uint64
}

// StrippedCounter is the stripped-publish failure accessor producing handles
// expose; registered only for loops that actually dual-emit. Mirrors
// internal/netcompose's StrippedCounter.
type StrippedCounter interface {
	StrippedPublishFailures() uint64
}

// VerifyCounts is the per-loop verify-outcome snapshot the metrics bridge
// polls — satisfied by *verifycount.Verifier. Mirrors internal/netcompose's
// VerifyCounts.
type VerifyCounts interface {
	Snapshot() map[string]uint64
}

// LoopMetrics is one loop's metrics wiring, populated by Build in
// construction order and returned by Runtime.Metrics(). Name becomes the
// series' `loop` attribute, Role records which capability set the wiring
// followed (a Role* constant value), and the non-nil accessors decide which
// metric families the loop participates in. Field-shape mirrors
// internal/netcompose's own LoopMetrics (which the metrics bridge — the
// composition root's OTel/Prometheus wiring — still consumes); cmd/standalone
// field-copies between the two so this package never imports the bridge's
// OTel/Prometheus dependency graph.
type LoopMetrics struct {
	Name string
	Role string // a Role* constant value
	// Emits is non-nil for producing loops (source/chained/aggregate).
	Emits EmitCounters
	// Stripped is non-nil when the loop dual-emits (a PayloadStore is wired).
	Stripped StrippedCounter
	// Verify is non-nil for consuming loops (sink/chained/aggregate).
	Verify VerifyCounts
}
