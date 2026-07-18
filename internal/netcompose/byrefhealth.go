package netcompose

// StrippedPublishHealthSource is the stripped-publish health a by-reference
// producer exposes. Both transport.Loop and aggregate.Process satisfy it. The
// gate lives here at the composition root, NOT in chainmanager — the control
// plane must not own data-plane transport-health policy (it consults only an
// abstract func() bool).
type StrippedPublishHealthSource interface {
	// StrippedPublishHealthy reports whether the producer's most recent stripped
	// publish succeeded (true also before it has emitted). Recovery is tied to an
	// actual successful stripped publish, not a time window, so a broken-but-quiet
	// producer never falsely reports healthy.
	StrippedPublishHealthy() bool
}

// ByRefHealthGate answers "is by-reference healthy to advertise right now?".
// It degrades whenever ANY producer's most recent stripped publish failed —
// any-producer-failing degrades the node, because the advertisement is
// node-level: under-advertising is safer than claiming a mode a producer can no
// longer honestly serve. With no sources it is always healthy (nothing to fail).
type ByRefHealthGate struct {
	sources []StrippedPublishHealthSource
}

// NewByRefHealthGate builds a gate over the given producers.
func NewByRefHealthGate(sources []StrippedPublishHealthSource) *ByRefHealthGate {
	return &ByRefHealthGate{sources: sources}
}

// Healthy reports whether by-reference should currently be advertised. Pull-
// evaluated (once per offeredPayloadModes call); no background goroutine, no
// clock — it reads each producer's last stripped-publish outcome. Exported
// because the composition root (cmd/standalone's main) reads this as a method
// value (byRefGate.Healthy) across the package boundary.
func (g *ByRefHealthGate) Healthy() bool {
	for _, src := range g.sources {
		if !src.StrippedPublishHealthy() {
			return false
		}
	}
	return true
}
