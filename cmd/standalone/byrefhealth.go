package main

// strippedPublishHealthSource is the stripped-publish health a by-reference
// producer exposes. Both transport.Loop and aggregate.Process satisfy it. The
// gate lives here at the composition root, NOT in chainmanager — the control
// plane must not own data-plane transport-health policy (it consults only an
// abstract func() bool).
type strippedPublishHealthSource interface {
	// StrippedPublishHealthy reports whether the producer's most recent stripped
	// publish succeeded (true also before it has emitted). Recovery is tied to an
	// actual successful stripped publish, not a time window, so a broken-but-quiet
	// producer never falsely reports healthy.
	StrippedPublishHealthy() bool
}

// byRefHealthGate answers "is by-reference healthy to advertise right now?".
// It degrades whenever ANY producer's most recent stripped publish failed —
// any-producer-failing degrades the node, because the advertisement is
// node-level: under-advertising is safer than claiming a mode a producer can no
// longer honestly serve. With no sources it is always healthy (nothing to fail).
type byRefHealthGate struct {
	sources []strippedPublishHealthSource
}

// newByRefHealthGate builds a gate over the given producers.
func newByRefHealthGate(sources []strippedPublishHealthSource) *byRefHealthGate {
	return &byRefHealthGate{sources: sources}
}

// healthy reports whether by-reference should currently be advertised. Pull-
// evaluated (once per offeredPayloadModes call); no background goroutine, no
// clock — it reads each producer's last stripped-publish outcome.
func (g *byRefHealthGate) healthy() bool {
	for _, src := range g.sources {
		if !src.StrippedPublishHealthy() {
			return false
		}
	}
	return true
}
