// Package filter defines the FilterFlow step contract: stateless conditional
// pass/drop over a single event payload.
//
// Statelessness is definitional: a Filter implementation must not read or
// write any cross-event state. Each Apply call is independent.
//
// Error semantics:
//
//   - A non-nil error means the step itself failed (maps to
//     contract.StatusErrored at the processor layer). The event cannot be
//     processed; the caller logs and drops it loudly.
//   - Pass=false with nil error means the expression verdict was falsy (maps
//     to contract.StatusFiltered). The event is intentionally dropped; the
//     caller logs and drops it silently.
//
// These two outcomes are distinct: an error is a step failure; a falsy verdict
// is a deliberate pass/drop decision.
package filter

import "context"

// Result is the outcome of one Apply call.
type Result struct {
	// Pass is true when the event satisfies all filter expressions and should
	// continue down the pipeline. Pass=false means the event is dropped
	// (filtered verdict); the caller maps this to contract.StatusFiltered.
	Pass bool
}

// Filter is the FilterFlow step contract. Implementations are stateless:
// no cross-event state is permitted. Apply must be safe to call concurrently.
type Filter interface {
	Apply(ctx context.Context, data []byte) (*Result, error)
}
