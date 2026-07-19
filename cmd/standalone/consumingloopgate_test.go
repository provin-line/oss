package main

import (
	"testing"

	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/batchresolver"
)

// gateConsumingLoopRunners reproduces BuildBatchResolver/BuildAuditRunner's former
// internal "no consuming loop -> nil" gate at this call site (Task 9): the builders now
// build unconditionally from their args, so cmd/standalone's zero-loop behavior — a
// source-only node runs neither background runner — depends on this caller-side gate
// instead. It must preserve the exact predicate the builders used to apply internally:
// pipelineconfig.Config.HasConsumingLoop().
func TestGateConsumingLoopRunners(t *testing.T) {
	// Non-nil stand-ins: a nil result below can only be this function's own doing, not
	// an upstream build failure (the zero-value composite literal is legal from outside
	// the package even though the struct's fields are unexported).
	br := &batchresolver.Runner{}
	ar := &auditor.Runner{}

	for _, tc := range []struct {
		name       string
		loops      []pipelineconfig.LoopConfig
		wantNonNil bool
	}{
		{"source-only", []pipelineconfig.LoopConfig{{Role: pipelineconfig.RoleSource}}, false},
		{"sink", []pipelineconfig.LoopConfig{{Role: pipelineconfig.RoleSink}}, true},
		{"chained", []pipelineconfig.LoopConfig{{Role: pipelineconfig.RoleChained}}, true},
		{"aggregate", []pipelineconfig.LoopConfig{{Role: pipelineconfig.RoleAggregate}}, true},
		{"no-loops", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &pipelineconfig.Config{Loops: tc.loops}
			gotBR, gotAR := gateConsumingLoopRunners(cfg, br, ar)
			if (gotBR != nil) != tc.wantNonNil {
				t.Errorf("batchRunner non-nil = %v, want %v", gotBR != nil, tc.wantNonNil)
			}
			if (gotAR != nil) != tc.wantNonNil {
				t.Errorf("auditRunner non-nil = %v, want %v", gotAR != nil, tc.wantNonNil)
			}
			if tc.wantNonNil && (gotBR != br || gotAR != ar) {
				t.Error("gate must pass the same runner instances through unchanged when a consuming loop exists")
			}
		})
	}
}
