package netcompose

import (
	"github.com/provin-line/oss/network/pkg/services/tlogservice/mirrorstore"
)

// MirrorWiring configures BuildHandler's D-T4 mirror-custody surface for a
// node that durably mirrors remote emission/receipt/reject logs
// (cmd/network): Store backs both TlogService's second read source (behind
// the static log map) and MirrorLogSegment's D-T2/D-T3 write path.
// MaxBatchRecords/MaxBatchBytes are the D-T2 rule 5 caps
// (pipelineconfig.TlogMirrorConfig). MaxBatchBytes additionally sizes
// MirrorLogSegment's own connect mount read cap (mirrorReadCapBytes) — the
// two are structurally the same knob, never independently configured.
//
// A nil *MirrorWiring keeps the map-only behavior: MirrorLogSegment/
// GetMirrorState both report ErrMirrorNotConfigured
// (CodeUnimplemented) rather than touching a store this node was never
// given, and TlogService mounts entirely under the proof-class read cap
// (no MirrorLogSegment override — see BuildHandler's mounting comment).
type MirrorWiring struct {
	Store           *mirrorstore.Store
	MaxBatchRecords int
	MaxBatchBytes   int
}
