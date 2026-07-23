package netcompose

import (
	"github.com/provin-line/oss/network/pkg/services/chainmanager/emithealth"
)

// EmitHealthWiring configures BuildHandler's publisher-scoped by-reference
// advertisement gate for a report-mode network node (cmd/network):
// ReportEmitHealth reports land in Store (mounted via chainhandler's
// WithEmitHealth), and chainmanager.WithPublisherHealth reads Store back per
// publisherDID to decide by-reference advertisement. AdvertiseWithoutReports
// is the advertise-without-reports config flag
// (provin.network.chain.emit-health.advertise-without-reports), threaded
// straight through to WithPublisherHealth.
//
// A nil *EmitHealthWiring disables the whole gate, leaving BuildHandler's
// byRefHealthy global gate (BuildHandler's byRefHealthy parameter) as the
// only advertisement gate in effect. The two composition models are mutually
// exclusive (chainmanager.New panics if both WithPublisherHealth and
// WithByReferenceHealth are wired on the same Service), so a caller must never
// pass both a non-nil byRefHealthy AND a non-nil EmitHealthWiring.
type EmitHealthWiring struct {
	// Store backs both the operator handler's ReportEmitHealth RPC (Report)
	// and the per-publisher advertisement lookup (State).
	Store *emithealth.Store
	// AdvertiseWithoutReports mirrors
	// provin.network.chain.emit-health.advertise-without-reports.
	AdvertiseWithoutReports bool
}
