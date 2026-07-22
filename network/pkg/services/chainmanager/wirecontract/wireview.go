// Package wirecontract holds chainmanager's wire-level contract for the
// ReportEmitHealth RPC: the wireauth op name and signed-view field builder
// the reportclient (signing) and chainmanager/handler (verifying) packages
// must derive IDENTICALLY.
//
// It is a LEAF (PR3b Task 8's depsguard fix, applying the T2 split
// auditor/payloadresolver/tlogservice already have — see e.g.
// auditor/wirecontract's own package doc): it imports nothing but this one
// file's own declarations, so a consumer that needs only the wire contract
// (chainmanager/reportclient today; cmd/pipeline transitively) can depend on
// it without dragging in the chainmanager service ROOT's Service
// implementation and its store/infra/emithealth dependencies — the entire
// architectural gap cmd/pipeline/depsguard_test.go used to carve a
// documented exception for. The chainmanager package keeps a back-compat
// const/var ALIAS for every symbol here (see chainmanager/wireview.go) so
// existing call sites (chainmanager.OpReportEmitHealth, in the handler and
// its tests) do not churn.
package wirecontract

// OpReportEmitHealth is the wireauth op name for the ReportEmitHealth RPC — it
// MUST match exactly between the client's signed view (reportclient) and the
// handler's verification view (chainmanager/handler). ReportEmitHealth is
// reached through the L1-authorized ChainService mux (like the rest of that
// service's RPCs), so its op name is namespaced to avoid ever colliding with
// another L1-authorized surface's short op name — mirrors
// auditor.OpRegisterEvidence and payloadresolver.OpRetainPayload.
//
// Exported (moved out of the chainmanager service root into this leaf
// package, PR3b Task 8 — the T2 split chainmanager never got) so the
// reportclient package can sign the SAME op the chainmanager/handler package
// verifies — living in one place is what keeps the two from ever drifting.
const OpReportEmitHealth = "dplaax.chain.v1.ChainService/ReportEmitHealth"

// ReportEmitHealthFields builds the exact wireauth signed-view fields for one
// ReportEmitHealth call: publisher_did verbatim, plus healthy encoded as the
// literal string "true"/"false" — deliberately NOT a raw Go bool. wireauth's
// fields value grammar happens to admit bool directly (validateFields), but
// this op does not rely on that special case: every other typed business
// field elsewhere in this codebase is carried as an explicit string (e.g.
// payloadresolver.RetainPayloadFields' declared_size, a decimal string), so
// healthy follows the SAME all-string-business-value convention rather than
// being the one field whose Go type is load-bearing for the signed bytes.
//
// Both the chainmanager/handler package (verifying) and reportclient package
// (signing) call this SAME builder — the one place that keeps the two
// derivations from drifting, mirroring auditor.RegisterEvidenceFields /
// payloadresolver.RetainPayloadFields. Moved out of the chainmanager service
// root into this leaf package, PR3b Task 8.
func ReportEmitHealthFields(publisherDID string, healthy bool) map[string]any {
	return map[string]any{
		"publisher_did": publisherDID,
		"healthy":       healthyString(healthy),
	}
}

// healthyString is ReportEmitHealthFields' deterministic string encoding of a
// bool: exactly "true" or "false", nothing else.
func healthyString(healthy bool) string {
	if healthy {
		return "true"
	}
	return "false"
}
