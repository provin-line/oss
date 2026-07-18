package chainmanager

// OpReportEmitHealth is the wireauth op name for the ReportEmitHealth RPC — it
// MUST match exactly between the client's signed view (reportclient) and the
// handler's verification view (chainmanager/handler). ReportEmitHealth is
// reached through the L1-authorized ChainService mux (like the rest of that
// service's RPCs), so its op name is namespaced to avoid ever colliding with
// another L1-authorized surface's short op name — mirrors
// auditor.OpRegisterEvidence and payloadresolver.OpRetainPayload.
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
// Both the handler (verifying) and reportclient (signing) call this SAME
// builder — the one place that keeps the two derivations from drifting,
// mirroring auditor.RegisterEvidenceFields / payloadresolver.RetainPayloadFields.
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
