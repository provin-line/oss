// Package wirecontract holds the payloadresolver service's wire-level
// contract: the wireauth op name and signed-view field builder every
// RetainPayload client and handler must derive IDENTICALLY.
//
// It is a LEAF (PR3b Task 2): it imports only stdlib — never the
// payloadresolver service root, never gen/ — so a consumer that needs only
// the wire contract (payloadresolver/client today; a future cmd/pipeline
// binary tomorrow) can depend on it without dragging in the service root's
// store/handler domain logic. The payloadresolver package keeps a
// back-compat const/var ALIAS for every symbol here (see
// payloadresolver/wireview.go) so existing handler/service/test call sites
// (payloadresolver.OpRetainPayload, etc.) do not churn.
package wirecontract

import "strconv"

// OpRetainPayload is the wireauth op name for the RetainPayload RPC — it MUST
// match exactly between the client's signed view (payloadresolver/client) and
// the handler's verification view (payloadresolver/storehandler). RetainPayload
// is reached through the L1-authorized PayloadStoreService mux (unlike
// PayloadService, which is mounted with no L1 interceptor at all — see the
// payloadresolver package's doc), so its op name is namespaced to avoid ever
// colliding with another L1-authorized surface's short op name — mirrors
// auditor's OpRegisterEvidence.
const OpRetainPayload = "dplaax.payload.v1.PayloadStoreService/RetainPayload"

// RetainPayloadFields builds the exact wireauth signed-view fields for one
// RetainPayload call: owner_did verbatim, plus declared_size as a decimal
// string (wireauth's fields value grammar forbids raw numbers — a caller-side
// or verifier-side int/float64 divergence would sign and verify differently,
// so every RPC's numeric business fields are carried as decimal strings by
// convention across this codebase).
//
// Both the payloadresolver/storehandler package (verifying) and the
// payloadresolver/client package (signing) call this SAME builder — the one
// place that keeps the two derivations from drifting, mirroring
// auditor's RegisterEvidenceFields.
func RetainPayloadFields(ownerDID string, declaredSize uint64) map[string]any {
	return map[string]any{
		"owner_did":     ownerDID,
		"declared_size": strconv.FormatUint(declaredSize, 10),
	}
}
