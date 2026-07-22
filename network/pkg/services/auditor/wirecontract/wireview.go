// Package wirecontract holds the auditor service's wire-level contract: the
// wireauth op names and signed-view field builders every write RPC's client
// and handler must derive IDENTICALLY (D7 — an evidence-write RPC carries an
// L2-style wireauth proof signed by the acting pipeline/process DID), plus
// the consumed-set canonicalization (consumedset.go) both the receipt stores
// and the RPC handler enforce.
//
// It is a LEAF (PR3b Task 2): it imports at most stdlib and vc — never the
// auditor service root, never gen/ — so a consumer that needs only the wire
// contract (auditor/client today; a future cmd/pipeline binary tomorrow) can
// depend on it without dragging in the service root's store/runner/handler
// domain logic. The auditor package keeps a back-compat const/var ALIAS for
// every symbol here (see auditor/wireview.go and auditor/receipt.go) so
// existing handler/service/test call sites (auditor.OpRegisterEvidence, etc.)
// do not churn.
package wirecontract

import "strings"

// OpRegisterEvidence is the wireauth op name for the RegisterEvidence RPC — it
// MUST match exactly between the client's signed view and the handler's
// verification view (D7: every evidence-write RPC carries an L2-style
// wireauth proof signed by the acting pipeline/process DID). Unlike the peer
// surface's short op names, this one carries the full RPC identity:
// RegisterEvidence is reached through the L1-authorized AuditService mux
// (unlike ChainPeerService/PayloadService, which are mounted with no L1
// interceptor at all), so its op name is namespaced to avoid ever colliding
// with another L1-authorized surface's short op name.
//
// Exported (moved out of the handler, slice pr2-evidence-wire D1 Task 6; moved
// again out of the auditor service root into this leaf package, PR3b Task 2)
// so the auditor/client package can sign the SAME op the auditor/handler
// package verifies — living in one place is what keeps the two from ever
// drifting.
const OpRegisterEvidence = "dplaax.audit.v1.AuditService/RegisterEvidence"

// registerEvidenceJoinSeparator deterministically joins the canonical
// consumed-source set into the single signed field the proof covers. A
// newline is unambiguous because CanonicalizeConsumedSet ENFORCES that every
// member is a well-formed "sha256:<64 lowercase hex>" content address
// (rejecting anything else, including an embedded "\n", with an error) — not
// merely an assumption at this join site. That fixed length and hex-only
// alphabet is what makes the join collision-free: two different consumed
// sets can never join to the same signed bytes, because no member can itself
// contain the separator or vary in length.
const registerEvidenceJoinSeparator = "\n"

// RegisterEvidenceFields builds the exact wireauth signed-view fields for one
// RegisterEvidence call: head_variant_address verbatim, plus the
// deterministic "\n" join of canonicalConsumed — which MUST already be the
// CanonicalizeConsumedSet output (sorted, deduplicated), never the
// as-submitted order, so a caller resubmitting the same set in a different
// order signs and verifies identically.
//
// headVariantAddr is documented (P1-A) as the WIRE VARIANT id StoreVC
// returns, not a body content address — but the signed-view KEY stays
// "head_variant_address": it names the proto field it signs 1:1
// (RegisterEvidenceRequest.head_variant_address, unchanged by P1-A), and a
// key that diverged from its field's name would read as covering a
// DIFFERENT value than the one actually signed. Renaming the map key alone,
// leaving the proto field name untouched, would trade one accuracy problem
// for another.
//
// Both the auditor/handler package (verifying) and the auditor/client
// package (signing) call this SAME builder — the one place that keeps the
// two derivations from drifting (moved out of the handler in slice
// pr2-evidence-wire D1 Task 6; moved again out of the auditor service root
// into this leaf package, PR3b Task 2).
func RegisterEvidenceFields(headVariantAddr string, canonicalConsumed []string) map[string]any {
	return map[string]any{
		"head_variant_address":      headVariantAddr,
		"consumed_source_addresses": strings.Join(canonicalConsumed, registerEvidenceJoinSeparator),
	}
}

// OpRegisterAuditHead is the wireauth op name for the RegisterAuditHead
// RPC — mirrors OpRegisterEvidence's exact convention (the full namespaced
// RPC identity, since RegisterAuditHead is reached through the SAME
// L1-authorized AuditService mux): it MUST match exactly between the
// client's signed view and the handler's verification view.
//
// Exported for the same reason OpRegisterEvidence is: the auditor/client
// package signs the SAME op this package's handler verifies — living in one
// place is what keeps the two from ever drifting.
const OpRegisterAuditHead = "dplaax.audit.v1.AuditService/RegisterAuditHead"

// RegisterAuditHeadFields builds the exact wireauth signed-view fields for
// one RegisterAuditHead call: head_variant_address verbatim — mirrors
// RegisterEvidenceFields' style and doc, minus the consumed-set join
// RegisterEvidenceFields also carries: RegisterAuditHead never carries a
// consumed set (it writes no receipt at all, see
// EvidenceService.RegisterHead's own doc), so there is nothing else to fold
// into the signed view.
//
// Both the auditor/handler package (verifying) and the auditor/client
// package (signing) call this SAME builder — the one place that keeps the
// two derivations from drifting.
func RegisterAuditHeadFields(headVariantAddr string) map[string]any {
	return map[string]any{
		"head_variant_address": headVariantAddr,
	}
}
