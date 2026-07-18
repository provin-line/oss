package auditor

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
// Exported (moved out of handler, slice pr2-evidence-wire D1 Task 6) so the
// auditclient package can sign the SAME op the handler verifies — living in
// one place is what keeps the two from ever drifting.
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
// Both the handler (verifying) and the auditclient package (signing) call
// this SAME builder — the one place that keeps the two derivations from
// drifting (moved out of the handler in slice pr2-evidence-wire D1 Task 6).
func RegisterEvidenceFields(headVariantAddr string, canonicalConsumed []string) map[string]any {
	return map[string]any{
		"head_variant_address":      headVariantAddr,
		"consumed_source_addresses": strings.Join(canonicalConsumed, registerEvidenceJoinSeparator),
	}
}
