package auditor

import "github.com/provin-line/oss/network/pkg/services/auditor/wirecontract"

// OpRegisterEvidence points at wirecontract.OpRegisterEvidence — defined in
// the leaf wirecontract package so a client-only consumer need
// not import this service root; this alias keeps existing call sites
// (auditor.OpRegisterEvidence, in the handler and elsewhere) unchanged. See
// wirecontract.OpRegisterEvidence for the full doc.
const OpRegisterEvidence = wirecontract.OpRegisterEvidence

// RegisterEvidenceFields calls wirecontract.RegisterEvidenceFields — see
// OpRegisterEvidence's doc.
func RegisterEvidenceFields(headVariantAddr string, canonicalConsumed []string) map[string]any {
	return wirecontract.RegisterEvidenceFields(headVariantAddr, canonicalConsumed)
}

// OpRegisterAuditHead points at wirecontract.OpRegisterAuditHead — see
// OpRegisterEvidence's doc.
const OpRegisterAuditHead = wirecontract.OpRegisterAuditHead

// RegisterAuditHeadFields calls wirecontract.RegisterAuditHeadFields —
// see OpRegisterEvidence's doc.
func RegisterAuditHeadFields(headVariantAddr string) map[string]any {
	return wirecontract.RegisterAuditHeadFields(headVariantAddr)
}
