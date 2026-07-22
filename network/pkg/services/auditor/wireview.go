package auditor

import "github.com/provin-line/oss/network/pkg/services/auditor/wirecontract"

// OpRegisterEvidence points at wirecontract.OpRegisterEvidence — moved into
// the leaf wirecontract package (PR3b Task 2) so a client-only consumer need
// not import this service root; this alias keeps existing call sites
// (auditor.OpRegisterEvidence, in the handler and elsewhere) unchanged. See
// wirecontract.OpRegisterEvidence for the full doc.
const OpRegisterEvidence = wirecontract.OpRegisterEvidence

// RegisterEvidenceFields points at wirecontract.RegisterEvidenceFields — see
// OpRegisterEvidence's alias doc.
var RegisterEvidenceFields = wirecontract.RegisterEvidenceFields

// OpRegisterAuditHead points at wirecontract.OpRegisterAuditHead — see
// OpRegisterEvidence's alias doc.
const OpRegisterAuditHead = wirecontract.OpRegisterAuditHead

// RegisterAuditHeadFields points at wirecontract.RegisterAuditHeadFields —
// see OpRegisterEvidence's alias doc.
var RegisterAuditHeadFields = wirecontract.RegisterAuditHeadFields
