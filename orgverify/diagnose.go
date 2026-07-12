package orgverify

import (
	"fmt"

	"github.com/provin-line/oss/did/dplaax"
)

// RemediationStep is one suggested action to fix or investigate a non-Verified
// result.
type RemediationStep struct {
	Action string `json:"action"` // short imperative ("Add DNS TXT record")
	Detail string `json:"detail"` // multi-line explanation, may include a sample TXT record
}

// Diagnose returns remediation steps for a Result. EndorsementVerified
// returns nil (no remediation needed).
func Diagnose(r *Result) []RemediationStep {
	if r == nil || r.Level == EndorsementVerified {
		return nil
	}
	switch r.Reason {
	case ReasonDIDNotEndorsed, ReasonNoDNSRecords:
		return diagnoseNoEndorsement(r)
	case ReasonKeyMismatch, ReasonKeyConflict:
		return diagnoseKeyMismatch(r)
	case ReasonMalformedRecord:
		return diagnoseMalformed(r)
	case ReasonDNSUnreachable, ReasonDocFetchFailed:
		return diagnoseTransient(r)
	case ReasonOrgIDNotFQDN:
		return diagnoseNotFQDN(r)
	}
	return nil
}

func diagnoseNoEndorsement(r *Result) []RemediationStep {
	sample, _ := GenerateTXT(r.OwnerDID, r.KeyFingerprint)
	return []RemediationStep{{
		Action: "Add DNS TXT record at " + RecordName(r.OrgID),
		Detail: fmt.Sprintf("As the operator of %s, publish this TXT record to endorse %s:\n\n  %s. IN TXT \"%s\"\n\nReceivers without this endorsement will treat the DID as squatting-suspect.", r.OrgID, r.OwnerDID, RecordName(r.OrgID), sample),
	}}
}

func diagnoseKeyMismatch(r *Result) []RemediationStep {
	sample, _ := GenerateTXT(r.OwnerDID, r.KeyFingerprint)
	return []RemediationStep{{
		Action: "Update DNS TXT record after key rotation",
		Detail: fmt.Sprintf("The signing key in the DID Document has been rotated, but DNS still endorses an older key. Update the TXT record at %s to:\n\n  %s. IN TXT \"%s\"\n\nIf no rotation was intended, this may indicate registry compromise — investigate immediately.", RecordName(r.OrgID), RecordName(r.OrgID), sample),
	}}
}

func diagnoseMalformed(r *Result) []RemediationStep {
	return []RemediationStep{{
		Action: "Fix malformed DNS TXT record",
		Detail: fmt.Sprintf("A TXT record for %s uses non-canonical encoding (uppercase hex, base64, or wrong format). Re-publish using `provin org generate-txt --did=%s ...` to produce a canonical record.", r.OwnerDID, r.OwnerDID),
	}}
}

func diagnoseTransient(r *Result) []RemediationStep {
	return []RemediationStep{{
		Action: "Retry after transient failure resolves",
		Detail: r.Detail + " — this may be a transient network or DNS issue. Retry, or check upstream service health.",
	}}
}

func diagnoseNotFQDN(r *Result) []RemediationStep {
	orgID := r.OwnerDID
	if parsed, err := dplaax.Parse(r.OwnerDID); err == nil {
		orgID = parsed.AccountID
	}
	return []RemediationStep{{
		Action: "Use an FQDN orgId for verifiable DIDs",
		Detail: fmt.Sprintf("orgId %q is not an FQDN, so DNS-based endorsement is not applicable. To enable it, issue a new DID with an FQDN orgId (e.g. acme.com) under your control.", orgID),
	}}
}
