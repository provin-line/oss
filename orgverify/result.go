package orgverify

import "time"

// Reason is a machine-readable code explaining why Verify assigned a
// particular Level. It is not part of the wire TXT format — it is
// diagnostic output for Result/InspectResult consumers (e.g. `org diagnose`).
type Reason string

const (
	ReasonOK              Reason = "ok"
	ReasonDIDNotEndorsed  Reason = "did_not_endorsed" // DNS responded but no record names this DID -> Missing
	ReasonNoDNSRecords    Reason = "no_dns_records"   // NXDOMAIN or NOERROR+empty -> Missing
	ReasonKeyMismatch     Reason = "key_mismatch"     // DID listed but no matching record's key agrees with the DID Document -> Invalid
	ReasonKeyConflict     Reason = "key_conflict"     // multiple records name this DID and disagree with each other -> Invalid
	ReasonMalformedRecord Reason = "malformed_record" // a record clearly intended for this DID violates the TXT grammar -> Invalid
	ReasonDNSUnreachable  Reason = "dns_unreachable"  // timeout / SERVFAIL / transport -> Unreachable
	ReasonDocFetchFailed  Reason = "doc_fetch_failed" // DID Document could not be fetched -> Unreachable
	ReasonOrgIDNotFQDN    Reason = "orgid_not_fqdn"   // single label / public suffix / unicode IDN -> N/A
)

// DNSRecord is a parsed _dplaax-org TXT record.
type DNSRecord struct {
	Raw            string `json:"raw"`             // original value from DNS
	Version        string `json:"version"`         // v= field
	DID            string `json:"did"`             // did= field
	KeyFingerprint string `json:"key_fingerprint"` // key= field (sha256:<hex>)
	TTL            uint32 `json:"ttl,omitempty"`
}

// Result is the outcome of Verify.
type Result struct {
	DID               string           `json:"did"`       // input DID (as given)
	OwnerDID          string           `json:"owner_did"` // normalized to Owner level
	OrgID             string           `json:"org_id"`    // FQDN orgId (lowercased)
	Level             EndorsementLevel `json:"endorsement_level"`
	Reason            Reason           `json:"reason"`
	Detail            string           `json:"detail,omitempty"`
	DNSRecords        []DNSRecord      `json:"dns_records,omitempty"`
	KeyFingerprint    string           `json:"key_fingerprint,omitempty"`     // computed from the DID Document's #signing key
	DIDDocumentSource string           `json:"did_document_source,omitempty"` // registry hostname the DID names
	VerifiedAt        time.Time        `json:"verified_at"`
}
