package orgverify

import (
	"context"
	"fmt"
	"time"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
)

// InspectResult is the raw observational output of Inspect.
type InspectResult struct {
	DID               string           `json:"did"`
	OwnerDID          string           `json:"owner_did"`
	OrgID             string           `json:"org_id,omitempty"`
	IsFQDN            bool             `json:"is_fqdn"`
	DocumentRetrieved *did.DIDDocument `json:"did_document,omitempty"`
	DocumentError     string           `json:"did_document_error,omitempty"`
	KeyFingerprint    string           `json:"key_fingerprint,omitempty"`
	DNSName           string           `json:"dns_name,omitempty"`
	DNSRecords        []DNSRecord      `json:"dns_records,omitempty"`
	DNSError          string           `json:"dns_error,omitempty"`
	ObservedAt        time.Time        `json:"observed_at"`
}

// Inspect collects the same observations as Verify but does NOT compute a
// verdict. It returns DNS records, the DID Document, and the computed
// fingerprint, even if some of these are missing/failed — useful for the
// `org inspect` UX where the operator wants to see raw state.
func Inspect(ctx context.Context, didStr string, opts Options) (*InspectResult, error) {
	if opts.DIDResolver == nil {
		return nil, fmt.Errorf("orgverify: Options.DIDResolver is required")
	}
	dnsR := opts.DNSResolver
	if dnsR == nil {
		dnsR = NewSystemDNSResolver()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	parsed, err := dplaax.Parse(didStr)
	if err != nil {
		return nil, fmt.Errorf("orgverify: parse DID: %w", err)
	}
	if err := dplaax.ValidateDID(parsed); err != nil {
		return nil, fmt.Errorf("orgverify: validate DID: %w", err)
	}
	owner := parsed.OwnerDID()
	out := &InspectResult{
		DID:        didStr,
		OwnerDID:   owner.String(),
		ObservedAt: now(),
	}

	canon, isFQDN, err := NormalizeFQDN(parsed.AccountID)
	if err != nil {
		return nil, fmt.Errorf("orgverify: orgId hostname syntax invalid: %w", err)
	}
	out.IsFQDN = isFQDN
	out.OrgID = canon

	// DID Document fetch (best-effort).
	doc, derr := opts.DIDResolver.Resolve(ctx, owner.String())
	if derr != nil {
		out.DocumentError = derr.Error()
	} else {
		out.DocumentRetrieved = doc
		if fp, ferr := FingerprintFromDIDDocument(doc); ferr == nil {
			out.KeyFingerprint = fp
		}
	}

	if !isFQDN {
		return out, nil
	}

	// DNS lookup (best-effort).
	out.DNSName = RecordName(canon)
	txtVals, derr := dnsR.LookupTXT(ctx, out.DNSName)
	if derr != nil {
		out.DNSError = derr.Error()
		return out, nil
	}
	for _, v := range txtVals {
		rec, err := ParseTXT(v)
		if err != nil {
			out.DNSRecords = append(out.DNSRecords, DNSRecord{Raw: v}) // raw-only entry signals malformed
			continue
		}
		out.DNSRecords = append(out.DNSRecords, *rec)
	}
	return out, nil
}
