package orgverify

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/resolver"
)

// Options bundles the dependencies and tunables for Verify/Inspect.
//
// DIDResolver is required — no useful default exists. It is the repository's
// existing top-level DID Document resolution contract (resolver.Resolver;
// see README.md's dependency DAG "orgverify -> did, resolver") — orgverify
// does not mint a parallel resolver interface. Callers (cmd/provin) own the
// wire: a resolver.Resolver implementation may do network I/O, but orgverify
// itself never imports network/ (see AGENTS.md layer rules).
//
// DNSResolver defaults to a system resolver (net.Resolver) when nil.
type Options struct {
	DNSResolver DNSResolver
	DIDResolver resolver.Resolver
	Now         func() time.Time
}

// Verify performs end-to-end DNS-based organization endorsement for didStr.
// See README.md for the wire format and verdict taxonomy.
func Verify(ctx context.Context, didStr string, opts Options) (*Result, error) {
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
	// Accept owner/pipeline/process; pipeline and process are normalized to
	// their owner for verification (README.md / spec §7.6). ValidateDID also
	// enforces the accountType=="org" gate and rejects unknown resource
	// patterns, so garbage DIDs don't silently coerce.
	if err := dplaax.ValidateDID(parsed); err != nil {
		return nil, fmt.Errorf("orgverify: validate DID: %w", err)
	}
	owner := parsed.OwnerDID()
	ownerStr := owner.String()

	res := &Result{
		DID:        didStr,
		OwnerDID:   ownerStr,
		VerifiedAt: now(),
	}

	// 1. FQDN normalization.
	canon, isFQDN, err := NormalizeFQDN(parsed.AccountID)
	if err != nil {
		return nil, fmt.Errorf("orgverify: orgId hostname syntax invalid: %w", err)
	}
	if !isFQDN {
		res.Level = EndorsementNA
		res.Reason = ReasonOrgIDNotFQDN
		res.Detail = fmt.Sprintf("orgId %q is not a valid FQDN (single label, public suffix, or unicode IDN)", parsed.AccountID)
		return res, nil
	}
	res.OrgID = canon

	// 2. DID Document fetch.
	doc, derr := opts.DIDResolver.Resolve(ctx, ownerStr)
	if derr != nil {
		res.Level = EndorsementUnreachable
		res.Reason = ReasonDocFetchFailed
		res.Detail = fmt.Sprintf("failed to fetch DID Document for %s: %v", ownerStr, derr)
		return res, nil
	}
	res.DIDDocumentSource = parsed.Registry

	// 3. Compute fingerprint from the DID Document's #signing key.
	docFP, err := FingerprintFromDIDDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("orgverify: compute fingerprint: %w", err)
	}
	res.KeyFingerprint = docFP

	// 4. DNS lookup at _dplaax-org.<orgId>.
	name := RecordName(canon)
	txtVals, derr := dnsR.LookupTXT(ctx, name)
	if derr != nil {
		if IsDNSReachabilityError(derr) {
			res.Level = EndorsementUnreachable
			res.Reason = ReasonDNSUnreachable
			res.Detail = fmt.Sprintf("DNS lookup failed for %s: %v", name, derr)
			return res, nil
		}
		if IsDNSNoRecordsError(derr) {
			res.Level = EndorsementMissing
			res.Reason = ReasonNoDNSRecords
			res.Detail = fmt.Sprintf("no DNS records at %s", name)
			return res, nil
		}
		res.Level = EndorsementUnreachable
		res.Reason = ReasonDNSUnreachable
		res.Detail = fmt.Sprintf("DNS lookup failed for %s: %v", name, derr)
		return res, nil
	}

	// 5. Parse TXT records and find matches for our Owner DID (spec §7.5
	// multi-record adjudication).
	matched, malformedForOurDID := scanTXTRecords(txtVals, ownerStr, res)

	// Branch (1): at least one record parses, its did= matches ownerStr.
	if len(matched) > 0 {
		allMatch := true
		anyMatch := false
		for _, m := range matched {
			if m.KeyFingerprint == docFP {
				anyMatch = true
			} else {
				allMatch = false
			}
		}
		if allMatch {
			res.Level = EndorsementVerified
			res.Reason = ReasonOK
			return res, nil
		}
		res.Level = EndorsementInvalid
		if anyMatch {
			res.Reason = ReasonKeyConflict
			res.Detail = fmt.Sprintf("DNS records for %s contain conflicting key fingerprints", ownerStr)
		} else {
			res.Reason = ReasonKeyMismatch
			res.Detail = fmt.Sprintf("DNS endorses different key (%s) than DID Document (%s)", matched[0].KeyFingerprint, docFP)
		}
		return res, nil
	}

	// Branch (2): no record's did= matched ownerStr.
	if malformedForOurDID {
		res.Level = EndorsementInvalid
		res.Reason = ReasonMalformedRecord
		res.Detail = fmt.Sprintf("DNS records for %s contain non-canonical encoding", ownerStr)
		return res, nil
	}
	res.Level = EndorsementMissing
	if len(res.DNSRecords) == 0 {
		res.Reason = ReasonNoDNSRecords
		res.Detail = fmt.Sprintf("no DNS records at %s", name)
	} else {
		res.Reason = ReasonDIDNotEndorsed
		res.Detail = fmt.Sprintf("DNS at %s does not endorse %s", name, ownerStr)
	}
	return res, nil
}

// scanTXTRecords parses each value, appends every successful parse to
// res.DNSRecords (inspection state), and returns the records whose did=
// equals ownerStr. The second return is true if a record that failed to
// parse nonetheless contains the literal substring "did=<ownerStr>" — a
// broken record clearly intended to endorse this DID (spec §7.5 branch (2)),
// as opposed to unrelated DNS noise at the same name.
func scanTXTRecords(values []string, ownerStr string, res *Result) (matched []DNSRecord, malformedForOurDID bool) {
	needle := "did=" + ownerStr
	for _, v := range values {
		rec, err := ParseTXT(v)
		if err != nil {
			if ownerStr != "" && strings.Contains(v, needle) {
				malformedForOurDID = true
			}
			continue
		}
		res.DNSRecords = append(res.DNSRecords, *rec)
		if rec.DID == ownerStr {
			matched = append(matched, *rec)
		}
	}
	return matched, malformedForOurDID
}
