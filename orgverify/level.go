// Package orgverify verifies that a did:dplaax Owner DID's orgId (FQDN) is
// endorsed by the actual domain owner via a DNS TXT record at
// _dplaax-org.<orgId>. See README.md for the wire format, verdict taxonomy,
// and security rationale — this package's implementation follows that
// document; where the two disagree, the README is the contract.
//
// Endorsement is one axis of a three-axis orthogonal trust model —
// independent of the DID method's own trust tier and of a VC's confidence
// state (vc.ConfidenceState).
package orgverify

// EndorsementLevel is the endorsement verdict Verify returns. Serialized on
// the wire (JSON field "endorsement_level", CLI text) as the lowercase values
// below — frozen together with the org verify exit codes (see ExitCode).
type EndorsementLevel string

const (
	// EndorsementVerified: the DID Document's #signing key fingerprint is
	// endorsed by the DNS TXT record(s) matching the DID.
	EndorsementVerified EndorsementLevel = "verified"
	// EndorsementMissing: no DNS TXT record endorses the DID — either no
	// records exist at the expected name, or records exist but none name
	// this DID.
	EndorsementMissing EndorsementLevel = "missing"
	// EndorsementInvalid: DNS records name this DID but disagree with the
	// DID Document's key, disagree with each other, or are malformed while
	// clearly intended for this DID.
	EndorsementInvalid EndorsementLevel = "invalid"
	// EndorsementUnreachable: a transient failure prevented a verdict — DNS
	// timeout/SERVFAIL/transport error, or the DID Document could not be
	// fetched. Not a security verdict; retry may succeed.
	EndorsementUnreachable EndorsementLevel = "unreachable"
	// EndorsementNA: the DID's orgId is not a usable FQDN (single label,
	// public suffix, or a non-ASCII/unicode IDN) — DNS-based endorsement
	// does not apply.
	EndorsementNA EndorsementLevel = "na"
)

// ExitCode returns the `provin org verify` process exit code for l — the
// single source of truth for the level ↔ exit-code mapping (spec §7.2), so
// the CLI layer never re-encodes it. The zero value / any other string
// never occurs from a Result this package constructs; the fallback is a
// visibly-out-of-range sentinel, not one of the five defined codes.
func (l EndorsementLevel) ExitCode() int {
	switch l {
	case EndorsementVerified:
		return 0
	case EndorsementMissing:
		return 1
	case EndorsementInvalid:
		return 2
	case EndorsementUnreachable:
		return 3
	case EndorsementNA:
		return 4
	default:
		return 70
	}
}
