package orgverify

import (
	"fmt"
	"regexp"
	"strings"
)

const txtVersion = "dplaax1"

// recordPrefix is the DNS TXT record name prefix; the full name is
// recordPrefix + orgId. RecordName is the single source of this string so
// the DNS lookup (Verify/Inspect) and the generated record name
// (GenerateTXT's caller, `org generate-txt`) cannot drift apart.
const recordPrefix = "_dplaax-org."

// strict: sha256:<exactly 64 lowercase hex chars>
var fingerprintRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// RecordName returns the DNS TXT record name for orgId (a normalized FQDN,
// see NormalizeFQDN) — "_dplaax-org.<orgId>".
func RecordName(orgID string) string { return recordPrefix + orgID }

// ParseTXT parses one _dplaax-org TXT record value of the form
// "v=dplaax1; did=<full-did>; key=sha256:<64-lowercase-hex>".
//
// Parsing is strict — this is a security boundary (see README.md), not a
// liberal wire-format reader:
//   - segments are ";"-separated and trimmed; each segment MUST be
//     "key=value" — a segment with no "=" is malformed (not silently
//     skipped).
//   - v / did / key are the known keys. A known key appearing more than once
//     is malformed (no last-wins conflation of two asserted values under one
//     name — that would let an attacker append a controlling occurrence to
//     an operator-authored record and rely on some readers preferring one
//     occurrence and other readers preferring the other). Unknown keys are
//     ignored (forward compatibility).
//   - v= must equal "dplaax1" exactly. key= must match
//     sha256:[0-9a-f]{64} exactly — uppercase hex and base64 are rejected,
//     never normalized.
func ParseTXT(raw string) (*DNSRecord, error) {
	rec := &DNSRecord{Raw: raw}
	var sawV, sawDID, sawKey bool
	for _, p := range strings.Split(raw, ";") {
		p = strings.TrimSpace(p)
		eq := strings.IndexByte(p, '=')
		if eq < 0 {
			return nil, fmt.Errorf("malformed segment %q: expected key=value", p)
		}
		k := strings.TrimSpace(p[:eq])
		v := strings.TrimSpace(p[eq+1:])
		switch k {
		case "v":
			if sawV {
				return nil, fmt.Errorf("duplicate v= field")
			}
			sawV = true
			rec.Version = v
		case "did":
			if sawDID {
				return nil, fmt.Errorf("duplicate did= field")
			}
			sawDID = true
			rec.DID = v
		case "key":
			if sawKey {
				return nil, fmt.Errorf("duplicate key= field")
			}
			sawKey = true
			rec.KeyFingerprint = v
		default:
			// unknown key: forward-compatible, ignored
		}
	}
	if rec.Version == "" {
		return nil, fmt.Errorf("missing v= field")
	}
	if rec.Version != txtVersion {
		return nil, fmt.Errorf("unsupported version: %q (expected %q)", rec.Version, txtVersion)
	}
	if rec.DID == "" {
		return nil, fmt.Errorf("missing did= field")
	}
	if rec.KeyFingerprint == "" {
		return nil, fmt.Errorf("missing key= field")
	}
	if !fingerprintRE.MatchString(rec.KeyFingerprint) {
		return nil, fmt.Errorf("malformed key fingerprint: %q (expected sha256:<64-lowercase-hex>)", rec.KeyFingerprint)
	}
	return rec, nil
}

// GenerateTXT builds a _dplaax-org TXT record value for the given DID and
// fingerprint. The fingerprint must be in canonical form
// (sha256:<64-lowercase-hex>); non-canonical inputs are rejected.
func GenerateTXT(didStr, fingerprint string) (string, error) {
	if didStr == "" {
		return "", fmt.Errorf("did is empty")
	}
	if !fingerprintRE.MatchString(fingerprint) {
		return "", fmt.Errorf("invalid fingerprint: %q (expected sha256:<64-lowercase-hex>)", fingerprint)
	}
	return fmt.Sprintf("v=%s; did=%s; key=%s", txtVersion, didStr, fingerprint), nil
}
