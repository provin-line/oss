package orgverify

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// NormalizeFQDN normalizes orgId to canonical FQDN form for DNS lookup and
// DID comparison. Returns (canonical, isFQDN, error).
//
//   - canonical: lowercase ASCII, no trailing dot, punycode for IDN.
//   - isFQDN=true means the input is a valid registrable domain (PSL+1 or
//     deeper).
//   - isFQDN=false with err=nil means the input is a valid hostname but not
//     usable as an FQDN orgId (single label, public suffix, unicode IDN) ->
//     EndorsementNA.
//   - err!=nil means the input violates RFC 1123 hostname syntax -> input
//     error (not a verdict; the caller's DID itself is malformed).
//
// Per README.md / spec §7.6 (carried over from the predecessor unchanged).
func NormalizeFQDN(input string) (string, bool, error) {
	if input == "" {
		return "", false, nil
	}

	// Reject non-ASCII unicode (IDN must be in punycode form).
	for _, r := range input {
		if r > 127 {
			return "", false, nil
		}
	}

	// Strip trailing dot.
	s := strings.TrimSuffix(input, ".")
	s = strings.ToLower(s)

	// Validate hostname syntax via idna.Lookup (strict mode).
	// idna.Lookup applies length, label, and character checks per RFC 1123.
	canonical, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", false, fmt.Errorf("invalid hostname: %w", err)
	}

	// Explicit DNS label length check (RFC 1035 §2.3.4): each label ≤ 63
	// octets. idna.Lookup does not enforce this for pure-ASCII labels.
	for _, label := range strings.Split(canonical, ".") {
		if len(label) > 63 {
			return "", false, fmt.Errorf("invalid hostname: label %q exceeds 63 octets", label)
		}
	}

	// Reject single-label.
	if !strings.Contains(canonical, ".") {
		return "", false, nil
	}

	// Reject public-suffix-only entries via PSL.
	etld1, err := publicsuffix.EffectiveTLDPlusOne(canonical)
	if err != nil {
		// e.g. "com" alone — public suffix with no registrable parent.
		return "", false, nil
	}

	// Accept any subdomain at or below the registrable domain.
	if canonical != etld1 && !strings.HasSuffix(canonical, "."+etld1) {
		return "", false, nil
	}

	return canonical, true, nil
}
