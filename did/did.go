// Package did is the method-agnostic DID domain: the W3C DID Document
// model shared by every consumer (resolution, verification, key
// extraction) and the method-dispatch primitive. DID methods live in
// subpackages — dplaax (the profile's T1 native method, the only method
// admitted on the credential-issuance plane) today; web-anchored methods
// land beside it when the authentication plane or the external-DID-source
// ingestion pattern needs them. Nothing in this package knows any
// method's identifier grammar.
package did

import (
	"fmt"
	"strings"
)

// MethodOf extracts the DID method name from a DID string, per the W3C
// DID Core syntax (v1.0 Recommendation §3.1; the ABNF is unchanged in
// the v1.1 Candidate Recommendation): "did:" method-name ":"
// method-specific-id, where method-name is 1*(%x61-7A / DIGIT) —
// lowercase letters and digits, a digit may lead — and the
// method-specific-id is non-empty and ends with an idchar (no trailing
// colon). Anything else fails closed. Finer method-specific-id grammar
// is the method package's job. This is the dispatch primitive: callers
// route to a method package (or reject) on the returned name without
// understanding any method's identifier grammar.
func MethodOf(s string) (string, error) {
	rest, ok := strings.CutPrefix(s, "did:")
	if !ok {
		return "", fmt.Errorf("not a DID: missing %q scheme prefix", "did:")
	}
	method, msid, found := strings.Cut(rest, ":")
	if !found {
		return "", fmt.Errorf("not a DID: expected \"did:\" method-name \":\" method-specific-id")
	}
	if msid == "" || strings.HasSuffix(msid, ":") {
		return "", fmt.Errorf("not a DID: method-specific id must be non-empty and end with an idchar")
	}
	if method == "" {
		return "", fmt.Errorf("not a DID: empty method name")
	}
	for _, r := range method {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return "", fmt.Errorf("invalid DID method name %q: DID Core restricts method names to [a-z0-9]", method)
		}
	}
	return method, nil
}
