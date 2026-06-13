package dplaax

import "fmt"

// supportedAccountTypes is the deployment's accepted account-type set.
// Forward-compatible parsing keeps unknown types parseable; this gate is
// where the current policy admits only "org".
var supportedAccountTypes = map[string]bool{"org": true}

// ValidateDID performs semantic validation beyond syntax: account type
// against the supported set (currently "org"), registry shape, and the
// known-pattern rule. Parsers stay forward-compatible; this gate is where
// the current deployment's policy lives.
func ValidateDID(d *DID) error {
	if !supportedAccountTypes[d.AccountType] {
		return fmt.Errorf("did:%s: unsupported accountType %q (supported: org)", Method, d.AccountType)
	}
	if d.Registry == "" {
		return fmt.Errorf("did:%s: empty registry", Method)
	}
	return RequireKnownPattern(d)
}

// RequireKnownPattern rejects DIDs whose resource path matches no known
// classifier (owner / pipeline / process). Future resource types extend the
// classifier set and add a case here.
func RequireKnownPattern(d *DID) error {
	if d.IsOwner() || d.IsPipeline() || d.IsProcess() {
		return nil
	}
	return fmt.Errorf("did:%s: resource path %v matches no known pattern (owner / pipeline / process)", Method, d.ResourcePath)
}

// RequireOwner guards service entry points that require owner-level
// authority.
func RequireOwner(d *DID) error {
	if !d.IsOwner() {
		return fmt.Errorf("did:%s: owner-level authority required, got %s", Method, d.String())
	}
	return nil
}
