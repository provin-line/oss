package dplaax

// ValidateDID performs semantic validation beyond syntax: account type
// against the supported set (currently "org"), registry shape, and the
// known-pattern rule. Parsers stay forward-compatible; this gate is where
// the current deployment's policy lives.
func ValidateDID(d *DID) error { panic("not implemented") }

// RequireKnownPattern rejects DIDs whose resource path matches no known
// classifier (owner / pipeline / process). Future resource types extend the
// classifier set and add a case here.
func RequireKnownPattern(d *DID) error { panic("not implemented") }

// RequireOwner guards service entry points that require owner-level
// authority.
func RequireOwner(d *DID) error { panic("not implemented") }
