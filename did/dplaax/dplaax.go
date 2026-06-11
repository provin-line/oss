// Package dplaax implements the did:dplaax DID method — the T1 native
// method of the provin profile and the only method admitted on the
// credential-issuance plane (Process / Pipeline / Owner DIDs behind a
// PipelinePassCredential's issuer). Parsing, semantic validation, and the
// segment grammar live here; the method-agnostic DID Document model and
// method dispatch live in the parent did package.
//
// Syntax:
//
//	did:dplaax:{registry}:{accountType}:{accountId}[:{resourcePath}]
//
// The parser is syntax-only. Semantic classification lives in classifier
// methods (IsOwner / IsPipeline / IsProcess); new resource types add a
// classifier method and a case in RequireKnownPattern — the parser does not
// change.
package dplaax

// Method is the DID method name implemented by this package.
const Method = "dplaax"

// DID is a parsed did:dplaax identifier.
//
// Registry is a domain name (e.g. "poc.dplaax.io"); resolution URLs derive
// from it (https://{registry}/did/...). Environment (PoC / production) is
// expressed in Registry, never in the method name.
type DID struct {
	Method       string
	Registry     string
	AccountType  string
	AccountID    string
	ResourcePath []string
}

// Parse parses s as a did:dplaax identifier. Every segment is validated
// against the safe-segment rule so parsed segments can participate in
// storage paths without traversal risk. Parse performs no semantic
// classification — see the Is* methods and validate.go.
func Parse(s string) (*DID, error) { panic("not implemented") }

// IsSafeSegment reports whether s satisfies the safe-segment rule
// ([a-zA-Z0-9._-]+ and not composed solely of dots). Callers composing
// filesystem paths from DID-derived segments MUST check this at the boundary.
func IsSafeSegment(s string) bool { panic("not implemented") }

// String reassembles the canonical DID string.
func (d *DID) String() string { panic("not implemented") }

// IsOwner reports whether d is an Owner DID (empty resource path).
func (d *DID) IsOwner() bool { panic("not implemented") }

// IsPipeline reports whether d is a Pipeline DID (resource path
// "pipeline/{id}").
func (d *DID) IsPipeline() bool { panic("not implemented") }

// IsProcess reports whether d is a Process DID (resource path
// "pipeline/{id}/process/{id}").
func (d *DID) IsProcess() bool { panic("not implemented") }

// OwnerDID returns a copy of d truncated to owner level.
func (d *DID) OwnerDID() *DID { panic("not implemented") }

// PipelineDID returns a copy of d truncated to pipeline level, or nil when d
// carries no pipeline segment.
func (d *DID) PipelineDID() *DID { panic("not implemented") }
