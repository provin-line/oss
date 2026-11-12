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

import (
	"fmt"
	"strings"

	"github.com/provin-line/oss/internal/excerpt"
)

// Method is the DID method name implemented by this package.
const Method = "dplaax"

// quoteLimit is the most bytes this package's errors take to quote what
// they refuse (internal/excerpt).
const quoteLimit = 128

// MaxRegistryLen is the most octets a DID's registry segment holds (dplaax
// did.dplaax.syntax). The bound comes from DNS: a registry names a host, and a
// DNS name is at most 253 octets in its text form. The registry is not checked
// as a DNS name: ValidateRegistry holds it to the safe-segment rule and this
// length, and nothing more.
const MaxRegistryLen = 253

// ValidateRegistry reports whether id can be the registry segment of a
// did:dplaax DID (did.dplaax.syntax): a safe segment (IsSafeSegment) of at most
// MaxRegistryLen octets. It is the check Parse applies to a DID's registry,
// for a registry ID that comes on its own, such as from configuration. It is
// not a DNS-name check: a segment with an underscore, or with a label longer
// than DNS allows, passes it. Its refusal is ErrSyntax (errors.Is).
func ValidateRegistry(id string) error {
	if err := validateRegistry(id); err != nil {
		return syntaxError(err.Error())
	}
	return nil
}

// validateRegistry is ValidateRegistry's check, its refusal not yet made
// ErrSyntax: Parse makes its own refusals ErrSyntax.
func validateRegistry(id string) error {
	if !IsSafeSegment(id) {
		return fmt.Errorf("did:%s registry %s violates the safe-segment rule ([A-Za-z0-9._-], not all dots)", Method, excerpt.Quoted(id, quoteLimit))
	}
	if len(id) > MaxRegistryLen {
		return fmt.Errorf("did:%s registry of %d octets, beyond %d", Method, len(id), MaxRegistryLen)
	}
	return nil
}

// DID is a parsed did:dplaax identifier.
//
// Registry is a domain name (e.g. "poc.dplaax.dev"); resolution URLs derive
// from it (https://{registry}/did/...). Environment (PoC / production) is
// expressed in Registry, never in the method name.
type DID struct {
	Method       string
	Registry     string
	AccountType  string
	AccountID    string
	ResourcePath []string
}

// Parse parses s as a did:dplaax identifier, by the dplaax rule
// did.dplaax.syntax. Every segment is validated against the safe-segment rule
// so parsed segments can participate in storage paths without traversal risk,
// and the registry against ValidateRegistry. Its refusal is ErrSyntax
// (errors.Is). Parse performs no semantic classification — see the Is*
// methods and validate.go.
func Parse(s string) (*DID, error) {
	d, err := parse(s)
	if err != nil {
		return nil, syntaxError(err.Error())
	}
	return d, nil
}

// parse is Parse, its refusal not yet made ErrSyntax.
func parse(s string) (*DID, error) {
	rest, ok := strings.CutPrefix(s, "did:"+Method+":")
	if !ok {
		return nil, fmt.Errorf("not a did:%s identifier: %s", Method, excerpt.Quoted(s, quoteLimit))
	}
	segs := strings.Split(rest, ":")
	if len(segs) < 3 {
		return nil, fmt.Errorf("did:%s requires registry:accountType:accountId, got %d segment(s)", Method, len(segs))
	}
	for _, seg := range segs {
		if !IsSafeSegment(seg) {
			return nil, fmt.Errorf("did:%s segment %s violates the safe-segment rule", Method, excerpt.Quoted(seg, quoteLimit))
		}
	}
	if err := validateRegistry(segs[0]); err != nil {
		return nil, err
	}
	d := &DID{
		Method:      Method,
		Registry:    segs[0],
		AccountType: segs[1],
		AccountID:   segs[2],
	}
	if len(segs) > 3 {
		d.ResourcePath = append([]string(nil), segs[3:]...)
	}
	return d, nil
}

// IsSafeSegment reports whether s satisfies the safe-segment rule
// ([a-zA-Z0-9._-]+ and not composed solely of dots). Callers composing
// filesystem paths from DID-derived segments MUST check this at the boundary.
func IsSafeSegment(s string) bool {
	if s == "" {
		return false
	}
	allDots := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			allDots = false
		case r == '_' || r == '-':
			allDots = false
		case r == '.':
			// allowed, but does not clear the all-dots flag
		default:
			return false
		}
	}
	return !allDots
}

// String reassembles the canonical DID string.
func (d *DID) String() string {
	segs := append([]string{d.Registry, d.AccountType, d.AccountID}, d.ResourcePath...)
	return "did:" + Method + ":" + strings.Join(segs, ":")
}

// IsOwner reports whether d is an Owner DID (empty resource path).
func (d *DID) IsOwner() bool { return len(d.ResourcePath) == 0 }

// IsPipeline reports whether d is a Pipeline DID (resource path
// "pipeline/{id}").
func (d *DID) IsPipeline() bool {
	return len(d.ResourcePath) == 2 && d.ResourcePath[0] == "pipeline"
}

// IsProcess reports whether d is a Process DID (resource path
// "pipeline/{id}/process/{id}").
func (d *DID) IsProcess() bool {
	return len(d.ResourcePath) == 4 && d.ResourcePath[0] == "pipeline" && d.ResourcePath[2] == "process"
}

// OwnerDID returns a copy of d truncated to owner level.
func (d *DID) OwnerDID() *DID {
	c := *d
	c.ResourcePath = nil
	return &c
}

// Pipeline returns a copy of the Pipeline DID of d, a Process, and true; for
// any other DID, and for nil, nil and false. Only a Process has a Pipeline
// (dplaax did.dplaax.hierarchy). It reads the shape of d's resource path and
// validates nothing: for a DID Parse returned, the result parses too.
func (d *DID) Pipeline() (*DID, bool) {
	if d == nil || !d.IsProcess() {
		return nil, false
	}
	return d.PipelineDID(), true
}

// PipelineDID returns a copy of d with its resource path truncated to its
// first two segments, or nil when the path does not begin with pipeline. It is
// a truncation, not the hierarchy: for a DID that is not a Process, the result
// is not a Pipeline the DID belongs to. Pipeline answers which Pipeline a
// Process has.
func (d *DID) PipelineDID() *DID {
	if len(d.ResourcePath) < 2 || d.ResourcePath[0] != "pipeline" {
		return nil
	}
	c := *d
	c.ResourcePath = append([]string(nil), d.ResourcePath[:2]...)
	return &c
}
