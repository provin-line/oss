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
)

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
func Parse(s string) (*DID, error) {
	rest, ok := strings.CutPrefix(s, "did:"+Method+":")
	if !ok {
		return nil, fmt.Errorf("not a did:%s identifier: %q", Method, s)
	}
	segs := strings.Split(rest, ":")
	if len(segs) < 3 {
		return nil, fmt.Errorf("did:%s requires registry:accountType:accountId, got %d segment(s)", Method, len(segs))
	}
	for _, seg := range segs {
		if !IsSafeSegment(seg) {
			return nil, fmt.Errorf("did:%s segment %q violates the safe-segment rule", Method, seg)
		}
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

// PipelineDID returns a copy of d truncated to pipeline level, or nil when d
// carries no pipeline segment.
func (d *DID) PipelineDID() *DID {
	if len(d.ResourcePath) < 2 || d.ResourcePath[0] != "pipeline" {
		return nil
	}
	c := *d
	c.ResourcePath = append([]string(nil), d.ResourcePath[:2]...)
	return &c
}
