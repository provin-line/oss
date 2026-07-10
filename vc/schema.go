package vc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ResolvedSchema is what a SchemaResolver returns for a reference: the schema
// body AS REGISTERED and its declared format. The verifier trusts nothing the
// resolver asserts about integrity — it recomputes sha256 over Body and
// compares against the reference's ContentHash itself, and compares Format
// against the reference's (signed) Type. A resolver that returns the wrong
// body or misdescribes the format cannot forge a verified verdict.
type ResolvedSchema struct {
	// Format is the schema language as registered (e.g. "JsonSchema").
	Format string
	// Body is the exact registered schema bytes.
	Body []byte
}

// SchemaResolver resolves a registered schema by its reference. Implementations
// live in the composition root (a bridge to the schema registry). It is a
// consumer-defined seam on the verifier: absent one, schema references are
// wire-form-checked only (shape), never resolved.
type SchemaResolver interface {
	ResolveSchema(ctx context.Context, ref SchemaRef) (*ResolvedSchema, error)
}

// Definitive schema-resolution failures — a resolver returns (or wraps) one to
// mark the outcome as established rather than transient. Both fail the
// data-integrity axis; every other resolver error is transient (indeterminate),
// mirroring the DID-resolution trichotomy (Resolved / Unavailable / NotFound).
var (
	// ErrSchemaNotFound: the reference names no registered schema.
	ErrSchemaNotFound = errors.New("vc: schema not found")
	// ErrSchemaInvalidRef: the reference itself is malformed (an unparseable or
	// out-of-charset ID) — a deterministic defect, not a retryable outage.
	ErrSchemaInvalidRef = errors.New("vc: schema reference invalid")
)

// WithSchemaResolver wires schema content-hash resolution into the
// data-integrity axis (credential.schema-ref): the verifier resolves a
// referenced schema from r and fails data-integrity on a content-hash or
// format mismatch. Without it, schema references remain shape-checked only.
func WithSchemaResolver(r SchemaResolver) VerifierOption {
	return func(v *Verifier) { v.schemaResolver = r }
}

// schemaURIScheme prefixes a canonical schema reference ID. The ID names a
// registry (name, version) rather than a network address, so a credential
// stays verifiable after the registry moves — the resolver maps the scheme to
// wherever the registry lives.
const schemaURIScheme = "dplaax:schema/"

// SchemaURI formats the canonical schema reference ID (SchemaRef.ID) from a
// registry (name, version): "dplaax:schema/<name>@<version>".
func SchemaURI(name, version string) string {
	return schemaURIScheme + name + "@" + version
}

// ParseSchemaURI parses a canonical schema reference ID back to its registry
// (name, version) — the inverse of SchemaURI. A malformed ID (wrong scheme,
// missing version, or an out-of-charset segment) is ErrSchemaInvalidRef so a
// verifier maps it to a failed data-integrity, never a transient retry.
func ParseSchemaURI(id string) (name, version string, err error) {
	rest, ok := strings.CutPrefix(id, schemaURIScheme)
	if !ok {
		return "", "", fmt.Errorf("%w: %q lacks the %q scheme", ErrSchemaInvalidRef, id, schemaURIScheme)
	}
	return SplitSchemaRef(rest)
}

// SplitSchemaRef splits a schema reference short-form "<name>@<version>" (the
// form an operator writes in config) into its registry (name, version). The
// split is on the LAST '@', and both segments must be non-empty and url-safe
// ([A-Za-z0-9._-]) so the reference embeds unambiguously in the canonical URI.
// A malformed reference is ErrSchemaInvalidRef.
func SplitSchemaRef(s string) (name, version string, err error) {
	at := strings.LastIndexByte(s, '@')
	if at < 0 {
		return "", "", fmt.Errorf("%w: %q is not <name>@<version>", ErrSchemaInvalidRef, s)
	}
	name, version = s[:at], s[at+1:]
	if !urlSafeSegment(name) || !urlSafeSegment(version) {
		return "", "", fmt.Errorf("%w: name and version must be non-empty [A-Za-z0-9._-] (got %q@%q)", ErrSchemaInvalidRef, name, version)
	}
	return name, version, nil
}

// urlSafeSegment reports whether s is a non-empty [A-Za-z0-9._-] token that is
// not a path-traversal token (".", ".."). This is the subset of the registry's
// validSegment charset that is safe and unambiguous inside the canonical schema
// URI; excluding "."/".." keeps the grammar STRICTER than the registry so a
// structurally-invalid reference fails at parse (ErrSchemaInvalidRef -> failed)
// rather than reaching the registry and surfacing as a transient error (which
// the verifier would misread as indeterminate).
func urlSafeSegment(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// evalSchema returns the schema reference's contribution to the data-integrity
// axis, having already established the credential is wire-form valid:
//
//   - no reference                       -> verified (nothing to resolve)
//   - reference, no resolver configured  -> indeterminate (cannot check)
//   - resolved, hash and format match    -> verified
//   - resolved, hash or format mismatch  -> failed
//   - ErrSchemaNotFound / ErrSchemaInvalidRef (definitive) -> failed
//   - any other resolver error (transient) -> indeterminate
//
// A context cancellation surfaces as a resolver error and is treated as
// transient — indeterminate, like any other non-definitive failure — not
// re-propagated as a Go error (evalDataIntegrity returns only a verdict). That
// matches the other axes' behavior on a cancelled resolution.
func (v *Verifier) evalSchema(ctx context.Context, ref SchemaRef) ConfidenceState {
	if ref == (SchemaRef{}) {
		return ConfidenceVerified
	}
	if v.schemaResolver == nil {
		return ConfidenceIndeterminate
	}
	resolved, err := v.schemaResolver.ResolveSchema(ctx, ref)
	if err != nil {
		if errors.Is(err, ErrSchemaNotFound) || errors.Is(err, ErrSchemaInvalidRef) {
			return ConfidenceFailed
		}
		return ConfidenceIndeterminate
	}
	if resolved == nil {
		return ConfidenceIndeterminate // no error but nothing resolved: cannot confirm
	}
	sum := sha256.Sum256(resolved.Body)
	if "sha256:"+hex.EncodeToString(sum[:]) != ref.ContentHash {
		return ConfidenceFailed // the registered schema is not the one the issuer committed to
	}
	if resolved.Format != ref.Type {
		return ConfidenceFailed // the signed Type misdescribes the registered schema language
	}
	return ConfidenceVerified
}
