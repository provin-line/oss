// Package pagination codifies the repo's paged-RPC conventions, set by the
// discovery slice's first paged RPCs and shared by every later one:
//
//   - page_size: 0 means DefaultPageSize, negative is an InvalidArgument
//     (ErrInvalidPageSize), above MaxPageSize is clamped — never an error.
//   - page_token: opaque and versioned. It carries the SCAN cursor (progress,
//     not matches — a filtered page may be short or empty with a non-empty
//     next token, so filtered listings can never livelock) plus a fingerprint
//     of the LISTING IDENTITY and the request's filter fields, so a token
//     replayed against a different RPC, or with different filters, is
//     rejected (ErrInvalidToken) instead of silently resuming the wrong
//     listing.
//
// Handlers own token encode/decode (the token is wire surface); services
// speak plain cursors.
package pagination

import (
	"encoding/base64"
	"errors"
	"fmt"
	"hash/fnv"
	"strings"
)

// DefaultPageSize is served when the request leaves page_size at 0.
const DefaultPageSize = 64

// MaxPageSize is the server-side clamp — a huge request must not translate
// into an unbounded scan or response.
const MaxPageSize = 256

var (
	// ErrInvalidPageSize reports a negative page_size (maps to InvalidArgument).
	ErrInvalidPageSize = errors.New("pagination: page_size must not be negative")
	// ErrInvalidToken reports a malformed, unversioned, or filter-mismatched
	// page token (maps to InvalidArgument).
	ErrInvalidToken = errors.New("pagination: invalid page token")
)

// ClampSize resolves a request's page_size to an effective limit.
func ClampSize(requested int32) (int, error) {
	switch {
	case requested < 0:
		return 0, fmt.Errorf("%w: %d", ErrInvalidPageSize, requested)
	case requested == 0:
		return DefaultPageSize, nil
	case requested > MaxPageSize:
		return MaxPageSize, nil
	default:
		return int(requested), nil
	}
}

const tokenVersion = "v1"

// EncodeToken packs a non-empty scan cursor into an opaque continuation
// token bound to one listing. listing is the LISTING IDENTITY — the fully
// qualified RPC name (e.g. "dplaax.audit.v1.AuditService.ListAuditStatuses")
// — a first-class parameter so no paged RPC can forget it: without it, a
// continuation minted by one RPC would resume a DIFFERENT RPC's listing
// from an arbitrary cursor (the same hash keys both a receipt page and a
// successor page), silently skipping entries. filters are the request's
// filter fields.
func EncodeToken(listing, cursor string, filters ...string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(tokenVersion + ":" + fingerprint(listing, filters) + ":" + cursor))
}

// DecodeToken unpacks a continuation token issued by EncodeToken, verifying
// it was issued by the same listing with the same filter fields. An empty
// token starts from the beginning.
func DecodeToken(listing, token string, filters ...string) (cursor string, err error) {
	if token == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	parts := strings.SplitN(string(raw), ":", 3)
	if len(parts) != 3 || parts[0] != tokenVersion {
		return "", fmt.Errorf("%w: malformed or unversioned", ErrInvalidToken)
	}
	if parts[1] != fingerprint(listing, filters) {
		return "", fmt.Errorf("%w: token was issued by a different listing or with different filters", ErrInvalidToken)
	}
	return parts[2], nil
}

// fingerprint hashes the listing identity and filter fields
// (order-sensitive, NUL-separated so field boundaries cannot alias).
func fingerprint(listing string, filters []string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(listing))
	_, _ = h.Write([]byte{0})
	for _, f := range filters {
		_, _ = h.Write([]byte(f))
		_, _ = h.Write([]byte{0})
	}
	return fmt.Sprintf("%08x", h.Sum32())
}
