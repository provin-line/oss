// Package schemaregistry is the domain service of the append-only schema
// registry: it assigns content-addressed versions, validates schema bodies at
// admission, and enforces idempotent registration over a SchemaStore. It holds
// no proto types (that is the handler's boundary) and no persistence logic (that
// is the store's).
//
// A version is "YYYY-MM-DD-{hash16}", where hash16 is the first 16 hex chars
// (64 bits) of a SHA-256 over a domain-separated (format, body, prerelease)
// encoding and the date comes from an injected clock. Because the hash covers
// prerelease, the version is a complete unique key; the Prerelease field is
// listing/display metadata, not a separate key dimension.
package schemaregistry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/provin-line/oss/network/pkg/services/schemaregistry/store"
	"github.com/provin-line/oss/schema"
)

// formatJSONSchema is the only schema_format this slice admits.
const formatJSONSchema = "JsonSchema"

// Sentinel errors. ErrNotFound / ErrExists from the store package surface
// unchanged; handlers map all of these to Connect codes with errors.Is.
var (
	ErrInvalidArgument   = errors.New("schemaregistry: invalid argument")
	ErrUnsupportedFormat = errors.New("schemaregistry: unsupported schema format")
)

// Service is the schema registry domain service.
type Service struct {
	store store.SchemaStore
	clock func() time.Time
}

// Option configures a Service.
type Option func(*Service)

// WithClock overrides the registration clock (the date component of versions).
// Defaults to time.Now; tests inject a fixed clock for deterministic versions.
func WithClock(clock func() time.Time) Option {
	return func(s *Service) { s.clock = clock }
}

// New returns a Service backed by st.
func New(st store.SchemaStore, opts ...Option) *Service {
	s := &Service{store: st, clock: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Register admits a schema and returns its version. Byte-identical content
// (format, body, prerelease) registered again within the same UTC day is
// idempotent: it returns the existing version rather than erroring. If that
// existing version was since deprecated, the returned record carries
// Deprecated=true — re-registration does not revive it (deprecation has no
// inverse, by design); the caller sees the truthful current state.
func (s *Service) Register(ctx context.Context, name, format string, body []byte, prerelease string) (*store.Schema, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validSegment(name) {
		return nil, fmt.Errorf("%w: invalid name %q", ErrInvalidArgument, name)
	}
	if format == "" || len(body) == 0 {
		return nil, fmt.Errorf("%w: format and body are required", ErrInvalidArgument)
	}
	if prerelease != "" && !validSegment(prerelease) {
		return nil, fmt.Errorf("%w: invalid prerelease %q", ErrInvalidArgument, prerelease)
	}
	if format != formatJSONSchema {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedFormat, format)
	}
	// D2: the body must be a well-formed, self-contained JsonSchema, so the
	// registry never holds a schema a downstream validator would reject.
	if err := schema.ValidateJSONSchema(body); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}

	sc := &store.Schema{
		Name:         name,
		Version:      s.version(format, body, prerelease),
		Prerelease:   prerelease,
		SchemaFormat: format,
		SchemaBody:   body,
	}

	// Idempotency: an existing identical record is success; an existing record
	// with different content under the same version is a hash collision.
	if existing, err := s.store.Get(name, sc.Version); err == nil {
		return reconcile(existing, sc)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	if err := s.store.Save(sc); err != nil {
		if errors.Is(err, store.ErrExists) {
			// A concurrent identical Register won the race between our Get and
			// Save — re-read and reconcile (the normal retry path, not corruption).
			existing, gerr := s.store.Get(name, sc.Version)
			if gerr != nil {
				return nil, gerr
			}
			return reconcile(existing, sc)
		}
		return nil, err
	}
	return sc, nil
}

// Get returns the exact version, or store.ErrNotFound.
func (s *Service) Get(ctx context.Context, name, version string) (*store.Schema, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validSegment(name) || !validSegment(version) {
		return nil, fmt.Errorf("%w: invalid name/version", ErrInvalidArgument)
	}
	return s.store.Get(name, version)
}

// List returns the versions of name, filtered by the include flags.
func (s *Service) List(ctx context.Context, name string, includeDeprecated, includePrerelease bool) ([]*store.Schema, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validSegment(name) {
		return nil, fmt.Errorf("%w: invalid name %q", ErrInvalidArgument, name)
	}
	return s.store.List(name, includeDeprecated, includePrerelease)
}

// Deprecate sets the soft flag (retaining the body), or store.ErrNotFound.
func (s *Service) Deprecate(ctx context.Context, name, version string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validSegment(name) || !validSegment(version) {
		return fmt.Errorf("%w: invalid name/version", ErrInvalidArgument)
	}
	return s.store.Deprecate(name, version)
}

// validSegment reports whether s is safe to use as a name/version key: a
// non-empty token with no path separators or traversal. This is domain input
// validation (the store enforces its own path-safety guard independently as
// defense-in-depth).
func validSegment(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, `/\`+"\x00")
}

// version computes "YYYY-MM-DD-{hash16}". The hash is over the documented wire
// contract: SHA-256 of length-prefixed (format, body, prerelease) in that exact
// order. Every field — including body — is length-prefixed so the order and the
// boundaries are unambiguous; any implementation following the documented order
// computes the same version (no cross-implementation hash divergence).
func (s *Service) version(format string, body []byte, prerelease string) string {
	h := sha256.New()
	writeField(h, []byte(format))
	writeField(h, body)
	writeField(h, []byte(prerelease))
	digest := hex.EncodeToString(h.Sum(nil))
	date := s.clock().UTC().Format("2006-01-02")
	return date + "-" + digest[:16]
}

// writeField writes a 4-byte big-endian length prefix then the bytes, so
// concatenation is unambiguous (("ab","c") and ("a","bc") hash differently).
func writeField(h io.Writer, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	h.Write(n[:])
	h.Write(b)
}

// reconcile returns existing if it is byte-identical to want; otherwise the
// version key holds different content than its own hash implies — corruption or
// a hash collision.
func reconcile(existing, want *store.Schema) (*store.Schema, error) {
	if existing.SchemaFormat == want.SchemaFormat &&
		existing.Prerelease == want.Prerelease &&
		bytes.Equal(existing.SchemaBody, want.SchemaBody) {
		return existing, nil
	}
	return nil, fmt.Errorf("schemaregistry: version %q already holds different content (hash collision or corruption)", want.Version)
}
