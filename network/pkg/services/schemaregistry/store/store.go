// Package store defines the persistence contract of the schema registry.
// Schemas are immutable and append-only: Save never overwrites, Deprecate
// never deletes.
package store

import "errors"

// ErrNotFound is returned for misses; ErrExists when saving an already
// registered version. Handlers map these with errors.Is.
var (
	ErrNotFound = errors.New("schemaregistry: not found")
	ErrExists   = errors.New("schemaregistry: version already exists")
)

// Schema is one immutable schema version. Version is content-addressed and
// assigned by the service: "YYYY-MM-DD-{hash16}", where hash16 is the first 16
// hex chars (64 bits) of a SHA-256 over a domain-separated (format, body,
// prerelease) encoding. Because the hash covers prerelease, Version is a complete
// unique key and Prerelease is listing/display metadata, not a key dimension.
type Schema struct {
	Name         string
	Version      string
	Prerelease   string
	SchemaFormat string
	SchemaBody   []byte
	Deprecated   bool
}

// SchemaStore persists schema versions.
type SchemaStore interface {
	// Save persists a new version; returns ErrExists if (name, version) is
	// already registered.
	Save(s *Schema) error
	// Get returns the exact version — there is no "latest" resolution, by
	// design.
	Get(name, version string) (*Schema, error)
	List(name string, includeDeprecated, includePrerelease bool) ([]*Schema, error)
	// Deprecate sets the soft flag; the schema body is retained.
	Deprecate(name, version string) error
}
