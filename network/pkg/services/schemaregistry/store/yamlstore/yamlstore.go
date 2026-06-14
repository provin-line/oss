// Package yamlstore is the filesystem SchemaStore: one YAML record per version
// at {root}/{name}/{version}.yaml. Immutability is structural — Save creates with
// O_EXCL (a second Save of the same version is ErrExists), and Deprecate is the
// one permitted mutation (a flag flip via atomic temp+rename, body retained).
//
// Path segments (name, version) are validated to single safe segments at the
// boundary before any path is built, so a crafted name/version can never escape
// root (the path-traversal guard lives here, not in callers).
package yamlstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/provin-line/oss/network/pkg/services/schemaregistry/store"
)

// Store persists schema versions as YAML files under root.
type Store struct {
	root string
}

var _ store.SchemaStore = (*Store)(nil)

// New returns a Store rooted at dir. Records live at dir/{name}/{version}.yaml.
func New(dir string) *Store {
	return &Store{root: dir}
}

// record is the on-disk shape. SchemaBody is []byte so the body round-trips
// byte-faithfully regardless of format (the store treats it as opaque).
type record struct {
	Name         string `yaml:"name"`
	Version      string `yaml:"version"`
	Prerelease   string `yaml:"prerelease"`
	SchemaFormat string `yaml:"schemaFormat"`
	SchemaBody   []byte `yaml:"schemaBody"`
	Deprecated   bool   `yaml:"deprecated"`
}

func toRecord(s *store.Schema) *record {
	return &record{
		Name:         s.Name,
		Version:      s.Version,
		Prerelease:   s.Prerelease,
		SchemaFormat: s.SchemaFormat,
		SchemaBody:   s.SchemaBody,
		Deprecated:   s.Deprecated,
	}
}

func fromRecord(r *record) *store.Schema {
	return &store.Schema{
		Name:         r.Name,
		Version:      r.Version,
		Prerelease:   r.Prerelease,
		SchemaFormat: r.SchemaFormat,
		SchemaBody:   r.SchemaBody,
		Deprecated:   r.Deprecated,
	}
}

// safeSegment rejects anything that is not a single, non-traversing path
// component, so name/version can be joined into a path without escaping root.
func safeSegment(s string) error {
	if s == "" || s == "." || s == ".." || s != filepath.Base(s) || strings.ContainsAny(s, `/\`+"\x00") {
		return fmt.Errorf("yamlstore: invalid path segment %q", s)
	}
	return nil
}

func (s *Store) recordPath(name, version string) (string, error) {
	if err := safeSegment(name); err != nil {
		return "", err
	}
	if err := safeSegment(version); err != nil {
		return "", err
	}
	return filepath.Join(s.root, name, version+".yaml"), nil
}

// Save persists a new version. The record is written to a temp file in the same
// directory and published with os.Link, which atomically creates the final path
// only if it does not already exist — so the file appears fully-written or not
// at all (a concurrent reader never sees a partial record), while a second Save
// of the same (name, version) still returns ErrExists.
func (s *Store) Save(sc *store.Schema) error {
	p, err := s.recordPath(sc.Name, sc.Version)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("yamlstore: mkdir: %w", err)
	}
	data, err := yaml.Marshal(toRecord(sc))
	if err != nil {
		return fmt.Errorf("yamlstore: marshal: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return fmt.Errorf("yamlstore: temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // link shares the inode; removing the temp name keeps p.
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("yamlstore: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("yamlstore: close temp: %w", err)
	}
	if err := os.Link(tmpName, p); err != nil {
		if errors.Is(err, os.ErrExist) {
			return store.ErrExists
		}
		return fmt.Errorf("yamlstore: publish: %w", err)
	}
	return nil
}

// Get returns the exact version, or ErrNotFound.
func (s *Store) Get(name, version string) (*store.Schema, error) {
	p, err := s.recordPath(name, version)
	if err != nil {
		return nil, err
	}
	r, err := readRecord(p)
	if err != nil {
		return nil, err
	}
	return fromRecord(r), nil
}

// List returns the versions of name, filtered by the include flags. An unknown
// name yields an empty list, not an error.
func (s *Store) List(name string, includeDeprecated, includePrerelease bool) ([]*store.Schema, error) {
	if err := safeSegment(name); err != nil {
		return nil, err
	}
	dir := filepath.Join(s.root, name)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("yamlstore: readdir: %w", err)
	}
	var out []*store.Schema
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		r, err := readRecord(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("yamlstore: list %s: %w", e.Name(), err)
		}
		if !includeDeprecated && r.Deprecated {
			continue
		}
		if !includePrerelease && r.Prerelease != "" {
			continue
		}
		out = append(out, fromRecord(r))
	}
	return out, nil
}

// Deprecate sets the soft flag (idempotent), retaining the body. The rewrite is
// atomic (temp file in the same dir + rename) so a reader never sees a partial
// record.
func (s *Store) Deprecate(name, version string) error {
	p, err := s.recordPath(name, version)
	if err != nil {
		return err
	}
	r, err := readRecord(p)
	if err != nil {
		return err
	}
	if r.Deprecated {
		return nil
	}
	r.Deprecated = true
	data, err := yaml.Marshal(r)
	if err != nil {
		return fmt.Errorf("yamlstore: marshal: %w", err)
	}
	return atomicWrite(p, data)
}

func readRecord(p string) (*record, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("yamlstore: read: %w", err)
	}
	var r record
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("yamlstore: unmarshal: %w", err)
	}
	return &r, nil
}

func atomicWrite(p string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return fmt.Errorf("yamlstore: temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("yamlstore: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("yamlstore: close temp: %w", err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("yamlstore: rename: %w", err)
	}
	return nil
}
