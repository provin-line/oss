package yamlstore_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/schemaregistry/store"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry/store/yamlstore"
)

func newStore(t *testing.T) *yamlstore.Store {
	t.Helper()
	return yamlstore.New(t.TempDir())
}

func sampleSchema() *store.Schema {
	return &store.Schema{
		Name:         "reading",
		Version:      "2026-06-14-a1b2c3d4e5f60718",
		Prerelease:   "",
		SchemaFormat: "JsonSchema",
		SchemaBody:   []byte(`{"type":"object"}`),
		Deprecated:   false,
	}
}

func TestSaveGet_RoundTrip(t *testing.T) {
	s := newStore(t)
	in := sampleSchema()
	if err := s.Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.Get(in.Name, in.Version)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != in.Name || got.Version != in.Version || got.SchemaFormat != in.SchemaFormat ||
		got.Prerelease != in.Prerelease || got.Deprecated != in.Deprecated {
		t.Errorf("scalar fields mismatch: got %+v want %+v", got, in)
	}
	if !bytes.Equal(got.SchemaBody, in.SchemaBody) {
		t.Errorf("body not byte-faithful: got %q want %q", got.SchemaBody, in.SchemaBody)
	}
}

func TestSave_DuplicateIsErrExists(t *testing.T) {
	s := newStore(t)
	in := sampleSchema()
	if err := s.Save(in); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	if err := s.Save(in); !errors.Is(err, store.ErrExists) {
		t.Errorf("second Save: got %v, want ErrExists", err)
	}
}

func TestGet_MissingIsErrNotFound(t *testing.T) {
	s := newStore(t)
	if _, err := s.Get("reading", "2026-06-14-deadbeefdeadbeef"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get on a missing version: got %v, want ErrNotFound", err)
	}
}

func TestList_FiltersDeprecatedAndPrerelease(t *testing.T) {
	s := newStore(t)
	stable := sampleSchema()
	stable.Version = "2026-06-14-1111111111111111"

	deprecated := sampleSchema()
	deprecated.Version = "2026-06-14-2222222222222222"
	deprecated.Deprecated = true

	pre := sampleSchema()
	pre.Version = "2026-06-14-3333333333333333"
	pre.Prerelease = "rc1"

	for _, sc := range []*store.Schema{stable, deprecated, pre} {
		if err := s.Save(sc); err != nil {
			t.Fatalf("Save %s: %v", sc.Version, err)
		}
	}

	// Default: hide deprecated and prerelease → only stable.
	got, err := s.List("reading", false, false)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].Version != stable.Version {
		t.Errorf("List(false,false): got %d records, want only %s", len(got), stable.Version)
	}

	// Include both → all three.
	all, err := s.List("reading", true, true)
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("List(true,true): got %d records, want 3", len(all))
	}
}

func TestList_UnknownNameIsEmpty(t *testing.T) {
	s := newStore(t)
	got, err := s.List("never-registered", true, true)
	if err != nil {
		t.Fatalf("List on unknown name: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("List on unknown name: got %d, want 0", len(got))
	}
}

func TestDeprecate_FlipsFlagRetainsBody(t *testing.T) {
	s := newStore(t)
	in := sampleSchema()
	if err := s.Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.Deprecate(in.Name, in.Version); err != nil {
		t.Fatalf("Deprecate: %v", err)
	}
	got, err := s.Get(in.Name, in.Version)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Deprecated {
		t.Error("Deprecate did not set the flag")
	}
	if !bytes.Equal(got.SchemaBody, in.SchemaBody) {
		t.Errorf("body not retained after Deprecate: got %q", got.SchemaBody)
	}
}

func TestDeprecate_MissingIsErrNotFound(t *testing.T) {
	s := newStore(t)
	if err := s.Deprecate("reading", "2026-06-14-deadbeefdeadbeef"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Deprecate on a missing version: got %v, want ErrNotFound", err)
	}
}

// Path-traversal segments must be rejected before any path is built, and must
// not create or read files outside the store root.
func TestPathTraversal_Rejected(t *testing.T) {
	root := t.TempDir()
	s := yamlstore.New(root)

	bad := []struct{ name, version string }{
		{"../evil", "2026-06-14-1111111111111111"},
		{"reading", "../../etc/passwd"},
		{"reading", ".."},
		{"", "2026-06-14-1111111111111111"},
		{"a/b", "2026-06-14-1111111111111111"},
	}
	for _, b := range bad {
		sc := sampleSchema()
		sc.Name, sc.Version = b.name, b.version
		if err := s.Save(sc); err == nil {
			t.Errorf("Save(name=%q,version=%q): want rejection", b.name, b.version)
		}
		if _, err := s.Get(b.name, b.version); err == nil {
			t.Errorf("Get(name=%q,version=%q): want rejection", b.name, b.version)
		}
	}

	// Nothing escaped the root.
	escaped := filepath.Join(filepath.Dir(root), "evil")
	if _, err := os.Stat(escaped); err == nil {
		t.Errorf("a file escaped the store root: %s", escaped)
	}
}
