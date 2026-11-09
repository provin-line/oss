package yamlstore_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/goccy/go-yaml"

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

// A version YAML would not read back as written is refused, so a later List
// over its name still works.
func TestSave_RefusesARecordThatWouldNotReadBackAsWritten(t *testing.T) {
	for _, pre := range []string{"rc\t1", "a\rb", ".nan", "a\xffb", "rc  \n"} {
		s := newStore(t)
		in := sampleSchema()
		in.Prerelease = pre
		if err := s.Save(in); err == nil {
			t.Errorf("prerelease %q: Save: want error", pre)
		}
		if got, err := s.List(in.Name, true, true); err != nil || len(got) != 0 {
			t.Errorf("prerelease %q: List after the refusal = %v, %v; want none, nil", pre, got, err)
		}
	}
}

// The body is written as one base64 string, in about 4/3 of its size, and read
// back byte for byte.
func TestSave_WritesTheBodyAsOneBase64String(t *testing.T) {
	dir := t.TempDir()
	s := yamlstore.New(dir)
	in := sampleSchema()
	in.SchemaBody = bytes.Repeat([]byte(`{"a":1}`), 1<<13) // 56 KiB
	if err := s.Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, in.Name, in.Version+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "schemaBody: " + base64.StdEncoding.EncodeToString(in.SchemaBody) + "\n"; !bytes.Contains(raw, []byte(want)) {
		t.Errorf("body not written as one base64 string:\n%.200s", raw)
	}
	if len(raw) > len(in.SchemaBody)*4/3+512 {
		t.Errorf("record is %d bytes for a %d-byte body", len(raw), len(in.SchemaBody))
	}
	got, err := s.Get(in.Name, in.Version)
	if err != nil || !bytes.Equal(got.SchemaBody, in.SchemaBody) {
		t.Errorf("Get = %v; body equal = %v", err, err == nil && bytes.Equal(got.SchemaBody, in.SchemaBody))
	}
}

// A record an earlier version wrote, its body a sequence of byte values, still
// reads.
func TestGet_ReadsABodyWrittenAsASequenceOfBytes(t *testing.T) {
	dir := t.TempDir()
	in := sampleSchema()
	legacy, err := yaml.Marshal(struct {
		Name         string `yaml:"name"`
		Version      string `yaml:"version"`
		Prerelease   string `yaml:"prerelease"`
		SchemaFormat string `yaml:"schemaFormat"`
		SchemaBody   []byte `yaml:"schemaBody"`
		Deprecated   bool   `yaml:"deprecated"`
	}{in.Name, in.Version, in.Prerelease, in.SchemaFormat, in.SchemaBody, in.Deprecated})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(legacy, []byte("- 123")) {
		t.Fatalf("precondition: the legacy encoding is a sequence:\n%s", legacy)
	}
	if err := os.MkdirAll(filepath.Join(dir, in.Name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, in.Name, in.Version+".yaml"), legacy, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := yamlstore.New(dir).Get(in.Name, in.Version)
	if err != nil || !bytes.Equal(got.SchemaBody, in.SchemaBody) {
		t.Fatalf("Get = %v, %v", got, err)
	}
}
