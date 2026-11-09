package bundle_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/provin-line/oss/bundle"
)

// v1Manifest is a v1 manifest document, with replace applied to its text.
func v1Manifest(replace ...string) []byte {
	doc := `{"v":1,"scope":"linear","head":"sha256:aa","chain":["sha256:aa"],"didDocuments":["did/a.json"],"files":{"did/a.json":"bb"},"createdAt":"2026-01-01T00:00:00Z"}`
	for i := 0; i+1 < len(replace); i += 2 {
		doc = strings.Replace(doc, replace[i], replace[i+1], 1)
	}
	return []byte(doc)
}

// A manifest decoded with encoding/json is read as Verify reads it: strictly,
// and in the exact shape of its version.
func TestManifest_UnmarshalJSONReadsAsVerifyDoes(t *testing.T) {
	for name, tc := range map[string]struct {
		doc       []byte
		integrity bool
	}{
		"duplicate key":              {v1Manifest(`"scope":"linear"`, `"scope":"linear","scope":"linear"`), true},
		"a field only by case":       {v1Manifest(`"scope"`, `"SCOPE"`), true},
		"invalid UTF-8":              {v1Manifest(`"did/a.json"]`, "\"did/\xff\"]"), false},
		"an unknown member":          {v1Manifest(`"createdAt"`, `"extra":1,"createdAt"`), false},
		"a v2 member on v1":          {v1Manifest(`"createdAt"`, `"receipts":null,"createdAt"`), false},
		"a scope of another version": {v1Manifest(`"linear"`, `"aggregate-complete"`), false},
		"an unknown version":         {v1Manifest(`"v":1`, `"v":3`), false},
	} {
		var m bundle.Manifest
		err := json.Unmarshal(tc.doc, &m)
		if err == nil {
			t.Errorf("%s: want error", name)
			continue
		}
		if got := errors.Is(err, bundle.ErrBundleIntegrity); got != tc.integrity {
			t.Errorf("%s: errors.Is(err, ErrBundleIntegrity) = %v, want %v (err %v)", name, got, tc.integrity, err)
		}
	}
}

// A manifest inside another value is read by its own strict pass.
func TestManifest_StrictInsideAnotherValue(t *testing.T) {
	var v struct{ M *bundle.Manifest }
	doc := `{"M":` + string(v1Manifest(`"scope"`, `"SCOPE"`)) + `}`
	if err := json.Unmarshal([]byte(doc), &v); !errors.Is(err, bundle.ErrBundleIntegrity) {
		t.Errorf("err = %v, want ErrBundleIntegrity", err)
	}
}

// The manifest is read afresh, as its version shapes it: a v1 manifest has no
// receipts, whatever the receiver held.
func TestManifest_UnmarshalJSONReadsAfresh(t *testing.T) {
	m := bundle.Manifest{Receipts: map[string][]string{"sha256:aa": {"sha256:bb"}}, Source: "kept"}
	if err := json.Unmarshal(v1Manifest(), &m); err != nil {
		t.Fatal(err)
	}
	if m.Receipts != nil || m.Source != "" {
		t.Errorf("decoded %+v, want no receipts and no source", m)
	}
	if m.V != 1 || m.Scope != bundle.ScopeLinear || m.Head != "sha256:aa" || len(m.Files) != 1 {
		t.Errorf("decoded %+v", m)
	}
}

// A decoded manifest encodes to a document that decodes to the same manifest.
func TestManifest_RoundTrip(t *testing.T) {
	for _, doc := range [][]byte{
		v1Manifest(),
		v1Manifest(`"createdAt"`, `"source":"src","createdAt"`),
		[]byte(`{"v":2,"scope":"aggregate-complete","head":"sha256:aa","chain":["sha256:aa"],"didDocuments":[],"files":{},"createdAt":"2026-01-01T00:00:00Z","receipts":{"sha256:aa":["sha256:bb"]}}`),
		[]byte(`{"v":2,"scope":"aggregate-complete","head":"sha256:aa","chain":["sha256:aa"],"didDocuments":[],"files":{},"createdAt":"2026-01-01T00:00:00Z","receipts":{}}`),
		[]byte(`{"v":2,"scope":"aggregate-complete","head":"sha256:aa","chain":["sha256:aa"],"didDocuments":[],"files":{},"createdAt":"2026-01-01T00:00:00Z","receipts":null}`),
		[]byte(`{"v":2,"scope":"aggregate-complete","head":"sha256:aa","chain":["sha256:aa"],"didDocuments":[],"files":{},"createdAt":"2026-01-01T00:00:00Z"}`),
	} {
		var m bundle.Manifest
		if err := json.Unmarshal(doc, &m); err != nil {
			t.Fatalf("%s: %v", doc, err)
		}
		// canonicalizer-hygiene-exempt: test round trip of a display encoding.
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var back bundle.Manifest
		if err := json.Unmarshal(out, &back); err != nil {
			t.Fatalf("%s: %v", out, err)
		}
		if !reflect.DeepEqual(m, back) {
			t.Errorf("round trip %+v, want %+v", back, m)
		}
	}
}

// A manifest is written in the exact wire shape of its version, so what
// encoding/json writes, UnmarshalJSON reads; a manifest no version can hold
// is not written.
func TestManifest_MarshalJSONWritesTheShapeOfItsVersion(t *testing.T) {
	var m bundle.Manifest
	if err := json.Unmarshal(v1Manifest(), &m); err != nil {
		t.Fatal(err)
	}
	// canonicalizer-hygiene-exempt: test of a display encoding.
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]any
	if err := json.Unmarshal(out, &keys); err != nil {
		t.Fatal(err)
	}
	if _, ok := keys["receipts"]; ok {
		t.Errorf("a v1 manifest was written with receipts: %s", out)
	}
	for name, bad := range map[string]bundle.Manifest{
		"a v1 manifest with receipts": func() bundle.Manifest {
			b := m
			b.Receipts = map[string][]string{}
			return b
		}(),
		"an unknown version": func() bundle.Manifest {
			b := m
			b.V = 3
			return b
		}(),
	} {
		// canonicalizer-hygiene-exempt: test of a display encoding.
		if _, err := json.Marshal(bad); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
