package appraisal_test

import (
	"errors"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/provin-line/oss/appraisal"
	"github.com/provin-line/oss/internal/jsondepth"
)

func deep(depth int) any {
	var v any = "x"
	for i := range depth {
		if i%2 == 0 {
			v = []any{v}
		} else {
			v = map[string]any{"k": v}
		}
	}
	return v
}

// An extension is held to where it sits in the manifest's document, so the
// document nests at most jsondepth.Max objects and arrays: a manifest's
// extension value sits at the second level and may nest jsondepth.Max-1
// deep; a spine entry's sits at the fourth (manifest, spine, entry) and may
// nest jsondepth.Max-3. Up to that, Validate, ID, CanonicalBytes and
// MarshalJSON succeed and the JSON decodes again; one level more is refused
// with ErrInvalidManifest naming the extension, in each of them, before the
// check recurses past the bound (held to a 64 MB stack, an extension a
// million deep would exhaust it, a fatal error).
func TestExtensions_HeldToTheManifestsDepth(t *testing.T) {
	defer debug.SetMaxStack(debug.SetMaxStack(64 << 20))
	withTop := func(depth int) appraisal.Manifest {
		m := manifest()
		m.Extensions = map[string]any{"x-deep": deep(depth)}
		return m
	}
	withSpine := func(depth int) appraisal.Manifest {
		m := manifest()
		m.Spine[0].Extensions = map[string]any{"x-deep": deep(depth)}
		return m
	}
	for name, m := range map[string]appraisal.Manifest{"a manifest's extension": withTop(jsondepth.Max - 1), "a spine entry's extension": withSpine(jsondepth.Max - 3)} {
		if err := m.Validate(); err != nil {
			t.Errorf("%s at the bound: Validate: %v", name, err)
		}
		if _, err := m.ID(); err != nil {
			t.Errorf("%s at the bound: ID: %v", name, err)
		}
		if _, err := m.CanonicalBytes(); err != nil {
			t.Errorf("%s at the bound: CanonicalBytes: %v", name, err)
		}
		b, err := m.MarshalJSON()
		if err != nil {
			t.Errorf("%s at the bound: MarshalJSON: %v", name, err)
			continue
		}
		var back appraisal.Manifest
		if err := back.UnmarshalJSON(b); err != nil {
			t.Errorf("%s at the bound: the JSON does not decode again: %v", name, err)
		}
	}
	for name, m := range map[string]appraisal.Manifest{
		"a manifest's extension, past the bound":    withTop(jsondepth.Max),
		"a spine entry's extension, past the bound": withSpine(jsondepth.Max - 2),
		"a manifest's extension, a million deep":    withTop(1000000),
		"a spine entry's extension, a million deep": withSpine(1000000),
	} {
		refused := func(what string, err error) {
			if !errors.Is(err, appraisal.ErrInvalidManifest) || !strings.Contains(err.Error(), `"x-deep"`) || !strings.Contains(err.Error(), "nested deeper than") {
				t.Errorf("%s: %s: %v, want ErrInvalidManifest naming the extension's nesting", name, what, err)
			}
		}
		refused("Validate", m.Validate())
		_, err := m.ID()
		refused("ID", err)
		_, err = m.CanonicalBytes()
		refused("CanonicalBytes", err)
		_, err = m.MarshalJSON()
		refused("MarshalJSON", err)
	}
	m := withSpine(jsondepth.Max - 2)
	if _, err := m.Spine[0].MarshalJSON(); !errors.Is(err, appraisal.ErrInvalidManifest) {
		t.Errorf("a spine entry's MarshalJSON past the bound: %v, want ErrInvalidManifest", err)
	}
}
