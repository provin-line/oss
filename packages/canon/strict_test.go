package canon_test

import (
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/provin-line/oss/packages/canon"
)

func TestStrictDecoderDuplicateKey(t *testing.T) {
	cases := []struct {
		doc string
		key string
	}{
		{`{"a":1,"a":2}`, "a"},
		{`{"x":{"y":1,"y":2}}`, "y"},
		{`[{"k":0},{"k":0,"k":1}]`, "k"},
	}
	for _, c := range cases {
		var v any
		err := canon.NewStrictDecoder([]byte(c.doc)).Decode(&v)
		var dup *canon.DuplicateKeyError
		if !errors.As(err, &dup) {
			t.Errorf("Decode(%s): want DuplicateKeyError, got %v", c.doc, err)
			continue
		}
		if dup.Key != c.key {
			t.Errorf("Decode(%s): Key = %q, want %q", c.doc, dup.Key, c.key)
		}
	}
}

func TestStrictDecoderTrailingData(t *testing.T) {
	for _, doc := range []string{`{} {}`, `1 2`, `{}x`, `null,`} {
		var v any
		if err := canon.NewStrictDecoder([]byte(doc)).Decode(&v); err == nil {
			t.Errorf("Decode(%q): want trailing-data error, got nil", doc)
		}
	}
	// Trailing whitespace is fine.
	var v any
	if err := canon.NewStrictDecoder([]byte("{\"a\":1}\n  ")).Decode(&v); err != nil {
		t.Errorf("Decode with trailing whitespace: %v", err)
	}
}

func TestStrictDecoderPreservesPrecision(t *testing.T) {
	var v any
	doc := `{"big":18446744073709551615,"neg":-9223372036854775808}`
	if err := canon.NewStrictDecoder([]byte(doc)).Decode(&v); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	m := v.(map[string]any)
	big, ok := m["big"].(json.Number)
	if !ok {
		t.Fatalf("big decoded as %T, want json.Number", m["big"])
	}
	if string(big) != "18446744073709551615" {
		t.Errorf("big = %s, want 18446744073709551615", big)
	}
}

func TestStrictDecoderSingleShot(t *testing.T) {
	d := canon.NewStrictDecoder([]byte(`{}`))
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatalf("first Decode: %v", err)
	}
	if err := d.Decode(&v); err != io.EOF {
		t.Errorf("second Decode = %v, want io.EOF", err)
	}
}

func TestStrictDecoderRejectsGarbage(t *testing.T) {
	for _, doc := range []string{``, `   `, `{`, `{"a":}`} {
		var v any
		if err := canon.NewStrictDecoder([]byte(doc)).Decode(&v); err == nil {
			t.Errorf("Decode(%q): want error, got nil", doc)
		}
	}
}
