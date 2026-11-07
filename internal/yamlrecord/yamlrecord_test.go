package yamlrecord_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/provin-line/oss/internal/yamlrecord"
)

type record struct {
	Name  string            `yaml:"name"`
	Info  map[string]string `yaml:"info,omitempty"`
	List  []string          `yaml:"list,omitempty"`
	Body  yamlrecord.Bytes  `yaml:"body,omitempty"`
	At    time.Time         `yaml:"at"`
	Flag  bool              `yaml:"flag"`
	Count int               `yaml:"count"`
}

// Each of these values YAML would read back as another, or not at all.
func TestEncode_RefusesARecordThatWouldNotReadBackAsWritten(t *testing.T) {
	for name, r := range map[string]record{
		"tab in a value":                 {Name: "a\tb"},
		"leading tab":                    {Name: "\ta"},
		"CR":                             {Name: "a\rb"},
		"invalid UTF-8":                  {Name: "a\xffb"},
		"nan":                            {Name: ".nan"},
		"trailing spaces before newline": {Name: "a  \n"},
		"trailing spaces in a map value": {Info: map[string]string{"k": "x    \n"}},
		"trailing spaces in a list item": {List: []string{"a  \n"}},
		"tab in a key":                   {Info: map[string]string{"sub\tject": "x"}},
		"newline in a key":               {Info: map[string]string{"a\nb": "x"}},
		"merge key":                      {Info: map[string]string{"<<": "x"}},
		"question-mark key":              {Info: map[string]string{"? a": "x"}},
		"invalid UTF-8 key":              {Info: map[string]string{"a\xff": "x"}},
	} {
		if _, err := yamlrecord.Encode(&r); !errors.Is(err, yamlrecord.ErrUnfaithful) {
			t.Errorf("%s: err = %v, want ErrUnfaithful", name, err)
		}
	}
}

// Records YAML reads back as written are encoded, and read back equal.
func TestEncode_EncodesWhatReadsBackAsWritten(t *testing.T) {
	for _, r := range []record{
		{},
		{Name: "~"}, {Name: "null"}, {Name: " lead"}, {Name: "trail "}, {Name: "#c"},
		{Name: "a\nb"}, {Name: " "}, {Name: "a: b"}, {Name: "- a"},
		{Info: map[string]string{"a: b": "x", "": "y", "- a": "z"}},
		{List: []string{"", "x"}},
		{Body: []byte{0, 0xff, 'x'}}, {Body: []byte{}},
		{At: time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC), Flag: true, Count: -3},
	} {
		data, err := yamlrecord.Encode(&r)
		if err != nil {
			t.Errorf("%+v: %v", r, err)
			continue
		}
		var back record
		if err := yaml.Unmarshal(data, &back); err != nil {
			t.Errorf("%+v: read back: %v", r, err)
		}
	}
}

// The error does not repeat the record's text.
func TestEncode_ErrorDoesNotQuoteTheRecord(t *testing.T) {
	r := record{Info: map[string]string{"<<": "x", "other": "secret-token-123"}}
	_, err := yamlrecord.Encode(&r)
	if err == nil || strings.Contains(err.Error(), "secret-token-123") {
		t.Errorf("err = %v", err)
	}
}

// Bytes are written as one base64 string, and read back from it or from the
// sequence of byte values an earlier version wrote.
func TestBytes_WritesBase64AndReadsBothForms(t *testing.T) {
	r := record{Body: []byte("hello")}
	data, err := yamlrecord.Encode(&r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("body: aGVsbG8=\n")) {
		t.Errorf("not one base64 string:\n%s", data)
	}
	legacy, err := yaml.Marshal(struct {
		Body []byte `yaml:"body"`
	}{[]byte("hello")})
	if err != nil || !bytes.Contains(legacy, []byte("- 104")) {
		t.Fatalf("precondition: legacy form is a sequence:\n%s", legacy)
	}
	var back record
	if err := yaml.Unmarshal(legacy, &back); err != nil || string(back.Body) != "hello" {
		t.Errorf("legacy read = %q, %v", back.Body, err)
	}
	if err := yaml.Unmarshal([]byte("body: AB==\n"), &back); err == nil {
		t.Error("non-canonical base64: want error")
	}
}
