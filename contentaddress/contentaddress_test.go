package contentaddress_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/provin-line/oss/contentaddress"
)

// The empty input's SHA-256 is the well-known e3b0c442…b855.
const emptyAddress = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestOf_IsTheSHA256OfTheBytes(t *testing.T) {
	if got := contentaddress.Of(nil).String(); got != emptyAddress {
		t.Errorf("Of(nil) = %s, want %s", got, emptyAddress)
	}
	if contentaddress.Of([]byte("a")) == contentaddress.Of([]byte("b")) {
		t.Error("two inputs gave one address")
	}
	if contentaddress.Of([]byte("a")) != contentaddress.Of([]byte("a")) {
		t.Error("one input gave two addresses")
	}
}

// Parse reads an address in its one spelling, and only that.
func TestParse_ReadsOnlyTheOneSpelling(t *testing.T) {
	a, err := contentaddress.Parse(emptyAddress)
	if err != nil || a != contentaddress.Of(nil) || a.String() != emptyAddress {
		t.Fatalf("Parse(%s) = %v, %v", emptyAddress, a, err)
	}
	hex := emptyAddress[len("sha256:"):]
	for name, s := range map[string]string{
		"empty":                "",
		"no prefix":            hex,
		"another prefix":       "sha512:" + hex,
		"prefix in capitals":   "SHA256:" + hex,
		"upper-case hex":       "sha256:" + strings.ToUpper(hex),
		"short":                emptyAddress[:len(emptyAddress)-1],
		"long":                 emptyAddress + "0",
		"not hex":              "sha256:" + strings.Repeat("g", 64),
		"a trailing line feed": emptyAddress + "\n",
		"a leading space":      " " + emptyAddress,
	} {
		if a, err := contentaddress.Parse(s); err == nil {
			t.Errorf("%s: Parse(%q) = %v, want an error", name, s, a)
		}
	}
}

// A refusal quotes at most the start of what it was given.
func TestParse_ErrorIsBounded(t *testing.T) {
	_, err := contentaddress.Parse(strings.Repeat("x", 1<<20))
	if err == nil || len(err.Error()) > 200 {
		t.Errorf("error of %d bytes", len(err.Error()))
	}
}

// The zero Address is no address.
func TestAddress_ZeroIsNoAddress(t *testing.T) {
	var zero contentaddress.Address
	if !zero.IsZero() || zero.String() != "" {
		t.Errorf("zero: IsZero %v, String %q", zero.IsZero(), zero.String())
	}
	if contentaddress.Of(nil).IsZero() {
		t.Error("Of(nil) is zero")
	}
	if _, err := zero.MarshalText(); err == nil {
		t.Error("the zero address was written as text")
	}
}

// An Address is written and read as JSON text in its one spelling; a field
// that is not one is refused.
func TestAddress_Text(t *testing.T) {
	type doc struct {
		A contentaddress.Address `json:"a"`
	}
	b, err := json.Marshal(doc{A: contentaddress.Of(nil)})
	if err != nil || string(b) != `{"a":"`+emptyAddress+`"}` {
		t.Fatalf("Marshal = %s, %v", b, err)
	}
	var back doc
	if err := json.Unmarshal(b, &back); err != nil || back.A != contentaddress.Of(nil) {
		t.Fatalf("Unmarshal = %v, %v", back, err)
	}
	if err := json.Unmarshal([]byte(`{"a":"sha256:`+strings.Repeat("A", 64)+`"}`), &back); err == nil {
		t.Error("an address in upper case was read")
	}
	if _, err := json.Marshal(doc{}); err == nil {
		t.Error("the zero address was written")
	}
	kept := contentaddress.Of(nil)
	if err := kept.UnmarshalText([]byte("sha256:")); err == nil || kept != contentaddress.Of(nil) {
		t.Errorf("UnmarshalText of a bad address: %v, left %v", err, kept)
	}
	m := map[contentaddress.Address]int{contentaddress.Of(nil): 1}
	if m[contentaddress.Of(nil)] != 1 {
		t.Error("an Address is not a map key")
	}
}
