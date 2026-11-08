package canon_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/canon"
)

func foldErr(t *testing.T, err error, key, other string) {
	t.Helper()
	var dk *canon.DuplicateKeyError
	if !errors.As(err, &dk) || dk.Key != key || dk.Other != other {
		t.Errorf("err = %v, want a DuplicateKeyError for %q against %q", err, key, other)
	}
}

// Two keys of one object that encoding/json folds to the same name are
// refused, whatever the target: into a struct, the later one would overwrite
// the earlier one's field.
func TestStrictDecoder_RefusesKeysThatFoldToOneName(t *testing.T) {
	for _, c := range []struct{ doc, key, other string }{
		{`{"a":1,"A":2}`, "A", "a"},
		{`{"k":1,"K":2}`, "K", "k"}, // Kelvin sign
		{`{"s":1,"ſ":2}`, "ſ", "s"}, // long s
		{`{"x":{"Id":1,"ID":2}}`, "ID", "Id"},
		{`[{"ab":1,"aB":2}]`, "aB", "ab"},
	} {
		var m any
		foldErr(t, canon.NewStrictDecoder([]byte(c.doc)).Decode(&m), c.key, c.other)
	}
	// An exact duplicate is reported as before, with no Other.
	var m any
	foldErr(t, canon.NewStrictDecoder([]byte(`{"a":1,"a":2}`)).Decode(&m), "a", "")
}

type inner struct {
	V int `json:"v"`
}

type Promoted struct {
	P string `json:"p"`
}

type target struct {
	Promoted
	Name   string            `json:"name"`
	Inner  inner             `json:"inner"`
	List   []inner           `json:"list"`
	ByKey  map[string]*inner `json:"byKey"`
	Raw    json.RawMessage   `json:"raw"`
	At     time.Time         `json:"at"`
	Plain  int
	hidden int
	Skip   int `json:"-"`
}

// Into a struct, a key that matches one of its fields only by folding is
// refused: encoding/json would fill the field, and a reader that tells case
// apart would not.
func TestStrictDecoder_RefusesAKeyMatchingAFieldOnlyByFolding(t *testing.T) {
	for _, c := range []struct{ doc, key, other string }{
		{`{"NAME":"x"}`, "NAME", "name"},
		{`{"inner":{"V":1}}`, "V", "v"},
		{`{"list":[{"v":1},{"V":2}]}`, "V", "v"},
		{`{"byKey":{"a":{"V":1}}}`, "V", "v"},
		{`{"P":"x"}`, "P", "p"},
		{`{"plain":1}`, "plain", "Plain"},
	} {
		var v target
		foldErr(t, canon.NewStrictDecoder([]byte(c.doc)).Decode(&v), c.key, c.other)
	}
}

// What matches exactly, what matches no field, and what a field decodes
// itself (json.RawMessage, time.Time) are read as before.
func TestStrictDecoder_ReadsExactAndUnknownKeysAsBefore(t *testing.T) {
	var v target
	doc := `{"name":"x","inner":{"v":1},"list":[{"v":2}],"byKey":{"A":{"v":3},"a":null},"p":"y","Plain":4,` +
		`"raw":{"V":1,"v":2},"at":"2026-01-01T00:00:00Z","unknown":1,"Skip":5,"hidden":6}`
	foldErr(t, canon.NewStrictDecoder([]byte(doc)).Decode(&v), "a", "A")
	doc = `{"name":"x","inner":{"v":1},"list":[{"v":2}],"byKey":{"A":{"v":3}},"p":"y","Plain":4,` +
		`"raw":{"V":1,"w":2},"at":"2026-01-01T00:00:00Z","unknown":1,"Skip":5,"hidden":6}`
	if err := canon.NewStrictDecoder([]byte(doc)).Decode(&v); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if v.Name != "x" || v.Inner.V != 1 || v.List[0].V != 2 || v.ByKey["A"].V != 3 || v.P != "y" || v.Plain != 4 || v.Skip != 0 {
		t.Errorf("decoded %+v", v)
	}
	var m map[string]any
	if err := canon.NewStrictDecoder([]byte(`{"a":1,"b":{"A":2}}`)).Decode(&m); err != nil {
		t.Errorf("keys in different objects: %v", err)
	}
}

type invalidTag struct {
	V int `json:"☃"` // not a valid tag name: encoding/json names the field V
}

type mapOrInner struct {
	X map[string]int
	Y inner `json:"X"` // the tagged field wins the name X
}

type holder struct {
	X any
}

type sideA struct{ X int }
type sideB struct{ X int }
type ambiguous struct {
	sideA
	sideB
}

type shared struct{ X int }
type viaA struct{ shared }
type viaB struct{ shared }
type twice struct {
	viaA
	viaB
}

// Fields are resolved as encoding/json resolves them: an invalid tag name falls
// back to the Go name, a tagged field wins over an untagged one of its name,
// and an interface already holding a pointer is decoded into.
func TestStrictDecoder_ResolvesFieldsAsEncodingJSONDoes(t *testing.T) {
	var a invalidTag
	foldErr(t, canon.NewStrictDecoder([]byte(`{"v":1}`)).Decode(&a), "v", "V")
	var b mapOrInner
	foldErr(t, canon.NewStrictDecoder([]byte(`{"X":{"V":1}}`)).Decode(&b), "V", "v")
	c := holder{X: &inner{}}
	foldErr(t, canon.NewStrictDecoder([]byte(`{"X":{"V":1}}`)).Decode(&c), "V", "v")
}

// A name encoding/json ignores, because fields at one depth conflict, is
// ignored here too: no field has it.
func TestStrictDecoder_IgnoresANameEncodingJSONIgnores(t *testing.T) {
	var a ambiguous
	if err := canon.NewStrictDecoder([]byte(`{"x":1}`)).Decode(&a); err != nil {
		t.Errorf("conflicting embedded X: %v", err)
	}
	var b twice
	if err := canon.NewStrictDecoder([]byte(`{"x":1}`)).Decode(&b); err != nil {
		t.Errorf("one type embedded twice at one depth: %v", err)
	}
}

// encoding/json decodes into the elements a slice already has, also past its
// length within its capacity, so an element already holding a pointer to a
// struct is checked too.
func TestStrictDecoder_FollowsTheElementsASliceAlreadyHas(t *testing.T) {
	x := []any{&inner{}}
	foldErr(t, canon.NewStrictDecoder([]byte(`[{"V":1}]`)).Decode(&x), "V", "v")
	y := []any{&inner{}}
	y = y[:0]
	foldErr(t, canon.NewStrictDecoder([]byte(`[{"V":1}]`)).Decode(&y), "V", "v")
}

// An element past a fixed array's length, which encoding/json drops, is not
// checked against the element type.
func TestStrictDecoder_DoesNotCheckElementsAnArrayDrops(t *testing.T) {
	var a [1]inner
	if err := canon.NewStrictDecoder([]byte(`[{"v":1},{"V":2}]`)).Decode(&a); err != nil {
		t.Errorf("dropped element: %v", err)
	}
}

type selfPointer *selfPointer

// A pointer type that points to itself is refused, null included.
func TestStrictDecoder_StopsAtAPointerTypeToItself(t *testing.T) {
	var p selfPointer
	done := make(chan error, 1)
	go func() { done <- canon.NewStrictDecoder([]byte(`null`)).Decode(&p) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "pointers and interfaces") {
			t.Errorf("err = %v, want the refusal of a target that holds itself", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Decode still running after 5s")
	}
}

// An interface holding a pointer to itself is refused.
func TestStrictDecoder_StopsAtAnInterfaceHoldingItself(t *testing.T) {
	var x any
	x = &x
	done := make(chan error, 1)
	go func() { done <- canon.NewStrictDecoder([]byte(`{"a":1}`)).Decode(&x) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "pointers and interfaces") {
			t.Errorf("err = %v, want the refusal of a target that holds itself", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Decode still running after 5s")
	}
}

type withTime struct {
	At struct {
		time.Time
		Name string `json:"name"`
	} `json:"at"`
}

type namedPointer *inner

type viaNamedPointer struct {
	P namedPointer `json:"p"`
}

// A type is taken as decoding itself only where encoding/json would call its
// method: an unnamed struct that embeds one, and a named pointer type without
// methods, are decoded field by field, so they are checked.
func TestStrictDecoder_ChecksTypesEncodingJSONDecodesFieldByField(t *testing.T) {
	var a withTime
	foldErr(t, canon.NewStrictDecoder([]byte(`{"at":{"NAME":"x"}}`)).Decode(&a), "NAME", "name")
	var b viaNamedPointer
	foldErr(t, canon.NewStrictDecoder([]byte(`{"p":{"V":1}}`)).Decode(&b), "V", "v")
}
