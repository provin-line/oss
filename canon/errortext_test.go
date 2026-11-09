package canon_test

import (
	"encoding/json" // decoder-hygiene-exempt: json.Number values and *json.UnmarshalTypeError are what these tests name
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/provin-line/oss/canon"
)

// quotedLimit is the most bytes an error of canon writes of one value it
// quotes from its input; decodeErrorLimit, of the error of a typed decode.
const (
	quotedLimit      = 128
	decodeErrorLimit = 1024
)

// long is a text of n bytes.
func long(c string, n int) string { return strings.Repeat(c, n) }

// checkBounded reports unless text is valid UTF-8 of at most bound bytes and
// holds each of parts.
func checkBounded(t *testing.T, what, text string, bound int, parts ...string) {
	t.Helper()
	if len(text) > bound || !utf8.ValidString(text) {
		t.Errorf("%s: %d bytes (at most %d), valid UTF-8 %v: %.200q", what, len(text), bound, utf8.ValidString(text), text)
	}
	for _, p := range parts {
		if !strings.Contains(text, p) {
			t.Errorf("%s: %.200q does not hold %q", what, text, p)
		}
	}
}

// An UnsafeNumberError whose literal and path fit writes them whole.
func TestUnsafeNumberError_WritesWhatFitsWhole(t *testing.T) {
	for e, want := range map[*canon.UnsafeNumberError]string{
		{Path: "credentialSubject.counts[1]", Literal: "1e30", Reason: "r"}: "canon: unsafe number 1e30 at credentialSubject.counts[1]: r",
		{Literal: "9007199254740993", Reason: "r"}:                          "canon: unsafe number 9007199254740993 at (root): r",
	} {
		if got := e.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	}
}

// A literal and a path of any length are written within quotedLimit bytes
// each, as their head and their length; the fields keep them whole.
func TestUnsafeNumberError_BoundsALongLiteralAndPath(t *testing.T) {
	key := long("k", 10000)
	lit := "1" + long("0", 10000)
	err := canon.AdmitSafeNumbers(map[string]any{key: json.Number(lit)})
	var u *canon.UnsafeNumberError
	if !errors.As(err, &u) {
		t.Fatalf("AdmitSafeNumbers = %v, want an *UnsafeNumberError", err)
	}
	if u.Literal != lit || u.Path != key {
		t.Errorf("fields: Literal of %d bytes, Path of %d bytes; want them whole (%d, %d)", len(u.Literal), len(u.Path), len(lit), len(key))
	}
	bound := len("canon: unsafe number ") + quotedLimit + len(" at ") + quotedLimit + len(": ") + len(u.Reason)
	checkBounded(t, "Error()", u.Error(), bound, "canon: unsafe number 1000", "… (10001 bytes) at kkk", "… (10000 bytes): ")
}

// What is not UTF-8 in a literal, a path or a reason is written as U+FFFD;
// the fields keep it as it is.
func TestUnsafeNumberError_WritesUTF8(t *testing.T) {
	e := &canon.UnsafeNumberError{Path: "a\xffb", Literal: "1\xfe", Reason: "r\xfd"}
	if got, want := e.Error(), "canon: unsafe number 1\uFFFD at a\uFFFDb: r\uFFFD"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if e.Path != "a\xffb" || e.Literal != "1\xfe" || e.Reason != "r\xfd" {
		t.Errorf("fields changed: %q, %q, %q", e.Path, e.Literal, e.Reason)
	}
}

// A DuplicateKeyError whose keys and path fit writes them whole.
func TestDuplicateKeyError_WritesWhatFitsWhole(t *testing.T) {
	for doc, want := range map[string]string{
		`{"a":1,"a":2}`:                   `duplicate JSON key "a" at []`,
		`{"a\"b\u0001":1,"a\"b\u0001":2}`: `duplicate JSON key "a\"b\x01" at []`,
		`{"o":{"A":1,"a":2}}`:             `JSON key "a" at [o] differs from "A" only in case, as encoding/json folds names`,
	} {
		var v any
		err := canon.NewStrictDecoder([]byte(doc)).Decode(&v)
		if err == nil || err.Error() != want {
			t.Errorf("Decode(%s) = %v, want %q", doc, err, want)
		}
	}
}

// Keys and a path of any length are written within quotedLimit bytes each;
// the fields keep them whole.
func TestDuplicateKeyError_BoundsLongKeysAndPath(t *testing.T) {
	parent, lower, upper := long("p", 10000), long("k", 10000), long("K", 10000)
	for _, c := range []struct {
		doc, other string
		bound      int
	}{
		{fmt.Sprintf(`{%q:{%q:1,%q:2}}`, parent, lower, lower), "", len(`duplicate JSON key  at `) + 2*quotedLimit},
		{fmt.Sprintf(`{%q:{%q:1,%q:2}}`, parent, upper, lower), upper, len(`JSON key  at  differs from  only in case, as encoding/json folds names`) + 3*quotedLimit},
	} {
		var v any
		err := canon.NewStrictDecoder([]byte(c.doc)).Decode(&v)
		var d *canon.DuplicateKeyError
		if !errors.As(err, &d) {
			t.Fatalf("Decode = %.200v, want a *DuplicateKeyError", err)
		}
		if d.Key != lower || d.Other != c.other || len(d.Path) != 1 || d.Path[0] != parent {
			t.Errorf("fields: Key of %d bytes, Other of %d, Path %d long; want them whole", len(d.Key), len(d.Other), len(d.Path))
		}
		checkBounded(t, "Error()", d.Error(), c.bound, `"kkk`, `"… (10000 bytes)`, "[ppp", "… (10002 bytes)")
	}
}

// The token after a document is named within quotedLimit bytes.
func TestStrictDecoder_BoundsTheTrailingToken(t *testing.T) {
	var v any
	err := canon.NewStrictDecoder([]byte(`{} "` + long("x", 10000) + `"`)).Decode(&v)
	if err == nil {
		t.Fatal("Decode accepted trailing data")
	}
	checkBounded(t, "Error()", err.Error(), len("canon: trailing data after JSON document (next token )")+quotedLimit, "(next token xxx", "… (10000 bytes))")
}

// loopPointer is a pointer type to itself: a decode target past any number
// of pointers.
type loopPointer *loopPointer

// The path to a decode target that holds itself is written within
// quotedLimit bytes.
func TestStrictDecoder_BoundsThePathToATargetThatHoldsItself(t *testing.T) {
	var m map[string]loopPointer
	err := canon.NewStrictDecoder([]byte(fmt.Sprintf(`{%q:1}`, long("k", 10000)))).Decode(&m)
	if err == nil {
		t.Fatal("Decode accepted a target that holds itself")
	}
	bound := len("canon: decode target at  is reached through more than 64 pointers and interfaces (as a target that holds itself is)") + quotedLimit
	checkBounded(t, "Error()", err.Error(), bound, "at [kkk", "… (10002 bytes) is reached")
}

// The error of a typed decode, which encoding/json and a type's own decoding
// write from the input (a number's literal, a time's text), is written within
// decodeErrorLimit bytes, and still is the error they returned to errors.As.
func TestStrictDecoder_BoundsTheErrorOfATypedDecode(t *testing.T) {
	var n struct {
		N int `json:"n"`
	}
	err := canon.NewStrictDecoder([]byte(`{"n":1` + long("0", 10000) + `}`)).Decode(&n)
	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) {
		t.Fatalf("Decode = %.200v, want an error that is an *json.UnmarshalTypeError", err)
	}
	checkBounded(t, "number into int", err.Error(), decodeErrorLimit, "… (")

	var at struct {
		T time.Time `json:"t"`
	}
	err = canon.NewStrictDecoder([]byte(`{"t":"` + long("x", 10000) + `"}`)).Decode(&at)
	var parseErr *time.ParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("Decode = %.200v, want an error that is a *time.ParseError", err)
	}
	checkBounded(t, "text into time.Time", err.Error(), decodeErrorLimit, "… (")
}

// An error of a typed decode that fits is the error encoding/json returned.
func TestStrictDecoder_ReturnsAShortTypedDecodeErrorAsItIs(t *testing.T) {
	var n struct {
		N int `json:"n"`
	}
	err := canon.NewStrictDecoder([]byte(`{"n":"x"}`)).Decode(&n)
	if _, ok := err.(*json.UnmarshalTypeError); !ok {
		t.Errorf("Decode = %T (%v), want *json.UnmarshalTypeError itself", err, err)
	}
}

// nilDecodeError is the error type of nilErrorField's decoding.
type nilDecodeError struct{ reason string }

func (e *nilDecodeError) Error() string { return e.reason }

// nilErrorField's own decoding fails with a nil *nilDecodeError, an error
// whose Error method panics.
type nilErrorField struct{}

func (*nilErrorField) UnmarshalJSON([]byte) error {
	var err *nilDecodeError
	return err
}

// An error a type's own decoding returns that is a nil pointer is returned
// wrapped, with the text fmt writes for it: neither Decode nor the Error
// method of what it returns panics, and errors.As still finds it.
func TestStrictDecoder_ATypedDecodeErrorThatIsANilPointer(t *testing.T) {
	var v struct {
		F nilErrorField `json:"f"`
	}
	var err error
	var text string
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panicked: %v", r)
			}
		}()
		err = canon.NewStrictDecoder([]byte(`{"f":1}`)).Decode(&v)
		text = err.Error()
	}()
	var target *nilDecodeError
	if !errors.As(err, &target) {
		t.Fatalf("Decode = %T, want an error that is a *nilDecodeError", err)
	}
	if text != "<nil>" {
		t.Errorf("text = %q, want %q", text, "<nil>")
	}
}

// canon.Float64 names a refused literal quoted within quotedLimit bytes, a
// byte that is not UTF-8 written as \xNN.
func TestFloat64_BoundsTheLiteralItNames(t *testing.T) {
	if _, err := canon.Float64(json.Number("1\xff")); err == nil || !strings.Contains(err.Error(), `"1\xff"`) {
		t.Errorf("Float64 of a literal that is not UTF-8: %v", err)
	}
	for _, lit := range []string{"1" + long("0", 10000), "x" + long("é", 5000)} {
		_, err := canon.Float64(json.Number(lit))
		if err == nil {
			t.Fatalf("Float64(%.12q…) accepted it", lit)
		}
		bound := max(len(canon.ErrNotJSONNumber), len(canon.ErrBeyondDoubleRange)) + len(": ") + quotedLimit
		checkBounded(t, "Error()", err.Error(), bound, fmt.Sprintf("… (%d bytes)", len(lit)))
	}
}

// Whatever the literal, the path, the reason and the keys, the errors' text
// is valid UTF-8 within its bound (the reason, its maker's, is written whole),
// and holds each value whole when it fits: a key quoted, a byte that is not
// UTF-8 as \xNN; the literal and the path made UTF-8.
func FuzzErrorTextIsBounded(f *testing.F) {
	f.Add("1e30", "a.b[1]", "r", "k", "K")
	f.Add(long("9", 300), long("é", 200), "r\xfd", "\xff", long("\x01", 100))
	f.Add("1", "a\xffb", "r", "k\xfe", "K\xff")
	f.Fuzz(func(t *testing.T, lit, path, reason, key, other string) {
		u := &canon.UnsafeNumberError{Path: path, Literal: lit, Reason: reason}
		r := strings.ToValidUTF8(reason, "\uFFFD")
		bound := len("canon: unsafe number ") + quotedLimit + len(" at ") + quotedLimit + len(": ") + len(r)
		got := u.Error()
		if len(got) > bound || !utf8.ValidString(got) {
			t.Fatalf("UnsafeNumberError.Error() = %q: %d bytes", got, len(got))
		}
		where := path
		if where == "" {
			where = "(root)"
		}
		if v := strings.ToValidUTF8(lit, "\uFFFD"); len(v) <= quotedLimit {
			if w := strings.ToValidUTF8(where, "\uFFFD"); len(w) <= quotedLimit {
				if want := "canon: unsafe number " + v + " at " + w + ": " + r; got != want {
					t.Fatalf("UnsafeNumberError.Error() = %q, want %q", got, want)
				}
			}
		}
		d := &canon.DuplicateKeyError{Key: key, Other: other, Path: []string{path}}
		got = d.Error()
		bound = len(`JSON key  at  differs from  only in case, as encoding/json folds names`) + 3*quotedLimit
		if len(got) > bound || !utf8.ValidString(got) {
			t.Fatalf("DuplicateKeyError.Error() = %q: %d bytes", got, len(got))
		}
		k, o := strconv.Quote(key), strconv.Quote(other)
		p := strings.ToValidUTF8(fmt.Sprint(d.Path), "\uFFFD")
		if len(k) <= quotedLimit && len(o) <= quotedLimit && len(p) <= quotedLimit {
			want := fmt.Sprintf("JSON key %s at %s differs from %s only in case, as encoding/json folds names", k, p, o)
			if other == "" {
				want = fmt.Sprintf("duplicate JSON key %s at %s", k, p)
			}
			if got != want {
				t.Fatalf("DuplicateKeyError.Error() = %q, want %q", got, want)
			}
		}
	})
}

// Whatever the document and the decode target, an error of Decode is valid
// UTF-8 within decodeErrorLimit bytes. (That a cut error is still found by
// errors.As is TestStrictDecoder_BoundsTheErrorOfATypedDecode's.)
func FuzzStrictDecoderErrorIsBounded(f *testing.F) {
	for _, doc := range []string{
		`{"a":1,"a":2}`,
		fmt.Sprintf(`{%q:1,%q:2}`, long("k", 2000), long("k", 2000)),
		`{"n":1` + long("0", 2000) + `}`,
		`{"t":"` + long("x", 2000) + `"}`,
		`{} "` + long("x", 2000) + `"`,
		`{"k":[1,}]}`,
		`[` + long(`"`+long("s", 50)+`",`, 40) + `}`,
	} {
		f.Add([]byte(doc))
	}
	f.Fuzz(func(t *testing.T, doc []byte) {
		var typed struct {
			N int       `json:"n"`
			T time.Time `json:"t"`
			M map[string]int
		}
		var untyped any
		for _, v := range []any{&typed, &untyped} {
			err := canon.NewStrictDecoder(doc).Decode(v)
			if err == nil {
				continue
			}
			if text := err.Error(); len(text) > decodeErrorLimit || !utf8.ValidString(text) {
				t.Fatalf("Decode(%.80q…) into %T: %d bytes: %.200q", doc, v, len(text), text)
			}
		}
	})
}
