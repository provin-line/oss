package delegation

import (
	"errors"
	"math"
	"testing"
)

// refusalSentinels is every sentinel a class names.
var refusalSentinels = []Error{
	ErrMalformed,
	ErrOwnerBinding,
	ErrProofPolicy,
	ErrScoped,
	ErrIssuerNotFound,
	ErrSignatureInvalid,
	ErrSignatureUnestablished,
}

// sentinelsOf is the sentinels of this package that err is (errors.Is).
func sentinelsOf(err error) []Error {
	var out []Error
	for _, s := range append(refusalSentinels, ErrNotForIdentity) {
		if errors.Is(err, s) {
			out = append(out, s)
		}
	}
	return out
}

// Every value of class: the seven name one refusal sentinel each, no two the
// same, and every other value names none, the zero value too.
func TestClass_EachValueNamesOneSentinelOrNone(t *testing.T) {
	named := map[Error]class{}
	for v := 0; v <= math.MaxUint8; v++ {
		c := class(v)
		switch got := sentinelsOf(refuse(c, "text", nil)); {
		case len(got) == 0:
		case len(got) == 1 && got[0] != ErrNotForIdentity:
			if prev, ok := named[got[0]]; ok {
				t.Errorf("classes %d and %d both name %q", prev, c, got[0])
			}
			named[got[0]] = c
		default:
			t.Errorf("class %d is %q", c, got)
		}
	}
	for _, s := range refusalSentinels {
		if _, ok := named[s]; !ok {
			t.Errorf("no class names %q", s)
		}
	}
	// A class whose sentinel refusalSentinels lacks would read as none above.
	classes := 0
	for v := 0; v <= math.MaxUint8; v++ {
		if s, ok := class(v).sentinel(); ok {
			classes++
			if _, listed := named[s]; !listed {
				t.Errorf("class %d names %q, which refusalSentinels lacks", v, s)
			}
		}
	}
	if classes != len(refusalSentinels) {
		t.Errorf("%d classes name a sentinel, want %d", classes, len(refusalSentinels))
	}
}

// A refusal of no class, the zero value or one made with the zero class, is
// none of the sentinels.
func TestRefusal_ZeroIsNoSentinel(t *testing.T) {
	for name, r := range map[string]*refusal{
		"the zero value":        {},
		"made with class 0":     refuse(0, "text", nil),
		"made past the classes": refuse(math.MaxUint8, "text", nil),
	} {
		if got := sentinelsOf(r); len(got) != 0 {
			t.Errorf("%s: is %q, want none", name, got)
		}
	}
}

// A refusal's text is the one it is made with, and its cause stays reachable.
func TestRefusal_KeepsTextAndCause(t *testing.T) {
	cause := errors.New("cause")
	r := refuse(classSignatureInvalid, "delegation: text", cause)
	if r.Error() != "delegation: text" {
		t.Errorf("text %q", r.Error())
	}
	if !errors.Is(r, cause) || errors.Unwrap(r) != cause {
		t.Error("the cause is not reachable")
	}
	if got := sentinelsOf(r); len(got) != 1 || got[0] != ErrSignatureInvalid {
		t.Errorf("is %q, want only ErrSignatureInvalid", got)
	}
	if errors.Unwrap(refuse(classMalformed, "delegation: nil credential", nil)) != nil {
		t.Error("a refusal made with no cause unwraps to one")
	}
}
