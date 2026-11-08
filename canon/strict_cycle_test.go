package canon_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/canon"
)

// A destination that holds itself through pointers and interfaces is refused
// before anything is decoded into it: encoding/json would follow it without
// end (Go 1.27's decoder overflows its stack). The refusal is the same on
// every toolchain.
func TestStrictDecoder_RefusesADestinationThatHoldsItself(t *testing.T) {
	type holder struct {
		F any `json:"f"`
	}
	for name, decode := range map[string]func() error{
		"an interface holding a pointer to itself": func() error {
			var x any
			x = &x
			return canon.NewStrictDecoder([]byte(`{"a":1}`)).Decode(&x)
		},
		"a field holding a pointer to itself": func() error {
			var h holder
			h.F = &h.F
			return canon.NewStrictDecoder([]byte(`{"f":{"a":1}}`)).Decode(&h)
		},
		"a slice element holding a pointer to itself": func() error {
			v := []any{nil}
			v[0] = &v[0]
			return canon.NewStrictDecoder([]byte(`[{"a":1}]`)).Decode(&v)
		},
		"a pointer type to itself": func() error {
			var p selfPointer
			return canon.NewStrictDecoder([]byte(`1`)).Decode(&p)
		},
		"two interfaces holding pointers to each other": func() error {
			var a, b any
			a, b = &b, &a
			return canon.NewStrictDecoder([]byte(`{"a":1}`)).Decode(&a)
		},
		"null into an interface holding itself": func() error {
			var x any
			x = &x
			return canon.NewStrictDecoder([]byte(`null`)).Decode(&x)
		},
	} {
		done := make(chan error, 1)
		go func() { done <- decode() }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "pointers and interfaces") {
				t.Errorf("%s: err = %v, want the refusal of a target that holds itself", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: Decode still running after 5s", name)
		}
	}
}

// A destination reached through a few pointers and interfaces, without a
// cycle, is decoded.
func TestStrictDecoder_FollowsPointersAndInterfacesWithoutACycle(t *testing.T) {
	m := map[string]any{}
	var x any = &m
	p := &x
	if err := canon.NewStrictDecoder([]byte(`{"a":"b"}`)).Decode(&p); err != nil || m["a"] != "b" {
		t.Errorf("Decode = %v, map %v", err, m)
	}
}

// pointers returns a non-nil value of n pointers to an int.
func pointers(n int) any {
	v := reflect.New(reflect.TypeOf(0))
	for i := 1; i < n; i++ {
		p := reflect.New(v.Type())
		p.Elem().Set(v)
		v = p
	}
	return v.Interface()
}

// The bound is 64 pointers and interfaces: 64 are followed, 65 are refused.
func TestStrictDecoder_TheBoundIs64PointersAndInterfaces(t *testing.T) {
	if err := canon.NewStrictDecoder([]byte(`1`)).Decode(pointers(64)); err != nil {
		t.Errorf("64 pointers: %v", err)
	}
	if err := canon.NewStrictDecoder([]byte(`1`)).Decode(pointers(65)); err == nil || !strings.Contains(err.Error(), "pointers and interfaces") {
		t.Errorf("65 pointers: err = %v, want the refusal", err)
	}
}
