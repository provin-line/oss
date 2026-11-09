package schemaregistry

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/schemaregistry/store"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry/store/yamlstore"
)

func TestValidSegment(t *testing.T) {
	for _, s := range []string{"reading", "rc1", "2026-06-14-deadbeefdeadbeef", "a.b_c-d", "0", strings.Repeat("a", 128)} {
		if !validSegment(s) {
			t.Errorf("%q: refused", s)
		}
	}
	for _, s := range []string{
		"", ".", "..", ".nan", "-x", "_x", "a b", " a", "a ", "a\tb", "a\nb", "rc  \n",
		"a/b", `a\b`, "a\x00b", "a:b", "é", "x<<", strings.Repeat("a", 129),
	} {
		if validSegment(s) {
			t.Errorf("%q: admitted", s)
		}
	}
}

// Every name and prerelease validSegment admits is stored and read back as it
// was: the store's own fidelity check, a backstop, is not reached by any of it.
func TestValidSegment_WhatItAdmitsReadsBackFromTheStore(t *testing.T) {
	const first = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	const rest = first + "._-"
	r := rand.New(rand.NewPCG(7, 8))
	segment := func() string {
		b := []byte{first[r.IntN(len(first))]}
		for range r.IntN(128) {
			b = append(b, rest[r.IntN(len(rest))])
		}
		return string(b)
	}
	s := yamlstore.New(t.TempDir())
	for i := range 3000 {
		name, pre := segment(), segment()
		if !validSegment(name) || !validSegment(pre) {
			t.Fatalf("generated %q / %q not admitted", name, pre)
		}
		version := fmt.Sprintf("2026-06-14-%016x", i)
		in := &store.Schema{Name: name, Version: version, Prerelease: pre, SchemaFormat: "JsonSchema", SchemaBody: []byte(`{}`)}
		if err := s.Save(in); err != nil {
			t.Fatalf("store refused %q / %q: %v", name, pre, err)
		}
		got, err := s.Get(name, version)
		if err != nil {
			t.Fatal(err)
		}
		if got.Name != name || got.Prerelease != pre {
			t.Fatalf("read back %q / %q, stored %q / %q", got.Name, got.Prerelease, name, pre)
		}
	}
}
