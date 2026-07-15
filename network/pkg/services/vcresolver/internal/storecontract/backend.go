package storecontract

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
)

// Backend runs the VariantBackend contract against a fresh implementation.
//
// SCOPE. This suite deliberately asks nothing about identity, canonicality,
// write-once, or projection winners: those live in vcresolver.VariantStore,
// which every backend sits behind, so testing them per backend would test the
// same code twice and imply — wrongly — that a backend could get them wrong.
// What a backend CAN get wrong is here: atomic create, faithful read-back,
// exhaustive listing, the absent/damaged distinction, and byte ownership.
func Backend(t *testing.T, newBackend func(t *testing.T) vcresolver.VariantBackend) {
	t.Helper()
	t.Run("create and read back", func(t *testing.T) { backendCreateReadBack(t, newBackend(t)) })
	t.Run("put if absent is create-only", func(t *testing.T) { backendPutIfAbsent(t, newBackend(t)) })
	t.Run("bytes are not shared with the caller", func(t *testing.T) { backendOwnsItsBytes(t, newBackend(t)) })
	t.Run("variant listing", func(t *testing.T) { backendVariantListing(t, newBackend(t)) })
	t.Run("projection slot", func(t *testing.T) { backendProjection(t, newBackend(t)) })
	t.Run("body listing unions both slots", func(t *testing.T) { backendBodyListing(t, newBackend(t)) })
}

// hex64 returns a distinct well-formed hex name per seed. Backends name by hex
// payload (vcresolver hands them vc.WireVariantHex output), so the suite does.
func hex64(b byte) string { return strings.Repeat(string("0123456789abcdef"[b%16]), 64) }

func backendCreateReadBack(t *testing.T, b vcresolver.VariantBackend) {
	body, variant := hex64(1), hex64(2)
	if _, err := b.ReadVariant(body, variant); !errors.Is(err, vcresolver.ErrNotFound) {
		t.Fatalf("absent variant: want ErrNotFound, got %v", err)
	}
	wire := []byte(`{"a":1}`)
	existed, err := b.PutIfAbsent(body, variant, wire)
	if err != nil || existed {
		t.Fatalf("PutIfAbsent on a free name: existed=%v err=%v", existed, err)
	}
	got, err := b.ReadVariant(body, variant)
	if err != nil {
		t.Fatalf("ReadVariant: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Errorf("read back %s, want %s", got, wire)
	}
}

// backendPutIfAbsent pins the property the write-once gate above it depends
// on: a taken name reports existed and the held bytes DO NOT MOVE. A backend
// that overwrote here would erase the evidence the façade is about to compare
// against, and the corruption would be reported as success.
func backendPutIfAbsent(t *testing.T, b vcresolver.VariantBackend) {
	body, variant := hex64(3), hex64(4)
	first := []byte(`{"first":true}`)
	if _, err := b.PutIfAbsent(body, variant, first); err != nil {
		t.Fatalf("PutIfAbsent: %v", err)
	}
	existed, err := b.PutIfAbsent(body, variant, []byte(`{"second":true}`))
	if err != nil {
		t.Fatalf("PutIfAbsent on a taken name: %v", err)
	}
	if !existed {
		t.Error("PutIfAbsent on a taken name reported existed=false")
	}
	got, err := b.ReadVariant(body, variant)
	if err != nil {
		t.Fatalf("ReadVariant: %v", err)
	}
	if !bytes.Equal(got, first) {
		t.Errorf("a taken name was overwritten: holds %s, want %s", got, first)
	}
}

// backendOwnsItsBytes: storage must not alias caller memory in either
// direction. An aliased slice lets a caller mutate "immutable" storage after
// the fact — write-once broken without any write call.
func backendOwnsItsBytes(t *testing.T, b vcresolver.VariantBackend) {
	body, variant := hex64(5), hex64(6)
	wire := []byte(`{"v":"original"}`)
	if _, err := b.PutIfAbsent(body, variant, wire); err != nil {
		t.Fatalf("PutIfAbsent: %v", err)
	}
	wire[0] = 'X' // the caller scribbles on the slice it handed over
	got, err := b.ReadVariant(body, variant)
	if err != nil {
		t.Fatalf("ReadVariant: %v", err)
	}
	if got[0] == 'X' {
		t.Error("mutating the caller's slice changed stored bytes (storage aliased the input)")
	}
	got[1] = 'Y' // the caller scribbles on what it was handed back
	again, err := b.ReadVariant(body, variant)
	if err != nil {
		t.Fatalf("ReadVariant: %v", err)
	}
	if again[1] == 'Y' {
		t.Error("mutating a returned slice changed stored bytes (storage aliased the output)")
	}

	if err := b.WriteProjection(body, wire); err != nil {
		t.Fatalf("WriteProjection: %v", err)
	}
	wire[1] = 'Z'
	proj, err := b.ReadProjection(body)
	if err != nil {
		t.Fatalf("ReadProjection: %v", err)
	}
	if proj[1] == 'Z' {
		t.Error("mutating the caller's slice changed the projection (storage aliased the input)")
	}
}

func backendVariantListing(t *testing.T, b vcresolver.VariantBackend) {
	body := hex64(7)
	if page, err := b.ListVariantHexes(body, "", 10); err != nil || len(page) != 0 {
		t.Fatalf("unknown body: page=%v err=%v, want empty page and no error", page, err)
	}
	names := []string{hex64(3), hex64(1), hex64(4), hex64(2)}
	for _, n := range names {
		if _, err := b.PutIfAbsent(body, n, []byte(`{"n":"`+n[:1]+`"}`)); err != nil {
			t.Fatal(err)
		}
	}
	want := append([]string(nil), names...)
	sortStrings(want)

	all, err := b.ListVariantHexes(body, "", 10)
	if err != nil || !reflect.DeepEqual(all, want) {
		t.Fatalf("ListVariantHexes(\"\", 10) = %v (err %v), want %v", all, err, want)
	}
	page, err := b.ListVariantHexes(body, want[0], 2)
	if err != nil || !reflect.DeepEqual(page, want[1:3]) {
		t.Fatalf("ListVariantHexes(after first, 2) = %v (err %v), want %v", page, err, want[1:3])
	}
	if rest, err := b.ListVariantHexes(body, want[3], 5); err != nil || len(rest) != 0 {
		t.Fatalf("ListVariantHexes past the end = %v (err %v), want empty", rest, err)
	}
	// Another body's variants are not this body's.
	if other, err := b.ListVariantHexes(hex64(8), "", 10); err != nil || len(other) != 0 {
		t.Fatalf("a second body sees %v (err %v), want empty", other, err)
	}
}

func backendProjection(t *testing.T, b vcresolver.VariantBackend) {
	body := hex64(9)
	if _, err := b.ReadProjection(body); !errors.Is(err, vcresolver.ErrNotFound) {
		t.Fatalf("absent projection: want ErrNotFound, got %v", err)
	}
	first, second := []byte(`{"p":1}`), []byte(`{"p":2}`)
	if err := b.WriteProjection(body, first); err != nil {
		t.Fatalf("WriteProjection: %v", err)
	}
	// Unlike a variant, the projection slot is a derived pointer: it MUST be
	// replaceable, or the winner could never move.
	if err := b.WriteProjection(body, second); err != nil {
		t.Fatalf("WriteProjection (replace): %v", err)
	}
	got, err := b.ReadProjection(body)
	if err != nil || !bytes.Equal(got, second) {
		t.Errorf("ReadProjection = %s (err %v), want %s", got, err, second)
	}
}

func backendBodyListing(t *testing.T, b vcresolver.VariantBackend) {
	if page, err := b.ListBodyHexes("", 10); err != nil || len(page) != 0 {
		t.Fatalf("empty backend: page=%v err=%v, want empty page and no error", page, err)
	}
	variantOnly, projectionOnly, both := hex64(1), hex64(2), hex64(3)
	if _, err := b.PutIfAbsent(variantOnly, hex64(5), []byte(`{"x":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := b.WriteProjection(projectionOnly, []byte(`{"x":2}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.PutIfAbsent(both, hex64(6), []byte(`{"x":3}`)); err != nil {
		t.Fatal(err)
	}
	if err := b.WriteProjection(both, []byte(`{"x":3}`)); err != nil {
		t.Fatal(err)
	}
	want := []string{variantOnly, projectionOnly, both}
	sortStrings(want)
	got, err := b.ListBodyHexes("", 10)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ListBodyHexes = %v (err %v), want %v — a body known through only ONE slot must still be listed", got, err, want)
	}
	if page, err := b.ListBodyHexes(want[0], 1); err != nil || !reflect.DeepEqual(page, want[1:2]) {
		t.Fatalf("ListBodyHexes(after first, 1) = %v (err %v), want %v", page, err, want[1:2])
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
