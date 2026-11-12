package contentaddress_test

import (
	"bytes"
	"math/rand/v2"
	"testing"

	"github.com/provin-line/oss/contentaddress"
)

// A Hasher's Address is Of the bytes written to it, however they were split
// into Writes.
func TestHasher_AddressIsOfTheBytesHoweverTheyAreWritten(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 8))
	for range 200 {
		b := make([]byte, rng.IntN(5000))
		for i := range b {
			b[i] = byte(rng.Uint32())
		}
		h := contentaddress.NewHasher()
		for rest := b; len(rest) > 0; {
			n := min(1+rng.IntN(300), len(rest))
			if w, err := h.Write(rest[:n]); w != n || err != nil {
				t.Fatalf("Write = %d, %v; want %d, nil", w, err, n)
			}
			rest = rest[n:]
		}
		if got, want := h.Address(), contentaddress.Of(b); got != want {
			t.Fatalf("%d bytes: Address() = %v, want Of = %v", len(b), got, want)
		}
	}
}

// Address does not end a Hasher: the bytes written after it count as well.
func TestHasher_WritesAfterAddress(t *testing.T) {
	h := contentaddress.NewHasher()
	h.Write([]byte("the first part, "))
	if got, want := h.Address(), contentaddress.Of([]byte("the first part, ")); got != want {
		t.Fatalf("Address() = %v, want %v", got, want)
	}
	h.Write([]byte("and the rest"))
	if got, want := h.Address(), contentaddress.Of([]byte("the first part, and the rest")); got != want {
		t.Errorf("Address() after more Writes = %v, want %v", got, want)
	}
}

// A Hasher with nothing written has the address of no bytes, which is an
// address, not the zero Address.
func TestHasher_NothingWrittenIsOfNoBytes(t *testing.T) {
	got := contentaddress.NewHasher().Address()
	if got != contentaddress.Of(nil) || got.IsZero() {
		t.Errorf("Address() = %q, want Of(nil) = %q", got, contentaddress.Of(nil))
	}
	if _, err := contentaddress.Parse(got.String()); err != nil {
		t.Errorf("Parse(%q): %v", got, err)
	}
	if !bytes.HasPrefix([]byte(got.String()), []byte("sha256:")) {
		t.Errorf("Address() = %q, want the sha256: spelling", got)
	}
}

// The zero Hasher is ready to use, with nothing written to it, as one from
// NewHasher is.
func TestHasher_TheZeroHasherIsReadyToUse(t *testing.T) {
	var empty contentaddress.Hasher
	if got := empty.Address(); got != contentaddress.Of(nil) {
		t.Errorf("zero Hasher's Address() = %q, want Of(nil) = %q", got, contentaddress.Of(nil))
	}
	var h contentaddress.Hasher
	if n, err := h.Write([]byte("some bytes")); n != len("some bytes") || err != nil {
		t.Fatalf("Write = %d, %v; want %d, nil", n, err, len("some bytes"))
	}
	if got, want := h.Address(), contentaddress.Of([]byte("some bytes")); got != want {
		t.Errorf("Address() = %v, want %v", got, want)
	}
}
