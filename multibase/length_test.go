package multibase_test

import (
	"crypto/rand"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/provin-line/oss/multibase"
)

const maxBase58BtcLength = 8192

// A value of up to 8192 characters after its prefix decodes; one character
// more is refused, leading "1"s (zero bytes) included.
func TestDecodeBase58Btc_RefusesAValueLongerThanTheBound(t *testing.T) {
	for _, c := range []struct {
		digits string
		ok     bool
	}{
		{strings.Repeat("2", maxBase58BtcLength), true},
		{strings.Repeat("2", maxBase58BtcLength+1), false},
		{strings.Repeat("1", maxBase58BtcLength), true},
		{strings.Repeat("1", maxBase58BtcLength+1), false},
		{"1" + strings.Repeat("z", maxBase58BtcLength), false},
	} {
		_, err := multibase.DecodeBase58Btc("z" + c.digits)
		if (err == nil) != c.ok {
			t.Errorf("DecodeBase58Btc(z + %.3s… × %d): err = %v, want decoded %t", c.digits, len(c.digits), err, c.ok)
		}
	}
}

// Every byte string of up to 5998 bytes encodes within the bound and decodes
// back; ML-DSA-87's 4627-byte signature fits with room to spare.
func TestBase58Btc_RoundTripUpToTheBound(t *testing.T) {
	for _, n := range []int{64, 4627, 5998} {
		for _, zeros := range []int{0, 1, 7} {
			data := make([]byte, n)
			rand.Read(data[zeros:])
			if zeros < n {
				data[zeros] |= 0x80
			}
			s := multibase.EncodeBase58Btc(data)
			if len(s)-1 > maxBase58BtcLength {
				t.Fatalf("%d bytes encode to %d characters", n, len(s)-1)
			}
			got, err := multibase.DecodeBase58Btc(s)
			if err != nil || string(got) != string(data) {
				t.Errorf("round trip of %d bytes (%d leading zeros): err = %v, equal = %t", n, zeros, err, string(got) == string(data))
			}
		}
	}
}

// bytesAllocated is what f allocates, on average over runs.
func bytesAllocated(runs int, f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range runs {
		f()
	}
	runtime.ReadMemStats(&after)
	return (after.TotalAlloc - before.TotalAlloc) / uint64(runs)
}

// A value past the bound, or without the prefix, is refused before any of it
// is decoded or copied: a megabyte costs what a short value costs.
func TestDecodeBase58Btc_RefusesALongValueWithoutDecodingOrCopyingIt(t *testing.T) {
	for name, s := range map[string]string{
		"past the bound":         "z" + strings.Repeat("z", 1<<20),
		"without the prefix":     "f" + strings.Repeat("0", 1<<20),
		"NUL without the prefix": strings.Repeat("\x00", 1<<20),
	} {
		if n := bytesAllocated(5, func() {
			if _, err := multibase.DecodeBase58Btc(s); err == nil {
				t.Fatalf("%s: decoded a megabyte", name)
			}
		}); n > 1024 {
			t.Errorf("%s: refusing a megabyte allocates %d bytes", name, n)
		}
	}
}

// 5998 bytes is the most that fits: 5999 bytes of 0xFF encode to 8193
// characters, and the decoder refuses them.
func TestBase58Btc_5999BytesDoNotFit(t *testing.T) {
	s := multibase.EncodeBase58Btc([]byte(strings.Repeat("\xff", 5999)))
	if len(s)-1 != maxBase58BtcLength+1 {
		t.Fatalf("5999 bytes of 0xFF encode to %d characters", len(s)-1)
	}
	if _, err := multibase.DecodeBase58Btc(s); err == nil {
		t.Error("decoded 5999 bytes")
	}
}

// Decoding costs the square of the length up to the bound and nothing past
// it: the time per value stays within what 8192 characters cost.
func BenchmarkDecodeBase58Btc(b *testing.B) {
	for _, n := range []int{88, 1 << 10, maxBase58BtcLength, 1 << 20} {
		s := "z" + strings.Repeat("z", n)
		b.Run(fmt.Sprintf("chars/%d", n), func(b *testing.B) {
			for b.Loop() {
				_, _ = multibase.DecodeBase58Btc(s)
			}
		})
	}
}
