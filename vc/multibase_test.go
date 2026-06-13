package vc

import (
	stded25519 "crypto/ed25519"
	"strings"
	"testing"
)

// Golden vectors for Bitcoin base58 (BTC alphabet). Leading-zero handling is
// the classic correctness trap, so it is covered explicitly.
func TestBase58_GoldenVectors(t *testing.T) {
	cases := []struct {
		in  []byte
		out string
	}{
		{[]byte{}, ""},
		{[]byte{0x00}, "1"},
		{[]byte{0x00, 0x00}, "11"},
		{[]byte("Hello World!"), "2NEpo7TZRRrLZSi2U"},
		{[]byte{0x00, 0x01}, "12"},
		{[]byte{0x61}, "2g"}, // 'a'
	}
	for _, tc := range cases {
		if got := base58Encode(tc.in); got != tc.out {
			t.Errorf("base58Encode(%x)=%q, want %q", tc.in, got, tc.out)
		}
		dec, err := base58Decode(tc.out)
		if err != nil {
			t.Errorf("base58Decode(%q): %v", tc.out, err)
			continue
		}
		if string(dec) != string(tc.in) {
			t.Errorf("base58Decode(%q)=%x, want %x", tc.out, dec, tc.in)
		}
	}
}

func TestBase58_RoundTrip_Signature(t *testing.T) {
	_, priv, _ := stded25519.GenerateKey(nil)
	sig := stded25519.Sign(priv, []byte("hashData"))
	enc := base58Encode(sig)
	dec, err := base58Decode(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(dec) != string(sig) {
		t.Error("64-byte signature did not round-trip through base58")
	}
}

func TestBase58Decode_InvalidChar(t *testing.T) {
	// '0', 'O', 'I', 'l' are not in the base58 alphabet.
	for _, bad := range []string{"0", "O", "I", "l", "abc!"} {
		if _, err := base58Decode(bad); err == nil {
			t.Errorf("base58Decode(%q): want error on invalid character", bad)
		}
	}
}

func TestMultibase_Z_RoundTrip(t *testing.T) {
	data := []byte("provenance signature bytes")
	enc := multibaseEncodeBase58(data)
	if !strings.HasPrefix(enc, "z") {
		t.Errorf("multibase encoding %q must carry the 'z' base58btc prefix", enc)
	}
	dec, err := multibaseDecodeBase58(enc)
	if err != nil {
		t.Fatalf("multibaseDecodeBase58: %v", err)
	}
	if string(dec) != string(data) {
		t.Error("multibase z round-trip mismatch")
	}
}

func TestMultibaseDecode_RejectsWrongPrefix(t *testing.T) {
	// 'f' is multibase hex, not base58btc — the verifier must reject a value
	// that is not 'z' base58btc rather than silently mis-decoding.
	for _, bad := range []string{"", "fdeadbeef", "Q123", base58Encode([]byte("x"))} {
		if _, err := multibaseDecodeBase58(bad); err == nil {
			t.Errorf("multibaseDecodeBase58(%q): want error (not 'z' base58btc)", bad)
		}
	}
}
