package multibase_test

import (
	stded25519 "crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/provin-line/oss/multibase"
)

// Golden vectors for Bitcoin base58 (BTC alphabet) under the "z" multibase
// prefix. Leading-zero handling is the classic correctness trap, so it is
// covered explicitly. These vectors were pinned before the codec moved here
// from package vc — they freeze the proofValue byte shape across the move.
func TestBase58Btc_GoldenVectors(t *testing.T) {
	cases := []struct {
		in  []byte
		out string
	}{
		{[]byte{}, "z"},
		{[]byte{0x00}, "z1"},
		{[]byte{0x00, 0x00}, "z11"},
		{[]byte("Hello World!"), "z2NEpo7TZRRrLZSi2U"},
		{[]byte{0x00, 0x01}, "z12"},
		{[]byte{0x61}, "z2g"}, // 'a'
	}
	for _, tc := range cases {
		if got := multibase.EncodeBase58Btc(tc.in); got != tc.out {
			t.Errorf("EncodeBase58Btc(%x)=%q, want %q", tc.in, got, tc.out)
		}
		dec, err := multibase.DecodeBase58Btc(tc.out)
		if err != nil {
			t.Errorf("DecodeBase58Btc(%q): %v", tc.out, err)
			continue
		}
		if string(dec) != string(tc.in) {
			t.Errorf("DecodeBase58Btc(%q)=%x, want %x", tc.out, dec, tc.in)
		}
	}
}

// The official W3C vc-di-eddsa test vector (Examples 15/16): the
// eddsa-rdfc-2022 signature bytes and their base58btc proofValue. An
// independent cross-implementation anchor for the codec, beyond the
// self-produced goldens above.
func TestBase58Btc_W3CProofValueVector(t *testing.T) {
	const proofValue = "z2YwC8z3ap7yx1nZYCg4L3j3ApHsF8kgPdSb5xoS1VR7vPG3F561B52hYnQF9iseabecm3ijx4K1FBTQsCZahKZme"
	const sigHex = "4d8e53c2d5b3f2a7891753eb16ca993325bdb0d3cfc5be1093d0a18426f5ef8578cadc0fd4b5f4dd0d1ce0aefd15ab120b7a894d0eb094ffda4e6553cd1ed50d"
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatal(err)
	}
	if got := multibase.EncodeBase58Btc(sig); got != proofValue {
		t.Errorf("EncodeBase58Btc(W3C signature) = %q, want %q", got, proofValue)
	}
	dec, err := multibase.DecodeBase58Btc(proofValue)
	if err != nil {
		t.Fatalf("DecodeBase58Btc(W3C proofValue): %v", err)
	}
	if hex.EncodeToString(dec) != sigHex {
		t.Errorf("DecodeBase58Btc(W3C proofValue) = %x, want %s", dec, sigHex)
	}
}

func TestBase58Btc_RoundTrip_Signature(t *testing.T) {
	_, priv, _ := stded25519.GenerateKey(nil)
	sig := stded25519.Sign(priv, []byte("hashData"))
	enc := multibase.EncodeBase58Btc(sig)
	if !strings.HasPrefix(enc, "z") {
		t.Errorf("encoding %q must carry the 'z' base58btc prefix", enc)
	}
	dec, err := multibase.DecodeBase58Btc(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(dec) != string(sig) {
		t.Error("64-byte signature did not round-trip through base58btc")
	}
}

func TestDecodeBase58Btc_InvalidChar(t *testing.T) {
	// '0', 'O', 'I', 'l' are not in the base58 alphabet.
	for _, bad := range []string{"z0", "zO", "zI", "zl", "zabc!"} {
		if _, err := multibase.DecodeBase58Btc(bad); err == nil {
			t.Errorf("DecodeBase58Btc(%q): want error on invalid character", bad)
		}
	}
}

func TestDecodeBase58Btc_RejectsWrongPrefix(t *testing.T) {
	// 'f' is multibase hex, not base58btc — a consumer must reject a value
	// that is not 'z' base58btc rather than silently mis-decoding it under
	// another base.
	for _, bad := range []string{"", "fdeadbeef", "Q123", "2g"} {
		if _, err := multibase.DecodeBase58Btc(bad); err == nil {
			t.Errorf("DecodeBase58Btc(%q): want error (not 'z' base58btc)", bad)
		}
	}
}
