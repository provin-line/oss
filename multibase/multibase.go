// Package multibase implements the multiformats multibase encoding for the
// self-describing byte strings this repository puts on the wire: Data
// Integrity proofValue and Multikey publicKeyMultibase, both base58btc
// ("z" prefix).
//
// It is the single codec shared by every producer and consumer (vc, did):
// two independent base58 implementations diverging on an edge case would
// partition signature verification from key decoding, so the codec is
// frozen here once. Decoding is fail-closed: a value that does not carry
// the expected multibase prefix is rejected rather than mis-decoded under
// another base.
package multibase

import (
	"fmt"
	"math/big"
	"strings"
)

// base58Alphabet is the Bitcoin base58 alphabet (no 0, O, I, l).
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58BtcPrefix is the multibase code for base58btc.
const base58BtcPrefix = "z"

// EncodeBase58Btc encodes data as multibase base58btc ("z" prefix) — the
// proofValue and publicKeyMultibase encoding.
func EncodeBase58Btc(data []byte) string {
	return base58BtcPrefix + base58Encode(data)
}

// DecodeBase58Btc decodes a multibase base58btc value. A value that does not
// carry the "z" prefix is rejected rather than mis-decoded under another base
// (defense against a verifier accepting a differently-encoded value).
func DecodeBase58Btc(s string) ([]byte, error) {
	rest, ok := strings.CutPrefix(s, base58BtcPrefix)
	if !ok {
		return nil, fmt.Errorf("multibase: value %q is not base58btc (missing %q prefix)", s, base58BtcPrefix)
	}
	return base58Decode(rest)
}

// base58Encode encodes b in Bitcoin base58. Each leading zero byte becomes a
// leading "1" (base58 of zero), per the standard.
func base58Encode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	num := new(big.Int).SetBytes(b)
	base := big.NewInt(58)
	mod := new(big.Int)
	var rev []byte
	for num.Sign() > 0 {
		num.DivMod(num, base, mod)
		rev = append(rev, base58Alphabet[mod.Int64()])
	}
	// Leading zero bytes → leading '1' characters.
	for i := 0; i < zeros; i++ {
		rev = append(rev, '1')
	}
	// rev holds least-significant first; reverse to most-significant first.
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return string(rev)
}

// base58Decode decodes a Bitcoin base58 string. An invalid character is an
// error. Leading "1" characters become leading zero bytes.
func base58Decode(s string) ([]byte, error) {
	num := big.NewInt(0)
	base := big.NewInt(58)
	for _, r := range s {
		idx := strings.IndexRune(base58Alphabet, r)
		if idx < 0 {
			return nil, fmt.Errorf("base58: invalid character %q", r)
		}
		num.Mul(num, base)
		num.Add(num, big.NewInt(int64(idx)))
	}
	decoded := num.Bytes()
	// Count leading '1' characters → leading zero bytes. Byte indexing is safe
	// here: the alphabet is ASCII-only, so any multi-byte rune would already
	// have failed the IndexRune check above.
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	out := make([]byte, zeros+len(decoded))
	copy(out[zeros:], decoded)
	return out, nil
}
