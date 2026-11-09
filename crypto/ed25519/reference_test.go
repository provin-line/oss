package ed25519_test

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/provin-line/oss/crypto/ed25519"
)

// referenceValidate is ValidatePublicKey written directly from its definition
// in big.Int arithmetic: reduce y, compare it with the five y coordinates of
// the small-order points, require y < p, and decide whether
// x^2 = (y^2-1)/(d*y^2+1) has a solution by Euler's criterion (a nonzero a is
// a square modulo p exactly when a^((p-1)/2) = 1), which shares no code with
// the Jacobi symbol ValidatePublicKey uses. ValidatePublicKey must agree with
// it on every input.
func referenceValidate(pub []byte) error {
	if len(pub) != 32 {
		return ed25519.ErrPublicKeySize
	}
	be := make([]byte, 32)
	for i, b := range pub {
		be[31-i] = b
	}
	be[0] &= 0x7f
	y := new(big.Int).SetBytes(be)
	y8, _ := new(big.Int).SetString("7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7", 16)
	reduced := new(big.Int).Mod(y, fieldP)
	for _, s := range []*big.Int{
		big.NewInt(0), big.NewInt(1), new(big.Int).Sub(fieldP, big.NewInt(1)), y8, new(big.Int).Sub(fieldP, y8),
	} {
		if reduced.Cmp(s) == 0 {
			return ed25519.ErrSmallOrder
		}
	}
	if y.Cmp(fieldP) >= 0 {
		return ed25519.ErrInvalidPoint
	}
	y2 := new(big.Int).Mul(y, y)
	num := new(big.Int).Sub(y2, big.NewInt(1))
	den := new(big.Int).Mul(curveD, y2)
	den.Add(den, big.NewInt(1)).Mod(den, fieldP)
	x2 := num.Mul(num, new(big.Int).ModInverse(den, fieldP)).Mod(num, fieldP)
	half := new(big.Int).Rsh(new(big.Int).Sub(fieldP, big.NewInt(1)), 1)
	if x2.Sign() == 0 || new(big.Int).Exp(x2, half, fieldP).Cmp(big.NewInt(1)) == 0 {
		return nil
	}
	return ed25519.ErrInvalidPoint
}

func sameVerdict(got, want error) bool {
	if want == nil {
		return got == nil
	}
	return errors.Is(got, want)
}

func checkAgainstReference(t *testing.T, pub []byte) {
	t.Helper()
	if got, want := ed25519.ValidatePublicKey(pub), referenceValidate(pub); !sameVerdict(got, want) {
		t.Errorf("ValidatePublicKey(%x) = %v, reference = %v", pub, got, want)
	}
}

// Every y near the edges of the field — the small values, the values just
// below p, and every non-canonical value p..2^255-1 — in both sign bits, and
// many random encodings agree with the reference.
func TestValidatePublicKey_MatchesReference(t *testing.T) {
	var ys []*big.Int
	for i := int64(0); i < 256; i++ {
		ys = append(ys, big.NewInt(i))
		ys = append(ys, new(big.Int).Sub(fieldP, big.NewInt(i+1)))
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 255)
	for y := new(big.Int).Set(fieldP); y.Cmp(limit) < 0; y.Add(y, big.NewInt(1)) {
		ys = append(ys, new(big.Int).Set(y))
	}
	for _, y := range ys {
		for _, sign := range []byte{0, 1} {
			checkAgainstReference(t, encode(y, sign))
		}
	}
	// Every single-byte change of the encodings of 2^255-1 and p, so that each
	// byte the y >= p comparison reads is varied on its own.
	top := new(big.Int).Sub(limit, big.NewInt(1))
	for _, base := range []*big.Int{top, fieldP} {
		for k := 0; k < 32; k++ {
			for _, v := range []byte{0x00, 0x7e, 0x7f, 0xec, 0xed, 0xee, 0xfe, 0xff} {
				b := encode(base, 0)
				b[k] = v
				for _, s := range []byte{0, 0x80} {
					c := append([]byte(nil), b...)
					c[31] = c[31]&0x7f | s
					checkAgainstReference(t, c)
				}
			}
		}
	}
	for _, b := range libsodiumEntries(t) {
		checkAgainstReference(t, b)
		withSign := append([]byte(nil), b...)
		withSign[31] |= 0x80
		checkAgainstReference(t, withSign)
	}
	buf := make([]byte, 32)
	for i := 0; i < 20000; i++ {
		if _, err := rand.Read(buf); err != nil {
			t.Fatal(err)
		}
		checkAgainstReference(t, buf)
	}
	for _, n := range []int{0, 1, 31, 33, 64} {
		checkAgainstReference(t, make([]byte, n))
	}
}

func FuzzValidatePublicKeyMatchesReference(f *testing.F) {
	for _, h := range libsodiumBlacklist {
		b, _ := hex.DecodeString(h)
		f.Add(b)
	}
	f.Add(make([]byte, 32))
	f.Fuzz(func(t *testing.T, pub []byte) {
		checkAgainstReference(t, pub)
	})
}
