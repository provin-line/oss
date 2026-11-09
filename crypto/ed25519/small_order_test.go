package ed25519_test

import (
	stded25519 "crypto/ed25519"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/provin-line/oss/crypto/ed25519"
)

// libsodiumBlacklist is the small-order blacklist of libsodium 1.0.18, from
// src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c
// (ge25519_has_small_order; entries are compared with the sign bit masked).
var libsodiumBlacklist = []string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
}

var (
	fieldP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	curveD = func() *big.Int {
		n := new(big.Int).Sub(fieldP, big.NewInt(121665))
		return n.Mul(n, new(big.Int).ModInverse(big.NewInt(121666), fieldP)).Mod(n, fieldP)
	}()
)

// point is an affine point of -x^2 + y^2 = 1 + d x^2 y^2.
type point struct{ x, y *big.Int }

func addPoints(a, b point) point {
	t := new(big.Int).Mul(a.x, b.x)
	t.Mul(t, a.y).Mul(t, b.y).Mod(t, fieldP)
	t.Mul(t, curveD).Mod(t, fieldP)
	x := new(big.Int).Add(new(big.Int).Mul(a.x, b.y), new(big.Int).Mul(b.x, a.y))
	x.Mul(x, new(big.Int).ModInverse(new(big.Int).Add(big.NewInt(1), t), fieldP)).Mod(x, fieldP)
	y := new(big.Int).Add(new(big.Int).Mul(a.y, b.y), new(big.Int).Mul(a.x, b.x))
	y.Mul(y, new(big.Int).ModInverse(new(big.Int).Sub(big.NewInt(1), t), fieldP)).Mod(y, fieldP)
	return point{x, y}
}

func (p point) isIdentity() bool { return p.x.Sign() == 0 && p.y.Cmp(big.NewInt(1)) == 0 }

// decompress returns the point with the given y and the x of the given sign.
func decompress(y *big.Int, sign uint) (point, bool) {
	y2 := new(big.Int).Mul(y, y)
	num := new(big.Int).Sub(y2, big.NewInt(1))
	den := new(big.Int).Mul(curveD, y2)
	den.Add(den, big.NewInt(1))
	x2 := num.Mul(num, new(big.Int).ModInverse(den, fieldP)).Mod(num, fieldP)
	x := new(big.Int).ModSqrt(x2, fieldP)
	if x == nil {
		return point{}, false
	}
	if x.Bit(0) != sign {
		x.Sub(fieldP, x).Mod(x, fieldP)
	}
	return point{x, new(big.Int).Set(y)}, true
}

// encode is the RFC 8032 point encoding: y little-endian, bit 255 = sign of x.
// y may exceed p (a non-canonical spelling) as long as it fits in 255 bits.
func encode(y *big.Int, sign byte) []byte {
	b := y.FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	b[31] |= sign << 7
	return b
}

func libsodiumEntries(t *testing.T) [][]byte {
	t.Helper()
	var out [][]byte
	for _, h := range libsodiumBlacklist {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			t.Fatalf("%s: %v", h, err)
		}
		out = append(out, b)
	}
	return out
}

// torsion returns the 8 points of order dividing 8, built from the order-8
// point of libsodium's blacklist by repeated addition (independent of the
// package's table).
func torsion(t *testing.T) []point {
	t.Helper()
	y8, _ := new(big.Int).SetString("7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7", 16)
	g, ok := decompress(y8, 0)
	if !ok {
		t.Fatal("order-8 generator is not on the curve")
	}
	pts := []point{{big.NewInt(0), big.NewInt(1)}}
	cur := pts[0]
	for i := 0; i < 7; i++ {
		cur = addPoints(cur, g)
		pts = append(pts, cur)
	}
	if !addPoints(cur, g).isIdentity() {
		t.Fatal("8*G is not the identity")
	}
	return pts
}

func TestValidatePublicKey_RefusesTheWholeTorsionSubgroupInEveryEncoding(t *testing.T) {
	pts := torsion(t)
	distinct := map[string]bool{}
	for _, pt := range pts {
		distinct[pt.x.String()+","+pt.y.String()] = true
		for _, sign := range []byte{0, 1} {
			// a point's own x sign, plus the flipped one (the other point with the same y)
			enc := encode(pt.y, sign)
			if err := ed25519.ValidatePublicKey(enc); !errors.Is(err, ed25519.ErrSmallOrder) {
				t.Errorf("y=%x sign=%d: err=%v, want ErrSmallOrder", pt.y, sign, err)
			}
			if alt := new(big.Int).Add(pt.y, fieldP); alt.BitLen() <= 255 {
				if err := ed25519.ValidatePublicKey(encode(alt, sign)); !errors.Is(err, ed25519.ErrSmallOrder) {
					t.Errorf("non-canonical y+p for y=%x sign=%d: err=%v", pt.y, sign, err)
				}
			}
		}
	}
	if len(distinct) != 8 {
		t.Fatalf("%d distinct torsion points, want 8", len(distinct))
	}
}

func TestValidatePublicKey_RefusesLibsodiumBlacklist(t *testing.T) {
	for _, b := range libsodiumEntries(t) {
		if err := ed25519.ValidatePublicKey(b); !errors.Is(err, ed25519.ErrSmallOrder) {
			t.Errorf("%x: err=%v", b, err)
		}
		flipped := append([]byte(nil), b...)
		flipped[31] ^= 0x80
		if err := ed25519.ValidatePublicKey(flipped); !errors.Is(err, ed25519.ErrSmallOrder) {
			t.Errorf("%x with sign bit flipped: err=%v", b, err)
		}
	}
}

func TestValidatePublicKey_AcceptsGeneratedKeysAndRefusesWrongSizes(t *testing.T) {
	for i := 0; i < 50; i++ {
		kp, err := ed25519.Generator{}.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := ed25519.ValidatePublicKey(kp.PublicKey); err != nil {
			t.Fatalf("generated key refused: %v", err)
		}
	}
	for _, n := range []int{0, 31, 33, 64} {
		err := ed25519.ValidatePublicKey(make([]byte, n))
		if !errors.Is(err, ed25519.ErrPublicKeySize) {
			t.Errorf("size %d: err=%v, want a size error", n, err)
		}
	}
}

// ordinaryYs returns the y values below 19 that are on the curve and not of
// small order, and those that are off the curve, by independent decompression.
// y < 19 is the range in which y+p still fits in 255 bits.
func ordinaryYs(t *testing.T) (onCurve, offCurve []*big.Int) {
	t.Helper()
	small := map[string]bool{}
	for _, pt := range torsion(t) {
		small[pt.y.String()] = true
	}
	for i := int64(2); i < 19; i++ {
		y := big.NewInt(i)
		if _, ok := decompress(y, 0); ok {
			if !small[y.String()] {
				onCurve = append(onCurve, y)
			}
		} else {
			offCurve = append(offCurve, y)
		}
	}
	return onCurve, offCurve
}

func TestValidatePublicKey_RefusesValuesOffTheCurve(t *testing.T) {
	_, off := ordinaryYs(t)
	have := map[int64]bool{}
	for _, y := range off {
		have[y.Int64()] = true
	}
	for _, want := range []int64{2, 7, 8, 11} {
		if !have[want] {
			t.Fatalf("y=%d is expected to be off the curve", want)
		}
	}
	for _, y := range off {
		for _, sign := range []byte{0, 1} {
			if err := ed25519.ValidatePublicKey(encode(y, sign)); !errors.Is(err, ed25519.ErrInvalidPoint) {
				t.Errorf("off-curve y=%d sign=%d: err=%v, want ErrInvalidPoint", y, sign, err)
			}
		}
	}
}

func TestValidatePublicKey_RefusesNonCanonicalSpellingsOfOrdinaryPoints(t *testing.T) {
	on, _ := ordinaryYs(t)
	if len(on) == 0 {
		t.Fatal("no ordinary on-curve y below 19")
	}
	for _, y := range on {
		for _, sign := range []byte{0, 1} {
			if err := ed25519.ValidatePublicKey(encode(y, sign)); err != nil {
				t.Errorf("canonical y=%d sign=%d refused: %v", y, sign, err)
			}
			alt := new(big.Int).Add(y, fieldP)
			if err := ed25519.ValidatePublicKey(encode(alt, sign)); !errors.Is(err, ed25519.ErrInvalidPoint) {
				t.Errorf("non-canonical y+p for y=%d sign=%d: err=%v, want ErrInvalidPoint", y, sign, err)
			}
		}
	}
}

func TestVerifier_Verify_RefusesOffCurveAndNonCanonicalPublicKey(t *testing.T) {
	kp, _ := ed25519.Generator{}.Generate()
	sig, _ := ed25519.Sign(kp.PrivateKey, []byte("m"))
	on, off := ordinaryYs(t)
	for _, key := range [][]byte{encode(off[0], 0), encode(new(big.Int).Add(on[0], fieldP), 0)} {
		if ok, err := (ed25519.Verifier{}).Verify(key, []byte("m"), sig); ok || !errors.Is(err, ed25519.ErrInvalidPoint) {
			t.Errorf("%x: ok=%v err=%v", key, ok, err)
		}
	}
}

func TestVerifier_Verify_RefusesSmallOrderPublicKey(t *testing.T) {
	// A well-formed signature from a generated key, so that the key is the
	// only small-order input.
	kp, err := ed25519.Generator{}.Generate()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("any message")
	sig, err := ed25519.Sign(kp.PrivateKey, msg)
	if err != nil {
		t.Fatal(err)
	}
	for _, pt := range torsion(t) {
		for _, sign := range []byte{0, 1} {
			ok, err := ed25519.Verifier{}.Verify(encode(pt.y, sign), msg, sig)
			if ok || !errors.Is(err, ed25519.ErrSmallOrder) {
				t.Errorf("y=%x sign=%d: ok=%v err=%v", pt.y, sign, ok, err)
			}
		}
	}
}

// The advisory reproduction: with the identity as public key, the signature
// identity || 0^32 verifies every message under the standard library.
func TestVerifier_Verify_RefusesIdentityKeyForgery(t *testing.T) {
	identity := encode(big.NewInt(1), 0)
	sig := append(append([]byte(nil), identity...), make([]byte, 32)...)
	for _, msg := range [][]byte{nil, []byte("a"), []byte("transfer everything")} {
		if !stded25519.Verify(identity, msg, sig) {
			t.Fatal("precondition: the standard library accepts the forgery")
		}
		ok, err := ed25519.Verifier{}.Verify(identity, msg, sig)
		if ok || !errors.Is(err, ed25519.ErrSmallOrder) {
			t.Errorf("msg=%q: ok=%v err=%v, want refusal", msg, ok, err)
		}
	}
}

// With the identity as public key, R = B (the base point) and S = 1 satisfy
// S*B = R + k*A for every message, and R is not of small order, so only the
// public-key check refuses it.
func TestVerifier_Verify_RefusesIdentityKeyForgeryWithBasePointR(t *testing.T) {
	identity := encode(big.NewInt(1), 0)
	baseY, _ := new(big.Int).SetString("6666666666666666666666666666666666666666666666666666666666666658", 16)
	r := encode(baseY, 0)
	if hasSmall := ed25519.ValidatePublicKey(r); hasSmall != nil {
		t.Fatalf("the base point must not be small order: %v", hasSmall)
	}
	sig := append(append([]byte(nil), r...), 1)
	sig = append(sig, make([]byte, 31)...)
	for _, msg := range [][]byte{nil, []byte("a"), []byte("transfer everything")} {
		if !stded25519.Verify(identity, msg, sig) {
			t.Fatal("precondition: the standard library accepts the forgery")
		}
		ok, err := ed25519.Verifier{}.Verify(identity, msg, sig)
		if ok || !errors.Is(err, ed25519.ErrSmallOrder) {
			t.Errorf("msg=%q: ok=%v err=%v, want refusal", msg, ok, err)
		}
	}
}

func TestVerifier_Verify_SizeErrorsAreDistinctFromSmallOrder(t *testing.T) {
	kp, _ := ed25519.Generator{}.Generate()
	sig, _ := ed25519.Sign(kp.PrivateKey, []byte("m"))
	if _, err := (ed25519.Verifier{}).Verify(kp.PublicKey[:31], []byte("m"), sig); !errors.Is(err, ed25519.ErrPublicKeySize) || errors.Is(err, ed25519.ErrSmallOrder) {
		t.Errorf("short key: err=%v", err)
	}
	if _, err := (ed25519.Verifier{}).Verify(kp.PublicKey, []byte("m"), sig[:63]); !errors.Is(err, ed25519.ErrSignatureSize) || errors.Is(err, ed25519.ErrSmallOrder) {
		t.Errorf("short signature: err=%v", err)
	}
	if err := ed25519.ValidatePublicKey(nil); !errors.Is(err, ed25519.ErrPublicKeySize) {
		t.Errorf("ValidatePublicKey(nil): err=%v", err)
	}
}

func TestVerifier_Verify_RefusesSmallOrderR(t *testing.T) {
	kp, err := ed25519.Generator{}.Generate()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("message")
	sig, err := ed25519.Sign(kp.PrivateKey, msg)
	if err != nil {
		t.Fatal(err)
	}
	for _, pt := range torsion(t) {
		bad := append([]byte(nil), sig...)
		copy(bad[:32], encode(pt.y, 0))
		ok, err := ed25519.Verifier{}.Verify(kp.PublicKey, msg, bad)
		if ok || !errors.Is(err, ed25519.ErrSmallOrder) {
			t.Errorf("R y=%x: ok=%v err=%v", pt.y, ok, err)
		}
	}
}

func TestVerifier_Verify_StillVerifiesValidAndRejectsTamperedSignatures(t *testing.T) {
	kp, err := ed25519.Generator{}.Generate()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("message")
	sig, err := ed25519.Sign(kp.PrivateKey, msg)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := (ed25519.Verifier{}).Verify(kp.PublicKey, msg, sig); err != nil || !ok {
		t.Fatalf("valid signature: ok=%v err=%v", ok, err)
	}
	if ok, err := (ed25519.Verifier{}).Verify(kp.PublicKey, []byte("other"), sig); err != nil || ok {
		t.Fatalf("other message: ok=%v err=%v, want false, nil", ok, err)
	}
}

// RFC 8032 section 7.1, TEST 1 (empty message) and TEST 3 (two-byte message).
// The public key is derived from the RFC's secret key (and compared with the
// RFC's where given), and the RFC's signature must be both reproduced by Sign
// and accepted by Verify.
func TestVerifier_Verify_RFC8032Vectors(t *testing.T) {
	vectors := []struct{ secret, pub, msg, sig string }{
		{
			"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
			"",
			"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
				"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
		},
		{
			"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
			"",
			"af82",
			"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
				"18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
		},
	}
	for i, v := range vectors {
		priv := stded25519.NewKeyFromSeed(mustDecode(t, v.secret))
		pub := priv.Public().(stded25519.PublicKey)
		if v.pub != "" && hex.EncodeToString(pub) != v.pub {
			t.Fatalf("vector %d: derived public key %x, RFC says %s", i, pub, v.pub)
		}
		msg, sig := mustDecode(t, v.msg), mustDecode(t, v.sig)
		got, err := ed25519.Sign(priv, msg)
		if err != nil || hex.EncodeToString(got) != v.sig {
			t.Fatalf("vector %d: Sign = %x, err=%v", i, got, err)
		}
		if err := ed25519.ValidatePublicKey(pub); err != nil {
			t.Errorf("vector %d: public key refused: %v", i, err)
		}
		ok, err := ed25519.Verifier{}.Verify(pub, msg, sig)
		if err != nil || !ok {
			t.Errorf("vector %d: ok=%v err=%v", i, ok, err)
		}
	}
}

func mustDecode(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
