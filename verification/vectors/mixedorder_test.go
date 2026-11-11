package vectors_test

import (
	stded25519 "crypto/ed25519"
	"math/big"
	"slices"
	"testing"
)

// edwards25519 is the curve -x² + y² = 1 + d·x²·y² over p = 2^255 - 19, in
// the arithmetic of math/big: enough to tell whether an encoding is a point
// whose order divides 8, without the product's table of such encodings.
var edwards25519 = func() (c struct{ p, d, sqrtM1 *big.Int }) {
	c.p = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	inv := new(big.Int).ModInverse(big.NewInt(121666), c.p)
	c.d = new(big.Int).Mod(new(big.Int).Mul(big.NewInt(-121665), inv), c.p)
	c.sqrtM1 = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(c.p, big.NewInt(1)), 2), c.p)
	return c
}()

// decodePoint reads enc, a 32-byte encoding with y little-endian in its low
// 255 bits and the sign of x in the top bit. It reports the point, whether
// it is on the curve, and whether enc is its canonical encoding (y below p,
// and no sign on x = 0).
func decodePoint(enc []byte) (x, y *big.Int, onCurve, canonical bool) {
	c := edwards25519
	le := slices.Clone(enc)
	sign := le[31] >> 7
	le[31] &= 0x7f
	slices.Reverse(le)
	raw := new(big.Int).SetBytes(le)
	y = new(big.Int).Mod(raw, c.p)
	y2 := new(big.Int).Mul(y, y)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	v := new(big.Int).Add(new(big.Int).Mul(c.d, y2), big.NewInt(1))
	x2 := new(big.Int).Mod(new(big.Int).Mul(u, new(big.Int).ModInverse(v, c.p)), c.p)
	x = new(big.Int).Exp(x2, new(big.Int).Rsh(new(big.Int).Add(c.p, big.NewInt(3)), 3), c.p)
	if sq := new(big.Int).Mod(new(big.Int).Mul(x, x), c.p); sq.Cmp(x2) != 0 {
		x.Mod(x.Mul(x, c.sqrtM1), c.p)
		if sq.Mod(sq.Mul(x, x), c.p); sq.Cmp(x2) != 0 {
			return nil, nil, false, false
		}
	}
	return x, y, true, raw.Cmp(c.p) < 0 && !(x.Sign() == 0 && sign == 1)
}

// smallOrder reports whether enc, in any spelling of y and with either sign
// of x, is a point of the curve of order dividing 8: [8]P is the identity.
func smallOrder(enc []byte) bool {
	x, y, onCurve, _ := decodePoint(enc)
	if !onCurve {
		return false
	}
	for range 3 {
		x, y = double(x, y)
	}
	return x.Sign() == 0 && y.Cmp(big.NewInt(1)) == 0
}

// double is P + P by the twisted Edwards addition law (a = -1), complete on
// this curve.
func double(x, y *big.Int) (*big.Int, *big.Int) {
	c := edwards25519
	xy := new(big.Int).Mul(x, y)
	t := new(big.Int).Mod(new(big.Int).Mul(c.d, new(big.Int).Mul(xy, xy)), c.p)
	nx := new(big.Int).Mul(big.NewInt(2), xy)
	dx := new(big.Int).Add(big.NewInt(1), t)
	ny := new(big.Int).Add(new(big.Int).Mul(y, y), new(big.Int).Mul(x, x))
	dy := new(big.Int).Sub(big.NewInt(1), t)
	nx.Mod(nx.Mul(nx, new(big.Int).ModInverse(dx.Mod(dx, c.p), c.p)), c.p)
	ny.Mod(ny.Mul(ny, new(big.Int).ModInverse(dy.Mod(dy, c.p), c.p)), c.p)
	return nx, ny
}

// The curve arithmetic finds the points of small order it should (the
// identity, of order 2, 4 and 8, in another spelling or sign), and no other.
func TestSmallOrderByCurveArithmetic(t *testing.T) {
	enc := func(b0 byte, rest byte, top byte) []byte {
		e := make([]byte, 32)
		for i := range e {
			e[i] = rest
		}
		e[0], e[31] = b0, top
		return e
	}
	for name, c := range map[string]struct {
		enc   []byte
		small bool
	}{
		"identity, y = 1":         {enc(0x01, 0x00, 0x00), true},
		"order 8, y = 26e8958f…":  {unhex(t, "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), true},
		"order 8, y = c7176a70…":  {unhex(t, "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), true},
		"order 8, the other sign": {unhex(t, "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"), true},
		"off the curve, y = 2":    {enc(0x02, 0x00, 0x00), false},
		"order 2, y = p - 1":      {enc(0xec, 0xff, 0x7f), true},
		"identity, y = p + 1":     {enc(0xee, 0xff, 0x7f), true},
		"order 4, y = 0":          {enc(0x00, 0x00, 0x00), true},
		"the base point, y = 4/5": {[]byte{0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66}, false},
	} {
		if got := smallOrder(c.enc); got != c.small {
			t.Errorf("%s: small order %v, want %v", name, got, c.small)
		}
	}
}

// Every Ed25519 vector's outcome is what the product's contract gives,
// derived without the product: a key of 32 bytes that is the canonical
// encoding of a point on the curve, not of small order; a signature of 64
// bytes whose R is not a point of small order; and the standard library's
// verdict on the rest. The table's rows, the mixed-order ones among them, and
// every vector's own outcome must agree with it.
func TestWycheproofEd25519RowsFollowFromTheStandardLibraryAndTheCurve(t *testing.T) {
	const file = "ed25519_test.json"
	f := loadWycheproof(t, file)
	rows := loadWycheproofExpected(t)[file]
	var mixed, mixedListed, byTheCurve int
	for _, g := range f.TestGroups {
		pk := unhex(t, g.PublicKey.Pk)
		_, _, onCurve, canonical := decodePoint(pk)
		keyOK := len(pk) == stded25519.PublicKeySize && onCurve && canonical && !smallOrder(pk)
		for _, tc := range g.Tests {
			msg, sig := unhex(t, tc.Msg), unhex(t, tc.Sig)
			stdlib := len(pk) == stded25519.PublicKeySize && stded25519.Verify(pk, msg, sig)
			derived := "refuse"
			if keyOK && len(sig) == stded25519.SignatureSize && !smallOrder(sig[:32]) && stdlib {
				derived = "accept"
			}
			if stdlib && derived == "refuse" {
				byTheCurve++
			}
			want := map[string]string{"valid": "accept", "invalid": "refuse"}[tc.Result]
			row, listed := rows[tc.TcID]
			if listed {
				want = row.outcome
			}
			if slices.Contains(tc.Flags, "MixedOrderPublicKey") {
				mixed++
				if listed {
					mixedListed++
				}
			}
			if derived != want {
				t.Errorf("tcId %d (%s %v, %s): derived %s, the table or the vector says %s", tc.TcID, tc.Comment, tc.Flags, tc.Result, derived, want)
			}
		}
	}
	if mixed != 22 || mixedListed != 21 {
		t.Errorf("%d vectors flagged MixedOrderPublicKey, %d of them listed; recorded 22 and 21", mixed, mixedListed)
	}
	if byTheCurve == 0 {
		t.Error("the curve's arithmetic refused no vector the standard library accepts: it decides nothing")
	}
	t.Logf("%d vectors the standard library accepts are refused by the curve's arithmetic", byTheCurve)
}
