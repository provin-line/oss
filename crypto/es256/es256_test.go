package es256_test

import (
	stdecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/es256"
)

var _ crypto.Verifier = es256.Verifier{}

// The sentinels are constants: these lines stop compiling if one is not.
const (
	_ = es256.ErrPublicKeySize
	_ = es256.ErrInvalidPoint
	_ = es256.ErrSignatureSize
	_ = es256.ErrInvalidSignature
)

// curveN is the order of the P-256 base point.
var curveN = elliptic.P256().Params().N

func newKey(t *testing.T) (*stdecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := stdecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func raw(r, s *big.Int) []byte {
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

func sign(t *testing.T, priv *stdecdsa.PrivateKey, data []byte) (r, s *big.Int) {
	t.Helper()
	sum := sha256.Sum256(data)
	r, s, err := stdecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return r, s
}

func TestVerifier_Algorithm(t *testing.T) {
	if got := (es256.Verifier{}).Algorithm(); got != "ES256" {
		t.Fatalf("Algorithm() = %q", got)
	}
}

// RFC 7515 appendix A.3: the example ES256 JWS and its key.
func TestVerifier_RFC7515Example(t *testing.T) {
	b64 := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	pub := append(append([]byte{0x04}, b64("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")...), b64("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")...)
	input := []byte("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ")
	sig := b64("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q")
	if ok, err := (es256.Verifier{}).Verify(pub, input, sig); err != nil || !ok {
		t.Fatalf("Verify = %v, %v; want true, nil", ok, err)
	}
	swapped := append(append([]byte(nil), sig[32:]...), sig[:32]...)
	if ok, err := (es256.Verifier{}).Verify(pub, input, swapped); err != nil || ok {
		t.Fatalf("Verify with s || r = %v, %v; want false, nil", ok, err)
	}
}

func TestVerifier_RoundTrip(t *testing.T) {
	priv, pub := newKey(t)
	data := []byte("operation bytes")
	r, s := sign(t, priv, data)
	ok, err := es256.Verifier{}.Verify(pub, data, raw(r, s))
	if err != nil || !ok {
		t.Fatalf("Verify = %v, %v; want true, nil", ok, err)
	}
	ok, err = es256.Verifier{}.Verify(pub, []byte("other bytes"), raw(r, s))
	if err != nil || ok {
		t.Fatalf("Verify of other data = %v, %v; want false, nil", ok, err)
	}
	_, other := newKey(t)
	ok, err = es256.Verifier{}.Verify(other, data, raw(r, s))
	if err != nil || ok {
		t.Fatalf("Verify under another key = %v, %v; want false, nil", ok, err)
	}
}

// The signature bytes of a message are not unique: (r, n-s) verifies as well
// as (r, s). Nothing may count signatures by their bytes.
func TestVerifier_SignatureBytesAreNotUnique(t *testing.T) {
	priv, pub := newKey(t)
	data := []byte("operation bytes")
	r, s := sign(t, priv, data)
	flipped := new(big.Int).Sub(curveN, s)
	for _, sig := range [][]byte{raw(r, s), raw(r, flipped)} {
		ok, err := es256.Verifier{}.Verify(pub, data, sig)
		if err != nil || !ok {
			t.Fatalf("Verify = %v, %v; want true, nil", ok, err)
		}
	}
}

func TestValidatePublicKey(t *testing.T) {
	_, pub := newKey(t)
	x := new(big.Int).SetBytes(pub[1:33])
	y := new(big.Int).SetBytes(pub[33:])
	point := func(prefix byte, x, y *big.Int) []byte {
		b := make([]byte, 65)
		b[0] = prefix
		x.FillBytes(b[1:33])
		y.FillBytes(b[33:])
		return b
	}
	p := elliptic.P256().Params().P
	compressed := append([]byte{0x02 | byte(y.Bit(0))}, pub[1:33]...)
	// (5, fiveY) is on P-256: y^2 = x^3 - 3x + b has a root for x = 5.
	five := big.NewInt(5)
	rhs := new(big.Int).Exp(five, big.NewInt(3), p)
	rhs.Sub(rhs, big.NewInt(15)).Add(rhs, elliptic.P256().Params().B).Mod(rhs, p)
	fiveY := new(big.Int).ModSqrt(rhs, p)
	if fiveY == nil {
		t.Fatal("x = 5 is not on P-256")
	}
	if err := es256.ValidatePublicKey(point(0x04, five, fiveY)); err != nil {
		t.Fatalf("ValidatePublicKey of (5, y) = %v", err)
	}
	cases := []struct {
		name string
		key  []byte
		want error
	}{
		{"empty", nil, es256.ErrPublicKeySize},
		{"the point at infinity (SEC1 0x00)", []byte{0x00}, es256.ErrPublicKeySize},
		{"compressed", compressed, es256.ErrPublicKeySize},
		{"one byte short", pub[:64], es256.ErrPublicKeySize},
		{"one byte long", append(append([]byte(nil), pub...), 0), es256.ErrPublicKeySize},
		{"hybrid prefix", point(0x06|byte(y.Bit(0)), x, y), es256.ErrInvalidPoint},
		{"compressed prefix on 65 bytes", point(0x02, x, y), es256.ErrInvalidPoint},
		{"zero coordinates", point(0x04, big.NewInt(0), big.NewInt(0)), es256.ErrInvalidPoint},
		{"off the curve", point(0x04, x, new(big.Int).Add(y, big.NewInt(1))), es256.ErrInvalidPoint},
		{"x not reduced (a point on the curve, x written as x + p)", point(0x04, new(big.Int).Add(five, p), fiveY), es256.ErrInvalidPoint},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := es256.ValidatePublicKey(c.key); !errors.Is(err, c.want) {
				t.Fatalf("ValidatePublicKey = %v, want %v", err, c.want)
			}
			ok, err := es256.Verifier{}.Verify(c.key, []byte("d"), make([]byte, 64))
			if ok || !errors.Is(err, c.want) {
				t.Fatalf("Verify = %v, %v; want false, %v", ok, err, c.want)
			}
		})
	}
	if err := es256.ValidatePublicKey(pub); err != nil {
		t.Fatalf("ValidatePublicKey of a valid key = %v", err)
	}
}

func TestVerifier_SignatureRefused(t *testing.T) {
	priv, pub := newKey(t)
	data := []byte("operation bytes")
	r, s := sign(t, priv, data)
	der, err := stdecdsa.SignASN1(rand.Reader, priv, func() []byte { h := sha256.Sum256(data); return h[:] }())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		sig  []byte
		want error
	}{
		{"empty", nil, es256.ErrSignatureSize},
		{"ASN.1 DER", der, es256.ErrSignatureSize},
		{"one byte short", raw(r, s)[:63], es256.ErrSignatureSize},
		{"one byte long", append(raw(r, s), 0), es256.ErrSignatureSize},
		{"r zero", raw(big.NewInt(0), s), es256.ErrInvalidSignature},
		{"s zero", raw(r, big.NewInt(0)), es256.ErrInvalidSignature},
		{"r equal to n", raw(curveN, s), es256.ErrInvalidSignature},
		{"s above n", raw(r, new(big.Int).Add(curveN, big.NewInt(1))), es256.ErrInvalidSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, err := es256.Verifier{}.Verify(pub, data, c.sig)
			if ok || !errors.Is(err, c.want) {
				t.Fatalf("Verify = %v, %v; want false, %v", ok, err, c.want)
			}
		})
	}
}

// r and s just below n are in range: a wrong signature is a non-match.
func TestVerifier_RangeEdgeIsANonMatch(t *testing.T) {
	_, pub := newKey(t)
	top := new(big.Int).Sub(curveN, big.NewInt(1))
	if ok, err := (es256.Verifier{}).Verify(pub, []byte("d"), raw(top, top)); ok || err != nil {
		t.Fatalf("Verify = %v, %v; want false, nil", ok, err)
	}
}
