package rs256_test

import (
	stdcrypto "crypto"
	"crypto/rand"
	stdrsa "crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/rs256"
)

var _ crypto.Verifier = rs256.Verifier{}

// The sentinels are constants: these lines stop compiling if one is not.
const (
	_ = rs256.ErrInvalidPublicKey
	_ = rs256.ErrModulusSize
	_ = rs256.ErrSignatureSize
	_ = rs256.ErrInvalidSignature
)

var (
	keysOnce sync.Once
	keys     map[int]*stdrsa.PrivateKey
)

func key(t *testing.T, bits int) *stdrsa.PrivateKey {
	t.Helper()
	keysOnce.Do(func() {
		keys = map[int]*stdrsa.PrivateKey{}
		for _, b := range []int{2048, 4096} {
			k, err := stdrsa.GenerateKey(rand.Reader, b)
			if err != nil {
				panic(err)
			}
			keys[b] = k
		}
	})
	return keys[bits]
}

func sign(t *testing.T, k *stdrsa.PrivateKey, data []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(data)
	sig, err := stdrsa.SignPKCS1v15(rand.Reader, k, stdcrypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifier_Algorithm(t *testing.T) {
	if got := (rs256.Verifier{}).Algorithm(); got != "RS256" {
		t.Fatalf("Algorithm() = %q", got)
	}
}

// RFC 7515 appendix A.2: the example RS256 JWS and its key.
func TestVerifier_RFC7515Example(t *testing.T) {
	n := b64(t, "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ")
	e := new(big.Int).SetBytes(b64(t, "AQAB"))
	pub := x509.MarshalPKCS1PublicKey(&stdrsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(e.Int64())})
	input := []byte("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ")
	sig := b64(t, "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw")
	if ok, err := (rs256.Verifier{}).Verify(pub, input, sig); err != nil || !ok {
		t.Fatalf("Verify = %v, %v; want true, nil", ok, err)
	}
	input[len(input)-1] ^= 1
	if ok, err := (rs256.Verifier{}).Verify(pub, input, sig); err != nil || ok {
		t.Fatalf("Verify of altered input = %v, %v; want false, nil", ok, err)
	}
}

func TestVerifier_RoundTrip(t *testing.T) {
	for _, bits := range []int{2048, 4096} {
		k := key(t, bits)
		pub := x509.MarshalPKCS1PublicKey(&k.PublicKey)
		data := []byte("operation bytes")
		sig := sign(t, k, data)
		ok, err := rs256.Verifier{}.Verify(pub, data, sig)
		if err != nil || !ok {
			t.Fatalf("%d bits: Verify = %v, %v; want true, nil", bits, ok, err)
		}
		ok, err = rs256.Verifier{}.Verify(pub, []byte("other bytes"), sig)
		if err != nil || ok {
			t.Fatalf("%d bits: Verify of other data = %v, %v; want false, nil", bits, ok, err)
		}
		tampered := append([]byte(nil), sig...)
		tampered[len(tampered)/2] ^= 1
		if ok, err := (rs256.Verifier{}).Verify(pub, data, tampered); err != nil || ok {
			t.Fatalf("%d bits: Verify of a tampered signature = %v, %v; want false, nil", bits, ok, err)
		}
	}
	other := x509.MarshalPKCS1PublicKey(&key(t, 4096).PublicKey)
	sig := sign(t, key(t, 2048), []byte("d"))
	if ok, err := (rs256.Verifier{}).Verify(other, []byte("d"), append(make([]byte, 256), sig...)); err != nil || ok {
		t.Fatalf("Verify under another key = %v, %v; want false, nil", ok, err)
	}
}

// fakeKey is a PKCS #1 public key with an n of the given bit length; no
// private key exists for it, so the size checks are tested without generating
// large keys.
func fakeKey(bits int) []byte {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1)) // odd, with its top bit set
	return x509.MarshalPKCS1PublicKey(&stdrsa.PublicKey{N: n, E: 65537})
}

func TestValidatePublicKey(t *testing.T) {
	k := key(t, 2048)
	pub := x509.MarshalPKCS1PublicKey(&k.PublicKey)
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	even := new(big.Int).Sub(k.N, big.NewInt(1))
	// The same SEQUENCE with its length in the long form of one more byte
	// than needed: BER, not DER. encoding/asn1 refuses it already; the check
	// that re-encodes the key and compares is a second line behind it.
	longLength := append([]byte{0x30, 0x83, 0x00}, pub[2:]...)
	refused := []struct {
		name string
		key  []byte
		want error
	}{
		{"empty", nil, rs256.ErrInvalidPublicKey},
		{"SubjectPublicKeyInfo", spki, rs256.ErrInvalidPublicKey},
		{"trailing byte", append(append([]byte(nil), pub...), 0), rs256.ErrInvalidPublicKey},
		{"length not in the shortest form", longLength, rs256.ErrInvalidPublicKey},
		{"even modulus", x509.MarshalPKCS1PublicKey(&stdrsa.PublicKey{N: even, E: 65537}), rs256.ErrInvalidPublicKey},
		{"even exponent", x509.MarshalPKCS1PublicKey(&stdrsa.PublicKey{N: k.N, E: 65536}), rs256.ErrInvalidPublicKey},
		{"exponent one", x509.MarshalPKCS1PublicKey(&stdrsa.PublicKey{N: k.N, E: 1}), rs256.ErrInvalidPublicKey},
		{"2047 bits", fakeKey(2047), rs256.ErrModulusSize},
		{"1024 bits", fakeKey(1024), rs256.ErrModulusSize},
		{"4097 bits", fakeKey(4097), rs256.ErrModulusSize},
		{"8192 bits", fakeKey(8192), rs256.ErrModulusSize},
		{"a megabyte", make([]byte, 1<<20), rs256.ErrModulusSize},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			if err := rs256.ValidatePublicKey(c.key); !errors.Is(err, c.want) {
				t.Fatalf("ValidatePublicKey = %v, want %v", err, c.want)
			}
			ok, err := rs256.Verifier{}.Verify(c.key, []byte("d"), make([]byte, 256))
			if ok || !errors.Is(err, c.want) {
				t.Fatalf("Verify = %v, %v; want false, %v", ok, err, c.want)
			}
		})
	}
	for _, accepted := range [][]byte{fakeKey(2048), fakeKey(4096), x509.MarshalPKCS1PublicKey(&stdrsa.PublicKey{N: k.N, E: 3})} {
		if err := rs256.ValidatePublicKey(accepted); err != nil {
			t.Fatalf("ValidatePublicKey = %v", err)
		}
	}
}

func TestVerifier_SignatureRefused(t *testing.T) {
	k := key(t, 2048)
	pub := x509.MarshalPKCS1PublicKey(&k.PublicKey)
	data := []byte("operation bytes")
	sig := sign(t, k, data)
	cases := []struct {
		name string
		sig  []byte
		want error
	}{
		{"empty", nil, rs256.ErrSignatureSize},
		{"one byte short", sig[:255], rs256.ErrSignatureSize},
		{"one byte long", append([]byte{0}, sig...), rs256.ErrSignatureSize},
		{"equal to the modulus", k.N.FillBytes(make([]byte, 256)), rs256.ErrInvalidSignature},
		{"all ones", bytesOf(0xff, 256), rs256.ErrInvalidSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, err := rs256.Verifier{}.Verify(pub, data, c.sig)
			if ok || !errors.Is(err, c.want) {
				t.Fatalf("Verify = %v, %v; want false, %v", ok, err, c.want)
			}
		})
	}
	below := new(big.Int).Sub(k.N, big.NewInt(1)).FillBytes(make([]byte, 256))
	if ok, err := (rs256.Verifier{}).Verify(pub, data, below); ok || err != nil {
		t.Fatalf("Verify of n-1 = %v, %v; want false, nil", ok, err)
	}
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
