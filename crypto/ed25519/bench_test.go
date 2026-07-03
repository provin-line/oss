package ed25519

import (
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"testing"
)

// Paper 04 §6.2 Table 4 (BENCH-RETAKE on provin): Ed25519 sign/verify latency across payload
// sizes. Cryptographic work only — keystore/network/serialization excluded (§6 preamble), so
// signing is benched over the raw primitive provin's Signer.Sign delegates to (stdlib
// crypto/ed25519), and verification over provin's pure Verifier (no keystore, no resolver).

var benchSizes = []struct {
	name string
	n    int
}{
	{"256B", 256},
	{"1KB", 1024},
	{"4KB", 4096},
}

func benchPayload(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

var (
	sinkSig  []byte
	sinkBool bool
)

func BenchmarkSign(b *testing.B) {
	kp, err := (Generator{}).Generate()
	if err != nil {
		b.Fatalf("keygen: %v", err)
	}
	priv := stded25519.PrivateKey(kp.PrivateKey)
	for _, sz := range benchSizes {
		data := benchPayload(sz.n)
		b.Run(sz.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(sz.n))
			for i := 0; i < b.N; i++ {
				sinkSig = stded25519.Sign(priv, data)
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	kp, err := (Generator{}).Generate()
	if err != nil {
		b.Fatalf("keygen: %v", err)
	}
	priv := stded25519.PrivateKey(kp.PrivateKey)
	v := Verifier{}
	for _, sz := range benchSizes {
		data := benchPayload(sz.n)
		sig := stded25519.Sign(priv, data)
		b.Run(sz.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(sz.n))
			for i := 0; i < b.N; i++ {
				ok, err := v.Verify(kp.PublicKey, data, sig)
				if err != nil || !ok {
					b.Fatalf("verify: ok=%v err=%v", ok, err)
				}
				sinkBool = ok
			}
		})
	}
}
