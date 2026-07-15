package core_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/core"
)

// LoadServerTLS is the boot preflight (P0-6 closure #2/#3): it loads and
// validates the certificate pair BEFORE any side-effectful boot work, pins the
// TLS 1.2 floor explicitly, and returns a config carrying the loaded pair so
// serving reuses exactly the bytes that were validated — a re-read at serve
// time would reopen the TOCTOU the preflight exists to close.

func TestLoadServerTLS_PinsTheFloorAndCarriesThePair(t *testing.T) {
	certFile, keyFile := writeSelfSignedCertCore(t)
	c := core.TLSConfig{CertFile: certFile, KeyFile: keyFile}
	conf, err := c.LoadServerTLS()
	if err != nil {
		t.Fatalf("LoadServerTLS: %v", err)
	}
	if conf.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want explicit tls.VersionTLS12 — the floor is a pinned contract, not a library default", conf.MinVersion)
	}
	if len(conf.Certificates) != 1 {
		t.Errorf("Certificates = %d entries, want the preloaded pair", len(conf.Certificates))
	}
}

func TestLoadServerTLS_CleartextPostureIsNil(t *testing.T) {
	conf, err := core.TLSConfig{}.LoadServerTLS()
	if err != nil {
		t.Fatalf("LoadServerTLS on cleartext posture: %v", err)
	}
	if conf != nil {
		t.Error("cleartext posture returned a TLS config")
	}
}

func TestLoadServerTLS_FailsClosedOnBadMaterial(t *testing.T) {
	certFile, keyFile := writeSelfSignedCertCore(t)
	otherCert, _ := writeSelfSignedCertCore(t)
	dir := t.TempDir()
	invalidPEM := filepath.Join(dir, "invalid.pem")
	if err := os.WriteFile(invalidPEM, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		c    core.TLSConfig
	}{
		{"unreadable cert", core.TLSConfig{CertFile: filepath.Join(dir, "missing.pem"), KeyFile: keyFile}},
		{"unreadable key", core.TLSConfig{CertFile: certFile, KeyFile: filepath.Join(dir, "missing.key")}},
		{"invalid PEM", core.TLSConfig{CertFile: invalidPEM, KeyFile: keyFile}},
		{"mismatched pair", core.TLSConfig{CertFile: otherCert, KeyFile: keyFile}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.c.LoadServerTLS(); err == nil {
				t.Error("bad material loaded — the boot would have started serving on it")
			}
		})
	}
}

func TestLoadServerTLS_EnforcesTheFloorOnTheWire(t *testing.T) {
	// The ledger's own acceptance shape: 1.0/1.1 handshake failure, 1.2/1.3
	// success, negotiated version at or above the floor.
	certFile, keyFile := writeSelfSignedCertCore(t)
	conf, err := core.TLSConfig{CertFile: certFile, KeyFile: keyFile}.LoadServerTLS()
	if err != nil {
		t.Fatalf("LoadServerTLS: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", conf)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()

	dial := func(maxVersion uint16) (*tls.Conn, error) {
		return tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			InsecureSkipVerify: true, // the floor is under test, not the chain
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         maxVersion,
		})
	}

	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		if conn, err := dial(v); err == nil {
			conn.Close()
			t.Errorf("handshake at %x succeeded below the floor", v)
		}
	}
	for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		conn, err := dial(v)
		if err != nil {
			t.Errorf("handshake at %x failed: %v", v, err)
			continue
		}
		if got := conn.ConnectionState().Version; got < tls.VersionTLS12 {
			t.Errorf("negotiated %x, below the floor", got)
		}
		conn.Close()
	}
}

// writeSelfSignedCertCore mirrors the standalone test helper: a minimal
// self-signed Ed25519 server certificate for 127.0.0.1.
func writeSelfSignedCertCore(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
