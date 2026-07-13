package vc

import (
	"testing"

	"github.com/provin-line/oss/canon/jcs"
)

// The Phase-1 MUST suite is registered by init().
func TestRegisterCryptosuite_JCSRegisteredAtInit(t *testing.T) {
	if _, err := canonicalizerFor(CryptosuiteEdDSAJCS2022); err != nil {
		t.Errorf("eddsa-jcs-2022 must be registered at init: %v", err)
	}
}

// The Phase-2 suite is registered by init() after passing the expansion
// probe, backed by URDNA2015.
func TestRegisterCryptosuite_RDFCRegisteredAtInit(t *testing.T) {
	c, err := canonicalizerFor(CryptosuiteEdDSARDFC2022)
	if err != nil {
		t.Fatalf("eddsa-rdfc-2022 must be registered at init: %v", err)
	}
	if got := c.Name(); got != "urdna2015" {
		t.Errorf("eddsa-rdfc-2022 canonicalizer = %q, want urdna2015", got)
	}
}

func TestCanonicalizerFor_Unknown(t *testing.T) {
	if _, err := canonicalizerFor("eddsa-nonexistent-9999"); err == nil {
		t.Error("unregistered cryptosuite: want error")
	}
}

func TestCanonicalizerFor_NoOpRejected(t *testing.T) {
	for _, name := range []string{"", "none", "null", "identity"} {
		if _, err := canonicalizerFor(name); err == nil {
			t.Errorf("no-op cryptosuite %q: want error (alg:none defense)", name)
		}
	}
}

func TestRegisterCryptosuite_NoOpPanics(t *testing.T) {
	for _, name := range []string{"", "none", "null", "identity"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("RegisterCryptosuite(%q) must panic (alg:none defense)", name)
				}
			}()
			RegisterCryptosuite(name, jcs.Canonicalizer{})
		}()
	}
}

func TestRegisterCryptosuite_NilCanonicalizerPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("RegisterCryptosuite with a nil canonicalizer must panic")
		}
	}()
	RegisterCryptosuite("eddsa-test-nilcanon", nil)
}

// Re-registering a name must panic — a late registration must not be able to
// swap the canonicalizer under an already-trusted suite. Uses the suite that
// init() already registered, so the test is idempotent across -count=N (it does
// not leak a new permanent registry entry).
func TestRegisterCryptosuite_DuplicateRejected(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("re-registering an existing cryptosuite must panic")
		}
	}()
	RegisterCryptosuite(CryptosuiteEdDSAJCS2022, jcs.Canonicalizer{})
}
