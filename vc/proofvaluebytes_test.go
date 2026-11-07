package vc_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/multibase"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// ProofValueBytes returns the bytes a proof's proofValue encodes (for
// eddsa-jcs-2022, the signature), without verifying them.
func TestDataIntegrityProof_ProofValueBytes(t *testing.T) {
	signer, _, doc := fixture(t)
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	sig, err := proof.ProofValueBytes()
	if err != nil {
		t.Fatalf("ProofValueBytes: %v", err)
	}
	if len(sig) != 64 || multibase.EncodeBase58Btc(sig) != proof.ProofValue {
		t.Errorf("ProofValueBytes = %d bytes that encode to %q, want the 64 bytes of %q", len(sig), multibase.EncodeBase58Btc(sig), proof.ProofValue)
	}
	// Each call returns bytes of its own.
	sig[0] ^= 0xff
	if again, _ := proof.ProofValueBytes(); bytes.Equal(sig, again) {
		t.Error("a change to the returned bytes reached the next call")
	}

	for name, value := range map[string]string{
		"not base58btc":                 "not base58btc",
		"a character base58 leaves out": "z0OIl",
		"longer than multibase allows":  "z" + strings.Repeat("1", 8193),
	} {
		bad := *proof
		bad.ProofValue = value
		if _, err := bad.ProofValueBytes(); err == nil || !strings.HasPrefix(err.Error(), "vc: decode proofValue: ") {
			t.Errorf("%s: err = %v, want a decode error", name, err)
		}
	}
	var none *vc.DataIntegrityProof
	if _, err := none.ProofValueBytes(); err == nil {
		t.Error("a nil proof gave bytes")
	}
}

// A proofValue that does not decode fails signer authenticity before the
// issuer's key is looked up: no key can verify it, so a lookup that cannot
// answer now does not make the verdict indeterminate.
func TestSignerAuthenticity_UndecodableProofValueFailsBeforeTheKeyLookup(t *testing.T) {
	// A genuine proof with a lookup that cannot answer is indeterminate.
	cred, _ := exampleCredential(t, issuerDID, nil)
	if state, s, l := verifyWithLookupsThatCannotAnswer(t, cred); state != vc.ConfidenceIndeterminate || s.keyCalls != 1 || l.calls != 1 {
		t.Fatalf("a genuine proof with a transient lookup error: State = %v after %d key and %d lifecycle lookups, want Indeterminate after 1 and 1", state, s.keyCalls, l.calls)
	}

	cred, _ = exampleCredential(t, issuerDID, func(m map[string]any) {
		m["proof"].(map[string]any)["proofValue"] = "not base58btc"
	})
	if state, s, l := verifyWithLookupsThatCannotAnswer(t, cred); state != vc.ConfidenceFailed || s.keyCalls != 0 || l.calls != 0 {
		t.Errorf("State = %v after %d key and %d lifecycle lookups, want Failed after 0 and 0", state, s.keyCalls, l.calls)
	}
}

// A proof whose cryptosuite no claim contract names verifies under no key
// either: it fails signer authenticity before any lookup.
func TestSignerAuthenticity_CryptosuiteWithoutAContractFailsBeforeTheKeyLookup(t *testing.T) {
	cred, _ := exampleCredential(t, issuerDID, func(m map[string]any) {
		m["proof"].(map[string]any)["cryptosuite"] = "ecdsa-rdfc-2019"
	})
	if state, s, l := verifyWithLookupsThatCannotAnswer(t, cred); state != vc.ConfidenceFailed || s.keyCalls != 0 || l.calls != 0 {
		t.Errorf("State = %v after %d key and %d lifecycle lookups, want Failed after 0 and 0", state, s.keyCalls, l.calls)
	}
}

// verifyWithLookupsThatCannotAnswer runs signer authenticity with an issuer
// verifier whose key lookup fails transiently and a lifecycle registry that
// answers Active, and returns the verdict with both, to count their lookups.
func verifyWithLookupsThatCannotAnswer(t *testing.T, cred *vc.Credential) (vc.ConfidenceState, *stageIssuers, *countingLifecycle) {
	t.Helper()
	s := &stageIssuers{keyErr: errors.New("registry unreachable")}
	l := &countingLifecycle{}
	v := vc.NewVerifier(local.New(), ed25519Verifier(), vc.WithIssuerVerifier(s), vc.WithLifecycleRegistry(l))
	res, err := v.VerifySignerAuthenticity(context.Background(), cred)
	if err != nil {
		t.Fatal(err)
	}
	return res.State, s, l
}

// countingLifecycle answers every suite Active and counts the lookups.
type countingLifecycle struct{ calls int }

func (l *countingLifecycle) PhaseAt(context.Context, string, time.Time) (vc.LifecyclePhase, error) {
	l.calls++
	return vc.PhaseActive, nil
}

func (l *countingLifecycle) Entries(context.Context, string) ([]vc.LifecycleEntry, error) {
	return nil, nil
}
