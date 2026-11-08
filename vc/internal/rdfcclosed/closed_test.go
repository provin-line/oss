// Package rdfcclosed tests a process that has not called
// vc.RegisterEdDSARDFC2022: it holds only tests, so its test binary registers
// nothing but what package vc registers itself.
package rdfcclosed

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/provin-line/oss/canon/urdna2015"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/multibase"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

const (
	issuerDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1"
	ownerDID  = "did:dplaax:poc.dplaax.dev:org:acme"
	keyID     = "signing"
	vmID      = issuerDID + "#" + keyID
)

type signer struct{ priv []byte }

// countingResolver is a resolver that is down: it counts the lookups and
// fails each as a transient error.
type countingResolver struct{ calls int }

func (r *countingResolver) Resolve(context.Context, string) (*did.DIDDocument, error) {
	r.calls++
	return nil, errors.New("resolver down")
}

func (s signer) Sign(_, _ string, data []byte) ([]byte, error) { return ed25519.Sign(s.priv, data) }

func subject() vc.CredentialSubjectFields {
	return vc.CredentialSubjectFields{
		PipelineID:          "p1",
		ProcessID:           "proc1",
		TransformationClaim: vc.ClaimConvert,
		InputHash:           "sha256:" + strings.Repeat("ab", 32),
		OutputHash:          "sha256:" + strings.Repeat("cd", 32),
	}
}

// rdfcProof signs body under eddsa-rdfc-2022 without vc's registry:
// SHA-256(canon(proof config)) ‖ SHA-256(canon(body)), canonicalized by
// urdna2015 over the contexts vc serves.
func rdfcProof(t *testing.T, kp *crypto.KeyPair, body map[string]any) *vc.DataIntegrityProof {
	t.Helper()
	c := urdna2015.NewCanonicalizer(map[string][]byte{
		vc.ContextCredentialsV2: vc.ContextCredentialsV2Document(),
		vc.ContextDplaaxVCV1:    vc.ContextDplaaxVCV1Document(),
		vc.ContextProvinVCV1:    vc.ContextProvinVCV1Document(),
	})
	proof := &vc.DataIntegrityProof{
		Context:            body["@context"],
		Type:               "DataIntegrityProof",
		Cryptosuite:        vc.CryptosuiteEdDSARDFC2022,
		VerificationMethod: vmID,
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC().Format(time.RFC3339),
	}
	config := map[string]any{
		"@context": proof.Context, "type": proof.Type, "cryptosuite": proof.Cryptosuite,
		"verificationMethod": proof.VerificationMethod, "proofPurpose": proof.ProofPurpose, "created": proof.Created,
	}
	var hashData []byte
	for _, v := range []map[string]any{config, body} {
		b, err := c.Canonicalize(v)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		hashData = append(hashData, sum[:]...)
	}
	sig, err := ed25519.Sign(kp.PrivateKey, hashData)
	if err != nil {
		t.Fatal(err)
	}
	proof.ProofValue = multibase.EncodeBase58Btc(sig)
	return proof
}

// childEnv marks the process TestRDFC_RefusedUntilRegistered runs its checks
// in: registering the suite cannot be undone, so each run of the test starts
// a process of its own (go test -count=N reuses one).
const childEnv = "RDFCCLOSED_CHILD"

// Until vc.RegisterEdDSARDFC2022 is called, every entry point that issues or
// verifies refuses eddsa-rdfc-2022, naming the function; once it is called
// (here from several goroutines at once), the same proof verifies and the
// suite issues.
func TestRDFC_RefusedUntilRegistered(t *testing.T) {
	if os.Getenv(childEnv) == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "--- PASS: "+t.Name()) {
			t.Fatalf("the check in a process of its own did not pass: %v\n%s", err, out)
		}
		return
	}
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	cred, err := vc.New(vc.CredentialFields{Issuer: issuerDID, ValidFrom: time.Now().UTC(), Subject: subject()})
	if err != nil {
		t.Fatal(err)
	}
	body := cred.Body()
	proof := rdfcProof(t, kp, body)
	wire := map[string]any{}
	for k, v := range body {
		wire[k] = v
	}
	wire["proof"] = proof
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var signed vc.PipelinePassCredential
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}
	vm, err := did.NewMultikeyVerificationMethod(vmID, issuerDID, kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	r := local.New()
	r.Add(did.New(did.DocumentFields{Context: did.IssuedDocumentContexts(), ID: issuerDID, Controller: ownerDID, VerificationMethod: []did.VerificationMethod{vm}, AssertionMethod: []string{vmID}}))
	r.Add(did.New(did.DocumentFields{Context: did.IssuedDocumentContexts(), ID: ownerDID, Controller: ownerDID}))
	verifier := vc.NewVerifier(r, ed25519.Verifier{})

	entryPoints := map[string]func() error{
		"CreateProof": func() error {
			_, err := vc.CreateProof(signer{kp.PrivateKey}, issuerDID, keyID, vmID, body, vc.CryptosuiteEdDSARDFC2022)
			return err
		},
		"Builder": func() error {
			_, err := vc.NewBuilder(signer{kp.PrivateKey}, vc.WithCryptosuite(vc.CryptosuiteEdDSARDFC2022)).BuildFirstDrop(issuerDID, keyID, vmID, subject(), nil)
			return err
		},
		"VerifyProof": func() error {
			return vc.VerifyProof(ed25519.Verifier{}, kp.PublicKey, proof, body)
		},
		"VerifyProofUnderContract": func() error {
			return vc.VerifyProofUnderContract(ed25519.Verifier{}, kp.PublicKey, proof, body, vc.ContractW3CEdDSARDFC2022)
		},
		"VerifyProofWithContract": func() error {
			_, err := vc.VerifyProofWithContract(ed25519.Verifier{}, kp.PublicKey, did.EncodingMultikey, proof, body)
			return err
		},
	}
	for name, f := range entryPoints {
		if err := f(); !errors.Is(err, vc.ErrCryptosuiteNotRegistered) || !strings.Contains(err.Error(), "vc.RegisterEdDSARDFC2022") {
			t.Errorf("%s before registering: %v, want vc.ErrCryptosuiteNotRegistered naming vc.RegisterEdDSARDFC2022", name, err)
		}
	}
	// The verify functions refuse the suite before reading anything else of
	// the proof or the document.
	noContext := map[string]any{}
	for k, v := range body {
		if k != "@context" {
			noContext[k] = v
		}
	}
	for name, err := range map[string]error{
		"VerifyProofUnderContract, a document without @context": vc.VerifyProofUnderContract(ed25519.Verifier{}, kp.PublicKey, proof, noContext, vc.ContractW3CEdDSARDFC2022),
		"VerifyProofUnderContract, the eddsa-jcs-2022 contract": vc.VerifyProofUnderContract(ed25519.Verifier{}, kp.PublicKey, proof, body, vc.ContractW3CEdDSAJCS2022),
		"VerifyProofWithContract, a JWK key": func() error {
			_, err := vc.VerifyProofWithContract(ed25519.Verifier{}, kp.PublicKey, did.EncodingJWK, proof, body)
			return err
		}(),
	} {
		if !errors.Is(err, vc.ErrCryptosuiteNotRegistered) || !strings.Contains(err.Error(), "vc.RegisterEdDSARDFC2022") {
			t.Errorf("%s before registering: %v, want vc.ErrCryptosuiteNotRegistered naming vc.RegisterEdDSARDFC2022", name, err)
		}
	}
	res, err := verifier.Verify(context.Background(), &signed)
	if err != nil {
		t.Fatal(err)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceFailed {
		t.Errorf("vc.Verifier before registering: signer authenticity %v, want failed", res.Axes.SignerAuthenticity)
	}
	// A proof this process cannot verify is failed before the issuer is
	// looked up: a resolver that is down does not make it indeterminate.
	var anyCred vc.Credential
	if err := json.Unmarshal(raw, &anyCred); err != nil {
		t.Fatal(err)
	}
	down := &countingResolver{}
	sa, err := vc.NewVerifier(down, ed25519.Verifier{}).VerifySignerAuthenticity(context.Background(), &anyCred)
	if err != nil {
		t.Fatal(err)
	}
	if sa.State != vc.ConfidenceFailed || down.calls != 0 {
		t.Errorf("vc.Verifier before registering, the resolver down: signer authenticity %v after %d lookups, want failed after none", sa.State, down.calls)
	}

	// Registered from several goroutines while proofs are verified: one
	// registration, and no race (go test -race).
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(2)
		go func() { defer wg.Done(); vc.RegisterEdDSARDFC2022() }()
		go func() { defer wg.Done(); _ = vc.VerifyProof(ed25519.Verifier{}, kp.PublicKey, proof, body) }()
	}
	wg.Wait()

	for name, f := range entryPoints {
		if err := f(); err != nil {
			t.Errorf("%s once registered: %v", name, err)
		}
	}
	res, err = verifier.Verify(context.Background(), &signed)
	if err != nil {
		t.Fatal(err)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceVerified {
		t.Errorf("vc.Verifier once registered: signer authenticity %v, want verified", res.Axes.SignerAuthenticity)
	}
}
