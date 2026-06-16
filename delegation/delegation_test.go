package delegation_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/resolver/local"
)

const (
	ownerDID   = "did:dplaax:poc.dplaax.io:org:acme"
	processDID = "did:dplaax:poc.dplaax.io:org:acme:pipeline:p1:process:proc1"
)

type memKeyStore struct{ keys map[string][]byte }

func newMemKeyStore() *memKeyStore { return &memKeyStore{keys: map[string][]byte{}} }
func (m *memKeyStore) SaveKeyPair(d string, keys map[keystore.KeyID]*crypto.KeyPair) error {
	for id, kp := range keys {
		m.keys[d+"#"+string(id)] = kp.PrivateKey
	}
	return nil
}
func (m *memKeyStore) GetPrivateKey(d string, id keystore.KeyID) ([]byte, error) {
	k, ok := m.keys[d+"#"+string(id)]
	if !ok {
		return nil, errNotFound
	}
	return k, nil
}
func (m *memKeyStore) DeleteKeys(string) error { return nil }

type errStr string

func (e errStr) Error() string { return string(e) }

var errNotFound = errStr("key not found")

func signingDoc(subject string, pub []byte) *did.DIDDocument {
	return signingDocAs(subject, subject, pub)
}

// signingDocAs builds a document with subject docID whose #signing assertion key
// is identified under vmSubject — equal for a genuine doc, divergent to forge a
// registry-substituted document for the substitution-defense test.
func signingDocAs(docID, vmSubject string, pub []byte) *did.DIDDocument {
	return did.New(did.DocumentFields{
		ID:         docID,
		Controller: docID,
		VerificationMethod: []did.VerificationMethod{{
			ID:         vmSubject + "#signing",
			Type:       "JsonWebKey2020",
			Controller: docID,
			PublicKeyJWK: map[string]any{
				"kty": "OKP", "crv": "Ed25519",
				"x": base64.RawURLEncoding.EncodeToString(pub),
			},
		}},
		AssertionMethod: []string{vmSubject + "#signing"},
	})
}

// fixture wires a signer for issuerDID and a resolver carrying its DID document.
func fixture(t *testing.T, issuerDID string) (crypto.Signer, *local.Resolver) {
	t.Helper()
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	ks := newMemKeyStore()
	if err := ks.SaveKeyPair(issuerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatalf("SaveKeyPair: %v", err)
	}
	r := local.New()
	r.Add(signingDoc(issuerDID, kp.PublicKey))
	return ed25519.NewSigner(ks), r
}

func sampleSubject() delegation.DelegationSubject {
	return delegation.DelegationSubject{
		ID:          processDID,
		DelegatedBy: ownerDID,
	}
}

func TestBuild_Verify_RoundTrip(t *testing.T) {
	signer, r := fixture(t, ownerDID)

	cred, err := delegation.Build(signer, ownerDID, sampleSubject())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if cred.Proof == nil {
		t.Fatal("built delegation is unsigned")
	}
	if cred.Issuer != ownerDID {
		t.Errorf("issuer=%q, want %q", cred.Issuer, ownerDID)
	}
	if err := delegation.Verify(context.Background(), ed25519.Verifier{}, r, cred); err != nil {
		t.Errorf("Verify on a genuine delegation: %v", err)
	}
}

func TestBuild_RejectsDelegatedByMismatch(t *testing.T) {
	signer, _ := fixture(t, ownerDID)
	subject := sampleSubject()
	subject.DelegatedBy = "did:dplaax:poc.dplaax.io:org:someone-else"
	if _, err := delegation.Build(signer, ownerDID, subject); err == nil {
		t.Error("Build with delegatedBy != issuer: want error")
	}
}

func TestVerify_DelegatedByMismatch(t *testing.T) {
	signer, r := fixture(t, ownerDID)
	cred, err := delegation.Build(signer, ownerDID, sampleSubject())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// delegatedBy no longer equals the issuer — checked before proof.
	cred.Issuer = "did:dplaax:poc.dplaax.io:org:other"
	if err := delegation.Verify(context.Background(), ed25519.Verifier{}, r, cred); err == nil {
		t.Error("Verify with delegatedBy != issuer: want error")
	}
}

func TestVerify_NonOwnerIssuer(t *testing.T) {
	// A delegation whose issuer is a Process DID (not an Owner) must be rejected:
	// delegations are owner-signed.
	signer, r := fixture(t, processDID)
	subject := delegation.DelegationSubject{ID: processDID, DelegatedBy: processDID}
	cred, err := delegation.Build(signer, processDID, subject)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := delegation.Verify(context.Background(), ed25519.Verifier{}, r, cred); err == nil {
		t.Error("Verify with a non-owner issuer: want error")
	}
}

func TestVerify_RejectsWireScope(t *testing.T) {
	// A delegation is signed without a scope; a scope is then appended on the
	// wire (an attacker, or a credential from a scope-using profile). provin must
	// reject it fail-closed — it never signs scope and must not pass on an
	// unverified scope to a downstream scope-aware consumer.
	signer, r := fixture(t, ownerDID)
	cred, err := delegation.Build(signer, ownerDID, sampleSubject())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	wire, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	withScope := strings.Replace(string(wire),
		`"delegatedBy":"`+ownerDID+`"`,
		`"delegatedBy":"`+ownerDID+`","scope":["process:sign"]`, 1)
	if withScope == string(wire) {
		t.Fatal("scope injection did not modify the wire bytes")
	}
	var rt delegation.DelegationCredential
	if err := json.Unmarshal([]byte(withScope), &rt); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := delegation.Verify(context.Background(), ed25519.Verifier{}, r, &rt); err == nil {
		t.Error("Verify on a delegation carrying a wire scope: want error (fail-closed)")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	signer, _ := fixture(t, ownerDID)
	cred, err := delegation.Build(signer, ownerDID, sampleSubject())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// A resolver returning a different key for the owner.
	other, _ := (ed25519.Generator{}).Generate()
	r := local.New()
	r.Add(signingDoc(ownerDID, other.PublicKey))
	if err := delegation.Verify(context.Background(), ed25519.Verifier{}, r, cred); err == nil {
		t.Error("Verify against a mismatched public key: want error")
	}
}

func TestVerify_Unsigned(t *testing.T) {
	_, r := fixture(t, ownerDID)
	cred := &delegation.DelegationCredential{Issuer: ownerDID, CredentialSubject: sampleSubject()}
	if err := delegation.Verify(context.Background(), ed25519.Verifier{}, r, cred); err == nil {
		t.Error("Verify on an unsigned delegation: want error")
	}
}

func TestVerify_Nil(t *testing.T) {
	_, r := fixture(t, ownerDID)
	if err := delegation.Verify(context.Background(), ed25519.Verifier{}, r, nil); err == nil {
		t.Error("Verify(nil): want error")
	}
}

func TestVerify_VerificationMethodNotIssuer(t *testing.T) {
	signer, r := fixture(t, ownerDID)
	cred, err := delegation.Build(signer, ownerDID, sampleSubject())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	cred.Proof.VerificationMethod = "did:dplaax:poc.dplaax.io:org:other#signing"
	if err := delegation.Verify(context.Background(), ed25519.Verifier{}, r, cred); err == nil {
		t.Error("Verify with a verificationMethod naming another DID: want error")
	}
}

func TestVerify_SubstitutedDocID(t *testing.T) {
	signer, _ := fixture(t, ownerDID)
	cred, err := delegation.Build(signer, ownerDID, sampleSubject())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// A resolver whose returned document has an ID other than the issuer.
	other, _ := (ed25519.Generator{}).Generate()
	r := local.New()
	doc := signingDocAs("did:dplaax:poc.dplaax.io:org:imposter", ownerDID, other.PublicKey)
	r.Add(doc) // stored under the imposter id; will not resolve the issuer
	if err := delegation.Verify(context.Background(), ed25519.Verifier{}, r, cred); err == nil {
		t.Error("Verify against a substituted document id: want error")
	}
}

func TestVerify_TamperedSubjectID(t *testing.T) {
	signer, r := fixture(t, ownerDID)
	cred, err := delegation.Build(signer, ownerDID, sampleSubject())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	cred.CredentialSubject.ID = "did:dplaax:poc.dplaax.io:org:acme:pipeline:p1:process:evil"
	if err := delegation.Verify(context.Background(), ed25519.Verifier{}, r, cred); err == nil {
		t.Error("Verify after delegated-id tampering: want error (proof covers the subject)")
	}
}

func TestVerify_SubjectNotUnderIssuer(t *testing.T) {
	signer, r := fixture(t, ownerDID)
	// acme owner signs a delegation for a pipeline under a DIFFERENT owner.
	subject := delegation.DelegationSubject{
		ID:          "did:dplaax:poc.dplaax.io:org:beta:pipeline:p1",
		DelegatedBy: ownerDID,
	}
	cred, err := delegation.Build(signer, ownerDID, subject)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := delegation.Verify(context.Background(), ed25519.Verifier{}, r, cred); err == nil {
		t.Error("Verify with a subject under another owner: want error (authority scoping)")
	}
}

func TestVerify_SubjectNotPipelineOrProcess(t *testing.T) {
	signer, r := fixture(t, ownerDID)
	subject := delegation.DelegationSubject{
		ID:          "did:dplaax:poc.dplaax.io:org:acme", // an owner DID, not pipeline/process
		DelegatedBy: ownerDID,
	}
	cred, err := delegation.Build(signer, ownerDID, subject)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := delegation.Verify(context.Background(), ed25519.Verifier{}, r, cred); err == nil {
		t.Error("Verify with a non-pipeline/process subject: want error")
	}
}

func TestVerify_MissingDelegationType(t *testing.T) {
	signer, r := fixture(t, ownerDID)
	cred, err := delegation.Build(signer, ownerDID, sampleSubject())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	cred.Type = []string{"VerifiableCredential"} // DelegationCredential dropped
	if err := delegation.Verify(context.Background(), ed25519.Verifier{}, r, cred); err == nil {
		t.Error("Verify without the DelegationCredential type: want error")
	}
}

func TestVerify_MalformedCreated(t *testing.T) {
	signer, r := fixture(t, ownerDID)
	cred, err := delegation.Build(signer, ownerDID, sampleSubject())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	cred.Proof.Created = "not-a-date"
	if err := delegation.Verify(context.Background(), ed25519.Verifier{}, r, cred); err == nil {
		t.Error("Verify with a malformed proof.created: want error")
	}
}

// A sub-second shift to validFrom (within the signed whole second) must break
// verification — the hash commits to full precision, not a normalized second.
func TestVerify_SubSecondValidFromTamper(t *testing.T) {
	signer, r := fixture(t, ownerDID)
	cred, err := delegation.Build(signer, ownerDID, sampleSubject())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	cred.ValidFrom = cred.ValidFrom.Add(500 * time.Millisecond)
	if err := delegation.Verify(context.Background(), ed25519.Verifier{}, r, cred); err == nil {
		t.Error("Verify after a sub-second validFrom shift: want error")
	}
}

func TestVerify_RejectsProofTypeOrPurpose(t *testing.T) {
	signer, r := fixture(t, ownerDID)

	wrongPurpose, err := delegation.Build(signer, ownerDID, sampleSubject())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	wrongPurpose.Proof.ProofPurpose = "authentication"
	if err := delegation.Verify(context.Background(), ed25519.Verifier{}, r, wrongPurpose); err == nil {
		t.Error("Verify with proofPurpose=authentication: want error")
	}

	wrongSuite, err := delegation.Build(signer, ownerDID, sampleSubject())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	wrongSuite.Proof.Cryptosuite = "eddsa-rdfc-2022"
	if err := delegation.Verify(context.Background(), ed25519.Verifier{}, r, wrongSuite); err == nil {
		t.Error("Verify with an unsupported cryptosuite: want error")
	}
}
