package vcdid_test

import (
	"context"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/pipeline/provenance"
	"github.com/provin-line/oss/pipeline/provenance/vcdid"
	"github.com/provin-line/oss/vc"
)

const (
	issuerDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1"
	keyID     = string(keystore.KeyIDSigning)
	vmID      = issuerDID + "#signing"
)

// Compile-time: one Signer value satisfies both capability interfaces.
var (
	_ provenance.SourceSigner  = (*vcdid.Signer)(nil)
	_ provenance.ChainedSigner = (*vcdid.Signer)(nil)
)

type memKeyStore struct{ keys map[string][]byte }

func newMemKeyStore() *memKeyStore { return &memKeyStore{keys: map[string][]byte{}} }
func (m *memKeyStore) SaveKeyPair(did string, keys map[keystore.KeyID]*crypto.KeyPair) error {
	for id, kp := range keys {
		m.keys[did+"#"+string(id)] = kp.PrivateKey
	}
	return nil
}
func (m *memKeyStore) GetPrivateKey(did string, id keystore.KeyID) ([]byte, error) {
	k, ok := m.keys[did+"#"+string(id)]
	if !ok {
		return nil, errNotFound
	}
	return k, nil
}
func (m *memKeyStore) DeleteKeys(string) error { return nil }

type errStr string

func (e errStr) Error() string { return string(e) }

var errNotFound = errStr("key not found")

// fixture wires a real Ed25519 signer/builder for issuerDID and returns the
// builder plus the issuer's public key.
func fixture(t *testing.T) (*vc.Builder, []byte) {
	t.Helper()
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	ks := newMemKeyStore()
	if err := ks.SaveKeyPair(issuerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatalf("SaveKeyPair: %v", err)
	}
	return vc.NewBuilder(ed25519.NewSigner(ks)), kp.PublicKey
}

func newSigner(t *testing.T, b *vc.Builder, opts func(*vcdid.Config)) *vcdid.Signer {
	t.Helper()
	cfg := vcdid.Config{
		Builder:             b,
		IssuerDID:           issuerDID,
		KeyID:               keyID,
		VerificationMethod:  vmID,
		PipelineID:          "p1",
		ProcessID:           "proc1",
		TransformationClaim: vc.ClaimConvert,
	}
	if opts != nil {
		opts(&cfg)
	}
	s, err := vcdid.NewSigner(cfg)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func TestSigner_SignFirstDrop_SignsAndVerifies(t *testing.T) {
	b, pub := fixture(t)
	s := newSigner(t, b, nil)

	cred, err := s.SignFirstDrop(context.Background(), []byte(`{"x":1}`), "sha256:in", "sha256:out")
	if err != nil {
		t.Fatalf("SignFirstDrop: %v", err)
	}
	if cred.Proof() == nil {
		t.Fatal("FirstDrop is unsigned")
	}
	if cred.PreviousCredential() != "" {
		t.Errorf("FirstDrop carries previousCredential %q", cred.PreviousCredential())
	}
	if cred.Issuer() != issuerDID {
		t.Errorf("issuer=%q, want %q", cred.Issuer(), issuerDID)
	}
	subj, _ := cred.Subject()
	if subj.PipelineID != "p1" || subj.ProcessID != "proc1" || subj.OutputHash != "sha256:out" {
		t.Errorf("subject=%+v, want pipeline p1 / process proc1 / outputHash sha256:out", subj)
	}
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, cred.Proof(), cred.Body()); err != nil {
		t.Errorf("issued FirstDrop proof does not verify: %v", err)
	}
}

func TestSigner_SignChainPreserving_LinksAndVerifies(t *testing.T) {
	b, pub := fixture(t)
	s := newSigner(t, b, nil)

	prev, err := s.SignFirstDrop(context.Background(), []byte(`{"x":1}`), "sha256:in", "sha256:mid")
	if err != nil {
		t.Fatalf("predecessor SignFirstDrop: %v", err)
	}
	prevHash, _ := prev.Hash()

	cred, err := s.SignChainPreserving(context.Background(), []byte(`{"x":1}`), "sha256:mid", "sha256:out", prev)
	if err != nil {
		t.Fatalf("SignChainPreserving: %v", err)
	}
	if cred.PreviousCredential() != prevHash {
		t.Errorf("previousCredential=%q, want %q", cred.PreviousCredential(), prevHash)
	}
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, cred.Proof(), cred.Body()); err != nil {
		t.Errorf("issued chain-preserving proof does not verify: %v", err)
	}
}

// In an audit-reachable deployment the chain-preserving signer attaches a source
// commitment over the consumed set — for a 1:1 process exactly {predecessor}.
func TestSigner_AuditReachable_AttachesCommitment(t *testing.T) {
	b, _ := fixture(t)
	s := newSigner(t, b, func(c *vcdid.Config) {
		c.AuditReachable = true
		c.SourceRootCanonical = vc.SourceRootCanonicalJCS
	})

	prev, err := s.SignFirstDrop(context.Background(), []byte(`{"x":1}`), "sha256:in", "sha256:mid")
	if err != nil {
		t.Fatalf("predecessor: %v", err)
	}
	cred, err := s.SignChainPreserving(context.Background(), []byte(`{"x":1}`), "sha256:mid", "sha256:out", prev)
	if err != nil {
		t.Fatalf("SignChainPreserving: %v", err)
	}
	sc := cred.SourceCommitment()
	if sc == nil {
		t.Fatal("audit-reachable chain-preserving credential carries no source commitment")
	}
	found := false
	for _, d := range sc.DerivedFrom {
		if d == prev.Issuer() {
			found = true
		}
	}
	if !found {
		t.Errorf("source commitment derived_from %v omits the predecessor's issuer %q", sc.DerivedFrom, prev.Issuer())
	}
	// The root must be the one a verifier recomputes over the predecessor as
	// received — DerivedFrom inclusion alone is also enforced by the Builder, so
	// only this catches an emit/verify root divergence.
	wantRoot, err := vc.ComputeSourceRoot([]*vc.PipelinePassCredential{prev}, vc.SourceRootCanonicalJCS)
	if err != nil {
		t.Fatalf("ComputeSourceRoot: %v", err)
	}
	if sc.SourceRoot != wantRoot {
		t.Errorf("source_root=%q, want recomputed %q", sc.SourceRoot, wantRoot)
	}
}

// A nil predecessor is an error, never a panic — including on the
// audit-reachable path, which would otherwise deref nil building the commitment.
func TestSigner_SignChainPreserving_NilPredecessor(t *testing.T) {
	b, _ := fixture(t)
	for _, audit := range []bool{false, true} {
		s := newSigner(t, b, func(c *vcdid.Config) {
			c.AuditReachable = audit
			if audit {
				c.SourceRootCanonical = vc.SourceRootCanonicalJCS
			}
		})
		if _, err := s.SignChainPreserving(context.Background(), []byte(`{}`), "sha256:in", "sha256:out", nil); err == nil {
			t.Errorf("SignChainPreserving(nil predecessor, audit=%v): want error", audit)
		}
	}
}

// Static config invalidity (malformed claim grammar, unknown commitment
// canonicalization) fails loud at construction, not at first sign.
func TestNewSigner_RejectsStaticInvalidity(t *testing.T) {
	b, _ := fixture(t)
	base := vcdid.Config{
		Builder: b, IssuerDID: issuerDID, KeyID: keyID, VerificationMethod: vmID,
		PipelineID: "p1", ProcessID: "proc1", TransformationClaim: vc.ClaimConvert,
	}

	bad := base
	bad.TransformationClaim = "no-namespace" // not a <ns>:<label> token
	if _, err := vcdid.NewSigner(bad); err == nil {
		t.Error("NewSigner with a malformed TransformationClaim: want error")
	}

	badCanon := base
	badCanon.AuditReachable = true
	badCanon.SourceRootCanonical = "unknown-canonical"
	if _, err := vcdid.NewSigner(badCanon); err == nil {
		t.Error("NewSigner with an unknown SourceRootCanonical: want error")
	}
}

func TestNewSigner_RequiresFields(t *testing.T) {
	b, _ := fixture(t)
	good := vcdid.Config{
		Builder: b, IssuerDID: issuerDID, KeyID: keyID, VerificationMethod: vmID,
		PipelineID: "p1", ProcessID: "proc1", TransformationClaim: vc.ClaimConvert,
	}
	mutate := map[string]func(*vcdid.Config){
		"nil builder":      func(c *vcdid.Config) { c.Builder = nil },
		"empty issuer":     func(c *vcdid.Config) { c.IssuerDID = "" },
		"empty keyID":      func(c *vcdid.Config) { c.KeyID = "" },
		"empty vm":         func(c *vcdid.Config) { c.VerificationMethod = "" },
		"empty pipelineID": func(c *vcdid.Config) { c.PipelineID = "" },
		"empty processID":  func(c *vcdid.Config) { c.ProcessID = "" },
		"empty claim":      func(c *vcdid.Config) { c.TransformationClaim = "" },
	}
	for name, m := range mutate {
		cfg := good
		m(&cfg)
		if _, err := vcdid.NewSigner(cfg); err == nil {
			t.Errorf("NewSigner(%s): want error", name)
		}
	}
}
