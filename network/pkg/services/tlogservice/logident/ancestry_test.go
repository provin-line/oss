package logident_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/network/pkg/services/didregistry"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store/yamlstore"
	"github.com/provin-line/oss/network/pkg/services/tlogservice/logident"
	"github.com/provin-line/oss/vc"
)

// --- fixture: a real didregistry.Service issuing real pipeline/process DIDs,
// mirroring network/pkg/services/didregistry/didregistry_test.go's own
// TestFullLifecycle setup — this is the "narrowest existing read" the task
// brief asked the adapter to be verified against: no synthetic mock of the
// registry, the actual Service + yamlstore.

const (
	ancestryRegistry = "poc.dplaax.dev"
	ancestryOwnerDID = "did:dplaax:poc.dplaax.dev:org:acme"
	// Two pipelines under the same owner, each with its own process — the
	// "other" pipeline suffix mirrors didregistry_test.go's own
	// TestIssue_RejectsDelegationTargetMismatch fixture naming. Two
	// pipelines exist so AncestorPipeline's tests can prove the adapter
	// reads the resolved document's actual Controller field rather than
	// vacuously passing with only one pipeline in scope.
	ancestryPipelineID  = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1"
	ancestryProcessID   = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1"
	ancestryPipelineID2 = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:other"
	ancestryProcessID2  = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:other:process:proc2"
)

type ancestryMemKS struct {
	mu   sync.Mutex
	keys map[string]map[keystore.KeyID]*crypto.KeyPair
}

func newAncestryMemKS() *ancestryMemKS {
	return &ancestryMemKS{keys: map[string]map[keystore.KeyID]*crypto.KeyPair{}}
}

func (m *ancestryMemKS) SaveKeyPair(d string, ks map[keystore.KeyID]*crypto.KeyPair) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[d] = ks
	return nil
}

func (m *ancestryMemKS) GetPrivateKey(d string, keyID keystore.KeyID) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ks, ok := m.keys[d]; ok {
		if kp, ok := ks[keyID]; ok {
			return kp.PrivateKey, nil
		}
	}
	return nil, keystore.ErrNotFound
}

func (m *ancestryMemKS) Sign(d string, keyID string, data []byte) ([]byte, error) {
	priv, err := m.GetPrivateKey(d, keystore.KeyID(keyID))
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, data)
}

func (m *ancestryMemKS) DeleteKeys(d string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, d)
	return nil
}

func ancestryFixedClock() time.Time { return time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC) }

// newAncestryService wires a real didregistry.Service over a temp-dir
// yamlstore and returns it with a signer bound to the owner's #signing key.
func newAncestryService(t *testing.T) (*didregistry.Service, crypto.Signer, []byte) {
	t.Helper()
	ownerKP, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate owner key: %v", err)
	}
	ownerKS := newAncestryMemKS()
	if err := ownerKS.SaveKeyPair(ancestryOwnerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: ownerKP}); err != nil {
		t.Fatalf("save owner key: %v", err)
	}
	svc := didregistry.New(
		yamlstore.New(t.TempDir()),
		newAncestryMemKS(),
		ed25519.Generator{},
		ed25519.Verifier{},
		ancestryRegistry,
		didregistry.WithClock(ancestryFixedClock),
	)
	return svc, ownerKS, ownerKP.PublicKey
}

func ancestrySignedOwnerDoc(t *testing.T, signer crypto.Signer, signPub []byte) *did.DIDDocument {
	t.Helper()
	vm, err := did.NewMultikeyVerificationMethod(ancestryOwnerDID+"#signing", ancestryOwnerDID, signPub)
	if err != nil {
		t.Fatalf("NewMultikeyVerificationMethod: %v", err)
	}
	base := did.New(did.DocumentFields{
		Context:            did.IssuedDocumentContexts(),
		ID:                 ancestryOwnerDID,
		Controller:         ancestryOwnerDID,
		VerificationMethod: []did.VerificationMethod{vm},
		AssertionMethod:    []string{ancestryOwnerDID + "#signing"},
	})
	body := base.Body()
	proof, err := vc.CreateProof(signer, ancestryOwnerDID, string(keystore.KeyIDSigning), ancestryOwnerDID+"#signing", body, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	pb, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var pm map[string]any
	if err := json.Unmarshal(pb, &pm); err != nil {
		t.Fatal(err)
	}
	body["proof"] = pm
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var full did.DIDDocument
	if err := json.Unmarshal(raw, &full); err != nil {
		t.Fatalf("unmarshal signed owner doc: %v", err)
	}
	return &full
}

func ancestryMustDelegate(t *testing.T, signer crypto.Signer, subject string) *delegation.DelegationCredential {
	t.Helper()
	dlg, err := delegation.Build(signer, ancestryOwnerDID, delegation.DelegationSubject{ID: subject, DelegatedBy: ancestryOwnerDID})
	if err != nil {
		t.Fatalf("delegation.Build(%s): %v", subject, err)
	}
	return dlg
}

// issuedTwoPipelinesWithProcesses registers the owner and issues TWO
// pipelines, each with its own process under it, returning the live
// service. Two pipelines (not one) so a test asserting AncestorPipeline
// returns the correct one can fail on a mixed-up read (e.g. an adapter bug
// that returned "the only pipeline registered" rather than the resolved
// document's actual controller) instead of vacuously passing.
func issuedTwoPipelinesWithProcesses(t *testing.T) *didregistry.Service {
	t.Helper()
	ctx := context.Background()
	svc, signer, signPub := newAncestryService(t)
	if _, err := svc.RegisterOwner(ctx, ancestrySignedOwnerDoc(t, signer, signPub), nil); err != nil {
		t.Fatalf("RegisterOwner: %v", err)
	}
	if _, _, err := svc.IssuePipeline(ctx, ancestryPipelineID, ancestryMustDelegate(t, signer, ancestryPipelineID), nil); err != nil {
		t.Fatalf("IssuePipeline(%s): %v", ancestryPipelineID, err)
	}
	if _, _, err := svc.IssueProcess(ctx, ancestryProcessID, ancestryMustDelegate(t, signer, ancestryProcessID), nil); err != nil {
		t.Fatalf("IssueProcess(%s): %v", ancestryProcessID, err)
	}
	if _, _, err := svc.IssuePipeline(ctx, ancestryPipelineID2, ancestryMustDelegate(t, signer, ancestryPipelineID2), nil); err != nil {
		t.Fatalf("IssuePipeline(%s): %v", ancestryPipelineID2, err)
	}
	if _, _, err := svc.IssueProcess(ctx, ancestryProcessID2, ancestryMustDelegate(t, signer, ancestryProcessID2), nil); err != nil {
		t.Fatalf("IssueProcess(%s): %v", ancestryProcessID2, err)
	}
	return svc
}

var _ logident.PipelineAncestry = (*logident.DIDRegistryAncestry)(nil)

// TestDIDRegistryAncestry_ResolvesIssuingPipeline proves the adapter reads
// EACH process's own resolved Controller field, not just "the pipeline that
// happens to be in scope": two pipelines are registered, each with its own
// process, and a process under pipeline A must resolve to A and NOT B (and
// symmetrically for B) — a single-pipeline fixture cannot distinguish
// "reads Controller correctly" from "returns the only pipeline available".
func TestDIDRegistryAncestry_ResolvesIssuingPipeline(t *testing.T) {
	svc := issuedTwoPipelinesWithProcesses(t)
	a := logident.NewDIDRegistryAncestry(svc)
	ctx := context.Background()

	gotA, err := a.AncestorPipeline(ctx, ancestryProcessID)
	if err != nil {
		t.Fatalf("AncestorPipeline(process under A): %v", err)
	}
	if gotA != ancestryPipelineID {
		t.Errorf("AncestorPipeline(process under A) = %q, want %q", gotA, ancestryPipelineID)
	}
	if gotA == ancestryPipelineID2 {
		t.Errorf("AncestorPipeline(process under A) = %q, must NOT equal the other pipeline %q", gotA, ancestryPipelineID2)
	}

	gotB, err := a.AncestorPipeline(ctx, ancestryProcessID2)
	if err != nil {
		t.Fatalf("AncestorPipeline(process under B): %v", err)
	}
	if gotB != ancestryPipelineID2 {
		t.Errorf("AncestorPipeline(process under B) = %q, want %q", gotB, ancestryPipelineID2)
	}
	if gotB == ancestryPipelineID {
		t.Errorf("AncestorPipeline(process under B) = %q, must NOT equal the other pipeline %q", gotB, ancestryPipelineID)
	}
}

func TestDIDRegistryAncestry_UnknownProcessFailsClosed(t *testing.T) {
	svc := issuedTwoPipelinesWithProcesses(t)
	a := logident.NewDIDRegistryAncestry(svc)

	unknown := "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:ghost"
	if got, err := a.AncestorPipeline(context.Background(), unknown); err == nil {
		t.Errorf("AncestorPipeline(unknown) = %q, nil, want an error", got)
	}
}

func TestDIDRegistryAncestry_RejectsNonProcessInputBeforeResolving(t *testing.T) {
	svc := issuedTwoPipelinesWithProcesses(t)
	a := logident.NewDIDRegistryAncestry(svc)

	cases := map[string]string{
		"empty":        "",
		"owner DID":    ancestryOwnerDID,
		"pipeline DID": ancestryPipelineID,
		"not a DID":    "not-a-did",
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := a.AncestorPipeline(context.Background(), id); err == nil {
				t.Errorf("AncestorPipeline(%q) = %q, nil, want an error", id, got)
			} else if !errors.Is(err, logident.ErrInvalidProcessDID) {
				t.Errorf("AncestorPipeline(%q) err = %v, want wrapping ErrInvalidProcessDID", id, err)
			}
		})
	}
}
