package didregistry_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/multibase"
	"github.com/provin-line/oss/network/pkg/services/didregistry"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store/yamlstore"
	"github.com/provin-line/oss/vc"
)

// mustMultikeyVM builds the Multikey verification method these fixtures model:
// a NEW owner, whose W3C-shaped proofs the classifier only accepts over
// Multikey (signer.suite.eddsa-jcs-2022).
func mustMultikeyVM(id, controller string, pub []byte) did.VerificationMethod {
	vm, err := did.NewMultikeyVerificationMethod(id, controller, pub)
	if err != nil {
		panic(err) // a non-Ed25519 fixture key is a test bug
	}
	return vm
}

// rawMultikeyVM builds a Multikey verification method for any 32 bytes,
// encoding them by hand: did.NewMultikeyVerificationMethod refuses an unusable
// Ed25519 key, and an adversarial owner document is not built with it.
func rawMultikeyVM(id, controller string, pub []byte) did.VerificationMethod {
	return did.VerificationMethod{
		ID:                 id,
		Type:               "Multikey",
		Controller:         controller,
		PublicKeyMultibase: multibase.EncodeBase58Btc(append([]byte{0xed, 0x01}, pub...)),
	}
}

const (
	registry    = "poc.dplaax.dev"
	ownerDID    = "did:dplaax:poc.dplaax.dev:org:acme"
	pipelineDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1"
	processDID  = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1"
)

// --- in-memory keystore -----------------------------------------------------

var errKeyNotFound = fmt.Errorf("key not found: %w", keystore.ErrNotFound)

type memKeyStore struct {
	mu   sync.Mutex
	keys map[string]map[keystore.KeyID]*crypto.KeyPair
}

func newMemKS() *memKeyStore {
	return &memKeyStore{keys: map[string]map[keystore.KeyID]*crypto.KeyPair{}}
}

func (m *memKeyStore) SaveKeyPair(d string, ks map[keystore.KeyID]*crypto.KeyPair) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make(map[keystore.KeyID]*crypto.KeyPair, len(ks))
	for k, v := range ks {
		cp[k] = v
	}
	m.keys[d] = cp
	return nil
}

func (m *memKeyStore) GetPrivateKey(d string, keyID keystore.KeyID) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ks, ok := m.keys[d]
	if !ok {
		return nil, errKeyNotFound
	}
	kp, ok := ks[keyID]
	if !ok {
		return nil, errKeyNotFound
	}
	return kp.PrivateKey, nil
}

func (m *memKeyStore) Sign(d string, keyID string, data []byte) ([]byte, error) {
	priv, err := m.GetPrivateKey(d, keystore.KeyID(keyID))
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, data)
}

func (m *memKeyStore) DeleteKeys(d string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, d)
	return nil
}

// --- fixtures ---------------------------------------------------------------

func fixedClock() time.Time { return time.Date(2026, 6, 16, 9, 0, 0, 0, time.UTC) }

// newService wires a Service over a temp-dir yamlstore, and returns it with a
// signer bound to ownerDID's #signing key (for building owner proofs and
// delegations) and the owner's signing public key.
func newService(t *testing.T) (*didregistry.Service, crypto.Signer, []byte) {
	t.Helper()
	svc, signer, pub, _ := newServiceWithKeys(t)
	return svc, signer, pub
}

// newServiceWithKeys is newService but additionally returns the Service's own
// keystore. The external-key issuance tests assert directly against it: an
// absent entry for the issued DID is the distinguishing property of that path
// (the registry never mints or stores a private key for it), which newService
// callers have no way to check since the keystore never leaves New's call.
func newServiceWithKeys(t *testing.T) (*didregistry.Service, crypto.Signer, []byte, *memKeyStore) {
	t.Helper()
	ownerKP, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate owner key: %v", err)
	}
	ownerKS := newMemKS()
	if err := ownerKS.SaveKeyPair(ownerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: ownerKP}); err != nil {
		t.Fatalf("save owner key: %v", err)
	}
	keys := newMemKS()
	svc := didregistry.New(
		yamlstore.New(t.TempDir()),
		keys,
		ed25519.Generator{},
		ed25519.Verifier{},
		registry,
		didregistry.WithClock(fixedClock),
		didregistry.WithServiceEndpoints([]did.ServiceEndpoint{
			{ID: "#vc-resolver", Type: "VCResolver", ServiceEndpoint: "https://" + registry + "/vc"},
		}),
	)
	return svc, ownerKS, ownerKP.PublicKey, keys
}

// localKeyPair generates a fresh Ed25519 keypair modeling loop-side local
// minting: the private key never crosses into any keystore this test can see,
// exactly as the external-key path promises for the registry itself.
func localKeyPair(t *testing.T) *crypto.KeyPair {
	t.Helper()
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate local key: %v", err)
	}
	return kp
}

// localSigner implements crypto.Signer directly over a caller-held raw
// Ed25519 private key — the loop side of the external-key path signs with a
// key the registry never receives or stores. did/keyID are ignored: unlike a
// keystore.KeyStore-backed signer, there is no lookup, only the one key held.
type localSigner struct{ priv []byte }

func (l localSigner) Sign(_, _ string, data []byte) ([]byte, error) {
	return ed25519.Sign(l.priv, data)
}

func ed25519JWK(pub []byte) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
}

// signedOwnerDoc builds an owner DID document with a #signing assertion key and
// a self-signed Data Integrity proof over the document body.
func signedOwnerDoc(t *testing.T, signer crypto.Signer, signPub []byte, aka []string) *did.DIDDocument {
	t.Helper()
	return signedOwnerDocFields(t, signer, did.DocumentFields{
		Context:            did.IssuedDocumentContexts(),
		ID:                 ownerDID,
		Controller:         ownerDID,
		AlsoKnownAs:        aka,
		VerificationMethod: []did.VerificationMethod{mustMultikeyVM(ownerDID+"#signing", ownerDID, signPub)},
		AssertionMethod:    []string{ownerDID + "#signing"},
	})
}

// signedOwnerDocFields signs the document built from fields with the owner's
// #signing key.
func signedOwnerDocFields(t *testing.T, signer crypto.Signer, fields did.DocumentFields) *did.DIDDocument {
	t.Helper()
	return signedOwnerDocBody(t, signer, did.New(fields).Body())
}

// signedOwnerDocBody self-signs the owner document body under #signing.
func signedOwnerDocBody(t *testing.T, signer crypto.Signer, body map[string]any) *did.DIDDocument {
	t.Helper()
	proof, err := vc.CreateProof(signer, ownerDID, string(keystore.KeyIDSigning), ownerDID+"#signing", body, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	pb, _ := json.Marshal(proof)
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

// registerOwner registers a freshly-signed owner and returns the signer for
// building delegations.
func registerOwner(t *testing.T, svc *didregistry.Service, signer crypto.Signer, signPub []byte) {
	t.Helper()
	if _, err := svc.RegisterOwner(context.Background(), signedOwnerDoc(t, signer, signPub, nil), nil); err != nil {
		t.Fatalf("RegisterOwner: %v", err)
	}
}

func mustDelegate(t *testing.T, signer crypto.Signer, subject string) *delegation.DelegationCredential {
	t.Helper()
	dlg, err := delegation.Build(signer, ownerDID, delegation.DelegationSubject{ID: subject, DelegatedBy: ownerDID})
	if err != nil {
		t.Fatalf("delegation.Build(%s): %v", subject, err)
	}
	return dlg
}

// --- tests ------------------------------------------------------------------

// The full lifecycle: register an owner, issue a pipeline then a process under
// owner-signed delegations, resolve, list, and read the lifecycle logs.
func TestFullLifecycle(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub := newService(t)
	registerOwner(t, svc, signer, signPub)

	pipeDoc, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID), nil)
	if err != nil {
		t.Fatalf("IssuePipeline: %v", err)
	}
	if pipeDoc.Controller() != ownerDID {
		t.Errorf("pipeline controller=%q, want owner", pipeDoc.Controller())
	}
	if got := pipeDoc.AssertionMethod(); len(got) != 1 || got[0] != pipelineDID+"#signing" {
		t.Errorf("pipeline assertionMethod=%v", got)
	}
	if got := pipeDoc.Authentication(); len(got) != 1 || got[0] != pipelineDID+"#auth" {
		t.Errorf("pipeline authentication=%v", got)
	}
	if svcs := pipeDoc.Service(); len(svcs) != 1 || svcs[0].ID != pipelineDID+"#vc-resolver" {
		t.Errorf("pipeline service=%v", svcs)
	}

	procDoc, _, err := svc.IssueProcess(ctx, processDID, mustDelegate(t, signer, processDID), nil)
	if err != nil {
		t.Fatalf("IssueProcess: %v", err)
	}
	if procDoc.Controller() != pipelineDID {
		t.Errorf("process controller=%q, want pipeline", procDoc.Controller())
	}

	// Resolution + delegation resolution.
	if got, err := svc.ResolveDID(ctx, processDID); err != nil || got.ID() != processDID {
		t.Fatalf("ResolveDID process: %q, %v", got, err)
	}
	if dlg, err := svc.ResolveDelegation(ctx, pipelineDID); err != nil || dlg.CredentialSubject.ID != pipelineDID {
		t.Fatalf("ResolveDelegation pipeline: %+v, %v", dlg, err)
	}

	// Listing.
	pipes, err := svc.ListPipelines(ctx, ownerDID)
	if err != nil || len(pipes) != 1 || pipes[0].DID != pipelineDID {
		t.Fatalf("ListPipelines: %+v, %v", pipes, err)
	}
	procs, err := svc.ListProcesses(ctx, pipelineDID)
	if err != nil || len(procs) != 1 || procs[0].DID != processDID {
		t.Fatalf("ListProcesses: %+v, %v", procs, err)
	}

	// Lifecycle logs: owner + pipeline + process each carry a register event.
	for _, d := range []string{ownerDID, pipelineDID, processDID} {
		log, err := svc.ReadLifecycleLog(ctx, d)
		if err != nil {
			t.Fatalf("ReadLifecycleLog(%s): %v", d, err)
		}
		if len(log) != 1 || log[0].EventType != "register" {
			t.Errorf("%s log = %+v, want one register event", d, log)
		}
		if log[0].PrevEventHash != "" {
			t.Errorf("%s first event PrevEventHash=%q, want empty", d, log[0].PrevEventHash)
		}
		if !log[0].WitnessedAt.Equal(fixedClock()) {
			t.Errorf("%s witnessedAt=%v, want injected clock", d, log[0].WitnessedAt)
		}
	}
}

func TestRegisterOwner_RecordsOutwardSnapshotAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub := newService(t)
	doc := signedOwnerDoc(t, signer, signPub, []string{"https://acme.example"})
	outward := []byte("outward-doc-bytes")

	if _, err := svc.RegisterOwner(ctx, doc, outward); err != nil {
		t.Fatalf("RegisterOwner: %v", err)
	}
	// Exact re-submission is idempotent: success, and no second event.
	if _, err := svc.RegisterOwner(ctx, doc, outward); err != nil {
		t.Fatalf("idempotent RegisterOwner: %v", err)
	}
	log, err := svc.ReadLifecycleLog(ctx, ownerDID)
	if err != nil {
		t.Fatal(err)
	}
	if len(log) != 1 {
		t.Fatalf("idempotent re-register produced %d events, want 1", len(log))
	}
	if string(log[0].OutwardSnapshot) != "outward-doc-bytes" {
		t.Errorf("outward snapshot=%q", log[0].OutwardSnapshot)
	}
	if log[0].WitnessSource != "self-asserted" {
		t.Errorf("witnessSource=%q, want self-asserted", log[0].WitnessSource)
	}
}

func TestRegisterOwner_RevokedOwnerReplayDoesNotResurrect(t *testing.T) {
	// Replay pin: re-sending the ORIGINAL RegisterOwner request against a
	// since-revoked owner must ride the idempotent path — same document
	// returned, status stays revoked, no new lifecycle event. A replayed
	// registration must never work as an un-revoke.
	ctx := context.Background()
	svc, signer, signPub := newService(t)
	doc := signedOwnerDoc(t, signer, signPub, nil)

	if _, err := svc.RegisterOwner(ctx, doc, nil); err != nil {
		t.Fatalf("RegisterOwner: %v", err)
	}
	if _, err := svc.UpdateStatus(ctx, ownerDID, "revoked"); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	got, err := svc.RegisterOwner(ctx, doc, nil)
	if err != nil {
		t.Fatalf("replayed RegisterOwner after revoke: %v", err)
	}
	wantHash, err := doc.Hash()
	if err != nil {
		t.Fatalf("hash original doc: %v", err)
	}
	gotHash, err := got.Hash()
	if err != nil {
		t.Fatalf("hash replayed doc: %v", err)
	}
	if gotHash != wantHash {
		t.Errorf("replay returned a different document: %s != %s", gotHash, wantHash)
	}

	resolved, err := svc.ResolveDID(ctx, ownerDID)
	if err != nil {
		t.Fatalf("ResolveDID: %v", err)
	}
	if rh, _ := resolved.Hash(); rh != wantHash {
		t.Errorf("stored document changed after replay")
	}
	log, err := svc.ReadLifecycleLog(ctx, ownerDID)
	if err != nil {
		t.Fatal(err)
	}
	// Exactly register + revoke — the replay appended nothing.
	if len(log) != 2 {
		t.Fatalf("lifecycle log has %d events after replay, want 2 (register, revoke)", len(log))
	}
	// Status is still revoked: an owner-gated operation must keep rejecting.
	if _, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID), nil); !errors.Is(err, didregistry.ErrUnauthorized) {
		t.Errorf("post-replay issue under revoked owner: want ErrUnauthorized, got %v", err)
	}
}

func TestRegisterOwner_RejectsTamperedProof(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub := newService(t)
	doc := signedOwnerDoc(t, signer, signPub, nil)
	// Tamper the body after signing: flip the alsoKnownAs via JSON surgery so
	// the signed body no longer matches.
	raw, _ := json.Marshal(doc)
	var m map[string]any
	json.Unmarshal(raw, &m)
	m["alsoKnownAs"] = []any{"https://evil.example"}
	raw2, _ := json.Marshal(m)
	var tampered did.DIDDocument
	if err := json.Unmarshal(raw2, &tampered); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterOwner(ctx, &tampered, nil); !errors.Is(err, didregistry.ErrUnauthorized) {
		t.Errorf("tampered owner doc: want ErrUnauthorized, got %v", err)
	}
}

func TestRegisterOwner_RejectsForeignRegistry(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newService(t)
	// An owner whose registry segment is not this registry.
	foreignKP, _ := (ed25519.Generator{}).Generate()
	foreignDID := "did:dplaax:other.dplaax.dev:org:acme"
	ks := newMemKS()
	ks.SaveKeyPair(foreignDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: foreignKP})
	fsigner := ks
	base := did.New(did.DocumentFields{
		Context: did.IssuedDocumentContexts(),
		ID:      foreignDID, Controller: foreignDID,
		VerificationMethod: []did.VerificationMethod{mustMultikeyVM(foreignDID+"#signing", foreignDID, foreignKP.PublicKey)},
		AssertionMethod:    []string{foreignDID + "#signing"},
	})
	body := base.Body()
	proof, _ := vc.CreateProof(fsigner, foreignDID, "signing", foreignDID+"#signing", body, vc.CryptosuiteEdDSAJCS2022)
	pb, _ := json.Marshal(proof)
	var pm map[string]any
	json.Unmarshal(pb, &pm)
	body["proof"] = pm
	raw, _ := json.Marshal(body)
	var foreign did.DIDDocument
	json.Unmarshal(raw, &foreign)

	if _, err := svc.RegisterOwner(ctx, &foreign, nil); !errors.Is(err, didregistry.ErrUnauthorized) {
		t.Errorf("foreign-registry owner: want ErrUnauthorized, got %v", err)
	}
}

func TestIssue_RejectsDelegationTargetMismatch(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub := newService(t)
	registerOwner(t, svc, signer, signPub)
	// Delegation authorizes a different pipeline than the target.
	otherPipe := "did:dplaax:poc.dplaax.dev:org:acme:pipeline:other"
	_, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, otherPipe), nil)
	if !errors.Is(err, didregistry.ErrUnauthorized) {
		t.Errorf("delegation/target mismatch: want ErrUnauthorized, got %v", err)
	}
}

func TestIssuePipeline_RejectsUnregisteredOwner(t *testing.T) {
	ctx := context.Background()
	svc, signer, _ := newService(t)
	// Owner never registered → delegation.Verify cannot resolve it.
	_, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID), nil)
	if !errors.Is(err, didregistry.ErrUnauthorized) {
		t.Errorf("unregistered owner: want ErrUnauthorized, got %v", err)
	}
}

func TestIssueProcess_RequiresParentPipeline(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub := newService(t)
	registerOwner(t, svc, signer, signPub)
	// No pipeline issued → the parent pipeline does not resolve.
	_, _, err := svc.IssueProcess(ctx, processDID, mustDelegate(t, signer, processDID), nil)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("missing parent pipeline: want ErrNotFound, got %v", err)
	}
}

func TestUpdateStatus_RevokeRecordsEventAndChains(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub := newService(t)
	registerOwner(t, svc, signer, signPub)

	doc, err := svc.UpdateStatus(ctx, ownerDID, "revoked")
	if err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	if doc.ID() != ownerDID {
		t.Errorf("revoked doc id=%q", doc.ID())
	}
	log, err := svc.ReadLifecycleLog(ctx, ownerDID)
	if err != nil {
		t.Fatal(err)
	}
	if len(log) != 2 || log[1].EventType != "revoke" {
		t.Fatalf("log=%+v, want register then revoke", log)
	}
	// The revoke event chains to the register event (non-empty PrevEventHash).
	if log[1].PrevEventHash == "" {
		t.Error("revoke event PrevEventHash is empty, want a chain to the register event")
	}
	// Unsupported status is rejected.
	if _, err := svc.UpdateStatus(ctx, ownerDID, "active"); !errors.Is(err, didregistry.ErrInvalidArgument) {
		t.Errorf("unsupported status: want ErrInvalidArgument, got %v", err)
	}
}

func TestResolveDID_NotFound(t *testing.T) {
	svc, _, _ := newService(t)
	if _, err := svc.ResolveDID(context.Background(), ownerDID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("resolve absent owner: want ErrNotFound, got %v", err)
	}
}

func TestIssuePipeline_DuplicateIsErrExists(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub := newService(t)
	registerOwner(t, svc, signer, signPub)
	if _, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID), nil); err != nil {
		t.Fatalf("first issue: %v", err)
	}
	_, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID), nil)
	if !errors.Is(err, store.ErrExists) {
		t.Errorf("duplicate issue: want ErrExists, got %v", err)
	}
}

// A revoked owner cannot mint new pipelines (revocation enforces, not just
// audits — confirmed slice-4 intent).
func TestIssuePipeline_RejectsRevokedOwner(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub := newService(t)
	registerOwner(t, svc, signer, signPub)
	if _, err := svc.UpdateStatus(ctx, ownerDID, "revoked"); err != nil {
		t.Fatalf("revoke owner: %v", err)
	}
	_, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID), nil)
	if !errors.Is(err, didregistry.ErrUnauthorized) {
		t.Errorf("issue under revoked owner: want ErrUnauthorized, got %v", err)
	}
}

// A revoked pipeline cannot parent new processes.
func TestIssueProcess_RejectsRevokedPipeline(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub := newService(t)
	registerOwner(t, svc, signer, signPub)
	if _, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID), nil); err != nil {
		t.Fatalf("issue pipeline: %v", err)
	}
	if _, err := svc.UpdateStatus(ctx, pipelineDID, "revoked"); err != nil {
		t.Fatalf("revoke pipeline: %v", err)
	}
	_, _, err := svc.IssueProcess(ctx, processDID, mustDelegate(t, signer, processDID), nil)
	if !errors.Is(err, didregistry.ErrUnauthorized) {
		t.Errorf("issue process under revoked pipeline: want ErrUnauthorized, got %v", err)
	}
}

// A foreign-registry DID must not alias a local record: the yamlstore omits the
// registry from its path, so without the registry-segment gate on reads,
// resolving did:dplaax:other.../org:acme would return THIS registry's acme doc.
func TestResolveDID_RejectsForeignRegistry(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub := newService(t)
	registerOwner(t, svc, signer, signPub) // registers the local org:acme owner
	foreign := "did:dplaax:other.dplaax.dev:org:acme"
	got, err := svc.ResolveDID(ctx, foreign)
	if !errors.Is(err, didregistry.ErrUnauthorized) {
		t.Errorf("foreign-registry resolve: want ErrUnauthorized, got doc=%v err=%v", got, err)
	}
}

// The lifecycle chain is verifiable by an independent reimplementation of the
// event hash: a revoke event's PrevEventHash equals the canonical hash of the
// register event before it.
func TestLifecycleChain_IndependentlyVerifies(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub := newService(t)
	registerOwner(t, svc, signer, signPub)
	if _, err := svc.UpdateStatus(ctx, ownerDID, "revoked"); err != nil {
		t.Fatal(err)
	}
	log, err := svc.ReadLifecycleLog(ctx, ownerDID)
	if err != nil || len(log) != 2 {
		t.Fatalf("log=%+v, err=%v", log, err)
	}
	if want := independentEventHash(t, log[0]); log[1].PrevEventHash != want {
		t.Errorf("chain broken: revoke.PrevEventHash=%q, independent hash of register=%q", log[1].PrevEventHash, want)
	}
}

// independentEventHash recomputes the canonical event hash from scratch — a
// second implementation of the chain rule, so a drift in the service's hashEvent
// canonicalization is caught.
func independentEventHash(t *testing.T, ev store.LifecycleEvent) string {
	t.Helper()
	m := map[string]any{
		"eventType":      ev.EventType,
		"didDocSnapshot": ev.DIDDocSnapshot,
		"witnessSource":  ev.WitnessSource,
		"witnessedAt":    ev.WitnessedAt.UTC().Format(time.RFC3339Nano),
		"prevEventHash":  ev.PrevEventHash,
	}
	if len(ev.OutwardSnapshot) > 0 {
		m["outwardSnapshot"] = base64.StdEncoding.EncodeToString(ev.OutwardSnapshot)
	}
	h, err := jcs.Hash(m)
	if err != nil {
		t.Fatalf("jcs.Hash: %v", err)
	}
	return h
}

// A proof carrying any member outside the signed six rides unsigned and must be
// rejected.
func TestRegisterOwner_RejectsExtraProofMember(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub := newService(t)
	doc := signedOwnerDoc(t, signer, signPub, nil)
	raw, _ := json.Marshal(doc)
	var m map[string]any
	json.Unmarshal(raw, &m)
	proof := m["proof"].(map[string]any)
	proof["domain"] = "https://evil.example" // an extra, unsigned member
	raw2, _ := json.Marshal(m)
	var tampered did.DIDDocument
	if err := json.Unmarshal(raw2, &tampered); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterOwner(ctx, &tampered, nil); !errors.Is(err, didregistry.ErrUnauthorized) {
		t.Errorf("extra proof member: want ErrUnauthorized, got %v", err)
	}
}

// The bootstrap key must be listed under assertionMethod: a #signing key the
// document only lists under authentication must not validate the proof.
func TestRegisterOwner_RejectsWrongRelationshipKey(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub := newService(t)
	// Build a doc that lists #signing under authentication, not assertionMethod.
	base := did.New(did.DocumentFields{
		ID: ownerDID, Controller: ownerDID,
		VerificationMethod: []did.VerificationMethod{{
			ID: ownerDID + "#signing", Type: "JsonWebKey2020", Controller: ownerDID,
			PublicKeyJWK: ed25519JWK(signPub),
		}},
		Authentication: []string{ownerDID + "#signing"},
	})
	body := base.Body()
	proof, _ := vc.CreateProof(signer, ownerDID, "signing", ownerDID+"#signing", body, vc.CryptosuiteEdDSAJCS2022)
	pb, _ := json.Marshal(proof)
	var pm map[string]any
	json.Unmarshal(pb, &pm)
	body["proof"] = pm
	raw, _ := json.Marshal(body)
	var doc did.DIDDocument
	json.Unmarshal(raw, &doc)
	if _, err := svc.RegisterOwner(ctx, &doc, nil); !errors.Is(err, didregistry.ErrUnauthorized) {
		t.Errorf("wrong-relationship bootstrap key: want ErrUnauthorized, got %v", err)
	}
}

func TestRegisterOwner_RejectsUnsafeIntegerInsteadOfRoundingAtRest(t *testing.T) {
	// The registry stores and snapshots the document's RFC 8785 canonical
	// bytes, and unknown members survive into them (body-as-SoT). An unsafe
	// integer in one would be silently rounded at rest — the stored document's
	// self-signed proof would never verify again, minted as damaged evidence by
	// the registry itself. The admission gate makes that a loud
	// invalid-argument instead.
	svc, signer, signPub := newService(t)
	// Build a signed owner doc, then splice an unsafe-integer unknown member
	// into the wire AFTER signing — modeling an external submission whose body
	// carries one (a locally-built doc cannot: CreateProof gates it).
	doc := signedOwnerDoc(t, signer, signPub, nil)
	wire, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(wire, &m); err != nil {
		t.Fatal(err)
	}
	m["extCounter"] = json.Number("9007199254740993")
	spliced, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var submitted did.DIDDocument
	if err := json.Unmarshal(spliced, &submitted); err != nil {
		t.Fatalf("unmarshal spliced doc: %v", err)
	}
	doc = &submitted
	if _, err := svc.RegisterOwner(context.Background(), doc, nil); err == nil {
		t.Fatal("RegisterOwner admitted a document whose bytes it would silently rewrite")
	} else if !errors.Is(err, didregistry.ErrInvalidArgument) {
		t.Errorf("err = %v, want ErrInvalidArgument", err)
	}
}

// --- external-key issuance (PR3c) --------------------------------------------
//
// These tests cover the additive external-key path: the caller mints its own
// #auth/#signing Ed25519 keypair locally and hands the registry only the
// public halves (didregistry.ExternalPublicKeys). The registry must assemble
// and register a document over EXACTLY those public keys, and — the
// distinguishing property versus the server-side mint path — never write a
// keystore entry for the DID.

// The issued document's #auth/#signing verification methods carry exactly the
// supplied public keys (byte-exact, decoded back through the same Multikey
// path a real verifier uses), and the service's keystore holds no entry for
// the DID at all.
func TestIssuePipeline_ExternalKeys_RegistersSuppliedPublicKeysAndSkipsKeystore(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub, keys := newServiceWithKeys(t)
	registerOwner(t, svc, signer, signPub)

	authKP := localKeyPair(t)
	signKP := localKeyPair(t)
	ext := &didregistry.ExternalPublicKeys{AuthPublicKey: authKP.PublicKey, SigningPublicKey: signKP.PublicKey}

	doc, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID), ext)
	if err != nil {
		t.Fatalf("IssuePipeline (external keys): %v", err)
	}

	gotAuth, err := did.ExtractPublicKey(doc, pipelineDID+"#auth", did.RelationshipAuthentication)
	if err != nil {
		t.Fatalf("ExtractPublicKey(#auth): %v", err)
	}
	if !bytes.Equal(gotAuth, authKP.PublicKey) {
		t.Errorf("#auth key = %x, want the supplied %x", gotAuth, authKP.PublicKey)
	}
	gotSign, err := did.ExtractPublicKey(doc, pipelineDID+"#signing", did.RelationshipAssertionMethod)
	if err != nil {
		t.Fatalf("ExtractPublicKey(#signing): %v", err)
	}
	if !bytes.Equal(gotSign, signKP.PublicKey) {
		t.Errorf("#signing key = %x, want the supplied %x", gotSign, signKP.PublicKey)
	}

	// The distinguishing property: the registry's keystore holds nothing for
	// this DID — verified against the real keystore, not inferred.
	if _, err := keys.GetPrivateKey(pipelineDID, keystore.KeyIDAuth); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("keystore GetPrivateKey(#auth) = %v, want keystore.ErrNotFound (no entry)", err)
	}
	if _, err := keys.GetPrivateKey(pipelineDID, keystore.KeyIDSigning); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("keystore GetPrivateKey(#signing) = %v, want keystore.ErrNotFound (no entry)", err)
	}
}

// Same contract for IssueProcess: the process is minted under a mint-path
// pipeline (mixing both modes in one chain), and the process itself goes
// through the external-key path.
func TestIssueProcess_ExternalKeys_RegistersSuppliedPublicKeysAndSkipsKeystore(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub, keys := newServiceWithKeys(t)
	registerOwner(t, svc, signer, signPub)
	if _, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID), nil); err != nil {
		t.Fatalf("IssuePipeline (mint path parent): %v", err)
	}

	authKP := localKeyPair(t)
	signKP := localKeyPair(t)
	ext := &didregistry.ExternalPublicKeys{AuthPublicKey: authKP.PublicKey, SigningPublicKey: signKP.PublicKey}

	doc, _, err := svc.IssueProcess(ctx, processDID, mustDelegate(t, signer, processDID), ext)
	if err != nil {
		t.Fatalf("IssueProcess (external keys): %v", err)
	}
	gotAuth, err := did.ExtractPublicKey(doc, processDID+"#auth", did.RelationshipAuthentication)
	if err != nil {
		t.Fatalf("ExtractPublicKey(#auth): %v", err)
	}
	if !bytes.Equal(gotAuth, authKP.PublicKey) {
		t.Errorf("#auth key = %x, want the supplied %x", gotAuth, authKP.PublicKey)
	}
	gotSign, err := did.ExtractPublicKey(doc, processDID+"#signing", did.RelationshipAssertionMethod)
	if err != nil {
		t.Fatalf("ExtractPublicKey(#signing): %v", err)
	}
	if !bytes.Equal(gotSign, signKP.PublicKey) {
		t.Errorf("#signing key = %x, want the supplied %x", gotSign, signKP.PublicKey)
	}
	if _, err := keys.GetPrivateKey(processDID, keystore.KeyIDAuth); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("keystore GetPrivateKey(#auth) = %v, want keystore.ErrNotFound (no entry)", err)
	}
	// The parent pipeline, by contrast, went through the mint path and DOES
	// hold a keystore entry — pinning that the "no entry" assertion above is
	// about the external-key DID specifically, not an artifact of an empty
	// keystore.
	if _, err := keys.GetPrivateKey(pipelineDID, keystore.KeyIDSigning); err != nil {
		t.Errorf("mint-path parent pipeline keystore entry missing: %v", err)
	}
}

// The mint path (ext == nil) is unchanged: it still populates the keystore.
// This is the contrapositive of the external-key "no entry" assertion above —
// together they pin that presence/absence of the keystore entry tracks ext,
// not some incidental test-fixture difference.
func TestIssuePipeline_MintPath_StillPopulatesKeystore(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub, keys := newServiceWithKeys(t)
	registerOwner(t, svc, signer, signPub)

	if _, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID), nil); err != nil {
		t.Fatalf("IssuePipeline (mint path): %v", err)
	}
	if _, err := keys.GetPrivateKey(pipelineDID, keystore.KeyIDAuth); err != nil {
		t.Errorf("mint path did not persist #auth key: %v", err)
	}
	if _, err := keys.GetPrivateKey(pipelineDID, keystore.KeyIDSigning); err != nil {
		t.Errorf("mint path did not persist #signing key: %v", err)
	}
}

// A malformed (short or absent) external public key is fail-closed
// InvalidArgument, never silently zero-padded or accepted into a document a
// holder cannot actually use.
func TestIssuePipeline_ExternalKeys_RejectsInvalidKeys(t *testing.T) {
	validKP := localKeyPair(t)
	cases := []struct {
		name       string
		ext        *didregistry.ExternalPublicKeys
		smallOrder bool
	}{
		{"short auth key", &didregistry.ExternalPublicKeys{AuthPublicKey: []byte{1, 2, 3}, SigningPublicKey: validKP.PublicKey}, false},
		{"short signing key", &didregistry.ExternalPublicKeys{AuthPublicKey: validKP.PublicKey, SigningPublicKey: []byte{1, 2, 3}}, false},
		{"zero-length auth key", &didregistry.ExternalPublicKeys{AuthPublicKey: nil, SigningPublicKey: validKP.PublicKey}, false},
		{"zero-length signing key", &didregistry.ExternalPublicKeys{AuthPublicKey: validKP.PublicKey, SigningPublicKey: nil}, false},
		{"oversized auth key", &didregistry.ExternalPublicKeys{AuthPublicKey: append(append([]byte{}, validKP.PublicKey...), 0xff), SigningPublicKey: validKP.PublicKey}, false},
		// An all-zeros key is a small-order point no private key matches —
		// forgeable by anyone; the mint path can never produce it.
		{"all-zeros auth key", &didregistry.ExternalPublicKeys{AuthPublicKey: make([]byte, 32), SigningPublicKey: validKP.PublicKey}, true},
		{"all-zeros signing key", &didregistry.ExternalPublicKeys{AuthPublicKey: validKP.PublicKey, SigningPublicKey: make([]byte, 32)}, true},
		// Every small-order point is a key anyone can sign with, in any encoding.
		{"identity as auth key", &didregistry.ExternalPublicKeys{AuthPublicKey: mustHex(t, "0100000000000000000000000000000000000000000000000000000000000000"), SigningPublicKey: validKP.PublicKey}, true},
		{"identity as signing key", &didregistry.ExternalPublicKeys{AuthPublicKey: validKP.PublicKey, SigningPublicKey: mustHex(t, "0100000000000000000000000000000000000000000000000000000000000000")}, true},
		{"identity with sign bit as auth key", &didregistry.ExternalPublicKeys{AuthPublicKey: mustHex(t, "0100000000000000000000000000000000000000000000000000000000000080"), SigningPublicKey: validKP.PublicKey}, true},
		{"identity with sign bit as signing key", &didregistry.ExternalPublicKeys{AuthPublicKey: validKP.PublicKey, SigningPublicKey: mustHex(t, "0100000000000000000000000000000000000000000000000000000000000080")}, true},
		{"order-2 point as auth key", &didregistry.ExternalPublicKeys{AuthPublicKey: mustHex(t, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), SigningPublicKey: validKP.PublicKey}, true},
		{"order-2 point as signing key", &didregistry.ExternalPublicKeys{AuthPublicKey: validKP.PublicKey, SigningPublicKey: mustHex(t, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")}, true},
		{"order-4 point as auth key", &didregistry.ExternalPublicKeys{AuthPublicKey: mustHex(t, "0000000000000000000000000000000000000000000000000000000000000080"), SigningPublicKey: validKP.PublicKey}, true},
		{"order-4 point as signing key", &didregistry.ExternalPublicKeys{AuthPublicKey: validKP.PublicKey, SigningPublicKey: mustHex(t, "0000000000000000000000000000000000000000000000000000000000000080")}, true},
		{"order-8 point as auth key", &didregistry.ExternalPublicKeys{AuthPublicKey: mustHex(t, "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), SigningPublicKey: validKP.PublicKey}, true},
		{"order-8 point as signing key", &didregistry.ExternalPublicKeys{AuthPublicKey: validKP.PublicKey, SigningPublicKey: mustHex(t, "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")}, true},
		{"non-canonical identity as auth key", &didregistry.ExternalPublicKeys{AuthPublicKey: mustHex(t, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), SigningPublicKey: validKP.PublicKey}, true},
		{"non-canonical identity as signing key", &didregistry.ExternalPublicKeys{AuthPublicKey: validKP.PublicKey, SigningPublicKey: mustHex(t, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")}, true},
		// The mint path always produces DISTINCT auth/signing keys; the external
		// path preserves that separation.
		{"identical auth and signing keys", &didregistry.ExternalPublicKeys{AuthPublicKey: validKP.PublicKey, SigningPublicKey: validKP.PublicKey}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			svc, signer, signPub, keys := newServiceWithKeys(t)
			registerOwner(t, svc, signer, signPub)

			_, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID), tc.ext)
			if !errors.Is(err, didregistry.ErrInvalidArgument) {
				t.Errorf("err = %v, want ErrInvalidArgument", err)
			}
			if got := errors.Is(err, ed25519.ErrSmallOrder); got != tc.smallOrder {
				t.Errorf("errors.Is(err, ErrSmallOrder) = %v, want %v (err = %v)", got, tc.smallOrder, err)
			}
			// The rejected attempt must leave no trace: no document, no keys.
			if _, rerr := svc.ResolveDID(ctx, pipelineDID); !errors.Is(rerr, store.ErrNotFound) {
				t.Errorf("resolve after rejected issue: want ErrNotFound, got %v", rerr)
			}
			if _, kerr := keys.GetPrivateKey(pipelineDID, keystore.KeyIDAuth); !errors.Is(kerr, keystore.ErrNotFound) {
				t.Errorf("keystore after rejected issue: want ErrNotFound, got %v", kerr)
			}
		})
	}
}

// The e2e-shaped proof this feature exists for: a credential signed with the
// LOCAL private key (never seen by the registry) verifies against the
// registry-resolved document. Sign locally, resolve+verify through the
// registry — the same shape a real holder/verifier pair would use.
func TestIssuePipeline_ExternalKeys_LocalPrivateKeySignsAndVerifiesAgainstResolvedDocument(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub, keys := newServiceWithKeys(t)
	registerOwner(t, svc, signer, signPub)

	signKP := localKeyPair(t) // the loop's local signing key — never sent to the registry
	authKP := localKeyPair(t)
	ext := &didregistry.ExternalPublicKeys{AuthPublicKey: authKP.PublicKey, SigningPublicKey: signKP.PublicKey}
	if _, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID), ext); err != nil {
		t.Fatalf("IssuePipeline (external keys): %v", err)
	}
	// Confirm the registry never learned the private key at all (belt and
	// braces alongside the dedicated keystore-emptiness tests above).
	if _, err := keys.GetPrivateKey(pipelineDID, keystore.KeyIDSigning); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("keystore holds a #signing entry for the externally-keyed DID: %v", err)
	}

	// Resolve the document THROUGH THE REGISTRY, exactly as an independent
	// verifier would.
	resolved, err := svc.ResolveDID(ctx, pipelineDID)
	if err != nil {
		t.Fatalf("ResolveDID: %v", err)
	}

	// Sign a small "credential" body with ONLY the local private key.
	localSigner := localSigner{priv: signKP.PrivateKey}
	body := map[string]any{
		// []any, not []string — the JCS canonicalizer works over the
		// interface{} shapes json.Unmarshal produces (did.New does the same
		// conversion internally via toAnySlice for a typed []string field).
		"@context": []any{did.ContextDIDV1, did.ContextMultikeyV1},
		"claim":    "signed locally, never touched the registry's keystore",
	}
	proof, err := vc.CreateProof(localSigner, pipelineDID, string(keystore.KeyIDSigning), pipelineDID+"#signing", body, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof (local signer): %v", err)
	}

	// Verify against the key extracted from the REGISTRY-RESOLVED document —
	// not against the local keypair directly, closing the loop the feature is
	// for.
	pub, encoding, err := did.ExtractPublicKeyAndEncoding(resolved, pipelineDID+"#signing", did.RelationshipAssertionMethod)
	if err != nil {
		t.Fatalf("ExtractPublicKeyAndEncoding: %v", err)
	}
	if _, err := vc.VerifyProofWithContract(ed25519.Verifier{}, pub, encoding, proof, body); err != nil {
		t.Errorf("credential signed locally does not verify against the registry-resolved document: %v", err)
	}
}

func mustHex(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Every Ed25519 key in an owner document is checked, whatever relationship
// lists it: an honest #signing beside an unusable #auth is refused, and the
// owner is never served.
func TestRegisterOwner_RefusesInvalidKeyInAnyVerificationMethod(t *testing.T) {
	keys := []struct {
		name string
		key  []byte
		want error
	}{
		{"identity", mustHex(t, "0100000000000000000000000000000000000000000000000000000000000000"), ed25519.ErrSmallOrder},
		{"off the curve", mustHex(t, "0200000000000000000000000000000000000000000000000000000000000000"), ed25519.ErrInvalidPoint},
		{"31 bytes", make([]byte, 31), ed25519.ErrPublicKeySize},
	}
	for _, k := range keys {
		for _, rel := range []string{"authentication", "assertionMethod"} {
			t.Run(k.name+"/"+rel, func(t *testing.T) {
				svc, signer, signPub := newService(t)
				fields := did.DocumentFields{
					Context:    did.IssuedDocumentContexts(),
					ID:         ownerDID,
					Controller: ownerDID,
					VerificationMethod: []did.VerificationMethod{
						mustMultikeyVM(ownerDID+"#signing", ownerDID, signPub),
						rawMultikeyVM(ownerDID+"#auth", ownerDID, k.key),
					},
					AssertionMethod: []string{ownerDID + "#signing"},
				}
				if rel == "authentication" {
					fields.Authentication = []string{ownerDID + "#auth"}
				} else {
					fields.AssertionMethod = append(fields.AssertionMethod, ownerDID+"#auth")
				}
				doc := signedOwnerDocFields(t, signer, fields)

				_, err := svc.RegisterOwner(context.Background(), doc, nil)
				if !errors.Is(err, didregistry.ErrInvalidArgument) || !errors.Is(err, did.ErrInvalidPublicKey) || !errors.Is(err, k.want) {
					t.Fatalf("err = %v, want ErrInvalidArgument wrapping did.ErrInvalidPublicKey and %v", err, k.want)
				}
				if _, rerr := svc.ResolveDID(context.Background(), ownerDID); !errors.Is(rerr, store.ErrNotFound) {
					t.Errorf("resolve after refused registration: want ErrNotFound, got %v", rerr)
				}
			})
		}
	}
}

// The proof's own key is held to the same rule as every other listed key: an
// owner document whose #signing key is unusable is an invalid argument, with
// the key's error kept, and the owner is never served.
func TestRegisterOwner_RefusesInvalidSigningKeyAsInvalidArgument(t *testing.T) {
	identity := mustHex(t, "0100000000000000000000000000000000000000000000000000000000000000")
	svc, signer, _ := newService(t)
	doc := signedOwnerDocFields(t, signer, did.DocumentFields{
		Context:            did.IssuedDocumentContexts(),
		ID:                 ownerDID,
		Controller:         ownerDID,
		VerificationMethod: []did.VerificationMethod{rawMultikeyVM(ownerDID+"#signing", ownerDID, identity)},
		AssertionMethod:    []string{ownerDID + "#signing"},
	})

	_, err := svc.RegisterOwner(context.Background(), doc, nil)
	if !errors.Is(err, didregistry.ErrInvalidArgument) || !errors.Is(err, did.ErrInvalidPublicKey) || !errors.Is(err, ed25519.ErrSmallOrder) {
		t.Fatalf("err = %v, want ErrInvalidArgument wrapping did.ErrInvalidPublicKey and ErrSmallOrder", err)
	}
	if _, rerr := svc.ResolveDID(context.Background(), ownerDID); !errors.Is(rerr, store.ErrNotFound) {
		t.Errorf("resolve after refused registration: want ErrNotFound, got %v", rerr)
	}
}

// signedOwnerDocWith signs an owner document built from fields after mutate
// edits its body: the way to build shapes did.DocumentFields cannot express
// (embedded methods, extra members).
func signedOwnerDocWith(t *testing.T, signer crypto.Signer, fields did.DocumentFields, mutate func(body map[string]any)) *did.DIDDocument {
	t.Helper()
	body := did.New(fields).Body()
	if mutate != nil {
		mutate(body)
	}
	return signedOwnerDocBody(t, signer, body)
}

func multikeyMap(id, controller string, pub []byte) map[string]any {
	return map[string]any{"id": id, "type": "Multikey", "controller": controller,
		"publicKeyMultibase": multibase.EncodeBase58Btc(append([]byte{0xed, 0x01}, pub...))}
}

// The registry stores an owner document only when every key in it is one a
// reader here extracts: every verification method and every entry of
// authentication and assertionMethod resolves through did.ExtractPublicKey,
// and nothing else in the document carries a key (an embedded method, the
// legacy publicKey member). The registry serves the document to resolvers
// outside this repository, whose readers may pick among other keys
// differently.
func TestRegisterOwner_RefusesKeysNoReaderHereExtracts(t *testing.T) {
	identity := mustHex(t, "0100000000000000000000000000000000000000000000000000000000000000")
	other, err := ed25519.Generator{}.Generate()
	if err != nil {
		t.Fatal(err)
	}
	const otherOrg = "did:dplaax:poc.dplaax.dev:org:other"
	cases := []struct {
		name        string
		vms         func(signPub []byte) []did.VerificationMethod
		auth        []string
		mutate      func(body map[string]any)
		unusableKey bool
		reason      string // a part of the error the case must fail with; empty for any
	}{
		{name: "an unlisted method with a usable key", vms: func(p []byte) []did.VerificationMethod {
			return []did.VerificationMethod{mustMultikeyVM(ownerDID+"#signing", ownerDID, p), mustMultikeyVM(ownerDID+"#spare", ownerDID, other.PublicKey)}
		}},
		{name: "an unlisted method with a small-order key", vms: func(p []byte) []did.VerificationMethod {
			return []did.VerificationMethod{mustMultikeyVM(ownerDID+"#signing", ownerDID, p), rawMultikeyVM(ownerDID+"#spare", ownerDID, identity)}
		}},
		{name: "two methods sharing a listed id, one with a small-order key", auth: []string{ownerDID + "#auth"}, vms: func(p []byte) []did.VerificationMethod {
			return []did.VerificationMethod{mustMultikeyVM(ownerDID+"#signing", ownerDID, p), mustMultikeyVM(ownerDID+"#auth", ownerDID, other.PublicKey), rawMultikeyVM(ownerDID+"#auth", ownerDID, identity)}
		}},
		{name: "two #signing methods", vms: func(p []byte) []did.VerificationMethod {
			return []did.VerificationMethod{mustMultikeyVM(ownerDID+"#signing", ownerDID, p), mustMultikeyVM(ownerDID+"#signing", ownerDID, other.PublicKey)}
		}},
		{name: "a listed method with another multicodec", auth: []string{ownerDID + "#auth"}, vms: func(p []byte) []did.VerificationMethod {
			return []did.VerificationMethod{mustMultikeyVM(ownerDID+"#signing", ownerDID, p), {
				ID: ownerDID + "#auth", Type: "Multikey", Controller: ownerDID,
				PublicKeyMultibase: multibase.EncodeBase58Btc(append([]byte{0x12, 0x20}, other.PublicKey...)),
			}}
		}},
		{name: "a listed method of an unknown type", auth: []string{ownerDID + "#auth"}, vms: func(p []byte) []did.VerificationMethod {
			return []did.VerificationMethod{mustMultikeyVM(ownerDID+"#signing", ownerDID, p), {
				ID: ownerDID + "#auth", Type: "X25519KeyAgreementKey2020", Controller: ownerDID,
				PublicKeyMultibase: "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
			}}
		}},
		{name: "a listed method controlled by another DID", auth: []string{ownerDID + "#auth"}, vms: func(p []byte) []did.VerificationMethod {
			return []did.VerificationMethod{mustMultikeyVM(ownerDID+"#signing", ownerDID, p), mustMultikeyVM(ownerDID+"#auth", otherOrg, other.PublicKey)}
		}},
		{name: "a listed JWK method that is not Ed25519", auth: []string{ownerDID + "#auth"}, vms: func(p []byte) []did.VerificationMethod {
			return []did.VerificationMethod{mustMultikeyVM(ownerDID+"#signing", ownerDID, p), {
				ID: ownerDID + "#auth", Type: "JsonWebKey2020", Controller: ownerDID,
				PublicKeyJWK: map[string]any{"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "AAAA"},
			}}
		}},
		{name: "a reference to a key of another DID", mutate: func(b map[string]any) {
			b["assertionMethod"] = append(b["assertionMethod"].([]any), otherOrg+"#signing")
		}},
		{name: "a reference to no method", mutate: func(b map[string]any) {
			b["authentication"] = []any{ownerDID + "#missing"}
		}},
		{name: "an embedded method with a small-order key", mutate: func(b map[string]any) {
			b["authentication"] = []any{multikeyMap(ownerDID+"#embedded", ownerDID, identity)}
		}},
		{name: "an embedded second #signing", mutate: func(b map[string]any) {
			b["assertionMethod"] = append(b["assertionMethod"].([]any), multikeyMap(ownerDID+"#signing", ownerDID, other.PublicKey))
		}},
		{name: "an embedded method under keyAgreement", mutate: func(b map[string]any) {
			b["keyAgreement"] = []any{multikeyMap(ownerDID+"#agree", ownerDID, other.PublicKey)}
		}},
		{name: "the legacy publicKey member", mutate: func(b map[string]any) {
			b["publicKey"] = []any{multikeyMap(ownerDID+"#legacy", ownerDID, other.PublicKey)}
		}},
		{name: "a method whose id names another DID", reason: "spelled #fragment", mutate: func(b map[string]any) {
			b["verificationMethod"] = append(b["verificationMethod"].([]any), multikeyMap(otherOrg+"#signing", ownerDID, other.PublicKey))
			b["authentication"] = []any{otherOrg + "#signing"}
		}},
		{name: "a method id with two fragments", reason: "spelled #fragment", mutate: func(b map[string]any) {
			b["verificationMethod"] = append(b["verificationMethod"].([]any), multikeyMap(ownerDID+"#x#auth", ownerDID, other.PublicKey))
			b["authentication"] = []any{ownerDID + "#x#auth"}
		}},
		{name: "a reference with two fragments that resolves to #signing here", reason: "spelled #fragment", mutate: func(b map[string]any) {
			b["authentication"] = []any{"#x#signing"}
		}},
		{name: "a bare reference without #", reason: "spelled #fragment", mutate: func(b map[string]any) {
			b["authentication"] = []any{"signing"}
		}},
		{name: "a reference with an empty fragment", reason: "spelled #fragment", mutate: func(b map[string]any) {
			b["capabilityInvocation"] = []any{ownerDID + "#"}
		}},
		{name: "a percent-encoded fragment read elsewhere as #signing", reason: "spelled #fragment", mutate: func(b map[string]any) {
			b["verificationMethod"] = append(b["verificationMethod"].([]any), multikeyMap(ownerDID+"#sign%69ng", ownerDID, other.PublicKey))
			b["assertionMethod"] = append(b["assertionMethod"].([]any), "#sign%69ng")
		}},
		{name: "a fragment with a tab", reason: "spelled #fragment", mutate: func(b map[string]any) {
			b["verificationMethod"] = append(b["verificationMethod"].([]any), multikeyMap(ownerDID+"#sig\tning", ownerDID, other.PublicKey))
			b["assertionMethod"] = append(b["assertionMethod"].([]any), ownerDID+"#sig\tning")
		}},
		{name: "a fragment with a trailing space", reason: "spelled #fragment", mutate: func(b map[string]any) {
			b["verificationMethod"] = append(b["verificationMethod"].([]any), multikeyMap(ownerDID+"#signing ", ownerDID, other.PublicKey))
			b["assertionMethod"] = append(b["assertionMethod"].([]any), ownerDID+"#signing ")
		}},
		{name: "a non-ASCII fragment", reason: "spelled #fragment", mutate: func(b map[string]any) {
			b["verificationMethod"] = append(b["verificationMethod"].([]any), multikeyMap(ownerDID+"#sígning", ownerDID, other.PublicKey))
			b["authentication"] = []any{ownerDID + "#sígning"}
		}},
		{name: "a capabilityDelegation reference to another DID", reason: "spelled #fragment", mutate: func(b map[string]any) {
			b["capabilityDelegation"] = []any{otherOrg + "#signing"}
		}},
		{name: "a keyAgreement reference to another DID", reason: "spelled #fragment", mutate: func(b map[string]any) {
			b["keyAgreement"] = []any{otherOrg + "#agree"}
		}},
		{name: "keyAgreement as a single embedded method", mutate: func(b map[string]any) {
			b["keyAgreement"] = multikeyMap(ownerDID+"#agree", ownerDID, other.PublicKey)
		}},
		{name: "capabilityInvocation as a single reference to another DID", mutate: func(b map[string]any) {
			b["capabilityInvocation"] = otherOrg + "#signing"
		}},
		{name: "capabilityDelegation as a single embedded method", mutate: func(b map[string]any) {
			b["capabilityDelegation"] = multikeyMap(ownerDID+"#delegate", ownerDID, identity)
		}},
		{name: "publicKey as a single method", mutate: func(b map[string]any) {
			b["publicKey"] = multikeyMap(ownerDID+"#legacy", ownerDID, other.PublicKey)
		}},
		{name: "a verificationMethod entry that is not an object", mutate: func(b map[string]any) {
			b["verificationMethod"] = append(b["verificationMethod"].([]any), ownerDID+"#signing")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, signer, signPub := newService(t)
			vms := []did.VerificationMethod{mustMultikeyVM(ownerDID+"#signing", ownerDID, signPub)}
			if tc.vms != nil {
				vms = tc.vms(signPub)
			}
			doc := signedOwnerDocWith(t, signer, did.DocumentFields{
				Context:            did.IssuedDocumentContexts(),
				ID:                 ownerDID,
				Controller:         ownerDID,
				VerificationMethod: vms,
				AssertionMethod:    []string{ownerDID + "#signing"},
				Authentication:     tc.auth,
			}, tc.mutate)
			_, err := svc.RegisterOwner(context.Background(), doc, nil)
			if !errors.Is(err, didregistry.ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
			if got := errors.Is(err, did.ErrInvalidPublicKey); got != tc.unusableKey {
				t.Errorf("errors.Is(err, did.ErrInvalidPublicKey) = %v, want %v (err = %v)", got, tc.unusableKey, err)
			}
			if tc.reason != "" && !strings.Contains(err.Error(), tc.reason) {
				t.Errorf("err = %v, want one about %q", err, tc.reason)
			}
			if strings.Contains(err.Error(), "\n") {
				t.Errorf("the error spans lines: %q", err)
			}
			if _, rerr := svc.ResolveDID(context.Background(), ownerDID); !errors.Is(rerr, store.ErrNotFound) {
				t.Errorf("resolve after refused registration: want ErrNotFound, got %v", rerr)
			}
		})
	}
}

// A document whose every key a reader here extracts is registered, with
// methods listed under one relationship or both.
func TestRegisterOwner_AcceptsDocumentsWhoseKeysAllExtract(t *testing.T) {
	auth, err := ed25519.Generator{}.Generate()
	if err != nil {
		t.Fatal(err)
	}
	both, err := ed25519.Generator{}.Generate()
	if err != nil {
		t.Fatal(err)
	}
	svc, signer, signPub := newService(t)
	doc := signedOwnerDocWith(t, signer, did.DocumentFields{
		Context:    did.IssuedDocumentContexts(),
		ID:         ownerDID,
		Controller: ownerDID,
		VerificationMethod: []did.VerificationMethod{
			mustMultikeyVM(ownerDID+"#signing", ownerDID, signPub),
			mustMultikeyVM(ownerDID+"#auth", ownerDID, auth.PublicKey),
			mustMultikeyVM(ownerDID+"#both", ownerDID, both.PublicKey),
		},
		AssertionMethod: []string{ownerDID + "#signing", ownerDID + "#both"},
		Authentication:  []string{ownerDID + "#auth", "#both"},
	}, func(b map[string]any) {
		// A relative method id, and a reference to an own key under another
		// relationship.
		vms := b["verificationMethod"].([]any)
		vms[1].(map[string]any)["id"] = "#auth"
		b["keyAgreement"] = []any{ownerDID + "#auth"}
	})
	if _, err := svc.RegisterOwner(context.Background(), doc, nil); err != nil {
		t.Fatalf("RegisterOwner: %v", err)
	}
}
