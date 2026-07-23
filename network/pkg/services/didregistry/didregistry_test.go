package didregistry_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
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
	base := did.New(did.DocumentFields{
		Context:            did.IssuedDocumentContexts(),
		ID:                 ownerDID,
		Controller:         ownerDID,
		AlsoKnownAs:        aka,
		VerificationMethod: []did.VerificationMethod{mustMultikeyVM(ownerDID+"#signing", ownerDID, signPub)},
		AssertionMethod:    []string{ownerDID + "#signing"},
	})
	body := base.Body()
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
func TestIssuePipeline_ExternalKeys_RejectsMalformedKeyLength(t *testing.T) {
	validKP := localKeyPair(t)
	cases := []struct {
		name string
		ext  *didregistry.ExternalPublicKeys
	}{
		{"short auth key", &didregistry.ExternalPublicKeys{AuthPublicKey: []byte{1, 2, 3}, SigningPublicKey: validKP.PublicKey}},
		{"short signing key", &didregistry.ExternalPublicKeys{AuthPublicKey: validKP.PublicKey, SigningPublicKey: []byte{1, 2, 3}}},
		{"zero-length auth key", &didregistry.ExternalPublicKeys{AuthPublicKey: nil, SigningPublicKey: validKP.PublicKey}},
		{"zero-length signing key", &didregistry.ExternalPublicKeys{AuthPublicKey: validKP.PublicKey, SigningPublicKey: nil}},
		{"oversized auth key", &didregistry.ExternalPublicKeys{AuthPublicKey: append(append([]byte{}, validKP.PublicKey...), 0xff), SigningPublicKey: validKP.PublicKey}},
		// An all-zeros key is a small-order point no private key matches —
		// forgeable by anyone; the mint path can never produce it.
		{"all-zeros auth key", &didregistry.ExternalPublicKeys{AuthPublicKey: make([]byte, 32), SigningPublicKey: validKP.PublicKey}},
		{"all-zeros signing key", &didregistry.ExternalPublicKeys{AuthPublicKey: validKP.PublicKey, SigningPublicKey: make([]byte, 32)}},
		// The mint path always produces DISTINCT auth/signing keys; the external
		// path preserves that separation.
		{"identical auth and signing keys", &didregistry.ExternalPublicKeys{AuthPublicKey: validKP.PublicKey, SigningPublicKey: validKP.PublicKey}},
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
