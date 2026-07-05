package didregistry_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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

const (
	registry    = "poc.dplaax.dev"
	ownerDID    = "did:dplaax:poc.dplaax.dev:org:acme"
	pipelineDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1"
	processDID  = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1"
)

// --- in-memory keystore -----------------------------------------------------

var errKeyNotFound = errors.New("key not found")

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
	ownerKP, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate owner key: %v", err)
	}
	ownerKS := newMemKS()
	if err := ownerKS.SaveKeyPair(ownerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: ownerKP}); err != nil {
		t.Fatalf("save owner key: %v", err)
	}
	svc := didregistry.New(
		yamlstore.New(t.TempDir()),
		newMemKS(),
		ed25519.Generator{},
		ed25519.Verifier{},
		registry,
		didregistry.WithClock(fixedClock),
		didregistry.WithServiceEndpoints([]did.ServiceEndpoint{
			{ID: "#vc-resolver", Type: "VCResolver", ServiceEndpoint: "https://" + registry + "/vc"},
		}),
	)
	return svc, ed25519.NewSigner(ownerKS), ownerKP.PublicKey
}

func ed25519JWK(pub []byte) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
}

// signedOwnerDoc builds an owner DID document with a #signing assertion key and
// a self-signed Data Integrity proof over the document body.
func signedOwnerDoc(t *testing.T, signer crypto.Signer, signPub []byte, aka []string) *did.DIDDocument {
	t.Helper()
	base := did.New(did.DocumentFields{
		Context:     []string{"https://www.w3.org/ns/did/v1"},
		ID:          ownerDID,
		Controller:  ownerDID,
		AlsoKnownAs: aka,
		VerificationMethod: []did.VerificationMethod{{
			ID: ownerDID + "#signing", Type: "JsonWebKey2020", Controller: ownerDID,
			PublicKeyJWK: ed25519JWK(signPub),
		}},
		AssertionMethod: []string{ownerDID + "#signing"},
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

	pipeDoc, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID))
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

	procDoc, _, err := svc.IssueProcess(ctx, processDID, mustDelegate(t, signer, processDID))
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
	if _, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID)); !errors.Is(err, didregistry.ErrUnauthorized) {
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
	fsigner := ed25519.NewSigner(ks)
	base := did.New(did.DocumentFields{
		ID: foreignDID, Controller: foreignDID,
		VerificationMethod: []did.VerificationMethod{{
			ID: foreignDID + "#signing", Type: "JsonWebKey2020", Controller: foreignDID,
			PublicKeyJWK: ed25519JWK(foreignKP.PublicKey),
		}},
		AssertionMethod: []string{foreignDID + "#signing"},
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
	_, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, otherPipe))
	if !errors.Is(err, didregistry.ErrUnauthorized) {
		t.Errorf("delegation/target mismatch: want ErrUnauthorized, got %v", err)
	}
}

func TestIssuePipeline_RejectsUnregisteredOwner(t *testing.T) {
	ctx := context.Background()
	svc, signer, _ := newService(t)
	// Owner never registered → delegation.Verify cannot resolve it.
	_, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID))
	if !errors.Is(err, didregistry.ErrUnauthorized) {
		t.Errorf("unregistered owner: want ErrUnauthorized, got %v", err)
	}
}

func TestIssueProcess_RequiresParentPipeline(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub := newService(t)
	registerOwner(t, svc, signer, signPub)
	// No pipeline issued → the parent pipeline does not resolve.
	_, _, err := svc.IssueProcess(ctx, processDID, mustDelegate(t, signer, processDID))
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
	if _, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID)); err != nil {
		t.Fatalf("first issue: %v", err)
	}
	_, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID))
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
	_, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID))
	if !errors.Is(err, didregistry.ErrUnauthorized) {
		t.Errorf("issue under revoked owner: want ErrUnauthorized, got %v", err)
	}
}

// A revoked pipeline cannot parent new processes.
func TestIssueProcess_RejectsRevokedPipeline(t *testing.T) {
	ctx := context.Background()
	svc, signer, signPub := newService(t)
	registerOwner(t, svc, signer, signPub)
	if _, _, err := svc.IssuePipeline(ctx, pipelineDID, mustDelegate(t, signer, pipelineDID)); err != nil {
		t.Fatalf("issue pipeline: %v", err)
	}
	if _, err := svc.UpdateStatus(ctx, pipelineDID, "revoked"); err != nil {
		t.Fatalf("revoke pipeline: %v", err)
	}
	_, _, err := svc.IssueProcess(ctx, processDID, mustDelegate(t, signer, processDID))
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
