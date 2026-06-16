// Package didregistry is the domain service of the DID-lifecycle registry: it
// registers self-sovereign Owner DIDs, issues Pipeline/Process DIDs under
// owner-signed delegations, resolves documents and delegations, revokes, lists,
// and maintains each DID's append-only lifecycle log. It holds no proto types
// (the handler's boundary) and no persistence logic (the store's); it owns the
// cryptographic checks, key generation, and the lifecycle hash chain.
//
// Trust model (owner-whitelist): an Owner is a self-sovereign root whose keys
// are caller-supplied — registration proves key control with a self-signed
// document proof, not prior authorization. Pipeline/Process keys are generated
// here at issuance and the authority to mint them is an owner-signed delegation
// whose subject is structurally under the owner on the did:dplaax plane.
package didregistry

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store"
	"github.com/provin-line/oss/vc"
)

// Sentinel errors. ErrNotFound / ErrExists / ErrConflict from the store package
// surface unchanged; handlers map all of these to Connect codes with errors.Is.
var (
	// ErrInvalidArgument is a malformed request (bad DID, wrong shape, unknown
	// status).
	ErrInvalidArgument = errors.New("didregistry: invalid argument")
	// ErrUnauthorized is a failed cryptographic check: a bad self-signed owner
	// proof, a delegation that does not verify, or a cross-registry DID.
	ErrUnauthorized = errors.New("didregistry: unauthorized")
)

const (
	eventRegister = "register"
	eventRevoke   = "revoke"
	// witnessSelfAsserted is the witness source until registry-side outward
	// resolution (D-d4 part A) lands.
	witnessSelfAsserted = "self-asserted"
	jwkType             = "JsonWebKey2020"
)

// Service is the DID-lifecycle domain service.
type Service struct {
	store     store.DIDStore
	keys      keystore.KeyStore
	keygen    crypto.KeyGenerator
	verifier  crypto.Verifier
	registry  string
	endpoints []did.ServiceEndpoint
	clock     func() time.Time
}

// Option configures a Service.
type Option func(*Service)

// WithClock overrides the lifecycle-event witnessed-at clock (registry receipt
// time). Defaults to time.Now; tests inject a fixed clock for determinism.
func WithClock(clock func() time.Time) Option {
	return func(s *Service) { s.clock = clock }
}

// WithServiceEndpoints sets the service endpoints embedded in every issued
// Pipeline/Process document. Each endpoint's ID is treated as a fragment and
// re-anchored to the issued DID (e.g. "#vc-resolver" → "{did}#vc-resolver").
func WithServiceEndpoints(eps []did.ServiceEndpoint) Option {
	return func(s *Service) { s.endpoints = append([]did.ServiceEndpoint(nil), eps...) }
}

// New returns a Service backed by st. registry is this registry's canonical
// identity (the did:dplaax {registry} segment it owns); every write rejects a
// DID whose registry segment differs (cross-registry replay defense, D-d8).
func New(st store.DIDStore, keys keystore.KeyStore, keygen crypto.KeyGenerator, verifier crypto.Verifier, registry string, opts ...Option) *Service {
	s := &Service{store: st, keys: keys, keygen: keygen, verifier: verifier, registry: registry, clock: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// requireDID parses and semantically validates didStr (account type, registry
// shape, known resource pattern). It does not check the registry-segment
// binding — that is a write-path authorization concern, applied explicitly by
// the mutating methods; a read of a foreign-registry DID simply misses.
func (s *Service) requireDID(didStr string) (*dplaax.DID, error) {
	d, err := dplaax.Parse(didStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	if err := dplaax.ValidateDID(d); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	return d, nil
}

// requireOwnRegistry enforces the registry-segment binding. It applies to reads
// as well as writes: the yamlstore omits the registry from its path (one
// registry per store), so without this gate a foreign-registry DID with the same
// account/resource segments would alias — and resolve to — a local record. This
// registry answers only for its own registry segment.
func (s *Service) requireOwnRegistry(d *dplaax.DID) error {
	if d.Registry != s.registry {
		return fmt.Errorf("%w: DID registry %q is not this registry %q", ErrUnauthorized, d.Registry, s.registry)
	}
	return nil
}

// requireActive confirms a DID exists and is active. Used to gate authority
// derivation: a revoked owner cannot mint pipelines/processes, and a revoked
// pipeline cannot parent new processes (revocation that did not stop derivation
// would be a hollow control).
func (s *Service) requireActive(d *dplaax.DID) error {
	st, err := s.store.GetStatus(d)
	if err != nil {
		return err // ErrNotFound when the DID does not exist
	}
	if st != store.StatusActive {
		return fmt.Errorf("%w: %s is %s, not active", ErrUnauthorized, d.String(), st)
	}
	return nil
}

// RegisterOwner records a self-sovereign Owner DID. doc is the owner DID
// Document carrying its self-signed Data Integrity proof (over the document body
// without the proof). The registry verifies the proof under the document's own
// embedded #signing key (key control), the registry-segment binding, and the
// owner shape; outwardSnapshot, when present, is recorded with the register
// event as a self-asserted witness. Exact re-submission is idempotent (the same
// document hash) and appends no second event; a different document for an
// existing owner is rejected.
func (s *Service) RegisterOwner(ctx context.Context, doc *did.DIDDocument, outwardSnapshot []byte) (*did.DIDDocument, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, fmt.Errorf("%w: nil document", ErrInvalidArgument)
	}
	owner, err := s.requireDID(doc.ID())
	if err != nil {
		return nil, err
	}
	if err := dplaax.RequireOwner(owner); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	if err := s.requireOwnRegistry(owner); err != nil {
		return nil, err
	}
	if err := s.verifyDocProof(doc); err != nil {
		return nil, err
	}
	snap, err := doc.Hash()
	if err != nil {
		return nil, fmt.Errorf("%w: hash document: %v", ErrInvalidArgument, err)
	}

	if err := s.store.SaveOwner(owner, doc); err != nil {
		if errors.Is(err, store.ErrExists) {
			// Idempotent insert (D-d8): an exact re-submission is non-mutating
			// success; a different document for an existing owner is rejected.
			existing, gerr := s.store.Resolve(owner)
			if gerr != nil {
				return nil, gerr
			}
			if eh, _ := existing.Hash(); eh == snap {
				return existing, nil
			}
			return nil, fmt.Errorf("%w: owner already registered with different content", store.ErrExists)
		}
		return nil, err
	}
	if err := s.appendEvent(owner, store.LifecycleEvent{
		EventType:       eventRegister,
		DIDDocSnapshot:  snap,
		OutwardSnapshot: outwardSnapshot,
		WitnessSource:   witnessSelfAsserted,
	}); err != nil {
		return nil, err
	}
	return doc, nil
}

// IssuePipeline mints a Pipeline DID under the delegation's owner. See issue.
func (s *Service) IssuePipeline(ctx context.Context, targetDID string, dlg *delegation.DelegationCredential) (*did.DIDDocument, *delegation.DelegationCredential, error) {
	return s.issue(ctx, targetDID, dlg, kindPipeline)
}

// IssueProcess mints a Process DID under a Pipeline of the delegation's owner.
func (s *Service) IssueProcess(ctx context.Context, targetDID string, dlg *delegation.DelegationCredential) (*did.DIDDocument, *delegation.DelegationCredential, error) {
	return s.issue(ctx, targetDID, dlg, kindProcess)
}

type didKind int

const (
	kindPipeline didKind = iota
	kindProcess
)

// issue mints a Pipeline/Process DID. It verifies the owner-signed delegation
// authorizes exactly this target, checks the parent is active, generates the
// #auth/#signing keypair, assembles and persists the document, then records the
// register lifecycle event. The document is committed (store.Save*) before the
// keys are persisted, so the store is the single linearization point: a
// concurrent duplicate loses at Save (ErrExists) before touching the keystore.
// Keys-before-document is deliberately NOT used — under a concurrent same-target
// race it would leave the document's embedded public key and the keystore's
// private key mismatched (a silent signing failure), which is worse than the
// failure this ordering admits.
//
// Known PoC partial-failure windows (the store has no delete, so cross-store
// atomicity is out of scope for this staged substrate — see the store package's
// durability note): if SaveKeyPair fails after the document is committed, a
// resolvable but keyless DID exists; if appendEvent fails after Save, a DID
// exists with no lifecycle snapshot. A retry hits ErrExists and cannot self-heal
// these. The durable tlog substrate is where transactional issuance lands.
func (s *Service) issue(ctx context.Context, targetDID string, dlg *delegation.DelegationCredential, kind didKind) (*did.DIDDocument, *delegation.DelegationCredential, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if dlg == nil {
		return nil, nil, fmt.Errorf("%w: nil delegation", ErrInvalidArgument)
	}
	target, err := s.requireDID(targetDID)
	if err != nil {
		return nil, nil, err
	}
	switch kind {
	case kindPipeline:
		if !target.IsPipeline() {
			return nil, nil, fmt.Errorf("%w: %q is not a pipeline DID", ErrInvalidArgument, targetDID)
		}
	case kindProcess:
		if !target.IsProcess() {
			return nil, nil, fmt.Errorf("%w: %q is not a process DID", ErrInvalidArgument, targetDID)
		}
	}
	if err := s.requireOwnRegistry(target); err != nil {
		return nil, nil, err
	}
	// The delegation must authorize exactly this target — delegation.Verify only
	// proves the subject is under the owner, so bind it to targetDID here.
	if dlg.CredentialSubject.ID != targetDID {
		return nil, nil, fmt.Errorf("%w: delegation subject %q does not authorize target %q", ErrUnauthorized, dlg.CredentialSubject.ID, targetDID)
	}
	// Verify the owner-signed delegation: the owner's document is resolved from
	// this store, so an unregistered owner fails here.
	if err := delegation.Verify(ctx, s.verifier, storeResolver{s.store}, dlg); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}

	// Authority must be live: a revoked owner cannot mint, and (for a process) a
	// revoked parent pipeline cannot parent. requireActive also confirms
	// existence, so it subsumes the parent-existence check.
	if err := s.requireActive(target.OwnerDID()); err != nil {
		return nil, nil, err
	}
	// controller = the structural parent (pipeline → owner; process → pipeline).
	parent := target.OwnerDID()
	if kind == kindProcess {
		parent = target.PipelineDID()
		if err := s.requireActive(parent); err != nil {
			return nil, nil, fmt.Errorf("parent pipeline: %w", err)
		}
	}

	authKP, err := s.keygen.Generate()
	if err != nil {
		return nil, nil, fmt.Errorf("didregistry: generate auth key: %w", err)
	}
	signKP, err := s.keygen.Generate()
	if err != nil {
		return nil, nil, fmt.Errorf("didregistry: generate signing key: %w", err)
	}
	doc := s.assembleDoc(target, parent.String(), authKP.PublicKey, signKP.PublicKey)

	switch kind {
	case kindPipeline:
		err = s.store.SavePipeline(target, doc, dlg)
	case kindProcess:
		err = s.store.SaveProcess(target, doc, dlg)
	}
	if err != nil {
		return nil, nil, err // ErrExists when the namespace slot is taken
	}
	// The document is committed; persist the keys for the winner only.
	if err := s.keys.SaveKeyPair(targetDID, map[keystore.KeyID]*crypto.KeyPair{
		keystore.KeyIDAuth:    authKP,
		keystore.KeyIDSigning: signKP,
	}); err != nil {
		return nil, nil, fmt.Errorf("didregistry: persist keys: %w", err)
	}
	snap, err := doc.Hash()
	if err != nil {
		return nil, nil, fmt.Errorf("didregistry: hash document: %w", err)
	}
	if err := s.appendEvent(target, store.LifecycleEvent{
		EventType:      eventRegister,
		DIDDocSnapshot: snap,
		WitnessSource:  witnessSelfAsserted,
	}); err != nil {
		return nil, nil, err
	}
	return doc, dlg, nil
}

// ResolveDID returns the DID Document for didStr.
func (s *Service) ResolveDID(ctx context.Context, didStr string) (*did.DIDDocument, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, err := s.requireDID(didStr)
	if err != nil {
		return nil, err
	}
	if err := s.requireOwnRegistry(d); err != nil {
		return nil, err
	}
	return s.store.Resolve(d)
}

// ResolveDelegation returns the owner-signed delegation that authorized a
// Pipeline/Process DID.
func (s *Service) ResolveDelegation(ctx context.Context, didStr string) (*delegation.DelegationCredential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, err := s.requireDID(didStr)
	if err != nil {
		return nil, err
	}
	if err := s.requireOwnRegistry(d); err != nil {
		return nil, err
	}
	return s.store.ResolveDelegation(d)
}

// UpdateStatus changes a DID's lifecycle status and records the transition.
// Slice-4 accepts only "revoked". The updated document is returned.
func (s *Service) UpdateStatus(ctx context.Context, didStr, status string) (*did.DIDDocument, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, err := s.requireDID(didStr)
	if err != nil {
		return nil, err
	}
	if err := s.requireOwnRegistry(d); err != nil {
		return nil, err
	}
	st := store.DIDStatus(status)
	if st != store.StatusRevoked {
		return nil, fmt.Errorf("%w: unsupported status %q (slice-4 accepts %q)", ErrInvalidArgument, status, store.StatusRevoked)
	}
	// Idempotent: re-revoking an already-revoked DID is a non-mutating success
	// and appends no second revoke event.
	if cur, err := s.store.GetStatus(d); err != nil {
		return nil, err
	} else if cur == store.StatusRevoked {
		return s.store.Resolve(d)
	}
	if err := s.store.UpdateStatus(d, st); err != nil {
		return nil, err
	}
	doc, err := s.store.Resolve(d)
	if err != nil {
		return nil, err
	}
	snap, err := doc.Hash()
	if err != nil {
		return nil, fmt.Errorf("didregistry: hash document: %w", err)
	}
	if err := s.appendEvent(d, store.LifecycleEvent{
		EventType:      eventRevoke,
		DIDDocSnapshot: snap,
		WitnessSource:  witnessSelfAsserted,
	}); err != nil {
		return nil, err
	}
	return doc, nil
}

// ListPipelines lists the Pipeline DIDs issued under an Owner.
func (s *Service) ListPipelines(ctx context.Context, ownerDID string) ([]store.DIDSummary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, err := s.requireDID(ownerDID)
	if err != nil {
		return nil, err
	}
	if err := s.requireOwnRegistry(d); err != nil {
		return nil, err
	}
	if err := dplaax.RequireOwner(d); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	return s.store.ListPipelines(d)
}

// ListProcesses lists the Process DIDs issued under a Pipeline.
func (s *Service) ListProcesses(ctx context.Context, pipelineDID string) ([]store.DIDSummary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, err := s.requireDID(pipelineDID)
	if err != nil {
		return nil, err
	}
	if err := s.requireOwnRegistry(d); err != nil {
		return nil, err
	}
	if !d.IsPipeline() {
		return nil, fmt.Errorf("%w: %q is not a pipeline DID", ErrInvalidArgument, pipelineDID)
	}
	return s.store.ListProcesses(d)
}

// ReadLifecycleLog returns the append-only lifecycle events for didStr (oldest
// first).
func (s *Service) ReadLifecycleLog(ctx context.Context, didStr string) ([]store.LifecycleEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, err := s.requireDID(didStr)
	if err != nil {
		return nil, err
	}
	if err := s.requireOwnRegistry(d); err != nil {
		return nil, err
	}
	return s.store.ReadLifecycleLog(d)
}

// assembleDoc builds a Pipeline/Process DID Document with the generated keys:
// #auth under authentication, #signing under assertionMethod, controller set to
// the structural parent, and the configured service endpoints re-anchored to the
// DID.
func (s *Service) assembleDoc(target *dplaax.DID, controller string, authPub, signPub []byte) *did.DIDDocument {
	id := target.String()
	vmAuth := id + "#" + string(keystore.KeyIDAuth)
	vmSign := id + "#" + string(keystore.KeyIDSigning)
	return did.New(did.DocumentFields{
		ID:         id,
		Controller: controller,
		VerificationMethod: []did.VerificationMethod{
			{ID: vmAuth, Type: jwkType, Controller: id, PublicKeyJWK: ed25519JWK(authPub)},
			{ID: vmSign, Type: jwkType, Controller: id, PublicKeyJWK: ed25519JWK(signPub)},
		},
		Authentication:  []string{vmAuth},
		AssertionMethod: []string{vmSign},
		Service:         s.endpointsFor(id),
	})
}

func (s *Service) endpointsFor(id string) []did.ServiceEndpoint {
	if len(s.endpoints) == 0 {
		return nil
	}
	out := make([]did.ServiceEndpoint, len(s.endpoints))
	for i, ep := range s.endpoints {
		frag := ep.ID
		if !strings.HasPrefix(frag, "#") {
			frag = "#" + frag
		}
		out[i] = did.ServiceEndpoint{ID: id + frag, Type: ep.Type, ServiceEndpoint: ep.ServiceEndpoint}
	}
	return out
}

// verifyDocProof verifies the owner's self-signed Data Integrity proof embedded
// in the document. The proof is over the document body WITHOUT the proof member,
// signed by a key the document itself lists under assertionMethod — proving the
// submitter controls the key in the document (key control, not authorization).
func (s *Service) verifyDocProof(doc *did.DIDDocument) error {
	proof, signing, err := splitProof(doc.Body())
	if err != nil {
		return err
	}
	if proof.Type != "DataIntegrityProof" || proof.ProofPurpose != "assertionMethod" {
		return fmt.Errorf("%w: proof type/purpose %q/%q not DataIntegrityProof/assertionMethod", ErrUnauthorized, proof.Type, proof.ProofPurpose)
	}
	if proof.Cryptosuite != vc.CryptosuiteEdDSAJCS2022 {
		return fmt.Errorf("%w: unsupported cryptosuite %q", ErrUnauthorized, proof.Cryptosuite)
	}
	if _, err := time.Parse(time.RFC3339, proof.Created); err != nil {
		return fmt.Errorf("%w: proof.created is not RFC3339: %v", ErrUnauthorized, err)
	}
	vmDID, _, found := strings.Cut(proof.VerificationMethod, "#")
	if !found || vmDID != doc.ID() {
		return fmt.Errorf("%w: verificationMethod %q does not name the owner %q", ErrUnauthorized, proof.VerificationMethod, doc.ID())
	}
	pub, err := did.ExtractPublicKey(doc, proof.VerificationMethod, did.RelationshipAssertionMethod)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	if err := vc.VerifyProof(s.verifier, pub, proof, signing); err != nil {
		return fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	return nil
}

// proofMembers is the exact set the provin Data Integrity proof carries; a proof
// with any other member is rejected (an extra member rides outside the signature
// and would be malleable if a consumer trusted it).
var proofMembers = map[string]bool{
	"type": true, "cryptosuite": true, "verificationMethod": true,
	"proofPurpose": true, "created": true, "proofValue": true,
}

// splitProof separates the embedded proof from the signing scope (the body
// without the proof member). The body is a defensive copy, so the caller's
// document is untouched.
func splitProof(body map[string]any) (*vc.DataIntegrityProof, map[string]any, error) {
	raw, ok := body["proof"]
	if !ok {
		return nil, nil, fmt.Errorf("%w: owner document is not self-signed (no proof)", ErrUnauthorized)
	}
	pm, ok := raw.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("%w: proof is not an object", ErrUnauthorized)
	}
	for k := range pm {
		if !proofMembers[k] {
			return nil, nil, fmt.Errorf("%w: proof carries unsigned member %q", ErrUnauthorized, k)
		}
	}
	signing := make(map[string]any, len(body)-1)
	for k, v := range body {
		if k != "proof" {
			signing[k] = v
		}
	}
	return &vc.DataIntegrityProof{
		Type:               getString(pm, "type"),
		Cryptosuite:        getString(pm, "cryptosuite"),
		VerificationMethod: getString(pm, "verificationMethod"),
		ProofPurpose:       getString(pm, "proofPurpose"),
		Created:            getString(pm, "created"),
		ProofValue:         getString(pm, "proofValue"),
	}, signing, nil
}

// appendEvent stamps the witnessed-at clock, chains PrevEventHash to the current
// tail, and appends. The hash chain is the service's responsibility (D-d6): on a
// concurrent-append ErrConflict the tail moved, so it re-reads, recomputes the
// chain, and retries.
func (s *Service) appendEvent(d *dplaax.DID, ev store.LifecycleEvent) error {
	ev.WitnessedAt = s.clock().UTC()
	const maxAttempts = 8
	for attempt := 0; attempt < maxAttempts; attempt++ {
		log, err := s.store.ReadLifecycleLog(d)
		if err != nil {
			return err
		}
		if n := len(log); n > 0 {
			prev, err := hashEvent(log[n-1])
			if err != nil {
				return err
			}
			ev.PrevEventHash = prev
		} else {
			ev.PrevEventHash = ""
		}
		err = s.store.AppendLifecycleEvent(d, ev)
		if err == nil {
			return nil
		}
		if errors.Is(err, store.ErrConflict) {
			continue // the tail advanced; re-read, recompute the chain, retry
		}
		return err
	}
	return fmt.Errorf("didregistry: lifecycle append on %s: too many conflicts: %w", d.String(), store.ErrConflict)
}

// hashEvent is the canonical content address of a lifecycle event over its
// stored representation (store.LifecycleEvent.CanonicalMap — the same shape the
// handler puts on the wire), including PrevEventHash so the chain is
// tamper-evident. Every reader recomputes it over the read-back event, so the
// chain verifies independent of on-disk serialization precision.
func hashEvent(ev store.LifecycleEvent) (string, error) {
	return jcs.Hash(ev.CanonicalMap())
}

// storeResolver adapts a DIDStore to resolver.Resolver so delegation.Verify can
// resolve the owner document from this registry's own store.
type storeResolver struct {
	st store.DIDStore
}

func (r storeResolver) Resolve(_ context.Context, didStr string) (*did.DIDDocument, error) {
	d, err := dplaax.Parse(didStr)
	if err != nil {
		return nil, err
	}
	return r.st.Resolve(d)
}

func ed25519JWK(pub []byte) map[string]any {
	return map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
}

func getString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}
