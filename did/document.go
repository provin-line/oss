package did

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/multibase"
)

// DIDDocument is the W3C DID Document model served by registries.
//
// Body-as-source-of-truth: the struct exposes no data fields. The canonical
// body map is the single source of truth for hashing and serialization;
// accessors return defensive copies/views. Unknown members survive
// unmarshal → marshal round-trips, so a resolved document's canonical hash
// (Hash) commits to members provin does not model. This is required, not a
// convenience: did:dplaax documents are integrity-protected — their JCS hash
// is recorded as a snapshot into the append-only lifecycle log — so a dropped
// member would corrupt the recorded snapshot and let a registry silently
// substitute document state. A closed typed struct structurally precludes
// this preservation; this is the same body-as-SoT model as
// vc.PipelinePassCredential.
//
// Construction has two paths: New (typed assembly, e.g. the registry building
// a subject document) and UnmarshalJSON (the resolution path, which preserves
// unknown members).
type DIDDocument struct {
	body map[string]any
}

// Wire member names (DID Document top level).
const (
	keyContext            = "@context"
	keyID                 = "id"
	keyController         = "controller"
	keyAlsoKnownAs        = "alsoKnownAs"
	keyVerificationMethod = "verificationMethod"
	keyAuthentication     = "authentication"
	keyAssertionMethod    = "assertionMethod"
	keyService            = "service"
)

// VerificationMethod is a public key entry in a DID Document. Two key
// encodings are read, selected by Type: JWK (type "JsonWebKey2020",
// publicKeyJwk) and Multikey (type "Multikey", publicKeyMultibase). The type
// and the encoding are mutually exclusive — a method carrying the encoding
// its type does not name, or both encodings at once, is rejected at
// extraction (see ExtractPublicKey). Documents this repository ISSUES use the
// JWK form; Multikey is a read capability for interoperating with W3C
// Data Integrity verifiers and controller documents. The PoC supports
// Ed25519 keys in both encodings.
type VerificationMethod struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	Controller   string         `json:"controller"`
	PublicKeyJWK map[string]any `json:"publicKeyJwk,omitempty"`
	// PublicKeyMultibase is the Multikey encoding: multibase base58btc ("z")
	// over multicodec ed25519-pub (0xed01) + 32 raw key bytes.
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
}

// ServiceEndpoint is a service entry in a DID Document (e.g. #vc-resolver,
// #chain-manager).
type ServiceEndpoint struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// DocumentFields is the typed write-side input for New. Only set members are
// emitted onto the body (omitempty semantics), matching the wire shape a
// registry assembles. New performs no verification-grade validation — those
// checks (relationship/controller/JWK) live in ExtractPublicKey, so adversarial
// shapes can be constructed for tests.
type DocumentFields struct {
	Context            []string
	ID                 string
	Controller         string
	AlsoKnownAs        []string
	VerificationMethod []VerificationMethod
	Authentication     []string
	AssertionMethod    []string
	Service            []ServiceEndpoint
}

// New assembles a DID Document body from typed fields. The inputs are copied
// into the body, so later mutation of the argument slices does not affect the
// document.
func New(fields DocumentFields) *DIDDocument {
	body := map[string]any{keyID: fields.ID}
	if len(fields.Context) > 0 {
		body[keyContext] = toAnySlice(fields.Context)
	}
	if fields.Controller != "" {
		body[keyController] = fields.Controller
	}
	if len(fields.AlsoKnownAs) > 0 {
		body[keyAlsoKnownAs] = toAnySlice(fields.AlsoKnownAs)
	}
	if len(fields.VerificationMethod) > 0 {
		vms := make([]any, len(fields.VerificationMethod))
		for i, vm := range fields.VerificationMethod {
			vms[i] = vm.toMap()
		}
		body[keyVerificationMethod] = vms
	}
	if len(fields.Authentication) > 0 {
		body[keyAuthentication] = toAnySlice(fields.Authentication)
	}
	if len(fields.AssertionMethod) > 0 {
		body[keyAssertionMethod] = toAnySlice(fields.AssertionMethod)
	}
	if len(fields.Service) > 0 {
		svcs := make([]any, len(fields.Service))
		for i, s := range fields.Service {
			svcs[i] = s.toMap()
		}
		body[keyService] = svcs
	}
	return &DIDDocument{body: body}
}

// ID returns the document subject DID.
func (d *DIDDocument) ID() string { return getString(d.body, keyID) }

// Controller returns the controller DID; empty when absent (a self-controlled
// owner may omit it).
func (d *DIDDocument) Controller() string { return getString(d.body, keyController) }

// AlsoKnownAs returns the outward-identity bindings (B7); empty when none. The
// binding is self-asserted at registration unless registry-witnessed — see the
// didregistry lifecycle log.
func (d *DIDDocument) AlsoKnownAs() []string { return getStringSlice(d.body, keyAlsoKnownAs) }

// Authentication returns the references listed under the authentication
// relationship (#auth peer/connection keys).
func (d *DIDDocument) Authentication() []string { return getStringSlice(d.body, keyAuthentication) }

// AssertionMethod returns the references listed under the assertionMethod
// relationship (#signing credential-issuance keys).
func (d *DIDDocument) AssertionMethod() []string { return getStringSlice(d.body, keyAssertionMethod) }

// VerificationMethod returns the public-key entries (typed copies). This is a
// lossy read view — members beyond the four modeled fields are not surfaced —
// not a round-trip surface; the body (Hash/MarshalJSON) remains the source of
// truth that commits to every member.
func (d *DIDDocument) VerificationMethod() []VerificationMethod {
	list, _ := d.body[keyVerificationMethod].([]any)
	out := make([]VerificationMethod, 0, len(list))
	for _, e := range list {
		if m, ok := e.(map[string]any); ok {
			out = append(out, vmFromMap(m))
		}
	}
	return out
}

// Service returns the service endpoints (typed copies). Like VerificationMethod,
// this is a lossy read view, not a round-trip surface.
func (d *DIDDocument) Service() []ServiceEndpoint {
	list, _ := d.body[keyService].([]any)
	out := make([]ServiceEndpoint, 0, len(list))
	for _, e := range list {
		if m, ok := e.(map[string]any); ok {
			out = append(out, ServiceEndpoint{
				ID:              getString(m, "id"),
				Type:            getString(m, "type"),
				ServiceEndpoint: getString(m, "serviceEndpoint"),
			})
		}
	}
	return out
}

// Body returns a defensive copy of the canonical body map.
func (d *DIDDocument) Body() map[string]any { return deepCopyMap(d.body) }

// Hash returns "sha256:<hex>" over the RFC 8785 canonical body — the document's
// content address recorded as a snapshot into the append-only lifecycle log.
// Unknown members participate in the hash (see the type doc).
func (d *DIDDocument) Hash() (string, error) { return jcs.HashRFC8785(d.body) }

// MarshalJSON emits the RFC 8785 canonical wire form. Deterministic output keeps
// the recorded snapshot and any byte comparison stable.
func (d *DIDDocument) MarshalJSON() ([]byte, error) { return jcs.CanonicalizeRFC8785(d.body) }

// UnmarshalJSON parses the wire form under strict-decoder rules, preserving
// unknown members in the body so the canonical hash commits to the document as
// resolved. Known members are type-checked and a wrong-typed one fails closed:
// preserving UNKNOWN members must not extend to tolerating MALFORMED known ones,
// which the accessors would otherwise coerce to a zero value — and a zero value
// can read as valid (a non-string controller would collapse to "", which the
// controller-chain walk treats as a self-controlled owner). This restores the
// fail-closed contract of the former typed decode.
func (d *DIDDocument) UnmarshalJSON(data []byte) error {
	var doc map[string]any
	if err := canon.NewStrictDecoder(data).Decode(&doc); err != nil {
		return fmt.Errorf("did: %w", err)
	}
	if err := validateKnownMembers(doc); err != nil {
		return err
	}
	d.body = doc
	return nil
}

// validateKnownMembers rejects a document whose known members are present but of
// the wrong JSON type. Unknown members are not inspected (they are preserved
// verbatim); only members this model assigns meaning to are constrained, so a
// malformed known member cannot be silently coerced past a security gate.
// @context is intentionally not constrained: it is not consumed by any accessor
// and JSON-LD legitimately allows a string, array, or object there.
func validateKnownMembers(body map[string]any) error {
	for _, k := range []string{keyID, keyController} {
		if v, present := body[k]; present {
			if _, ok := v.(string); !ok {
				return fmt.Errorf("did: member %q must be a string, got %T", k, v)
			}
		}
	}
	for _, k := range []string{keyAlsoKnownAs, keyVerificationMethod, keyAuthentication, keyAssertionMethod, keyService} {
		if v, present := body[k]; present {
			if _, ok := v.([]any); !ok {
				return fmt.Errorf("did: member %q must be an array, got %T", k, v)
			}
		}
	}
	return nil
}

func (vm VerificationMethod) toMap() map[string]any {
	m := map[string]any{
		"id":         vm.ID,
		"type":       vm.Type,
		"controller": vm.Controller,
	}
	if vm.PublicKeyJWK != nil {
		m["publicKeyJwk"] = deepCopyMap(vm.PublicKeyJWK)
	}
	if vm.PublicKeyMultibase != "" {
		m["publicKeyMultibase"] = vm.PublicKeyMultibase
	}
	return m
}

func vmFromMap(m map[string]any) VerificationMethod {
	vm := VerificationMethod{
		ID:                 getString(m, "id"),
		Type:               getString(m, "type"),
		Controller:         getString(m, "controller"),
		PublicKeyMultibase: getString(m, "publicKeyMultibase"),
	}
	if jwk, ok := m["publicKeyJwk"].(map[string]any); ok {
		vm.PublicKeyJWK = deepCopyMap(jwk)
	}
	return vm
}

func (s ServiceEndpoint) toMap() map[string]any {
	return map[string]any{
		"id":              s.ID,
		"type":            s.Type,
		"serviceEndpoint": s.ServiceEndpoint,
	}
}

// VerificationRelationship names the DID Document relationship a key must be
// listed under for a given use.
type VerificationRelationship string

const (
	// RelationshipAuthentication gates peer/connection authentication keys
	// (#auth).
	RelationshipAuthentication VerificationRelationship = "authentication"
	// RelationshipAssertionMethod gates credential-signing keys
	// (#signing).
	RelationshipAssertionMethod VerificationRelationship = "assertionMethod"
)

// ExtractPublicKey returns the raw public key bytes for keyID (absolute or
// fragment-relative reference) after checking that the verification method is
// listed under the required relationship and that its controller matches the
// document. This is the single extraction implementation in the repository —
// consumers must not maintain copies.
//
// The PoC supports Ed25519 keys, as OKP JWKs (type "JsonWebKey2020") or as
// Multikey (type "Multikey"). The relationship and controller checks are
// security gates: a key not listed under the required relationship, or whose
// controller is not the document subject, is rejected (key-confusion and
// cross-document injection defense). The method type and its key encoding are
// enforced as mutually exclusive — see decodeVMPublicKey.
func ExtractPublicKey(doc *DIDDocument, keyID string, rel VerificationRelationship) ([]byte, error) {
	if doc == nil {
		return nil, fmt.Errorf("did: nil document")
	}
	frag := fragmentOf(keyID)
	if frag == "" {
		return nil, fmt.Errorf("did: empty key reference")
	}
	subject := doc.ID()

	// The key must be listed under the required relationship.
	var refs []string
	switch rel {
	case RelationshipAuthentication:
		refs = doc.Authentication()
	case RelationshipAssertionMethod:
		refs = doc.AssertionMethod()
	default:
		return nil, fmt.Errorf("did: unknown verification relationship %q", rel)
	}
	// Resolve the reference to an absolute method id against the document
	// subject, and match by that absolute id — NOT by fragment alone. Fragment-
	// only matching lets a verification method with a different DID id but the
	// same fragment be selected (key-confusion / fragment-collision injection).
	wantID := absoluteKeyID(subject, keyID)

	listed := false
	for _, r := range refs {
		if absoluteKeyID(subject, r) == wantID {
			listed = true
			break
		}
	}
	if !listed {
		return nil, fmt.Errorf("did: key %q is not listed under relationship %q", keyID, rel)
	}

	// Locate the verification method by exact absolute id. Duplicate matching
	// ids are ambiguous (a substituted key could shadow the genuine one) and are
	// rejected rather than silently resolving to the first.
	methods := doc.VerificationMethod()
	var vm *VerificationMethod
	for i := range methods {
		if absoluteKeyID(subject, methods[i].ID) != wantID {
			continue
		}
		if vm != nil {
			return nil, fmt.Errorf("did: duplicate verification method id %q (ambiguous)", wantID)
		}
		vm = &methods[i]
	}
	if vm == nil {
		return nil, fmt.Errorf("did: no verification method for key %q", keyID)
	}

	// The verification method must be controlled by the document subject.
	if vm.Controller != subject {
		return nil, fmt.Errorf("did: verification method controller %q != document %q", vm.Controller, subject)
	}

	// Exclusivity is checked against the RAW method, not the typed copy: the
	// projection turns a wrong-typed or null foreign member into a zero value,
	// which reads as absent (see rawVMByID).
	raw, err := doc.rawVMByID(subject, wantID)
	if err != nil {
		return nil, err
	}
	if err := checkEncodingExclusivity(raw, vm); err != nil {
		return nil, err
	}
	return decodeVMPublicKey(vm)
}

// KeyEncoding names the wire encoding a verification method used for its public
// key. It is a wire fact, and the suite classifier dispatches on it, so it is
// resolved in the same operation as the key itself — never re-derived from a
// second reading that could disagree.
type KeyEncoding string

const (
	// EncodingMultikey is publicKeyMultibase on a Multikey method.
	EncodingMultikey KeyEncoding = "Multikey"
	// EncodingJWK is publicKeyJwk on a JsonWebKey2020 method.
	EncodingJWK KeyEncoding = "JsonWebKey2020"
)

// ExtractPublicKeyAndEncoding resolves a key exactly as ExtractPublicKey does
// and additionally reports the encoding it resolved through.
//
// The pair comes from one reading of one method on purpose: a caller that
// resolved the key here and inspected the encoding separately could see two
// different methods (or two different members of one), and a suite dispatch
// built on that discrepancy would not be the exact dispatch it claims to be.
func ExtractPublicKeyAndEncoding(doc *DIDDocument, keyID string, rel VerificationRelationship) ([]byte, KeyEncoding, error) {
	key, err := ExtractPublicKey(doc, keyID, rel)
	if err != nil {
		return nil, "", err
	}
	// ExtractPublicKey has already proven the method exists, is unique, is
	// listed, is controlled by the subject, and carries exactly one encoding —
	// so the type here is the encoding, with no second decision to get wrong.
	vm, err := doc.verificationMethodByID(keyID)
	if err != nil {
		return nil, "", err
	}
	switch vm.Type {
	case vmTypeMultikey:
		return key, EncodingMultikey, nil
	case vmTypeJSONWebKey2020:
		return key, EncodingJWK, nil
	default:
		return nil, "", fmt.Errorf("did: unsupported verification method type %q", vm.Type)
	}
}

// verificationMethodByID returns the typed method with the given absolute id.
func (d *DIDDocument) verificationMethodByID(keyID string) (*VerificationMethod, error) {
	subject := d.ID()
	wantID := absoluteKeyID(subject, keyID)
	methods := d.VerificationMethod()
	for i := range methods {
		if absoluteKeyID(subject, methods[i].ID) == wantID {
			return &methods[i], nil
		}
	}
	return nil, fmt.Errorf("did: no verification method for key %q", keyID)
}

// rawVMByID returns the verification method as it appears on the wire.
func (d *DIDDocument) rawVMByID(subject, wantID string) (map[string]any, error) {
	list, _ := d.body[keyVerificationMethod].([]any)
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if absoluteKeyID(subject, getString(m, "id")) == wantID {
			return m, nil
		}
	}
	return nil, fmt.Errorf("did: no verification method for key %q", wantID)
}

// checkEncodingExclusivity rejects a method that carries the encoding member
// belonging to the other type, whatever its value.
//
// Presence is the violation. A null, empty, or wrong-typed foreign member is
// still a member the document's hash commits to, and a reader that keys on raw
// presence would see a dual-encoded method where the typed projection sees a
// clean one — the disagreement about key identity this exclusivity exists to
// prevent.
func checkEncodingExclusivity(raw map[string]any, vm *VerificationMethod) error {
	var foreign string
	switch vm.Type {
	case vmTypeMultikey:
		foreign = "publicKeyJwk"
	case vmTypeJSONWebKey2020:
		foreign = "publicKeyMultibase"
	default:
		return nil // decodeVMPublicKey rejects the unknown type with a better message
	}
	if _, present := raw[foreign]; present {
		return fmt.Errorf("did: %s method %q also carries %s (type and encoding are exclusive)", vm.Type, vm.ID, foreign)
	}
	return nil
}

// Verification method types whose key encodings this package reads.
const (
	vmTypeJSONWebKey2020 = "JsonWebKey2020"
	vmTypeMultikey       = "Multikey"
)

// decodeVMPublicKey extracts the raw public key bytes for a verification
// method, enforcing type↔encoding exclusivity: a Multikey method must carry
// publicKeyMultibase and nothing else; a JsonWebKey2020 method must carry
// publicKeyJwk and nothing else. A method with both encodings, an encoding
// contradicting its type, or an unrecognized type is rejected — never
// resolved by silently picking one encoding, because a dual-encoded method
// whose encodings disagree would let key identity depend on which reader
// looked (an alternate wire shape this profile does not freeze).
func decodeVMPublicKey(vm *VerificationMethod) ([]byte, error) {
	switch vm.Type {
	case vmTypeMultikey:
		if vm.PublicKeyJWK != nil {
			return nil, fmt.Errorf("did: Multikey method %q also carries publicKeyJwk (type and encoding are exclusive)", vm.ID)
		}
		if vm.PublicKeyMultibase == "" {
			return nil, fmt.Errorf("did: Multikey method %q has no publicKeyMultibase", vm.ID)
		}
		return decodeEd25519Multikey(vm.PublicKeyMultibase)
	case vmTypeJSONWebKey2020:
		if vm.PublicKeyMultibase != "" {
			return nil, fmt.Errorf("did: JsonWebKey2020 method %q also carries publicKeyMultibase (type and encoding are exclusive)", vm.ID)
		}
		return decodeEd25519JWK(vm.PublicKeyJWK)
	default:
		return nil, fmt.Errorf("did: unsupported verification method type %q (want %q or %q)", vm.Type, vmTypeJSONWebKey2020, vmTypeMultikey)
	}
}

// ed25519PubMulticodec is the multicodec varint prefix for ed25519-pub
// (0xed01) that leads every Ed25519 Multikey value.
var ed25519PubMulticodec = []byte{0xed, 0x01}

// decodeEd25519Multikey extracts the 32-byte Ed25519 public key from a
// Multikey publicKeyMultibase value: multibase base58btc ("z" prefix) over
// the ed25519-pub multicodec prefix + raw key. Any other multibase base,
// multicodec, or key length fails closed.
func decodeEd25519Multikey(s string) ([]byte, error) {
	raw, err := multibase.DecodeBase58Btc(s)
	if err != nil {
		return nil, fmt.Errorf("did: publicKeyMultibase: %w", err)
	}
	if len(raw) < len(ed25519PubMulticodec) || !bytes.Equal(raw[:len(ed25519PubMulticodec)], ed25519PubMulticodec) {
		return nil, fmt.Errorf("did: publicKeyMultibase is not an ed25519-pub Multikey (want multicodec 0xed01 prefix)")
	}
	key := raw[len(ed25519PubMulticodec):]
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("did: Ed25519 public key length %d, want %d", len(key), ed25519.PublicKeySize)
	}
	return key, nil
}

// absoluteKeyID resolves a DID URL key reference to its absolute form against
// the document subject: a reference that already carries a DID part before its
// "#" (e.g. "did:…:proc1#signing") is returned verbatim; a relative "#signing"
// or a bare "signing" becomes "<subject>#signing". This is what lets key
// matching compare full ids rather than fragments alone.
func absoluteKeyID(subject, ref string) string {
	if i := strings.Index(ref, "#"); i > 0 {
		return ref // already absolute: a DID part precedes the fragment
	}
	return subject + "#" + fragmentOf(ref)
}

// fragmentOf returns the fragment of a key reference: the part after the last
// "#", or the whole string when there is no "#" (a bare fragment id).
func fragmentOf(ref string) string {
	if i := strings.LastIndex(ref, "#"); i >= 0 {
		return ref[i+1:]
	}
	return ref
}

// decodeEd25519JWK extracts the 32-byte Ed25519 public key from an OKP JWK.
func decodeEd25519JWK(jwk map[string]any) ([]byte, error) {
	if jwk == nil {
		return nil, fmt.Errorf("did: verification method has no publicKeyJwk")
	}
	if kty, _ := jwk["kty"].(string); kty != "OKP" {
		return nil, fmt.Errorf("did: unsupported JWK kty %q (want OKP)", jwk["kty"])
	}
	if crv, _ := jwk["crv"].(string); crv != "Ed25519" {
		return nil, fmt.Errorf("did: unsupported JWK crv %q (want Ed25519)", jwk["crv"])
	}
	x, ok := jwk["x"].(string)
	if !ok {
		return nil, fmt.Errorf("did: JWK has no string x parameter")
	}
	raw, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("did: JWK x is not valid base64url: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("did: Ed25519 public key length %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return raw, nil
}

func getString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func getStringSlice(m map[string]any, key string) []string {
	list, _ := m[key].([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func toAnySlice(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func deepCopyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = deepCopyValue(v)
	}
	return out
}

func deepCopyValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return deepCopyMap(t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = deepCopyValue(e)
		}
		return out
	default:
		// Scalars (string, json.Number, bool, nil) are immutable.
		return v
	}
}

// EncodeEd25519Multikey renders an Ed25519 public key as a Multikey
// publicKeyMultibase value: multibase base58btc ("z") over the ed25519-pub
// multicodec prefix + the raw key. It is the inverse of the decoder above, and
// exists as the one place issuance builds the value — a second, hand-rolled
// encoder is how a key that cannot be read back gets published.
func EncodeEd25519Multikey(key []byte) (string, error) {
	if len(key) != ed25519.PublicKeySize {
		return "", fmt.Errorf("did: Ed25519 public key length %d, want %d", len(key), ed25519.PublicKeySize)
	}
	return multibase.EncodeBase58Btc(append(append([]byte{}, ed25519PubMulticodec...), key...)), nil
}

// NewMultikeyVerificationMethod builds a Multikey verification method for an
// Ed25519 key — the encoding the W3C eddsa-jcs-2022 suite requires
// (signer.suite.eddsa-jcs-2022).
func NewMultikeyVerificationMethod(id, controller string, key []byte) (VerificationMethod, error) {
	mb, err := EncodeEd25519Multikey(key)
	if err != nil {
		return VerificationMethod{}, err
	}
	return VerificationMethod{
		ID:                 id,
		Type:               vmTypeMultikey,
		Controller:         controller,
		PublicKeyMultibase: mb,
	}, nil
}

// Frozen @context URIs for issued DID documents. DID Core requires @context on
// the JSON-LD representation, and the Multikey verification-method type is
// defined by the security/multikey context — a document carrying Multikey
// methods without naming that context is not honestly self-describing to an
// external resolver.
//
// Unlike the credential contexts (vc/context.go), these need no embedded
// document copies: DID documents are canonicalized with JCS only, never RDF
// expansion, so the URIs ride the signing scope as inert bytes. What must not
// drift is the strings themselves — TestIssuedDocumentContextsAreFrozen pins
// them — because a changed URI changes every issued document's hash.
const (
	// ContextDIDV1 is the W3C DID Core base context.
	ContextDIDV1 = "https://www.w3.org/ns/did/v1"
	// ContextMultikeyV1 is the W3C security context defining the Multikey
	// verification-method type.
	ContextMultikeyV1 = "https://w3id.org/security/multikey/v1"
)

// IssuedDocumentContexts returns the @context every document this repository
// issues carries, in order. One function rather than N call-site literals: the
// proof classifier keys on the presence of a proof-local @context mirrored from
// the document (signer.suite.eddsa-jcs-2022), so an issuance path that forgot
// the context would mint documents whose self-signed proofs match no claim
// contract.
func IssuedDocumentContexts() []string {
	return []string{ContextDIDV1, ContextMultikeyV1}
}
