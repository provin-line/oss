package conformance_test

import (
	"context"
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/canon/jcs"
	ossed "github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keybinding"
	"github.com/provin-line/oss/multibase"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// --- keybinding family ---
//
// keybinding's Verifier checks REAL signatures under the eddsa-jcs-2022
// contract. A vector's proof is a fixture: no real signature and no
// proof-local @context. The driver signs each credential of a vector again as
// an eddsa-jcs-2022 proof (dplaax signer.suite.eddsa-jcs-2022) with a fixture
// key for the verification method its proof names, and serves those keys
// from a fixture resolver. It adds only the proof-local @context (the
// document's) and the proofValue, and signs every other proof member as
// written, created among them (dplaax vectors/README.md, "Fixture proofs"),
// so the re-signing repairs no defect a vector carries.

// kbAudience is the relying party a vector that names none (one about a
// list alone) is verified for; such a vector reads no audience.
const kbAudience = "did:dplaax:conformance.example:org:relying-party"

// kbReasons maps a vector's expected reason to the refusal it names.
var kbReasons = map[string]error{
	"status-list-rewound":            keybinding.ErrStatusListRewound,
	"status-list-revocation-cleared": keybinding.ErrStatusListRevocationCleared,
}

// kbRefusal is the refusal a reject vector is tied to: the sentinel of the
// condition its description names, and whether that refusal comes when the
// list the verifier is to hold is restored rather than when the vector's
// credential is verified. Only a binding vector has such a list to restore.
type kbRefusal struct {
	err       error
	atRestore bool
}

// kbRefusals ties every keybinding reject vector to its refusal, so a vector
// refused with another sentinel fails. A rule can have several refusals
// (keybinding.status.entry: a malformed entry, a revoked one, a list not
// current), so the table is by vector, not by rule.
//
// The driver holds a binding vector's list as of the vector's time, the only
// time the vector gives. keybinding-023's list is dated after that time, and
// RestoreStatusList refuses a list dated after the time it is restored at, so
// its refusal is at the restore. Every other binding vector's list restores.
var kbRefusals = map[string]kbRefusal{
	"keybinding-002": {err: keybinding.ErrMalformed},
	"keybinding-003": {err: keybinding.ErrSignature},
	"keybinding-004": {err: keybinding.ErrSignature},
	"keybinding-005": {err: keybinding.ErrNotValidAt},
	"keybinding-006": {err: keybinding.ErrValidityTooLong},
	"keybinding-007": {err: keybinding.ErrAudience},
	"keybinding-008": {err: keybinding.ErrMalformed},
	"keybinding-009": {err: keybinding.ErrRevoked},
	"keybinding-010": {err: keybinding.ErrStatusListStale},
	"keybinding-012": {err: keybinding.ErrMalformed},
	"keybinding-013": {err: keybinding.ErrMalformed},
	"keybinding-014": {err: keybinding.ErrMalformed},
	"keybinding-019": {err: keybinding.ErrStatusListRewound},
	"keybinding-020": {err: keybinding.ErrStatusListRewound},
	"keybinding-021": {err: keybinding.ErrStatusListRevocationCleared},
	"keybinding-022": {err: keybinding.ErrStatusListStale},
	"keybinding-023": {err: keybinding.ErrStatusListStale, atRestore: true},
	"keybinding-026": {err: keybinding.ErrSignature},
	"keybinding-027": {err: keybinding.ErrSignature},
	"keybinding-033": {err: keybinding.ErrMalformed},
	"keybinding-034": {err: keybinding.ErrMalformed},
	"keybinding-035": {err: keybinding.ErrMalformed},
	"keybinding-036": {err: keybinding.ErrMalformed},
	"keybinding-037": {err: keybinding.ErrStatusListStale},
	"keybinding-040": {err: keybinding.ErrMalformed},
	"keybinding-041": {err: keybinding.ErrMalformed},
	"keybinding-042": {err: keybinding.ErrMalformed},
	"keybinding-043": {err: keybinding.ErrStatusListStale},
	"keybinding-045": {err: keybinding.ErrMalformed},
	"keybinding-047": {err: keybinding.ErrMalformed},
	"keybinding-048": {err: keybinding.ErrMalformed},
	"keybinding-049": {err: keybinding.ErrMalformed},
	"keybinding-050": {err: keybinding.ErrMalformed},
	"keybinding-051": {err: keybinding.ErrMalformed},
	"keybinding-052": {err: keybinding.ErrMalformed},
	"keybinding-053": {err: keybinding.ErrMalformed},
	"keybinding-054": {err: keybinding.ErrMalformed},
}

// kbExpect reads a vector's expect: "accept", "reject", or an object with a
// result and a reason. A vector about a content hash has neither, and reads "".
func kbExpect(t *testing.T, v dplaaxVector) (result, reason string) {
	t.Helper()
	if json.Unmarshal(v.Expect, &result) == nil {
		return result, ""
	}
	var want struct {
		Result string `json:"result"`
		Reason string `json:"reason"`
	}
	mustParse(t, v.Expect, &want)
	return want.Result, want.Reason
}

// kbKeys signs as DID#fragment with the fixture keys it holds.
type kbKeys map[string]stded25519.PrivateKey

func (k kbKeys) Sign(didStr, keyID string, data []byte) ([]byte, error) {
	priv, ok := k[didStr+"#"+keyID]
	if !ok {
		return nil, fmt.Errorf("no fixture key %s#%s", didStr, keyID)
	}
	return stded25519.Sign(priv, data), nil
}

// kbFixture makes a key for each verification method and a resolver serving,
// for each DID, a document that lists its methods as assertion methods.
func kbFixture(t *testing.T, methods []string) (kbKeys, *local.Resolver) {
	t.Helper()
	keys := kbKeys{}
	byDID := map[string][]string{}
	for _, m := range methods {
		d, _, ok := strings.Cut(m, "#")
		if !ok {
			t.Fatalf("verification method %q is not DID#fragment", m)
		}
		byDID[d] = append(byDID[d], m)
	}
	r := local.New()
	for _, d := range slices.Sorted(maps.Keys(byDID)) {
		var vms []did.VerificationMethod
		for _, m := range byDID[d] {
			pub, priv, err := stded25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			keys[m] = priv
			vm, err := did.NewMultikeyVerificationMethod(m, d, pub)
			if err != nil {
				t.Fatal(err)
			}
			vms = append(vms, vm)
		}
		r.Add(did.New(did.DocumentFields{Context: did.IssuedDocumentContexts(), ID: d, Controller: d, VerificationMethod: vms, AssertionMethod: byDID[d]}))
	}
	return keys, r
}

// kbMethod is the verification method raw's proof names.
func kbMethod(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var c struct {
		Proof struct {
			VerificationMethod string `json:"verificationMethod"`
		} `json:"proof"`
	}
	mustParse(t, raw, &c)
	return c.Proof.VerificationMethod
}

// kbResign signs raw's body again by eddsa-jcs-2022 for the verification
// method its proof names. The proof config is raw's proof as written, without
// its proofValue, and with the document's @context when the proof has none;
// the signature is over SHA-256(JCS(config)) ‖ SHA-256(JCS(body without its
// proof)). The proof returned is that config and the new proofValue.
func kbResign(t *testing.T, keys kbKeys, raw json.RawMessage) []byte {
	t.Helper()
	var body map[string]any
	if err := canon.NewStrictDecoder(raw).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	proof, ok := body["proof"].(map[string]any)
	if !ok {
		t.Fatal("the credential has no proof object to re-sign")
	}
	delete(body, "proof")
	delete(proof, "proofValue")
	if _, has := proof["@context"]; !has {
		if docContext, ok := body["@context"]; ok {
			proof["@context"] = docContext
		}
	}
	config, err := jcs.CanonicalizeRFC8785(proof)
	if err != nil {
		t.Fatalf("proof config: %v", err)
	}
	document, err := jcs.CanonicalizeRFC8785(body)
	if err != nil {
		t.Fatalf("document: %v", err)
	}
	configHash, documentHash := sha256.Sum256(config), sha256.Sum256(document)
	vm, _ := proof["verificationMethod"].(string)
	signer, fragment, _ := strings.Cut(vm, "#")
	sig, err := keys.Sign(signer, fragment, append(configHash[:], documentHash[:]...))
	if err != nil {
		t.Fatalf("re-sign: %v", err)
	}
	proof["proofValue"] = multibase.EncodeBase58Btc(sig)
	body["proof"] = proof
	out, err := jcs.CanonicalizeRFC8785(body)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func runKeybinding(t *testing.T, v dplaaxVector) {
	var in struct {
		Credential json.RawMessage `json:"credential"`
		StatusList json.RawMessage `json:"status_list"`
		Held       json.RawMessage `json:"held"`
		Anchor     *struct {
			Issuer              string   `json:"issuer"`
			IssuanceKeys        []string `json:"issuance_keys"`
			MaxValiditySeconds  int64    `json:"max_validity_seconds"`
			MaxStatusAgeSeconds int64    `json:"max_status_age_seconds"`
		} `json:"anchor"`
		At       string `json:"at"`
		Verifier struct {
			Audience    string `json:"audience"`
			SkewSeconds int64  `json:"skew_seconds"`
		} `json:"verifier"`
	}
	mustParse(t, v.Input, &in)

	var methods []string
	for _, raw := range []json.RawMessage{in.Credential, in.StatusList, in.Held} {
		if raw != nil {
			methods = append(methods, kbMethod(t, raw))
		}
	}
	keys, r := kbFixture(t, slices.Compact(slices.Sorted(slices.Values(methods))))

	// keybinding.status-list.content-hash: the list credential alone, its
	// signature not read. It is re-signed as every credential of an input is;
	// the hash leaves the proof out.
	if in.Anchor == nil {
		var want struct {
			ContentHash string `json:"contentHash"`
		}
		mustParse(t, v.Expect, &want)
		got, err := keybinding.StatusListContentHash(kbResign(t, keys, in.Credential))
		if err != nil || got != want.ContentHash {
			t.Errorf("StatusListContentHash = %q, %v, want %q", got, err, want.ContentHash)
		}
		return
	}
	audience := in.Verifier.Audience
	if audience == "" {
		audience = kbAudience
	}
	verifier, err := keybinding.NewVerifier(vc.NewVerifier(r, ossed.Verifier{}), audience, time.Duration(in.Verifier.SkewSeconds)*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	anchor := keybinding.Anchor{
		Issuer: in.Anchor.Issuer, IssuanceKeys: in.Anchor.IssuanceKeys,
		MaxValidity:  time.Duration(in.Anchor.MaxValiditySeconds) * time.Second,
		MaxStatusAge: time.Duration(in.Anchor.MaxStatusAgeSeconds) * time.Second,
	}
	at, err := time.Parse(time.RFC3339, in.At)
	if err != nil {
		t.Fatalf("at: %v", err)
	}
	ctx := context.Background()
	result, reason := kbExpect(t, v)
	refusal, tied := kbRefusals[v.ID]
	if refusal.atRestore && in.StatusList == nil {
		t.Fatalf("kbRefusals refuses %s at the restore, but it holds no list to restore", v.ID)
	}

	switch {
	case in.StatusList != nil: // a binding, with the list the verifier holds
		// The list is held as RestoreStatusList holds one. It refuses a list
		// dated after at, and leaves its age and its validUntil to
		// VerifyBinding (keybinding.status-list.fresh).
		l, rerr := verifier.RestoreStatusList(ctx, kbResign(t, keys, in.StatusList), anchor, at)
		switch {
		case refusal.atRestore:
			if rerr == nil {
				t.Fatalf("the vector's list restores, want the restore refused with %v", refusal.err)
			}
			err = rerr
		case rerr != nil:
			t.Fatalf("the vector's list does not restore: %v", rerr)
		default:
			_, err = verifier.VerifyBinding(ctx, kbResign(t, keys, in.Credential), anchor, l, at)
		}
	case in.Held != nil: // a list, against the one held
		held, herr := verifier.RestoreStatusList(ctx, kbResign(t, keys, in.Held), anchor, at)
		if herr != nil {
			t.Fatalf("the vector's held list does not restore: %v", herr)
		}
		_, err = verifier.VerifyStatusList(ctx, kbResign(t, keys, in.Credential), anchor, held, at)
	default: // a list alone
		_, err = verifier.VerifyStatusList(ctx, kbResign(t, keys, in.Credential), anchor, nil, at)
	}

	switch result {
	case "accept":
		if err != nil {
			t.Errorf("refused: %v, want accept", err)
		}
	case "reject":
		if !tied {
			t.Fatalf("no refusal tied to %s in kbRefusals", v.ID)
		}
		if !errors.Is(err, refusal.err) {
			t.Errorf("refused with %v, want %v", err, refusal.err)
		}
		if reason != "" && kbReasons[reason] != refusal.err {
			t.Errorf("reason %q names %v, kbRefusals %v", reason, kbReasons[reason], refusal.err)
		}
	default:
		t.Fatalf("expect %s names no outcome", v.Expect)
	}
}

// kbRefusals ties exactly the keybinding vectors the manifest lists as
// reject: an accept vector tied, or a reject vector untied, fails.
func TestKbRefusalsTieEveryRejectVector(t *testing.T) {
	listed := map[string]bool{}
	for _, id := range manifestIDs(t) {
		if !strings.HasPrefix(id, "keybinding-") {
			continue
		}
		listed[id] = true
		result, _ := kbExpect(t, loadDplaax(t, id))
		if _, tied := kbRefusals[id]; tied != (result == "reject") {
			t.Errorf("%s expects %q, tied in kbRefusals: %t", id, result, tied)
		}
	}
	for id := range kbRefusals {
		if !listed[id] {
			t.Errorf("kbRefusals ties %s, which the manifest does not list", id)
		}
	}
}

// Every keybinding vector the manifest lists is driven, and none is left in
// the skip ledger.
func TestKeybindingVectorsAreDrivenNotSkipped(t *testing.T) {
	n := 0
	for _, id := range manifestIDs(t) {
		if !strings.HasPrefix(id, "keybinding-") {
			continue
		}
		n++
		if _, ok := dplaaxRunners[id]; !ok {
			t.Errorf("%s has no runner", id)
		}
		if reason, ok := dplaaxSkips[id]; ok {
			t.Errorf("%s is still skipped: %s", id, reason)
		}
	}
	if n == 0 {
		t.Error("the manifest lists no keybinding vector")
	}
}

// Re-signing adds only the proof-local @context (the document's) and the
// proofValue: every other proof member stays as written, a created that is
// not a time among them, so the verifier judges it.
func TestKbResignAddsOnlyContextAndProofValue(t *testing.T) {
	const vm = "did:dplaax:poc.dplaax.dev:org:acme#issuer"
	keys, _ := kbFixture(t, []string{vm})
	for _, created := range []string{"2026-01-01T00:00:00Z", "not a time"} {
		proof := map[string]any{
			"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": vm,
			"proofPurpose": "assertionMethod", "created": created, "proofValue": "z1111",
		}
		doc := map[string]any{"@context": []any{"https://www.w3.org/ns/credentials/v2"}, "id": "urn:x", "proof": proof}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(kbResign(t, keys, raw), &out); err != nil {
			t.Fatal(err)
		}
		got := out["proof"].(map[string]any)
		for m, v := range proof {
			if m != "proofValue" && !reflect.DeepEqual(got[m], v) {
				t.Errorf("created %q: proof.%s = %v, want %v as written", created, m, got[m], v)
			}
		}
		for m := range got {
			if _, had := proof[m]; !had && m != "@context" {
				t.Errorf("created %q: re-signing adds proof.%s", created, m)
			}
		}
		if !reflect.DeepEqual(got["@context"], doc["@context"]) || got["proofValue"] == "z1111" {
			t.Errorf("created %q: proof @context %v, proofValue %v; want the document's and a new signature", created, got["@context"], got["proofValue"])
		}
	}
}
