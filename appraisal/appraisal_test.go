package appraisal_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/provin-line/oss/appraisal"
	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/canon/jcs"
)

const (
	head   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	viewID = "sha256:4382e8875ce5c79e0f053215993f901331003e89d125de78bc610dbdb90b06aa"
)

func manifest() appraisal.Manifest {
	return appraisal.Manifest{
		Head: head,
		Spine: []appraisal.SpineEntry{
			{BodyAddress: "sha256:1111111111111111111111111111111111111111111111111111111111111111", WireVariantID: "wire:v1:jcs-rfc8785:sha256:2222222222222222222222222222222222222222222222222222222222222222"},
			{BodyAddress: head, WireVariantID: "wire:v1:jcs-rfc8785:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		},
		ClaimContractID: "linear-provenance@1",
		CanonicalizerID: appraisal.CanonicalizerRFC8785,
		CryptosuiteID:   "W3C_EDDSA_JCS_2022_REC_20250515@1",
		SchemaVersion:   "pipeline-pass-credential@1",
		InputSnapshotDigests: map[string]string{
			"did:did:dplaax:factory-a": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			"lifecycle:factory-a":      "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		},
	}
}

func truth(v appraisal.TruthState) *appraisal.TruthState { return &v }

func TestManifestIDMatchesIndependentVector(t *testing.T) {
	got, err := manifest().ID()
	if err != nil {
		t.Fatal(err)
	}
	if got != viewID {
		t.Fatalf("ID=%s want %s", got, viewID)
	}
}

func TestManifestIdentityIncludesExtensions(t *testing.T) {
	m := manifest()
	base, _ := m.ID()
	m.Extensions = map[string]any{"futureInput": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}
	extended, err := m.ID()
	if err != nil {
		t.Fatal(err)
	}
	if base == extended {
		t.Fatal("extension member did not change EvidenceViewID")
	}
}

func TestManifestJSONRoundTripPreservesExtensions(t *testing.T) {
	raw := []byte(`{"head":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","spine":[{"bodyAddress":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wireVariantId":"wire:v1:jcs-rfc8785:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],"claimContractId":"linear-provenance@1","canonicalizerId":"jcs-rfc8785","cryptosuiteId":"suite@1","schemaVersion":"credential@1","inputSnapshotDigests":{"did":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"future":{"mode":"strict"}}`)
	var m appraisal.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Extensions["future"]; !ok {
		t.Fatal("extension was dropped")
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["future"]; !ok {
		t.Fatal("extension missing after round trip")
	}
}

func TestValidateIDRejectsMismatch(t *testing.T) {
	v, err := appraisal.NewView(manifest(), []appraisal.ScopeEntry{{Scope: "LINEAR_ATTESTATION@1", Coverage: appraisal.CoverageEvaluated, TruthState: truth(appraisal.TruthVerified)}})
	if err != nil {
		t.Fatal(err)
	}
	v.EvidenceViewID = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	if err := v.ValidateID(); !errors.Is(err, appraisal.ErrViewIDMismatch) {
		t.Fatalf("ValidateID error=%v", err)
	}
}

func TestValidateVectorCoverageTruthCoupling(t *testing.T) {
	tests := []appraisal.ScopeEntry{
		{Scope: "LINEAR_ATTESTATION@1", Coverage: appraisal.CoverageNotEvaluated, TruthState: truth(appraisal.TruthVerified)},
		{Scope: "LINEAR_ATTESTATION@1", Coverage: appraisal.CoverageEvaluated},
	}
	for _, entry := range tests {
		if err := appraisal.ValidateVector([]appraisal.ScopeEntry{entry}); !errors.Is(err, appraisal.ErrInvalidVector) {
			t.Errorf("entry=%+v error=%v", entry, err)
		}
	}
}

func TestDecideFailClosedTable(t *testing.T) {
	profile := appraisal.Profile{ID: "purpose-first-agent-access@1", RequiredScopes: []string{"LINEAR_ATTESTATION@1", "SOURCE_SET_BINDING@1"}}
	tests := []struct {
		name   string
		vector []appraisal.ScopeEntry
		want   appraisal.Decision
	}{
		{"all verified", []appraisal.ScopeEntry{
			{Scope: "LINEAR_ATTESTATION@1", Coverage: appraisal.CoverageEvaluated, TruthState: truth(appraisal.TruthVerified)},
			{Scope: "SOURCE_SET_BINDING@1", Coverage: appraisal.CoverageEvaluated, TruthState: truth(appraisal.TruthVerified)},
		}, appraisal.DecisionAccept},
		{"missing", []appraisal.ScopeEntry{{Scope: "LINEAR_ATTESTATION@1", Coverage: appraisal.CoverageEvaluated, TruthState: truth(appraisal.TruthVerified)}}, appraisal.DecisionQuarantine},
		{"unsupported", []appraisal.ScopeEntry{
			{Scope: "LINEAR_ATTESTATION@1", Coverage: appraisal.CoverageEvaluated, TruthState: truth(appraisal.TruthVerified)},
			{Scope: "SOURCE_SET_BINDING@1", Coverage: appraisal.CoverageUnsupported},
		}, appraisal.DecisionQuarantine},
		{"indeterminate", []appraisal.ScopeEntry{
			{Scope: "LINEAR_ATTESTATION@1", Coverage: appraisal.CoverageEvaluated, TruthState: truth(appraisal.TruthIndeterminate)},
			{Scope: "SOURCE_SET_BINDING@1", Coverage: appraisal.CoverageEvaluated, TruthState: truth(appraisal.TruthVerified)},
		}, appraisal.DecisionQuarantine},
		{"failed wins", []appraisal.ScopeEntry{
			{Scope: "LINEAR_ATTESTATION@1", Coverage: appraisal.CoverageEvaluated, TruthState: truth(appraisal.TruthFailed)},
			{Scope: "SOURCE_SET_BINDING@1", Coverage: appraisal.CoverageUnsupported},
		}, appraisal.DecisionDeny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := appraisal.Decide(profile, tt.vector)
			if err != nil {
				t.Fatal(err)
			}
			if got.Decision != tt.want {
				t.Fatalf("decision=%s want %s", got.Decision, tt.want)
			}
		})
	}
}

func TestTwoLocalProfilesDifferOverOneEvidenceVector(t *testing.T) {
	vector := []appraisal.ScopeEntry{
		{Scope: "LINEAR_ATTESTATION@1", Coverage: appraisal.CoverageEvaluated, TruthState: truth(appraisal.TruthVerified)},
		{Scope: "SOURCE_SET_BINDING@1", Coverage: appraisal.CoverageUnsupported},
	}
	permissive, err := appraisal.Decide(appraisal.Profile{ID: "purpose-first-agent-access@1", RequiredScopes: []string{"LINEAR_ATTESTATION@1"}}, vector)
	if err != nil {
		t.Fatal(err)
	}
	strict, err := appraisal.Decide(appraisal.Profile{ID: "strict-source-binding@1", RequiredScopes: []string{"LINEAR_ATTESTATION@1", "SOURCE_SET_BINDING@1"}}, vector)
	if err != nil {
		t.Fatal(err)
	}
	if permissive.Decision != appraisal.DecisionAccept || strict.Decision != appraisal.DecisionQuarantine {
		t.Fatalf("same vector: permissive=%s strict=%s", permissive.Decision, strict.Decision)
	}
}

// manifestJSON is a manifest document, with replace applied to its text.
func manifestJSON(replace ...string) []byte {
	doc := `{"head":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","spine":[{"bodyAddress":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wireVariantId":"wire:v1:jcs-rfc8785:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],"claimContractId":"linear-provenance@1","canonicalizerId":"jcs-rfc8785","cryptosuiteId":"suite@1","schemaVersion":"credential@1","inputSnapshotDigests":{"did":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"future":{"mode":"strict"}}`
	for i := 0; i+1 < len(replace); i += 2 {
		doc = strings.Replace(doc, replace[i], replace[i+1], 1)
	}
	return []byte(doc)
}

// Every member of a manifest is read exactly as named, or kept as an
// extension in its identity: none is read under another spelling, and none is
// dropped.
func TestManifestUnmarshal_ReadsEachMemberAsNamedOrRefuses(t *testing.T) {
	for name, doc := range map[string][]byte{
		"a known field in another case":   manifestJSON(`"head"`, `"HEAD"`),
		"a known field with a long s":     manifestJSON(`"schemaVersion"`, "\"\u017fchemaVersion\""),
		"a spine key in another case":     manifestJSON(`"bodyAddress"`, `"BodyAddress"`),
		"a spine key with a long s":       manifestJSON(`"bodyAddress"`, "\"bodyAddre\u017fs\""),
		"a spine entry repeating a key":   manifestJSON(`"wireVariantId"`, `"wireVariantId":"x","wireVariantId"`),
		"a known field of the wrong type": manifestJSON(`"schemaVersion":"credential@1"`, `"schemaVersion":1`),
		"a snapshot digest not a string":  manifestJSON(`"did":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"`, `"did":1`),
		"a spine entry not an object":     manifestJSON(`[{"bodyAddress"`, `["x",{"bodyAddress"`),
	} {
		var m appraisal.Manifest
		if err := json.Unmarshal(doc, &m); !errors.Is(err, appraisal.ErrInvalidManifest) {
			t.Errorf("%s: err = %v, want ErrInvalidManifest", name, err)
		}
	}
}

// A manifest's identity is the digest of the document it was read from: no
// member is read under another spelling, and none is dropped.
func TestManifestUnmarshal_IdentityIsTheDigestOfTheDocument(t *testing.T) {
	for _, doc := range [][]byte{
		manifestJSON(),
		manifestJSON(`"future"`, `"headRef"`),
		manifestJSON(`"wireVariantId"`, `"note":"x","wireVariantId"`),
		manifestJSON(`"wireVariantId"`, `"origin":{"site":"a","seq":["b"]},"wireVariantId"`),
	} {
		var m appraisal.Manifest
		if err := json.Unmarshal(doc, &m); err != nil {
			t.Fatal(err)
		}
		id, err := m.ID()
		if err != nil {
			t.Fatal(err)
		}
		var raw any
		if err := canon.NewStrictDecoder(doc).Decode(&raw); err != nil {
			t.Fatal(err)
		}
		want, err := jcs.HashRFC8785(raw)
		if err != nil {
			t.Fatal(err)
		}
		if id != want {
			t.Errorf("ID %s, digest of the document %s", id, want)
		}
	}
}

// Every known field, spelled in upper case, is refused: the rule covers each
// name the manifest reads.
func TestManifestUnmarshal_RefusesEveryKnownFieldInUpperCase(t *testing.T) {
	for _, name := range []string{"head", "spine", "claimContractId", "canonicalizerId", "cryptosuiteId", "schemaVersion", "inputSnapshotDigests"} {
		var m appraisal.Manifest
		if err := json.Unmarshal(manifestJSON(`"`+name+`"`, `"`+strings.ToUpper(name)+`"`), &m); !errors.Is(err, appraisal.ErrInvalidManifest) {
			t.Errorf("%s in upper case: err = %v, want ErrInvalidManifest", name, err)
		}
	}
}

// A manifest built in Go with an extension that is a known field in another
// case gets no identity: a reader that folds names would read it as the field.
func TestManifestValidate_RefusesAnExtensionInAnotherCaseOfAField(t *testing.T) {
	m := manifest()
	m.Extensions = map[string]any{"ſchemaVersion": "other@1"}
	if _, err := m.ID(); !errors.Is(err, appraisal.ErrInvalidManifest) {
		t.Errorf("ID: err = %v, want ErrInvalidManifest", err)
	}
}

// A member of a spine entry other than its two fields is kept as the entry's
// extension, as the schema admits it, and is in the manifest's identity.
func TestManifestUnmarshal_KeepsAnUnknownMemberOfASpineEntry(t *testing.T) {
	var m appraisal.Manifest
	if err := json.Unmarshal(manifestJSON(`"wireVariantId"`, `"note":"x","wireVariantId"`), &m); err != nil {
		t.Fatal(err)
	}
	if got := m.Spine[0].Extensions["note"]; got != "x" {
		t.Fatalf("spine[0].Extensions[note] = %v, want x", got)
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var back appraisal.Manifest
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatal(err)
	}
	if got := back.Spine[0].Extensions["note"]; got != "x" {
		t.Fatalf("after a round trip, spine[0].Extensions[note] = %v, want x", got)
	}
	id, err := m.ID()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := back.ID(); err != nil || got != id {
		t.Errorf("ID after a round trip = %s, %v; want %s", got, err, id)
	}
}

// An extension of a spine entry changes the manifest's identity.
func TestManifestIdentityIncludesSpineEntryExtensions(t *testing.T) {
	m := manifest()
	base, err := m.ID()
	if err != nil {
		t.Fatal(err)
	}
	m.Spine[1].Extensions = map[string]any{"note": "x"}
	extended, err := m.ID()
	if err != nil {
		t.Fatal(err)
	}
	if base == extended {
		t.Fatal("a spine entry extension did not change the identity")
	}
}

// A spine entry built in Go with an extension that is one of its fields,
// exactly or in another case, gets no identity.
func TestManifestValidate_RefusesASpineEntryExtensionThatIsAField(t *testing.T) {
	for _, key := range []string{"bodyAddress", "wireVariantId", "BodyAddress", "wireVariantID", "bodyAddre\u017fs"} {
		m := manifest()
		m.Spine[0].Extensions = map[string]any{key: "x"}
		if _, err := m.ID(); !errors.Is(err, appraisal.ErrInvalidManifest) {
			t.Errorf("extension %q: ID err = %v, want ErrInvalidManifest", key, err)
		}
		if _, err := json.Marshal(m); err == nil && (key == "bodyAddress" || key == "wireVariantId") {
			t.Errorf("extension %q: MarshalJSON wrote a second %q", key, key)
		}
	}
}

// A spine entry encoded and decoded on its own reads as it does in a
// manifest: its extensions are kept, and a field in another case is refused.
func TestSpineEntryJSON_ReadsAsInAManifest(t *testing.T) {
	entry := appraisal.SpineEntry{BodyAddress: head, WireVariantID: "wire:v1:jcs-rfc8785:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Extensions: map[string]any{"note": "x"}}
	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	var back appraisal.SpineEntry
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatal(err)
	}
	if back.BodyAddress != entry.BodyAddress || back.WireVariantID != entry.WireVariantID || back.Extensions["note"] != "x" {
		t.Fatalf("round trip = %+v, want %+v", back, entry)
	}
	for name, doc := range map[string]string{
		"a field in another case": `{"BodyAddress":"x","wireVariantId":"y"}`,
		"a repeated key":          `{"bodyAddress":"x","bodyAddress":"y","wireVariantId":"z"}`,
		"a field not a string":    `{"bodyAddress":1,"wireVariantId":"y"}`,
		"not an object":           `["x"]`,
	} {
		var e appraisal.SpineEntry
		if err := json.Unmarshal([]byte(doc), &e); !errors.Is(err, appraisal.ErrInvalidManifest) {
			t.Errorf("%s: err = %v, want ErrInvalidManifest", name, err)
		}
	}
}

// A number in an extension, at the top or in a spine entry, is admitted as on
// the other identity paths (canon.AdmitSafeNumbers) before the manifest gets
// an identity; an ordinary number is admitted.
func TestManifestValidate_AdmitsExtensionNumbersAsTheOtherIdentityPathsDo(t *testing.T) {
	for name, doc := range map[string][]byte{
		"at the top":         manifestJSON(`"future":{"mode":"strict"}`, `"future":{"n":9007199254740993}`),
		"in a spine entry":   manifestJSON(`"wireVariantId"`, `"n":9007199254740993,"wireVariantId"`),
		"nested in a member": manifestJSON(`"wireVariantId"`, `"n":{"m":[9007199254740993]},"wireVariantId"`),
	} {
		var m appraisal.Manifest
		if err := json.Unmarshal(doc, &m); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_, err := m.ID()
		var unsafe *canon.UnsafeNumberError
		if !errors.Is(err, appraisal.ErrInvalidManifest) || !errors.As(err, &unsafe) {
			t.Errorf("%s: ID err = %v, want ErrInvalidManifest and *canon.UnsafeNumberError", name, err)
		}
		if _, err := m.CanonicalBytes(); !errors.Is(err, appraisal.ErrInvalidManifest) {
			t.Errorf("%s: CanonicalBytes err = %v, want ErrInvalidManifest", name, err)
		}
	}
	m := manifest()
	m.Spine[0].Extensions = map[string]any{"n": int64(1) << 60}
	if _, err := m.ID(); !errors.Is(err, appraisal.ErrInvalidManifest) {
		t.Errorf("Go-built: ID err = %v, want ErrInvalidManifest", err)
	}
	var ok appraisal.Manifest
	if err := json.Unmarshal(manifestJSON(`"wireVariantId"`, `"n":42,"wireVariantId"`), &ok); err != nil {
		t.Fatal(err)
	}
	if _, err := ok.ID(); err != nil {
		t.Errorf("an ordinary number: ID err = %v", err)
	}
}

// An extension built in Go holds what decoding JSON gives (or a Go integer):
// a value whose JSON form reads back as another value gets no identity.
func TestManifestValidate_RefusesAnExtensionValueJSONWouldReadBackOtherwise(t *testing.T) {
	for name, set := range map[string]func(*appraisal.Manifest){
		"a float32 at the top":       func(m *appraisal.Manifest) { m.Extensions = map[string]any{"v": float32(0.1)} },
		"a float32 in a spine entry": func(m *appraisal.Manifest) { m.Spine[0].Extensions = map[string]any{"v": float32(0.1)} },
		"a float32 nested": func(m *appraisal.Manifest) {
			m.Extensions = map[string]any{"v": []any{map[string]any{"w": float32(0.5)}}}
		},
	} {
		m := manifest()
		set(&m)
		if _, err := m.ID(); !errors.Is(err, appraisal.ErrInvalidManifest) {
			t.Errorf("%s: ID err = %v, want ErrInvalidManifest", name, err)
		}
	}
}

// A manifest built in Go has the identity of the document it encodes to.
func TestManifestID_IsTheIdentityOfItsEncoding(t *testing.T) {
	m := manifest()
	m.Extensions = map[string]any{"n": 42, "f": 0.25, "list": []any{"a", int64(7), nil, true}, "obj": map[string]any{"k": json.Number("3")}}
	m.Spine[0].Extensions = map[string]any{"note": "x", "u": uint8(9)}
	id, err := m.ID()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var back appraisal.Manifest
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatal(err)
	}
	if got, err := back.ID(); err != nil || got != id {
		t.Errorf("ID after a round trip = %s, %v; want %s", got, err, id)
	}
}

// What MarshalJSON writes, UnmarshalJSON reads: an extension that is a field in
// another case is not written.
func TestManifestMarshalJSON_RefusesAnExtensionInAnotherCaseOfAField(t *testing.T) {
	for name, set := range map[string]func(*appraisal.Manifest){
		"at the top":       func(m *appraisal.Manifest) { m.Extensions = map[string]any{"HEAD": "x"} },
		"in a spine entry": func(m *appraisal.Manifest) { m.Spine[0].Extensions = map[string]any{"BodyAddress": "x"} },
	} {
		m := manifest()
		set(&m)
		if _, err := json.Marshal(m); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if _, err := json.Marshal(appraisal.SpineEntry{Extensions: map[string]any{"wireVariantID": "x"}}); err == nil {
		t.Error("a spine entry alone: want error")
	}
}

// null is not a manifest, a spine entry, or the value of a field.
func TestManifestUnmarshal_RefusesNull(t *testing.T) {
	for name, doc := range map[string][]byte{
		"the manifest":         []byte(`null`),
		"head":                 manifestJSON(`"head":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, `"head":null`),
		"spine":                manifestJSON(`"spine":[`, `"spine":null,"x":[`),
		"inputSnapshotDigests": manifestJSON(`"inputSnapshotDigests":{"did":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`, `"inputSnapshotDigests":null`),
		"bodyAddress":          manifestJSON(`"bodyAddress":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, `"bodyAddress":null`),
		"a spine entry":        manifestJSON(`"spine":[`, `"spine":[null,`),
	} {
		var m appraisal.Manifest
		if err := json.Unmarshal(doc, &m); !errors.Is(err, appraisal.ErrInvalidManifest) {
			t.Errorf("%s: err = %v, want ErrInvalidManifest", name, err)
		}
	}
	var v appraisal.View
	if err := json.Unmarshal([]byte(`{"manifest":null}`), &v); !errors.Is(err, appraisal.ErrInvalidManifest) {
		t.Errorf("a view's manifest: err = %v, want ErrInvalidManifest", err)
	}
	var e appraisal.SpineEntry
	if err := json.Unmarshal([]byte(`null`), &e); !errors.Is(err, appraisal.ErrInvalidManifest) {
		t.Errorf("a spine entry alone: err = %v, want ErrInvalidManifest", err)
	}
}

// Validate reports the same refusal however the extensions map iterates.
func TestManifestValidate_ReportsTheFirstExtensionInOrder(t *testing.T) {
	var first string
	for i := 0; i < 32; i++ {
		m := manifest()
		m.Extensions = map[string]any{"HEAD": "x", "SPINE": "y", "SchemaVersion": "z"}
		_, err := m.ID()
		if err == nil {
			t.Fatal("want error")
		}
		if i == 0 {
			first = err.Error()
		} else if err.Error() != first {
			t.Fatalf("refusal %q, then %q", first, err.Error())
		}
	}
}
