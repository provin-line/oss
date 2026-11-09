package vc_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/vc"
)

// A proof decodes under the strict rules on every path, also through
// encoding/json: a duplicate key or invalid Unicode is refused.
func TestDataIntegrityProof_UnmarshalJSONIsStrict(t *testing.T) {
	for name, doc := range map[string]string{
		"duplicate key":      `{"type":"DataIntegrityProof","type":"x"}`,
		"invalid UTF-8":      "{\"type\":\"DataIntegrityProof\",\"proofValue\":\"z\xff\"}",
		"unpaired surrogate": `{"type":"DataIntegrityProof","proofValue":"z\ud800"}`,
	} {
		var p vc.DataIntegrityProof
		if err := json.Unmarshal([]byte(doc), &p); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	var p vc.DataIntegrityProof
	if err := json.Unmarshal([]byte(`{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","proofValue":"z1","previousProof":"urn:x"}`), &p); err != nil || p.Cryptosuite != "eddsa-jcs-2022" {
		t.Errorf("valid proof with an unknown member: %+v, %v", p, err)
	}
}

// The method refuses trailing data itself, for a caller that hands it bytes
// directly.
func TestDataIntegrityProof_UnmarshalJSONRefusesTrailingData(t *testing.T) {
	var p vc.DataIntegrityProof
	if err := p.UnmarshalJSON([]byte(`{"type":"DataIntegrityProof"} {}`)); err == nil {
		t.Error("want error")
	}
}

// A proof inside another value is read by its own strict pass, and the
// duplicate key error stays reachable through the wrap.
func TestDataIntegrityProof_StrictInsideAnotherValue(t *testing.T) {
	var v struct{ P *vc.DataIntegrityProof }
	err := json.Unmarshal([]byte(`{"P":{"type":"a","type":"b"}}`), &v)
	var dup *canon.DuplicateKeyError
	if !errors.As(err, &dup) {
		t.Errorf("err = %v, want a *canon.DuplicateKeyError", err)
	}
}

// A number in a proof's @context decodes as a json.Number, as in a document
// decoded strictly.
func TestDataIntegrityProof_ContextNumberIsAJSONNumber(t *testing.T) {
	var p vc.DataIntegrityProof
	if err := json.Unmarshal([]byte(`{"type":"DataIntegrityProof","@context":["https://example.org",{"v":1}]}`), &p); err != nil {
		t.Fatal(err)
	}
	list, ok := p.Context.([]any)
	if !ok || len(list) != 2 {
		t.Fatalf("@context = %#v", p.Context)
	}
	obj, ok := list[1].(map[string]any)
	if !ok {
		t.Fatalf("@context[1] = %#v", list[1])
	}
	if _, ok := obj["v"].(json.Number); !ok {
		t.Errorf("@context[1].v is %T, want json.Number", obj["v"])
	}
}

// The proof is read afresh: a member the document omits is zero, whatever the
// receiver held, so an absent @context is nil.
func TestDataIntegrityProof_UnmarshalJSONReadsAfresh(t *testing.T) {
	p := vc.DataIntegrityProof{Context: []any{"https://example.org"}, Cryptosuite: "kept"}
	if err := json.Unmarshal([]byte(`{"type":"DataIntegrityProof"}`), &p); err != nil {
		t.Fatal(err)
	}
	if p.Context != nil || p.Cryptosuite != "" {
		t.Errorf("decoded %+v, want omitted members zero", p)
	}
}

// A member that matches a field only by case is refused, so "@Context": null
// cannot stand for an absent @context.
func TestDataIntegrityProof_RefusesAFieldMatchedOnlyByCase(t *testing.T) {
	for name, doc := range map[string]string{
		"@Context null":         `{"type":"DataIntegrityProof","@Context":null}`,
		"two cases of @context": `{"type":"DataIntegrityProof","@context":["https://example.org"],"@CONTEXT":null}`,
		"CRYPTOSUITE":           `{"type":"DataIntegrityProof","CRYPTOSUITE":"eddsa-jcs-2022"}`,
	} {
		var p vc.DataIntegrityProof
		err := json.Unmarshal([]byte(doc), &p)
		var dup *canon.DuplicateKeyError
		if !errors.As(err, &dup) {
			t.Errorf("%s: err = %v, want a *canon.DuplicateKeyError", name, err)
		}
	}
}
