package vc_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/provin-line/oss/vc"
)

// The sha256 pinned in the spec's contexts/README.md (dplaax.spec_draft).
// The @context array is inside the signing scope, so a byte divergence from
// the canonical document is a cross-implementation hash partition — this
// test fails on any local drift of the vendored copy. Upstream divergence
// (the spec updating its canonical file and pin) is NOT detected here; the
// sync is push-based per the spec's contexts/README.md.
const contextDplaaxVCV1SHA256 = "4f79e1f18e257de0a822668b63b625831c37788e1e45441a01b48c53f4c5e6b2"

func TestContextDocumentMatchesSpec(t *testing.T) {
	doc := vc.ContextDplaaxVCV1Document()
	sum := sha256.Sum256(doc)
	if got := hex.EncodeToString(sum[:]); got != contextDplaaxVCV1SHA256 {
		t.Errorf("vendored context sha256 = %s, want %s (sync byte-exact from dplaax.spec_draft contexts/v1.jsonld)", got, contextDplaaxVCV1SHA256)
	}

	var parsed struct {
		Context map[string]any `json:"@context"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("context document is not valid JSON: %v", err)
	}
	// Every dplaax wire key must have a term — a missing term means the
	// vendored document and the wire vocabulary have drifted.
	for _, key := range []string{
		"pipelineId", "processId", "transformationClaim", "schema",
		"contentHash", "inputHash", "outputHash", "previousCredential",
		"derived_from", "source_root", "source_root_canonical",
		"PipelinePassCredential",
	} {
		if _, ok := parsed.Context[key]; !ok {
			t.Errorf("context document missing term %q", key)
		}
	}
	if protected, _ := parsed.Context["@protected"].(bool); !protected {
		t.Error("context document must set @protected: true")
	}
}

func TestProvinContextGroundsClaimNamespace(t *testing.T) {
	doc := vc.ContextProvinVCV1Document()
	var parsed struct {
		Context map[string]any `json:"@context"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("provin context document is not valid JSON: %v", err)
	}
	// The profile context's job is grounding: every namespace prefix the
	// provin claim registry emits must be mapped to a vocabulary URL.
	if got, _ := parsed.Context["provin"].(string); got != "https://provin-line.io/vocab#" {
		t.Errorf("provin prefix grounding = %q, want https://provin-line.io/vocab#", got)
	}
	if protected, _ := parsed.Context["@protected"].(bool); !protected {
		t.Error("provin context must set @protected: true")
	}
}

func TestContextDocumentDefensiveCopy(t *testing.T) {
	for name, accessor := range map[string]func() []byte{
		"ContextDplaaxVCV1Document": vc.ContextDplaaxVCV1Document,
		"ContextProvinVCV1Document": vc.ContextProvinVCV1Document,
	} {
		a := accessor()
		a[0] = '!'
		if b := accessor(); b[0] == '!' {
			t.Errorf("%s returned a live reference, want defensive copy", name)
		}
	}
}
