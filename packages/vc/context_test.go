package vc_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/provin-line/oss/packages/vc"
)

// The sha256 pinned in the spec's contexts/README.md (dplaax.spec_draft).
// The @context array is inside the signing scope, so a byte divergence from
// the canonical document is a cross-implementation hash partition — this
// test fails on any drift of the vendored copy.
const contextDplaaxVCV1SHA256 = "617e644219e06d1ca2f8f5bffb942e0e390bba8303903e6e4f7f386ebadeaefd"

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

func TestContextDocumentDefensiveCopy(t *testing.T) {
	a := vc.ContextDplaaxVCV1Document()
	a[0] = '!'
	if b := vc.ContextDplaaxVCV1Document(); b[0] == '!' {
		t.Error("ContextDplaaxVCV1Document returned a live reference, want defensive copy")
	}
}
