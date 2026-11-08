package vc_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/provin-line/oss/vc"
)

// The sha256 pinned in the spec's contexts/README.md (dplaax.spec).
// The @context array is inside the signing scope, so a byte divergence from
// the canonical document is a cross-implementation hash partition — this
// test fails on any local drift of the vendored copy. Upstream divergence
// (the spec updating its canonical file and pin) is NOT detected here; the
// sync is push-based per the spec's contexts/README.md.
const contextDplaaxVCV1SHA256 = "9716bca789bdb1042451746800cc463a616a57817008001a3a895e88c0aff25f"

func TestContextDocumentMatchesSpec(t *testing.T) {
	doc := vc.ContextDplaaxVCV1Document()
	sum := sha256.Sum256(doc)
	if got := hex.EncodeToString(sum[:]); got != contextDplaaxVCV1SHA256 {
		t.Errorf("vendored context sha256 = %s, want %s (sync byte-exact from dplaax.spec contexts/v1.jsonld)", got, contextDplaaxVCV1SHA256)
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
		"DelegationCredential", "delegatedBy", "scope",
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
	if got, _ := parsed.Context["provin"].(string); got != "https://provin.dev/vocab#" {
		t.Errorf("provin prefix grounding = %q, want https://provin.dev/vocab#", got)
	}
	if protected, _ := parsed.Context["@protected"].(bool); !protected {
		t.Error("provin context must set @protected: true")
	}
}

// The sha256 the W3C VCDM 2.0 specification publishes for its base context
// (https://www.w3.org/ns/credentials/v2, a permanently-cacheable static
// document). Pinning the NORMATIVE digest — not a digest of whatever was
// fetched on vendoring day — means a copy that diverges from the official
// bytes by even one byte fails here, however the divergence happened.
const contextCredentialsV2SHA256 = "59955ced6697d61e03f2b2556febe5308ab16842846f5b586d7f1f7adec92734"

func TestCredentialsV2ContextMatchesNormativeDigest(t *testing.T) {
	sum := sha256.Sum256(vc.ContextCredentialsV2Document())
	if got := hex.EncodeToString(sum[:]); got != contextCredentialsV2SHA256 {
		t.Errorf("embedded credentials/v2 sha256 = %s, want the W3C-published %s (re-fetch verbatim from https://www.w3.org/ns/credentials/v2)", got, contextCredentialsV2SHA256)
	}
}

// The embedded credentials/v2 must be self-contained: RDFC expansion runs
// against an offline allowlist, so a nested remote context reference (a
// string or array @context inside any term definition) would either fail at
// runtime or, worse, demand widening the allowlist. The W3C document embeds
// all its scoped contexts inline; this pins that property.
func TestCredentialsV2ContextSelfContained(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(vc.ContextCredentialsV2Document(), &doc); err != nil {
		t.Fatalf("credentials/v2 is not valid JSON: %v", err)
	}
	// What breaks the offline loader is a nested @context value that names a
	// REMOTE document: a string IRI, or an array containing one. An inline
	// object and a null (JSON-LD's context reset) are self-contained.
	remoteRef := func(v any) bool {
		switch t2 := v.(type) {
		case string:
			return true
		case []any:
			for _, e := range t2 {
				if _, isStr := e.(string); isStr {
					return true
				}
			}
		}
		return false
	}
	var walk func(v any, path string)
	walk = func(v any, path string) {
		switch t2 := v.(type) {
		case map[string]any:
			for k, e := range t2 {
				if k == "@context" && path != "" && remoteRef(e) {
					t.Errorf("nested @context at %s references a remote document (%v) — breaks the offline loader", path, e)
				}
				if k == "@import" {
					t.Errorf("@import at %s: the embedded context must be self-contained", path)
				}
				walk(e, path+"/"+k)
			}
		case []any:
			for i, e := range t2 {
				walk(e, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	walk(doc, "")
}

func TestContextDocumentDefensiveCopy(t *testing.T) {
	for name, accessor := range map[string]func() []byte{
		"ContextDplaaxVCV1Document":    vc.ContextDplaaxVCV1Document,
		"ContextProvinVCV1Document":    vc.ContextProvinVCV1Document,
		"ContextCredentialsV2Document": vc.ContextCredentialsV2Document,
	} {
		a := accessor()
		a[0] = '!'
		if b := accessor(); b[0] == '!' {
			t.Errorf("%s returned a live reference, want defensive copy", name)
		}
	}
}

// The sha256 pinned in the profile spec's contexts/README.md
// (provin-line/profile.spec). Same discipline as the protocol context above,
// and for the same reason: the @context array rides the signing scope, so a
// byte divergence from the canonical document partitions hashes across
// implementations instead of failing loudly.
//
// This pin is what makes the ownership move real. Until profile.spec existed
// this file was the canonical, so there was nothing to drift FROM and no test
// could exist; now the profile owns the document and this proves the vendored
// copy still is it.
const contextProvinVCV1SHA256 = "35c8066d47eba1c0c284632f3b390fdb525162b45f5629b31457b030e41a9b86"

func TestProvinContextDocumentMatchesProfileSpec(t *testing.T) {
	doc := vc.ContextProvinVCV1Document()
	sum := sha256.Sum256(doc)
	if got := hex.EncodeToString(sum[:]); got != contextProvinVCV1SHA256 {
		t.Errorf("vendored profile context sha256 = %s, want %s (sync byte-exact from provin-line/profile.spec contexts/v1.jsonld)", got, contextProvinVCV1SHA256)
	}

	// Grounding is the document's whole job: the prefix must map to the
	// vocabulary URL the claim registry is written against. A context that
	// parsed but grounded nothing would leave every provin: claim ownerless
	// while looking correct.
	var parsed struct {
		Context map[string]any `json:"@context"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("profile context does not parse: %v", err)
	}
	if got := parsed.Context["provin"]; got != "https://provin.dev/vocab#" {
		t.Errorf("provin prefix grounds to %v, want https://provin.dev/vocab#", got)
	}
	if protected, _ := parsed.Context["@protected"].(bool); !protected {
		t.Error("profile context is not @protected: it could redefine protocol terms")
	}
}

// The contexts vc serves to RDFC hold only what the canonicalizer counts a
// document's values by (urdna2015's conserve.go), scoped contexts included:
// the keyword aliases id and type and no other, no map container (@id,
// @type, @index or @language), and no reference to another context (a
// string @context, or @import). A context added to the served set that
// defines more fails here, where the counting would need to change with it.
func TestServedContexts_HoldOnlyWhatCanonicalizationCounts(t *testing.T) {
	for name, doc := range map[string][]byte{
		"credentials/v2": vc.ContextCredentialsV2Document(),
		"dplaax vc/v1":   vc.ContextDplaaxVCV1Document(),
		"provin vc/v1":   vc.ContextProvinVCV1Document(),
	} {
		var d map[string]any
		if err := json.Unmarshal(doc, &d); err != nil {
			t.Fatalf("%s is not JSON: %v", name, err)
		}
		aliases := map[string]string{}
		var read func(ctx any, path string)
		read = func(ctx any, path string) {
			switch c := ctx.(type) {
			case string:
				t.Errorf("%s: @context at %s names another context, %s", name, path, c)
			case []any:
				for i, x := range c {
					read(x, fmt.Sprintf("%s[%d]", path, i))
				}
			case map[string]any:
				for term, def := range c {
					if term == "@import" {
						t.Errorf("%s: @import at %s", name, path)
					}
					switch v := def.(type) {
					case string:
						if term[0] != '@' && v != "" && v[0] == '@' {
							aliases[term] = v
						}
					case map[string]any:
						if id, ok := v["@id"].(string); ok && term[0] != '@' && id != "" && id[0] == '@' {
							aliases[term] = id
						}
						containers, ok := v["@container"].([]any)
						if !ok {
							containers = []any{v["@container"]}
						}
						for _, kind := range containers {
							switch kind {
							case "@id", "@type", "@index", "@language":
								t.Errorf("%s: %s at %s has a %s container", name, term, path, kind)
							}
						}
						if scoped, ok := v["@context"]; ok && scoped != nil {
							read(scoped, path+"/"+term)
						}
					}
				}
			}
		}
		read(d["@context"], "")
		for term, kw := range aliases {
			if !(term == "id" && kw == "@id") && !(term == "type" && kw == "@type") {
				t.Errorf("%s: %s is an alias of %s; the served contexts alias only id and type", name, term, kw)
			}
		}
	}
}
