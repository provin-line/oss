// Package conformance pins the provin profile's machine-checkable facts as
// data: the vectors under vectors/ are consumed by these tests against the
// implementation, so the profile artifacts and the code cannot drift apart
// unnoticed. Normative meaning is NOT defined here — see README.md for
// where the sources of truth live.
package conformance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/vc"
)

type claimVector struct {
	ID           string   `json:"id"`
	Instantiates []string `json:"instantiates"`
	Description  string   `json:"description"`
	Input        struct {
		Claim   string   `json:"claim"`
		Context []string `json:"context"`
	} `json:"input"`
	Expect struct {
		Valid bool   `json:"valid"`
		IRI   string `json:"iri"`
	} `json:"expect"`
}

type contextVector struct {
	ID           string   `json:"id"`
	Instantiates []string `json:"instantiates"`
	Description  string   `json:"description"`
	Input        struct {
		ContextURI string `json:"context_uri"`
	} `json:"input"`
	Expect struct {
		SHA256    string            `json:"sha256"`
		Grounds   map[string]string `json:"grounds"`
		Protected bool              `json:"protected"`
	} `json:"expect"`
}

func loadVector(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	// Unknown-field rejection so a typo'd vector key fails loudly instead
	// of silently defaulting the expectation.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

// parsedProfileContext returns the @context object of the embedded provin
// profile context document.
func parsedProfileContext(t *testing.T) map[string]any {
	t.Helper()
	var parsed struct {
		Context map[string]any `json:"@context"`
	}
	if err := json.Unmarshal(vc.ContextProvinVCV1Document(), &parsed); err != nil {
		t.Fatalf("provin profile context document is not valid JSON: %v", err)
	}
	return parsed.Context
}

func TestClaimVectors(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("vectors", "claim-*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no claim vectors found: %v", err)
	}
	grounds := parsedProfileContext(t)
	for _, path := range paths {
		var v claimVector
		loadVector(t, path, &v)
		t.Run(v.ID, func(t *testing.T) {
			cred, err := vc.New(vc.CredentialFields{
				Issuer:    "did:dplaax:poc.dplaax.io:org:conformance:process:p1",
				ValidFrom: time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC),
				Subject: vc.CredentialSubjectFields{
					PipelineID:          "conformance",
					ProcessID:           "conformance",
					TransformationClaim: vc.TransformationClaim(v.Input.Claim),
				},
			})
			if v.Expect.Valid != (err == nil) {
				t.Fatalf("New(%q): valid = %v, want %v (err: %v)", v.Input.Claim, err == nil, v.Expect.Valid, err)
			}
			if !v.Expect.Valid {
				return
			}

			// The wire @context the implementation emits must be exactly the
			// vector's context list (credential.field.context ordering).
			wire, err := json.Marshal(cred)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var doc struct {
				Context []string `json:"@context"`
			}
			if err := json.Unmarshal(wire, &doc); err != nil {
				t.Fatalf("re-parse wire: %v", err)
			}
			if len(doc.Context) != len(v.Input.Context) {
				t.Fatalf("@context = %v, want %v", doc.Context, v.Input.Context)
			}
			for i := range doc.Context {
				if doc.Context[i] != v.Input.Context[i] {
					t.Fatalf("@context[%d] = %q, want %q", i, doc.Context[i], v.Input.Context[i])
				}
			}

			if err := cred.ValidateTransformationClaim(); err != nil {
				t.Fatalf("ValidateTransformationClaim(%q): %v", v.Input.Claim, err)
			}

			// Claim identity is the (grounding URL, label) pair: the expansion
			// under the profile context must match the pinned vocabulary IRI.
			prefix, label, _ := strings.Cut(v.Input.Claim, ":")
			vocab, _ := grounds[prefix].(string)
			if vocab == "" {
				t.Fatalf("profile context grounds no prefix %q", prefix)
			}
			if got := vocab + label; got != v.Expect.IRI {
				t.Errorf("expansion = %q, want %q", got, v.Expect.IRI)
			}
		})
	}
}

func TestContextVector(t *testing.T) {
	var v contextVector
	loadVector(t, filepath.Join("vectors", "context-001.json"), &v)

	if vc.ContextProvinVCV1 != v.Input.ContextURI {
		t.Errorf("ContextProvinVCV1 = %q, want %q", vc.ContextProvinVCV1, v.Input.ContextURI)
	}

	doc := vc.ContextProvinVCV1Document()
	sum := sha256.Sum256(doc)
	if got := hex.EncodeToString(sum[:]); got != v.Expect.SHA256 {
		t.Errorf("profile context sha256 = %s, want %s (the document is byte-canonical; update the vector ledger deliberately, never incidentally)", got, v.Expect.SHA256)
	}

	grounds := parsedProfileContext(t)
	for prefix, wantURL := range v.Expect.Grounds {
		if got, _ := grounds[prefix].(string); got != wantURL {
			t.Errorf("grounding %q = %q, want %q", prefix, got, wantURL)
		}
	}
	if v.Expect.Protected {
		if protected, _ := grounds["@protected"].(bool); !protected {
			t.Error("profile context must set @protected: true")
		}
	}
}
