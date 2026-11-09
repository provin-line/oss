package vc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/canon/urdna2015"
	"github.com/provin-line/oss/internal/rdfccorpus"
)

// servedOnlyRefusal is what the refusal of a context the suite does not
// serve says.
const servedOnlyRefusal = "only the IRIs of the contexts it serves"

// servedIRIs are the contexts the registered eddsa-rdfc-2022 serves.
var servedIRIs = map[string]bool{ContextCredentialsV2: true, ContextDplaaxVCV1: true, ContextProvinVCV1: true}

// onlyServedContexts reports whether every @context in v, at any depth, is
// the IRI of a served context or a list of them. It is the tests' own
// reading, written apart from the check it tests.
func onlyServedContexts(v any) bool {
	ok := true
	var visit func(v any)
	visit = func(v any) {
		switch t := v.(type) {
		case []any:
			for _, x := range t {
				visit(x)
			}
		case map[string]any:
			for k, x := range t {
				if k != "@context" {
					visit(x)
					continue
				}
				list, isList := x.([]any)
				if !isList {
					list = []any{x}
				}
				for _, c := range list {
					if iri, isString := c.(string); !isString || !servedIRIs[iri] {
						ok = false
					}
				}
			}
		}
	}
	visit(v)
	return ok
}

// servedCredential is a provin credential of the served contexts alone.
func servedCredential(t *testing.T) map[string]any {
	t.Helper()
	cred, err := New(CredentialFields{
		Issuer:    "did:dplaax:t.dplaax.dev:org:t:pipeline:p:process:s",
		ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Subject: CredentialSubjectFields{
			PipelineID:          "p",
			ProcessID:           "s",
			TransformationClaim: ClaimConvert,
			InputHash:           "sha256:" + probeHex,
			OutputHash:          "sha256:" + probeHex,
		},
		PreviousCredential: "sha256:" + probeHex,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cred.Body()
}

func registeredRDFC(t *testing.T) func(any) ([]byte, error) {
	t.Helper()
	c, err := canonicalizerFor(CryptosuiteEdDSARDFC2022)
	if err != nil {
		t.Fatal(err)
	}
	return c.Canonicalize
}

// eddsa-rdfc-2022 reads only the contexts it serves: a document holding any
// other @context, at any place JSON-LD reads one, is refused before it is
// canonicalized, both when a proof is created and when one is verified (each
// takes the suite's canonicalizer from canonicalizerFor). The refusal names
// what it found, in JSON's words, and where, as a JSON pointer. A credential
// of the served contexts alone is accepted.
func TestRDFC_ReadsOnlyTheServedContexts(t *testing.T) {
	canonicalize := registeredRDFC(t)
	if _, err := canonicalize(servedCredential(t)); err != nil {
		t.Fatalf("a credential of the served contexts: %v", err)
	}
	inline := map[string]any{"x": "urn:x"}
	subject := func(d map[string]any) map[string]any { return d["credentialSubject"].(map[string]any) }
	for name, tc := range map[string]struct {
		change func(d map[string]any)
		at     string
		what   string
	}{
		"an object among the IRIs": {func(d map[string]any) { d["@context"] = append(d["@context"].([]any), inline) }, `"/@context/3"`, "a context written in the document"},
		"an object alone":          {func(d map[string]any) { d["@context"] = inline }, `"/@context"`, "a context written in the document"},
		"in a nested node":         {func(d map[string]any) { subject(d)["@context"] = inline }, `"/credentialSubject/@context"`, "a context written in the document"},
		"under @graph": {func(d map[string]any) {
			subject(d)["@graph"] = []any{map[string]any{"@context": inline, "@id": "urn:g"}}
		}, `"/credentialSubject/@graph/0/@context"`, "a context written in the document"},
		"under @included": {func(d map[string]any) {
			subject(d)["@included"] = []any{map[string]any{"@context": inline, "@id": "urn:i"}}
		}, `"/credentialSubject/@included/0/@context"`, "a context written in the document"},
		"under @reverse": {func(d map[string]any) {
			subject(d)["@reverse"] = map[string]any{"urn:r": map[string]any{"@context": inline, "@id": "urn:r"}}
		}, `"/credentialSubject/@reverse/urn:r/@context"`, "a context written in the document"},
		"under @nest": {func(d map[string]any) {
			subject(d)["@nest"] = map[string]any{"@context": inline}
		}, `"/credentialSubject/@nest/@context"`, "a context written in the document"},
		"under a key holding / and ~": {func(d map[string]any) {
			subject(d)["urn:a/b~c"] = map[string]any{"@context": inline, "@id": "urn:x"}
		}, `"/credentialSubject/urn:a~1b~0c/@context"`, "a context written in the document"},
		"a term's scoped context": {func(d map[string]any) {
			d["@context"] = append(d["@context"].([]any), map[string]any{"t": map[string]any{"@id": "urn:t", "@context": inline}})
		}, `"/@context/3"`, "a context written in the document"},
		"a type-scoped context": {func(d map[string]any) {
			d["@context"] = append(d["@context"].([]any), map[string]any{"T": map[string]any{"@id": "urn:T", "@context": inline}})
			d["type"] = append(d["type"].([]any), "T")
		}, `"/@context/3"`, "a context written in the document"},
		"a context in a context": {func(d map[string]any) {
			d["@context"] = append(d["@context"].([]any), map[string]any{"@context": ContextCredentialsV2})
		}, `"/@context/3"`, "a context written in the document"},
		"an inline context importing a served one": {func(d map[string]any) {
			d["@context"] = append(d["@context"].([]any), map[string]any{"@import": ContextCredentialsV2})
		}, `"/@context/3"`, "a context written in the document"},
		"null":             {func(d map[string]any) { subject(d)["@context"] = nil }, `"/credentialSubject/@context"`, "null"},
		"a boolean":        {func(d map[string]any) { subject(d)["@context"] = true }, `"/credentialSubject/@context"`, "a boolean"},
		"a list in a list": {func(d map[string]any) { d["@context"] = append(d["@context"].([]any), []any{ContextCredentialsV2}) }, `"/@context/3"`, "a list"},
		"an IRI not served": {func(d map[string]any) {
			d["@context"] = append(d["@context"].([]any), "https://www.w3.org/ns/credentials/examples/v2")
		}, `"/@context/3"`, `the IRI "https://www.w3.org/ns/credentials/examples/v2", which it does not serve`},
	} {
		doc := servedCredential(t)
		tc.change(doc)
		_, err := canonicalize(doc)
		if err == nil || !strings.Contains(err.Error(), servedOnlyRefusal) {
			t.Errorf("%s: %v, want it refused as a context not served", name, err)
			continue
		}
		if want := tc.what + " at " + tc.at; !strings.HasSuffix(err.Error(), want) {
			t.Errorf("%s: %q, want it to end %q", name, err, want)
		}
	}
}

// Every document of the RDFC tests' corpus that holds a context other than
// the served ones is refused for that, whatever canon/urdna2015 would make of
// it; one that holds only served contexts is left to canon/urdna2015.
func TestRDFC_RefusesTheCorpusFormsOfOtherContexts(t *testing.T) {
	canonicalize := registeredRDFC(t)
	docs := map[string]any{}
	for name, pair := range rdfccorpus.DifferentValues() {
		docs[name+", a"], docs[name+", b"] = pair("a"), pair("b")
	}
	for name, pair := range rdfccorpus.AcceptedPairs() {
		docs["accepted "+name+", a"], docs["accepted "+name+", b"] = pair("a"), pair("b")
	}
	for name, doc := range rdfccorpus.Refusals() {
		docs["refused "+name] = doc
	}
	refused := 0
	for name, doc := range docs {
		_, err := canonicalize(doc)
		other := err != nil && strings.Contains(err.Error(), servedOnlyRefusal)
		if want := !onlyServedContexts(doc); other != want {
			t.Errorf("%s: %v, want refused as a context not served: %v", name, err, want)
		}
		if other {
			refused++
		}
	}
	if refused == 0 || refused == len(docs) {
		t.Errorf("%d of %d documents refused for their contexts: the corpus does not test both sides", refused, len(docs))
	}
}

// A presentation of the served contexts alone is accepted, and a value it
// holds changes its canonical form.
func TestRDFC_AcceptsAPresentationOfTheServedContexts(t *testing.T) {
	canonicalize := registeredRDFC(t)
	pair := rdfccorpus.AcceptedPairs()["a presentation's credential as an IRI"]
	a, errA := canonicalize(pair("a"))
	b, errB := canonicalize(pair("b"))
	if errA != nil || errB != nil || string(a) == string(b) {
		t.Errorf("%v, %v, one form: %v", errA, errB, string(a) == string(b))
	}
}

// JSON-LD gives @context no alias (json-gold: "cannot alias @context"), so
// reading the key @context written out finds every context: a document that
// defines one is refused where a document's own contexts are read
// (canon/urdna2015 with WithLocalContexts), and on the suite's path, where
// its context is not served, before they are read.
func TestRDFC_ContextHasNoAlias(t *testing.T) {
	canonicalize := registeredRDFC(t)
	local := urdna2015.NewCanonicalizer(map[string][]byte{ContextCredentialsV2: contextCredentialsV2Document}, urdna2015.WithLocalContexts())
	for name, alias := range map[string]any{"a term": "@context", "a term's @id": map[string]any{"@id": "@context"}} {
		var doc map[string]any
		if err := json.Unmarshal([]byte(`{"@context":[{"ctx":null}],"@id":"urn:s","ctx":{"x":"urn:x"},"urn:p":"v"}`), &doc); err != nil {
			t.Fatal(err)
		}
		doc["@context"].([]any)[0].(map[string]any)["ctx"] = alias
		if _, err := local.Canonicalize(doc); err == nil || !strings.Contains(err.Error(), "alias") {
			t.Errorf("%s, its own contexts read: %v, want the alias refused", name, err)
		}
		if _, err := canonicalize(doc); err == nil || !strings.Contains(err.Error(), servedOnlyRefusal) {
			t.Errorf("%s, the suite: %v, want it refused as a context not served", name, err)
		}
	}
}

// The canonicalizer the suite wraps refuses a context written in the document
// by itself, behind the suite's own refusal: vc does not open
// urdna2015.WithLocalContexts, so either check alone keeps a document from
// defining a term.
func TestRDFC_TheWrappedCanonicalizerRefusesALocalContext(t *testing.T) {
	inner := servedContextsOnly(map[string][]byte{ContextCredentialsV2: contextCredentialsV2Document}).(servedContexts).inner
	doc := map[string]any{"@context": []any{ContextCredentialsV2, map[string]any{"q": "urn:q"}}, "id": "urn:s", "q": "v"}
	if _, err := inner.Canonicalize(doc); err == nil || !strings.Contains(err.Error(), "a context written in the document") {
		t.Errorf("%v, want it refused as a context written in the document", err)
	}
}

// The suite's check and the canonicalizer it wraps hold one rule for
// @context, the IRI of a served context or a list of them: for each shape,
// in a node, both accept it or both refuse it.
func TestRDFC_BothContextChecksAgree(t *testing.T) {
	wrapped := servedContextsOnly(map[string][]byte{ContextCredentialsV2: contextCredentialsV2Document}).(servedContexts)
	for name, ctx := range map[string]any{
		"a served IRI":             ContextCredentialsV2,
		"a list of served IRIs":    []any{ContextCredentialsV2, ContextCredentialsV2},
		"an empty list":            []any{},
		"a context written":        map[string]any{"q": "urn:q"},
		"a list holding one":       []any{ContextCredentialsV2, map[string]any{"q": "urn:q"}},
		"an IRI not served":        "https://e.x/unserved",
		"a list in a list":         []any{[]any{ContextCredentialsV2}},
		"a boolean":                true,
		"null":                     nil,
		"a list holding a boolean": []any{ContextCredentialsV2, false},
	} {
		doc := map[string]any{"@context": ContextCredentialsV2, "id": "urn:s", "credentialSubject": map[string]any{"@context": ctx, "id": "urn:o"}}
		var path []string
		walkErr := wrapped.walk(doc, &path)
		_, innerErr := wrapped.inner.Canonicalize(doc)
		innerRefuses := innerErr != nil && strings.Contains(innerErr.Error(), "@context at")
		if (walkErr != nil) != innerRefuses {
			t.Errorf("%s: the suite's check: %v; the wrapped canonicalizer: %v", name, walkErr, innerErr)
		}
	}
}

// On the suite's path, as in canon/urdna2015, two documents of the corpus
// that differ in a value and hold only the served contexts have different
// canonical forms, or are refused.
func TestRDFC_SignsEveryValueOfTheServedCorpusOrRefuses(t *testing.T) {
	canonicalize := registeredRDFC(t)
	served := 0
	for name, pair := range rdfccorpus.DifferentValues() {
		docA, docB := pair("a"), pair("b")
		if !onlyServedContexts(docA) || !onlyServedContexts(docB) {
			continue
		}
		served++
		a, errA := canonicalize(docA)
		b, errB := canonicalize(docB)
		if errA == nil && errB == nil && string(a) == string(b) {
			t.Errorf("%s: two documents differing in a value have one canonical form", name)
		}
	}
	if served == 0 {
		t.Error("no pair of the corpus holds only the served contexts")
	}
}

// On the suite's path, a document nested as deep as encoding/json decodes,
// 10,000 objects and arrays, is accepted; one deeper, however it was built,
// is refused with an error wrapping urdna2015.ErrTooComplex. The suite's own
// walk, which runs before canon/urdna2015's, refuses it before entering the
// level past the bound.
func TestRDFC_RefusesNestingPastTheBound(t *testing.T) {
	canonicalize := registeredRDFC(t)
	nested := func(depth int) map[string]any {
		node := map[string]any{"@id": "urn:leaf", "https://e.x/q": "v"}
		for i := 2; i < depth; i++ {
			node = map[string]any{"@id": fmt.Sprintf("urn:d:%d", i), "https://e.x/p": node}
		}
		return map[string]any{"@context": ContextCredentialsV2, "@id": "urn:s", "https://e.x/p": node}
	}
	if _, err := canonicalize(nested(10000)); err != nil {
		t.Fatalf("10,000 deep: %v", err)
	}
	for _, depth := range []int{10001, 30000} {
		if _, err := canonicalize(nested(depth)); !errors.Is(err, urdna2015.ErrTooComplex) {
			t.Errorf("%d deep: %v, want urdna2015.ErrTooComplex", depth, err)
		}
	}
	walk := servedContextsOnly(map[string][]byte{ContextCredentialsV2: contextCredentialsV2Document}).(servedContexts).walk
	for depth, refused := range map[int]bool{10000: false, 10001: true} {
		var path []string
		err := walk(nested(depth), &path)
		if got := errors.Is(err, urdna2015.ErrTooComplex) && strings.HasPrefix(err.Error(), "vc: eddsa-rdfc-2022: "); got != refused || (!refused && err != nil) {
			t.Errorf("the suite's walk, %d deep: %v, want refused: %v", depth, err, refused)
		}
	}
}
