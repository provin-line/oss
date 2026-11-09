package urdna2015

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/piprate/json-gold/ld"
)

// A member named "" is refused before json-gold runs, wherever it is outside
// a context, whatever its value: in a node, a list item, a reverse value, a
// graph, an included node, a nested group, a value object's @type, and a
// structure json-gold drops whole.
func TestCanonicalize_RefusesAMemberNamedEmpty(t *testing.T) {
	c := testContexts(t)
	for _, value := range []any{"v", map[string]any{"urn:q": "v"}, []any{"v"}, []any{}} {
		listed := subjectWith(nil)
		listed["@list"] = []any{map[string]any{"": value}}
		for where, doc := range map[string]any{
			"/credentialSubject":                subjectWith(map[string]any{"": value}),
			"/credentialSubject/urn:p/@list/0":  subjectWith(map[string]any{"urn:p": map[string]any{"@list": []any{map[string]any{"": value, "urn:q": "v"}}}}),
			"/credentialSubject/@reverse/urn:r": subjectWith(map[string]any{"@reverse": map[string]any{"urn:r": map[string]any{"": value, "urn:q": "v"}}}),
			"/credentialSubject/urn:g/@graph/0": subjectWith(map[string]any{"urn:g": map[string]any{"@id": "urn:g", "@graph": []any{map[string]any{"": value, "urn:q": "v"}}}}),
			"/credentialSubject/@included/0":    subjectWith(map[string]any{"@included": []any{map[string]any{"@id": "urn:i", "": value}}}),
			"/credentialSubject/@nest":          subjectWith(map[string]any{"@nest": map[string]any{"": value, "urn:q": "v"}}),
			"/credentialSubject/urn:p/@type":    subjectWith(map[string]any{"urn:p": map[string]any{"@value": "v", "@type": map[string]any{"": value}}}),
			"/@list/0":                          listed,
			"":                                  map[string]any{"@id": "urn:s", "urn:p": "v", "": value},
		} {
			_, err := c.Canonicalize(doc)
			want := fmt.Sprintf("urdna2015: a member named \"\" at %q:", where)
			if err == nil || !strings.HasPrefix(err.Error(), want) {
				t.Errorf("%T at %q: %v, want %s…", value, where, err, want)
			}
		}
	}
}

// A document whose own context gives a member named "" a meaning, a term ""
// or a @vocab, and uses it, is refused; json-gold kept some
// (TestJSONGold_KeepsNoMemberNamedEmptyButThroughItsOwnContext). JSON-LD 1.1
// makes "" an invalid term definition (Create Term Definition, step 2), and
// json-gold reads a value under "" as if at the top level.
func TestCanonicalize_RefusesADocumentGivingTheEmptyNameAMeaning(t *testing.T) {
	c := testContexts(t)
	for name, doc := range emptyNameDocuments() {
		if _, err := c.Canonicalize(doc); err == nil || !strings.HasPrefix(err.Error(), `urdna2015: a member named "" at "":`) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// emptyNameDocuments are documents whose own context gives a member named ""
// a meaning, a term "" or a @vocab, in forms json-gold keeps.
func emptyNameDocuments() map[string]map[string]any {
	return map[string]map[string]any{
		"\"\" an alias of @type":             {"@context": map[string]any{"": "@type"}, "@id": "urn:s", "": "urn:T", "urn:p": "v"},
		"\"\" an alias of @id":               {"@context": map[string]any{"": "@id"}, "": "urn:s", "urn:p": "v"},
		"\"\" an IRI, in a node with a type": {"@context": map[string]any{"": "urn:x"}, "@id": "urn:s", "@type": "urn:T", "": map[string]any{"urn:q": "v"}},
		"a @vocab, in a node with a type":    {"@context": map[string]any{"@vocab": "urn:v:"}, "@id": "urn:s", "@type": "urn:T", "": map[string]any{"urn:q": "v"}},
	}
}

// A context may still define the term "", in it or in a scoped context, and
// leave it unused: a context's own text is not signed, and only a member named
// "" is refused.
func TestCanonicalize_AcceptsAContextDefiningAnUnusedEmptyTerm(t *testing.T) {
	c := testContexts(t)
	for name, ctx := range map[string]map[string]any{
		"in the context":      {"": "urn:x", "q": "urn:q"},
		"in a scoped context": {"T": map[string]any{"@id": "urn:T", "@context": map[string]any{"": "urn:x"}}, "q": "urn:q"},
	} {
		if _, err := c.Canonicalize(ownContext(ctx, map[string]any{"q": "v"})); err != nil {
			t.Errorf("\"\" defined %s, unused: %v", name, err)
		}
	}
}

// json-gold, in the mode Canonicalize runs it, keeps no value of a member
// named "" unless the document's own context gives it a meaning, a term "" or
// a @vocab, and the node has a type: otherwise it fails on the member or drops
// its value, which the count of values refuses. A document whose contexts give
// "" no meaning, as the contexts vc serves do not, had no such member
// accepted.
func TestJSONGold_KeepsNoMemberNamedEmptyButThroughItsOwnContext(t *testing.T) {
	c := testContexts(t)
	for _, ctx := range []map[string]any{nil, {"@vocab": "urn:v:"}, {"": "urn:x"}, {"": map[string]any{"@id": "urn:x", "@type": "@id"}}} {
		for _, typ := range []any{nil, "urn:T"} {
			if ctx != nil && typ != nil {
				continue
			}
			for _, value := range []any{"urn:v", map[string]any{"urn:q": "v"}} {
				members := map[string]any{"urn:p": "v", "": value}
				if typ != nil {
					members["@type"] = typ
				}
				if kept, err := jsonGoldKeeps(t, c, ownContext(ctx, members)); kept {
					t.Errorf("context %v, type %v, %T: json-gold kept the member named \"\" (err %v)", ctx, typ, value, err)
				}
			}
		}
	}
	for name, doc := range emptyNameDocuments() {
		if kept, err := jsonGoldKeeps(t, c, doc); !kept {
			t.Errorf("%s: json-gold did not keep the member (err %v)", name, err)
		}
	}
}

// jsonGoldKeeps expands doc, an object with a member named "", as Canonicalize
// does, and reports whether json-gold keeps every value of it: no error, and
// as many values expanded as the rest of doc and the member hold.
func jsonGoldKeeps(t *testing.T, c *Canonicalizer, doc map[string]any) (bool, error) {
	t.Helper()
	rest := map[string]any{}
	for k, v := range doc {
		if k != "" {
			rest[k] = v
		}
	}
	values, err := c.dataValues(rest)
	if err != nil {
		t.Fatalf("dataValues: %v", err)
	}
	member, err := c.dataValues(doc[""])
	if err != nil {
		t.Fatalf("dataValues: %v", err)
	}
	expanded, err := ld.NewJsonLdProcessor().Expand(doc, c.options())
	if err != nil {
		return false, err
	}
	return expandedValues(expanded) == values+member, nil
}

// subjectWith is a credential of the W3C VC v2 context alone whose subject
// urn:o holds the members given.
func subjectWith(members map[string]any) map[string]any {
	subject := map[string]any{"@id": "urn:o"}
	for k, v := range members {
		subject[k] = v
	}
	return map[string]any{
		"@context":          "https://www.w3.org/ns/credentials/v2",
		"@id":               "urn:s",
		"type":              "VerifiableCredential",
		"issuer":            "urn:issuer",
		"credentialSubject": subject,
	}
}

// fromJSONGold returns the call's error as it is, and a panic of the call,
// whatever its value, as an error whose text is bounded.
func TestFromJSONGold_ReturnsAPanicAsAnError(t *testing.T) {
	own := errors.New("own")
	if err := fromJSONGold(func() error { return own }); err != own {
		t.Errorf("the call's own error: %v", err)
	}
	if err := fromJSONGold(func() error { return nil }); err != nil {
		t.Errorf("no error: %v", err)
	}
	for name, value := range map[string]any{
		"a string":                    "interface conversion",
		"an error":                    errors.New("index out of range"),
		"nil":                         nil,
		"an error whose Error panics": panickingError{},
		"a value whose String panics": panickingStringer{},
		"a long text":                 strings.Repeat("x", 10000),
		"text not UTF-8":              "\xff\xfe",
		"a map":                       map[string]any{"k": "v"},
	} {
		var err error
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("%s: fromJSONGold panicked: %v", name, p)
				}
			}()
			err = fromJSONGold(func() error { panic(value) })
		}()
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if !strings.HasPrefix(err.Error(), "json-gold panicked: ") || len(err.Error()) > len("json-gold panicked: ")+panicQuoteLimit {
			t.Errorf("%s: %q", name, err)
		}
	}
}

type panickingError struct{}

func (panickingError) Error() string { panic("Error") }

type panickingStringer struct{}

func (panickingStringer) String() string { panic("String") }

// underPanicNil names the variable set when this test binary runs itself with
// GODEBUG=panicnil=1, under which recover returns nil for panic(nil).
const underPanicNil = "URDNA2015_TEST_UNDER_PANICNIL"

// fromJSONGold returns a panic with a nil value as an error under
// GODEBUG=panicnil=1 too.
func TestFromJSONGold_UnderPanicNil(t *testing.T) {
	if os.Getenv(underPanicNil) != "" {
		var r any
		func() {
			defer func() { r = recover() }()
			panic(nil)
		}()
		if r != nil {
			t.Fatalf("recover() = %T: GODEBUG=panicnil=1 is not in effect", r)
		}
		if err := fromJSONGold(func() error { panic(nil) }); err == nil {
			t.Error("a panic with a nil value: no error")
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestFromJSONGold_UnderPanicNil$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "GODEBUG=panicnil=1", underPanicNil+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("under GODEBUG=panicnil=1: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "--- PASS: TestFromJSONGold_UnderPanicNil ") {
		t.Errorf("under GODEBUG=panicnil=1, the test did not pass:\n%s", out)
	}
}
