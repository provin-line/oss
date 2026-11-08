// Package rdfccorpus holds the documents the RDFC canonicalization tests
// read: pairs of JSON-LD documents that differ in one value, in forms where
// JSON-LD processing could leave that value out of what is signed; pairs near
// those forms that hold every value; and documents refused for the form they
// use. canon/urdna2015's tests canonicalize them directly, and vc's tests
// through the eddsa-rdfc-2022 path, so a form added here is checked on both.
//
// Only tests import it (scripts/check-rdfc-registration.sh), so no program
// carries these documents. Each call returns new documents, which a caller
// may change; they hold only what encoding/json gives (maps, slices, strings
// and booleans), no numbers.
package rdfccorpus

// OwnContext is a document of its own context, the terms q and those given,
// whose node https://e.x/s holds the given members.
func OwnContext(terms map[string]any, members map[string]any) map[string]any {
	ctx := map[string]any{"q": "https://e.x/q"}
	for k, v := range terms {
		ctx[k] = v
	}
	doc := map[string]any{"@context": ctx, "@id": "https://e.x/s"}
	for k, v := range members {
		doc[k] = v
	}
	return doc
}

// GraphTerm is the definition of a term whose container is a graph, with the
// further entries given.
func GraphTerm(container any, entries map[string]any) map[string]any {
	d := map[string]any{"@id": "https://e.x/g", "@container": container}
	for k, v := range entries {
		d[k] = v
	}
	return d
}

// CredentialV2 is a credential of the W3C VC v2 contexts alone.
func CredentialV2(subject map[string]any) map[string]any {
	return map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:example:issuer",
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": subject,
	}
}

// servedSubject is a credential of the W3C VC v2 context alone, which vc
// serves, whose subject urn:o holds urn:p with the value given.
func servedSubject(value any) map[string]any {
	return servedSubjectWith(map[string]any{"urn:p": value})
}

// servedSubjectWith is a credential of the W3C VC v2 context alone whose
// subject urn:o holds the members given.
func servedSubjectWith(members map[string]any) map[string]any {
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

// undefinedTerm is a term the W3C VC v2 context does not define, for m.
func undefinedTerm(m string) string {
	return map[string]string{"a": "approved", "b": "rejected"}[m]
}

// setThroughATerm is a context in which s2 stands for @set through s, a
// term of a term the context rules do not read as an alias.
func setThroughATerm() map[string]any {
	return map[string]any{"s": "@set", "s2": "s"}
}

// aNode is a node with a property, beside the value a pair changes.
func aNode() map[string]any { return map[string]any{"@id": "https://e.x/n", "q": "v"} }

// noneThroughATerm makes k a term of n, which is @none, while a scope not in
// use makes k @type.
func noneThroughATerm() map[string]any {
	return map[string]any{
		"n":      "@none",
		"k":      "n",
		"Unused": map[string]any{"@id": "urn:Unused", "@context": map[string]any{"k": "@type"}},
	}
}

// DifferentValues are pairs of documents that differ in one value, m: "a" in
// one and "b" in the other. Each is a form in which JSON-LD processing could
// leave that value out of the dataset, so the two must have different
// canonical forms or be refused.
func DifferentValues() map[string]func(m string) any {
	return map[string]func(m string) any{
		"a string in a graph container": func(m string) any {
			return OwnContext(map[string]any{"g": GraphTerm("@graph", nil)}, map[string]any{"g": m})
		},
		"strings in a graph and set container": func(m string) any {
			return OwnContext(map[string]any{"g": GraphTerm([]any{"@graph", "@set"}, nil)}, map[string]any{"g": []any{m, "x"}})
		},
		"a string in a graph and id container": func(m string) any {
			return OwnContext(map[string]any{"g": GraphTerm([]any{"@graph", "@id"}, nil)}, map[string]any{"g": map[string]any{"https://e.x/gid": m}})
		},
		"a node of only @id in a graph container": func(m string) any {
			return OwnContext(map[string]any{"g": GraphTerm("@graph", nil)}, map[string]any{"g": map[string]any{"@id": "https://e.x/" + m}})
		},
		"an IRI in a graph container of @type @id": func(m string) any {
			return OwnContext(map[string]any{"g": GraphTerm("@graph", map[string]any{"@type": "@id"})}, map[string]any{"g": "https://e.x/" + m})
		},
		"a list in a graph container": func(m string) any {
			return OwnContext(map[string]any{"g": GraphTerm("@graph", nil)}, map[string]any{"g": map[string]any{"@list": []any{m}}})
		},
		"a value with a language in a graph container": func(m string) any {
			return OwnContext(map[string]any{"g": GraphTerm("@graph", nil)}, map[string]any{"g": map[string]any{"@value": m, "@language": "en"}})
		},
		"a value object in a top-level @graph": func(m string) any {
			return map[string]any{"@context": map[string]any{"q": "https://e.x/q"}, "@graph": []any{map[string]any{"@value": m}, aNode()}}
		},
		"a node of only @id in a top-level @graph": func(m string) any {
			return map[string]any{"@context": map[string]any{"q": "https://e.x/q"}, "@graph": []any{map[string]any{"@id": "https://e.x/" + m}, aNode()}}
		},
		"a value object in a top-level array": func(m string) any {
			ctx := func() map[string]any { return map[string]any{"q": "https://e.x/q"} }
			return []any{map[string]any{"@context": ctx(), "@value": m}, map[string]any{"@context": ctx(), "@id": "https://e.x/n", "q": "v"}}
		},
		"a string under an alias of @graph": func(m string) any {
			return OwnContext(map[string]any{"gg": "@graph"}, map[string]any{"gg": []any{m, aNode()}})
		},
		"a string under @graph": func(m string) any {
			return OwnContext(nil, map[string]any{"@graph": []any{m, aNode()}})
		},
		"a credential's proof as an IRI": func(m string) any {
			d := CredentialV2(map[string]any{"id": "did:example:s", "name": "x"})
			d["proof"] = "https://e.x/" + m
			return d
		},
		"a credential's proof as a node of only id": func(m string) any {
			d := CredentialV2(map[string]any{"id": "did:example:s", "name": "x"})
			d["proof"] = map[string]any{"id": "https://e.x/" + m}
			return d
		},
		"a proof as an IRI in a subject typed VerifiableCredential": func(m string) any {
			return CredentialV2(map[string]any{"id": "did:example:s", "name": "x", "type": "VerifiableCredential", "proof": "https://e.x/" + m})
		},
		"a graph and type container": func(m string) any {
			return OwnContext(map[string]any{"g": GraphTerm([]any{"@graph", "@type"}, nil)}, map[string]any{"g": map[string]any{"https://e.x/T": m}})
		},
		"a string in a graph container of an included node": func(m string) any {
			return OwnContext(map[string]any{"g": GraphTerm("@graph", nil)}, map[string]any{"q": "x", "@included": []any{map[string]any{"@id": "https://e.x/i", "g": m}}})
		},
		"a reverse term of a graph container": func(m string) any {
			return OwnContext(map[string]any{"rg": map[string]any{"@reverse": "https://e.x/g", "@container": "@graph"}}, map[string]any{"rg": map[string]any{"@id": "https://e.x/" + m}})
		},
		"a string in a graph container under @nest": func(m string) any {
			return OwnContext(map[string]any{"g": GraphTerm("@graph", nil), "n": "@nest"}, map[string]any{"q": "x", "n": map[string]any{"g": m}})
		},
		"a JSON literal in a graph container": func(m string) any {
			return OwnContext(map[string]any{"g": GraphTerm("@graph", map[string]any{"@type": "@json"})}, map[string]any{"g": map[string]any{"k": m}})
		},
		"a node of only @id in @included": func(m string) any {
			return OwnContext(nil, map[string]any{"q": "x", "@included": []any{map[string]any{"@id": "https://e.x/" + m}}})
		},
		"a key of an id map whose item has its own @id": func(m string) any {
			return OwnContext(map[string]any{"im": map[string]any{"@id": "https://e.x/im", "@container": "@id"}}, map[string]any{"im": map[string]any{"https://e.x/k" + m: map[string]any{"@id": "https://e.x/x", "q": "v"}}})
		},
		"the @index of a set object": func(m string) any {
			return OwnContext(nil, map[string]any{"q": map[string]any{"@set": []any{"v"}, "@index": m}})
		},
		"an object of only @language": func(m string) any {
			return OwnContext(nil, map[string]any{"q": []any{"x", map[string]any{"@language": map[string]string{"a": "en", "b": "fr"}[m]}}})
		},
		"a value repeated": func(m string) any {
			values := []any{"x", "d"}
			if m == "b" {
				values = append(values, "d")
			}
			return OwnContext(nil, map[string]any{"q": values})
		},
		"a second datatype of a value object": func(m string) any {
			return map[string]any{"@id": "https://e.x/s", "https://e.x/p": map[string]any{"@value": "v", "@type": []any{"https://e.x/T", "https://e.x/" + m}}}
		},
		"a string hidden by an alias from a scope not in use": func(m string) any {
			return map[string]any{
				"@context": []any{
					map[string]any{"v": "https://e.x/v", "t": "@graph"},
					map[string]any{"Unused": map[string]any{"@id": "https://e.x/Unused", "@context": map[string]any{"v": "@value", "t": "@type"}}},
				},
				"@id": "https://e.x/s", "v": "kept", "t": m,
			}
		},
		"a value of type rdf:JSON": func(m string) any {
			value := map[string]string{"a": `{"a":true}`, "b": `{ "a":true}`}[m]
			return map[string]any{"@id": "https://e.x/s", "https://e.x/p": map[string]any{"@value": value, "@type": "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON"}}
		},
		"a boolean or a string of one datatype": func(m string) any {
			value := map[string]any{"a": true, "b": "true"}[m]
			return map[string]any{"@id": "https://e.x/s", "https://e.x/p": map[string]any{"@value": value, "@type": "http://www.w3.org/2001/XMLSchema#string"}}
		},
		"a node of only an IRI the document names, in @included": func(m string) any {
			iri := map[string]string{"a": "https://e.x/s", "b": "https://e.x/o"}[m]
			return OwnContext(nil, map[string]any{"q": map[string]any{"@id": "https://e.x/o"}, "@included": []any{map[string]any{"@id": iri}}})
		},
		"a proof naming an IRI the credential names": func(m string) any {
			iri := map[string]string{"a": "did:example:s", "b": "did:example:issuer"}[m]
			return CredentialV2(map[string]any{"id": "did:example:s", "name": "x", "type": "VerifiableCredential", "proof": iri})
		},
		"a node of only @id named as a type": func(m string) any {
			types := map[string][]any{"a": {"https://e.x/T", "https://e.x/U"}, "b": {"https://e.x/U", "https://e.x/T"}}[m]
			node := map[string]string{"a": "https://e.x/T", "b": "https://e.x/U"}[m]
			return []any{map[string]any{"@id": "https://e.x/s", "@type": types}, map[string]any{"@id": node, "https://e.x/p": []any{}}}
		},
		"the node of a graph that holds only another graph": func(m string) any {
			return map[string]any{"@id": "urn:" + m, "@graph": []any{map[string]any{"@id": "urn:b", "@graph": []any{map[string]any{"@id": "urn:c", "urn:p": "v"}}}}}
		},
		"a value dropped beside a map key of a wrapped context": func(m string) any {
			return map[string]any{
				"@context": map[string]any{"@context": map[string]any{"m": map[string]any{"@id": "urn:m", "@container": "@id"}, "q": "urn:q"}},
				"@id":      "urn:s", "@graph": m, "m": map[string]any{"urn:o": map[string]any{"q": "kept"}},
			}
		},
		"a blank node's label": func(m string) any {
			return CredentialV2(map[string]any{"id": "_:" + m, "name": "x"})
		},
		"a blank node's label in a reference": func(m string) any {
			return OwnContext(nil, map[string]any{"q": []any{map[string]any{"@id": "_:" + m, "q": "v"}, map[string]any{"@id": "_:" + m}}})
		},
		"a node of only @id beside a node in a graph container": func(m string) any {
			return OwnContext(map[string]any{"g": GraphTerm("@graph", nil)}, map[string]any{"g": []any{aNode(), map[string]any{"@id": "https://e.x/" + m}}})
		},
		"a relative @id with dot segments, against @base": func(m string) any {
			return map[string]any{"@context": map[string]any{"@base": "https://e.x/"}, "@id": "pay-" + m + "/../s", "https://e.x/p": "v"}
		},
		"a relative value of a term typed @id, against @base": func(m string) any {
			return OwnContext(map[string]any{"@base": "https://e.x/", "r": map[string]any{"@id": "https://e.x/r", "@type": "@id"}}, map[string]any{"r": "x" + m + "/../y"})
		},
		"a relative type, against @base": func(m string) any {
			return map[string]any{"@context": map[string]any{"@base": "https://e.x/"}, "@id": "https://e.x/s", "@type": m + "/../T"}
		},
		"a relative @id against a type-scoped @base": func(m string) any {
			return OwnContext(map[string]any{"T": map[string]any{"@id": "https://e.x/T", "@context": map[string]any{"@base": "https://e.x/"}}}, map[string]any{"@type": "T", "q": map[string]any{"@id": "pay-" + m + "/../n", "q": "v"}})
		},
		"an absolute @id with dot segments": func(m string) any {
			return map[string]any{"@id": "https://e.x/" + m + "/../s", "https://e.x/p": "v"}
		},
		"a value object's key, a term of a term of @none": func(m string) any {
			return map[string]any{"@context": noneThroughATerm(), "@id": "urn:s", "urn:p": map[string]any{"@value": "kept", "k": m}}
		},
		"a value object's key, a term of a term of @none, a boolean": func(m string) any {
			return map[string]any{"@context": noneThroughATerm(), "@id": "urn:s", "urn:p": map[string]any{"@value": "kept", "k": m == "a"}}
		},
		"a language tag Unicode lowercases to ASCII": func(m string) any {
			return map[string]any{"@id": "urn:s", "urn:p": map[string]any{"@value": "v", "@language": map[string]string{"a": "\u0130t", "b": "it"}[m]}}
		},
		"a default language Unicode lowercases to ASCII": func(m string) any {
			return map[string]any{"@context": map[string]any{"@language": map[string]string{"a": "\u212Ar", "b": "kr"}[m], "q": "urn:q"}, "@id": "urn:s", "q": "v"}
		},
		"a list object's type": func(m string) any {
			return servedSubject(map[string]any{"@list": []any{"v"}, "@type": "urn:" + m})
		},
		"a property beside a list, with a type": func(m string) any {
			return servedSubject(map[string]any{"@list": []any{"v"}, "@type": "urn:L", "urn:q": m})
		},
		"an @id beside a list, with a type": func(m string) any {
			return servedSubject(map[string]any{"@list": []any{"v"}, "@type": "urn:L", "@id": "urn:" + m})
		},
		"a set object's type": func(m string) any {
			return servedSubject(map[string]any{"@set": []any{"v"}, "@type": "urn:" + m})
		},
		"a set object's type, through a term of a term of @set": func(m string) any {
			return map[string]any{"@context": setThroughATerm(), "@id": "urn:o", "urn:p": map[string]any{"s2": []any{"v"}, "@type": "urn:" + m}}
		},
		"an undefined term under @set": func(m string) any {
			return servedSubject(map[string]any{"@set": []any{map[string]any{undefinedTerm(m): []any{}}}})
		},
		"an undefined term under @default": func(m string) any {
			return servedSubjectWith(map[string]any{"urn:p": "v", "@default": map[string]any{undefinedTerm(m): []any{}}})
		},
		"a term's language Unicode lowercases to ASCII": func(m string) any {
			return map[string]any{"@context": map[string]any{"q": map[string]any{"@id": "urn:q", "@language": map[string]string{"a": "\u0130t", "b": "it"}[m]}}, "@id": "urn:s", "q": "v"}
		},
	}
}

// AcceptedPairs are pairs of documents near the forms of DifferentValues
// that hold every value: both are accepted, and their differing values make
// different canonical forms.
func AcceptedPairs() map[string]func(m string) any {
	return map[string]func(m string) any{
		"a node with a property in a graph container": func(m string) any {
			return OwnContext(map[string]any{"g": GraphTerm("@graph", nil)}, map[string]any{"g": map[string]any{"https://e.x/q": m}})
		},
		"a presentation's credential as an IRI": func(m string) any {
			return map[string]any{"@context": []any{"https://www.w3.org/ns/credentials/v2"}, "type": []any{"VerifiablePresentation"}, "verifiableCredential": "urn:uuid:" + m}
		},
		"a value with a language, a value of a type": func(m string) any {
			return OwnContext(nil, map[string]any{"q": []any{map[string]any{"@value": m, "@language": "en"}, map[string]any{"@value": "x", "@type": "https://e.x/T"}}})
		},
		"@nest": func(m string) any {
			return OwnContext(map[string]any{"n": "@nest"}, map[string]any{"n": map[string]any{"q": m}})
		},
		"@included": func(m string) any {
			return OwnContext(nil, map[string]any{"q": "x", "@included": []any{map[string]any{"@id": "https://e.x/i", "q": m}}})
		},
		"a boolean under a term typed xsd:boolean": func(m string) any {
			return OwnContext(map[string]any{"f": map[string]any{"@id": "https://e.x/f", "@type": "http://www.w3.org/2001/XMLSchema#boolean"}}, map[string]any{"f": m == "a"})
		},
	}
}

// Refusals are documents refused for the form they use, one for each reason
// a value could leave the dataset.
func Refusals() map[string]any {
	dv := DifferentValues()
	return map[string]any{
		"a list object with a type":                          dv["a list object's type"]("a"),
		"a set object with a type":                           dv["a set object's type"]("a"),
		"an empty set object with a type":                    servedSubject(map[string]any{"@set": []any{}, "@type": "urn:a"}),
		"a set object with a type, through a term of a term": dv["a set object's type, through a term of a term of @set"]("a"),
		"an undefined term under @set":                       dv["an undefined term under @set"]("a"),
		"an undefined term under @default":                   dv["an undefined term under @default"]("a"),
		"an undefined term in a list item":                   servedSubject(map[string]any{"@list": []any{map[string]any{"approved": []any{}}}}),
		"@index in the document":                             dv["the @index of a set object"]("a"),
		"@direction in the document":                         OwnContext(nil, map[string]any{"q": map[string]any{"@value": "x", "@direction": "rtl"}}),
		"@language outside a value":                          dv["an object of only @language"]("a"),
		"a map container":                                    dv["a key of an id map whose item has its own @id"]("a"),
		"a value expansion drops":                            dv["a value object in a top-level @graph"]("a"),
		"a value in no node's property":                      dv["a string in a graph container"]("a"),
		"a node in no quad":                                  dv["a proof as an IRI in a subject typed VerifiableCredential"]("a"),
		"a value twice":                                      dv["a value repeated"]("b"),
		"a node written out twice":                           map[string]any{"@id": "https://e.x/s", "https://e.x/p": map[string]any{"@id": "https://e.x/n", "https://e.x/q": "v"}, "https://e.x/r": map[string]any{"@id": "https://e.x/n", "https://e.x/q": "v"}},
		"an alias of @value":                                 OwnContext(map[string]any{"val": "@value"}, map[string]any{"q": map[string]any{"val": "x"}}),
		"a term aliasing two keywords":                       OwnContext(map[string]any{"A": map[string]any{"@id": "https://e.x/A", "@context": map[string]any{"k": "@id"}}, "B": map[string]any{"@id": "https://e.x/B", "@context": map[string]any{"k": "@type"}}}, map[string]any{"q": "x"}),
		"two datatypes":                                      dv["a second datatype of a value object"]("a"),
		"a datatype of rdf:JSON":                             dv["a value of type rdf:JSON"]("a"),
		"a boolean with a datatype":                          dv["a boolean or a string of one datatype"]("a"),
		"a blank node label":                                 dv["a blank node's label"]("a"),
		"a wrapped context's container":                      map[string]any{"@context": map[string]any{"@context": map[string]any{"m": map[string]any{"@id": "urn:m", "@container": "@index"}}}, "@id": "urn:s", "urn:q": "x"},
		"a JSON literal written":                             OwnContext(nil, map[string]any{"q": map[string]any{"@value": map[string]any{"k": "v"}, "@type": "@json"}}),
		"a language tag not ASCII":                           map[string]any{"@id": "urn:s", "urn:p": map[string]any{"@value": "v", "@language": "\u0130t"}},
		"a default language not ASCII":                       map[string]any{"@context": map[string]any{"@language": "\u212Ar", "q": "urn:q"}, "@id": "urn:s", "q": "v"},
		"a term's language not ASCII":                        map[string]any{"@context": map[string]any{"q": map[string]any{"@id": "urn:q", "@language": "\u0130t"}}, "@id": "urn:s", "q": "v"},
		"a @base":                                            map[string]any{"@context": map[string]any{"@base": "https://e.x/"}, "@id": "https://e.x/s", "https://e.x/p": "v"},
		"one RDF value in two spellings":                     OwnContext(nil, map[string]any{"q": []any{"x", map[string]any{"@value": "x", "@type": "http://www.w3.org/2001/XMLSchema#string"}}}),
		"a boolean in two spellings":                         OwnContext(nil, map[string]any{"q": []any{true, map[string]any{"@value": "true", "@type": "http://www.w3.org/2001/XMLSchema#boolean"}}}),
		"an alias in a value object":                         OwnContext(map[string]any{"t": "@type"}, map[string]any{"q": map[string]any{"@value": "x", "t": "https://e.x/T"}}),
		"a term of @none in a value":                         dv["a value object's key, a term of a term of @none"]("a"),
		"a @vocab of @value":                                 map[string]any{"@context": map[string]any{"@vocab": "@value", "v": map[string]any{"@id": ""}}, "@id": "urn:s", "urn:p": map[string]any{"v": "kept"}},
		"a @vocab of @":                                      map[string]any{"@context": map[string]any{"@vocab": "@"}, "@id": "urn:s", "urn:p": map[string]any{"value": "kept"}},
		"a JSON literal by a term":                           CredentialV2(map[string]any{"id": "did:example:s", "name": "x", "credentialSchema": map[string]any{"id": "https://e.x/schema", "type": "JsonSchema", "jsonSchema": map[string]any{"k": "v"}}}),
	}
}
