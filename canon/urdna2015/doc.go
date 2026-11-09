// Package urdna2015 implements RDF Dataset Canonicalization (URDNA2015) for
// the eddsa-rdfc-2022 cryptosuite. github.com/piprate/json-gold expands the
// document and builds its RDF dataset; the blank nodes are labelled here,
// within a work bound (see label.go).
//
// JSON-LD contexts are resolved exclusively from an in-process allowlist of
// embedded documents — never the network. Any context IRI outside the
// allowlist is an error, and a non-object input (which json-gold would treat
// as a remote document URL) is rejected before it reaches the processor.
// Canonicalize reads a context written in the document too, holding it to
// the forms below. vc's eddsa-rdfc-2022 refuses such a document before it
// is canonicalized, accepting as @context only the IRIs of the contexts it
// serves; a program that calls this package itself gets no such refusal.
//
// # What is signed
//
// Unlike JCS, which signs every member of the input bytes, RDF canonicalization
// signs the RDF dataset the input expands to, its meaning. So a value of the
// document the dataset does not hold, or a shape of its JSON, would ride the
// document unsigned: it could be changed without breaking the signature.
// Canonicalize refuses such a document, and every byte it signs is the RDFC-1.0
// canonical form of the dataset (its Appendix A), in which no byte the frozen
// v0 wire signs changes. Spellings JSON-LD gives one RDF term are signed as
// that term: an IRI written as a term, a compact IRI or in full; a language tag
// in any ASCII case; a string with xsd:string written or not; a boolean written
// as true or false, or as the string of its name typed xsd:boolean. The values
// of a property outside a list are signed as a set, in no order, so one written
// twice is refused (a node written out in full in two places, or a type
// repeated): write a node once and refer to it elsewhere by its @id. A
// context's own text is not signed, nor which context a document names: a term
// the document does not use adds nothing to the dataset. A @nest group is
// signed as the members of the object holding it.
//
// Every value of a document Canonicalize accepts is in the dataset, and the
// document's JSON holds no shape the dataset does not, but one: a property
// whose value is an empty array ("derived_from": []) adds no quad, so its
// presence is not itself signed at the proof layer. That is safe for provin's
// only empty-array member because the binding lives one layer up: the signed
// source_root commits to the (empty) set cryptographically and
// VerifySourceCommitment — the chainwalk layer, not VerifyProof — recomputes
// the root over derived_from and rejects a mismatch; wire-form validation
// additionally couples the commitment fields together. JCS — the default
// suite — signs the bytes verbatim either way.
//
// # What is refused, and by which stage
//
// JSON-LD processing, and json-gold with it, leaves values out, rewrites
// them, or fails, at many steps. Canonicalize refuses each such form before
// anything is signed, and counts the document's values through the stages so
// that a value lost in a form not listed is refused too (conserve.go). Each
// line names what json-gold does with a form, and the check that refuses it;
// the checks are unexported, in the files named:
//
//	The input's grammar (input.go):
//	  a string input, fetched as a URL; a scalar at the top or in
//	    @graph, dropped                          Canonicalize's type switch,
//	                                             requireNodeObjects
//	  a number, carried through float64 (integers above 2^53 cut):
//	    write it as a string                     rejectSilentDrops
//	  null, dropped (JSON-LD's null-equals-omission): omit the member
//	                                             rejectSilentDrops
//	  a member named "", given no meaning        rejectSilentDrops
//	  nesting past 10,000 objects and arrays, recursed into
//	                                             jsondepth.Within (ErrTooComplex)
//	The boundary with json-gold (jsongold.go):
//	  a value of a type it asserts without checking, a panic
//	                                             fromJSONGold, which returns an
//	                                             error for it
//	  a term no context defines, dropped         its safe mode, set by
//	                                             Canonicalizer.options
//	The context rules (contexts.go):
//	  a term with a map container, whose keys become values
//	                                             contextRules.read
//	  @base, resolving relative IRIs, so two spellings of one IRI
//	                                             contextRules.read
//	  a context keyword it does not know, ignored; a @vocab beginning
//	    with @, making keys keywords             contextRules.read
//	  a language tag, in a context or a value object, lowercased with
//	    Unicode case mapping                     asciiLanguage
//	  an alias of @value; a term aliasing two keywords; a term naming
//	    an alias of a keyword                    contextRules.alias,
//	                                             contextRules.rejectAliasChains
//	The document's forms (conserve.go, forms.go):
//	  @index and @direction, which RDF does not carry
//	                                             contextRules.dataValues
//	  @set and the framing keywords, under which it drops what it
//	    cannot expand without an error           contextRules.dataValues
//	  @language outside a value object, dropped  contextRules.dataValues
//	  a value object's other keys; a JSON literal (@json) written,
//	    rewritten                                contextRules.dataValues
//	  an empty object or array where it keeps nothing; an array in an
//	    array, flattened, in a list too; a list where it keeps none;
//	    a keyword it does not read in a document
//	                                             rejectUnsignedShapes
//	The count of values (conserve.go):
//	  any value it leaves out, in whatever form  contextRules.dataValues
//	                                             against expandedValues
//	The expanded form (expanded.go):
//	  a list or set object holding another key (with @type, its shape
//	    check skipped)                           rejectListBeside
//	  an item of a list it could not expand, left as null
//	                                             rejectDroppableNodes
//	  an IRI that is not absolute or fails its quad validity, dropped
//	    with its quad; a blank-node predicate, dropped
//	                                             rejectDroppableNodes
//	  a blank node label, relabelled             rejectDroppableNodes
//	  @index and @direction, which toRDF does not write (behind
//	    contextRules.dataValues)                 rejectDroppableNodes
//	  a language tag failing its grammar, dropping the literal
//	                                             rejectDroppableNodes
//	  the RDF collection vocabulary written out, signed as a list
//	                                             rejectDroppableNodes
//	  more than one datatype, the first kept; a JSON literal (@json,
//	    by a term, or rdf:JSON), rewritten; a boolean with a datatype
//	    other than xsd:boolean                   rejectLossyValue
//	The node map (nodemap.go):
//	  a value outside any node's property; a node object in no quad;
//	    one RDF term twice on a property, kept once
//	                                             nodeMapWork.conserved
//	  the values a property gathers, compared pairwise
//	                                             nodeMapWork.bound (ErrTooComplex)
//	  a dataset holding other quads than the values make (it expands
//	    the document a second time inside ToRDF) nodeMapWork.holds
//	The dataset (size.go, dataset.go, label.go):
//	  a canonical form longer than a bound linear in the document
//	                                             boundCanonicalSize (ErrTooComplex)
//	  an IRI or a literal the canonical N-Quads would not write as one
//	    spelling of RDFC-1.0's form              rejectUnspellable
//	  blank nodes so alike that labelling them takes long
//	                                             the labelling's work bound (ErrTooComplex)
//
// The JCS path needs none of this because it has no expansion step.
package urdna2015
