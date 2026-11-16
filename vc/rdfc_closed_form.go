package vc

import (
	"fmt"
	"sort"
	"strings"
)

// memberForm is the JSON form vc reads a member in.
type memberForm int

const (
	formString  memberForm = iota // a string
	formStrings                   // an array of strings
	formObject                    // an object
)

func (f memberForm) String() string {
	switch f {
	case formString:
		return "a string"
	case formStrings:
		return "an array of strings"
	default:
		return "an object"
	}
}

// The closed form of an eddsa-rdfc-2022 PipelinePassCredential: the members
// each object may hold, and the form of each. They are the members dplaax's
// PipelinePassCredential JSON Schema
// (https://dplaax.dev/schemas/pipeline-pass-credential.json) defines, which vc
// reads and vc.New writes, and the ids credential.field.id lets a credential
// carry. A member that schema adds is added here too. Under eddsa-jcs-2022
// nothing here applies.
var (
	closedCredentialForm = map[string]memberForm{
		keyContext:   formStrings,
		"id":         formString,
		keyType:      formStrings,
		keyIssuer:    formString,
		keyValidFrom: formString,
		keySubject:   formObject,
	}
	closedSubjectForm = map[string]memberForm{
		"id":                   formString,
		keyPipelineID:          formString,
		keyProcessID:           formString,
		keyTransformationClaim: formString,
		keySchema:              formObject,
		keyInputHash:           formString,
		keyOutputHash:          formString,
		keyPreviousCredential:  formString,
		keyDerivedFrom:         formStrings,
		keySourceRoot:          formString,
		keySourceRootCanon:     formString,
	}
	closedSchemaForm = map[string]memberForm{
		"id":          formString,
		"type":        formString,
		"contentHash": formString,
	}
)

// checkRDFCClosedForm returns nil unless c's proof names eddsa-rdfc-2022. For such
// a credential it requires the closed form: the credential, its
// credentialSubject and the subject's schema hold only the members of
// closedCredentialForm, closedSubjectForm and closedSchemaForm, each in its form;
// the source commitment's three members are all present or all absent; no two
// of the credential, its subject and its schema name one node; and
// derived_from is strictly ascending. An eddsa-rdfc-2022 credential holds the
// members vc reads under their names and in their forms, and no others.
// Under eddsa-jcs-2022, and for a credential with no proof, nothing here
// applies.
//
// The cryptosuite is read through proofView, as signerAuthenticity reads it,
// and is in the signed proof configuration.
func checkRDFCClosedForm(c *PipelinePassCredential) error {
	if p := proofView(c.proof); p == nil || p.Cryptosuite != CryptosuiteEdDSARDFC2022 {
		return nil
	}
	if err := checkMembers("the credential", c.body, closedCredentialForm); err != nil {
		return err
	}
	subject, ok := c.body[keySubject].(map[string]any)
	if !ok {
		return nil // absent: the wire form requires it, and no other form can hold it
	}
	if err := checkMembers("credentialSubject", subject, closedSubjectForm); err != nil {
		return err
	}
	schema, hasSchema := subject[keySchema].(map[string]any)
	if hasSchema {
		if err := checkMembers("schema", schema, closedSchemaForm); err != nil {
			return err
		}
	}
	if err := checkDistinctNodes(c.body, subject, schema); err != nil {
		return err
	}
	_, hasDerived := subject[keyDerivedFrom]
	_, hasRoot := subject[keySourceRoot]
	_, hasCanon := subject[keySourceRootCanon]
	if (hasDerived || hasRoot || hasCanon) && !(hasDerived && hasRoot && hasCanon) {
		return fmt.Errorf("eddsa-rdfc-2022 credential: the source commitment's %s, %s and %s are not all present", keyDerivedFrom, keySourceRoot, keySourceRootCanon)
	}
	if hasDerived {
		list := subject[keyDerivedFrom].([]any) // checkMembers held it to formStrings
		derived := make([]string, len(list))
		for i, e := range list {
			derived[i] = e.(string)
		}
		if !isSortedUniqueSet(derived) {
			return fmt.Errorf("eddsa-rdfc-2022 credential: %s is not a strictly ascending set", keyDerivedFrom)
		}
	}
	return nil
}

// checkMembers requires obj (named where, for the error) to hold only the
// members of form, each in its form. It names the least offending member in
// byte order.
func checkMembers(where string, obj map[string]any, form map[string]memberForm) error {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		want, ok := form[k]
		if !ok {
			return fmt.Errorf("eddsa-rdfc-2022 credential: %s holds member %s, which is not one vc reads there", where, errQuote(k))
		}
		if !inForm(obj[k], want) {
			return fmt.Errorf("eddsa-rdfc-2022 credential: %s's member %s is not %s", where, errQuote(k), want)
		}
	}
	return nil
}

// inForm reports whether v is in form f.
func inForm(v any, f memberForm) bool {
	switch f {
	case formString:
		_, ok := v.(string)
		return ok
	case formStrings:
		list, ok := v.([]any)
		if !ok {
			return false
		}
		for _, e := range list {
			if _, ok := e.(string); !ok {
				return false
			}
		}
		return true
	default:
		_, ok := v.(map[string]any)
		return ok
	}
}

// The predicates that link the node objects of the closed form in the
// canonical N-Quads: the credential to its subject, and the subject to its
// schema.
const (
	predCredentialSubject = "<https://www.w3.org/2018/credentials#credentialSubject>"
	predSchema            = "<https://dplaax.dev/vocab#schema>"
)

// checkDistinctNodes requires the node objects of the closed form (the
// credential, its credentialSubject and its schema, nil when absent) to be
// three nodes of the RDF dataset the credential signs. JSON-LD joins node
// objects that expand to one @id into one node and merges their members, so
// members written on one of them can be written on another without changing
// the dataset. A node object with no id is a blank node of its own; two with
// an id each are compared by the id written, and, when those differ, by the
// node each becomes in the canonical N-Quads, which is the expansion of the
// id (a compact IRI against a full IRI) done by the registered
// eddsa-rdfc-2022 canonicalizer. When none is registered the ids are compared
// as written: nothing of this suite is signed or verified then.
func checkDistinctNodes(body, subject, schema map[string]any) error {
	type object struct {
		where string
		obj   map[string]any
	}
	var withID []object
	for _, n := range []object{{"the credential", body}, {"credentialSubject", subject}, {"schema", schema}} {
		if _, ok := n.obj["id"].(string); ok {
			withID = append(withID, n)
		}
	}
	if len(withID) < 2 {
		return nil
	}
	for i, a := range withID {
		for _, b := range withID[i+1:] {
			if a.obj["id"] == b.obj["id"] {
				return fmt.Errorf("eddsa-rdfc-2022 credential: %s and %s carry the id %s", a.where, b.where, errQuote(a.obj["id"].(string)))
			}
		}
	}
	c, err := canonicalizerFor(CryptosuiteEdDSARDFC2022)
	if err != nil {
		return nil
	}
	nquads, err := c.Canonicalize(body)
	if err != nil {
		return fmt.Errorf("eddsa-rdfc-2022 credential: the ids of its node objects cannot be compared: %w", err)
	}
	var rootTerm, subjectTerm, schemaTerm string
	var schemaLinks [][2]string // each subject → schema quad: its subject and its object
	for _, line := range strings.Split(string(nquads), "\n") {
		s, rest, _ := strings.Cut(line, " ")
		p, o, _ := strings.Cut(rest, " ")
		o = strings.TrimSuffix(o, " .")
		switch p {
		case predCredentialSubject:
			rootTerm, subjectTerm = s, o
		case predSchema:
			schemaLinks = append(schemaLinks, [2]string{s, o})
		}
	}
	for _, l := range schemaLinks {
		if l[0] == subjectTerm {
			schemaTerm = l[1]
		}
	}
	terms := []node{{"the credential", rootTerm}, {"credentialSubject", subjectTerm}}
	if schema != nil {
		terms = append(terms, node{"schema", schemaTerm})
	}
	seen := map[string]string{}
	for _, n := range terms {
		if n.term == "" {
			return fmt.Errorf("eddsa-rdfc-2022 credential: %s is not found in the canonical form", n.where)
		}
		if other, dup := seen[n.term]; dup {
			return fmt.Errorf("eddsa-rdfc-2022 credential: %s and %s carry ids that expand to one node", other, n.where)
		}
		seen[n.term] = n.where
	}
	return nil
}

// node is a node object of the closed form, named where for an error: as the
// object it is, or as the term it is in the canonical N-Quads.
type node struct {
	where string
	term  string
}
