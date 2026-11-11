package vc

import (
	"fmt"
	"sort"
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
// each object may hold, and the form of each. They are the members vc reads
// and vc.New writes, and the ids credential.field.id lets a credential carry.
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
// the source commitment's three members are all present or all absent; and
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
	if schema, ok := subject[keySchema].(map[string]any); ok {
		if err := checkMembers("schema", schema, closedSchemaForm); err != nil {
			return err
		}
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
