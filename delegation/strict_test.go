package delegation_test

import (
	"encoding/json"
	"testing"

	"github.com/provin-line/oss/delegation"
)

// A delegation credential decodes under the strict rules on every path, also
// through encoding/json: a duplicate key or invalid UTF-8 is refused, at the
// top and in its proof.
func TestDelegationCredential_UnmarshalJSONIsStrict(t *testing.T) {
	for name, doc := range map[string]string{
		"duplicate key":          `{"issuer":"did:x","issuer":"did:y"}`,
		"duplicate key in proof": `{"issuer":"did:x","proof":{"type":"a","type":"b"}}`,
		"invalid UTF-8":          "{\"issuer\":\"did:\xff\"}",
		"unpaired surrogate":     `{"issuer":"did:\ud800"}`,
		"ISSUER":                 `{"ISSUER":"did:x"}`,
		"SCOPE in the subject":   `{"issuer":"did:x","credentialSubject":{"SCOPE":["a"]}}`,
	} {
		var c delegation.DelegationCredential
		if err := json.Unmarshal([]byte(doc), &c); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	var c delegation.DelegationCredential
	if err := json.Unmarshal([]byte(`{"issuer":"did:x","validFrom":"2026-01-01T00:00:00Z","credentialSubject":{"id":"did:y","delegatedBy":"did:x"}}`), &c); err != nil || c.Issuer != "did:x" || c.CredentialSubject.ID != "did:y" {
		t.Errorf("valid credential: %+v, %v", c, err)
	}
}

// As encoding/json does, members the document omits keep the values the
// credential already had.
func TestDelegationCredential_UnmarshalJSONKeepsOmittedMembers(t *testing.T) {
	c := delegation.DelegationCredential{Issuer: "did:kept"}
	if err := json.Unmarshal([]byte(`{"type":["VerifiableCredential"]}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.Issuer != "did:kept" || len(c.Type) != 1 {
		t.Errorf("decoded %+v", c)
	}
}
