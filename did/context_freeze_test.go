package did_test

import (
	"testing"

	"github.com/provin-line/oss/did"
)

// The issued-document contexts are frozen: they ride every issued document's
// signing scope as bytes, so a changed URI changes every document hash and
// every self-signed proof. A deliberate change is a protocol migration, not an
// edit — this test is the tripwire.
func TestIssuedDocumentContextsAreFrozen(t *testing.T) {
	got := did.IssuedDocumentContexts()
	want := []string{
		"https://www.w3.org/ns/did/v1",
		"https://w3id.org/security/multikey/v1",
	}
	if len(got) != len(want) {
		t.Fatalf("IssuedDocumentContexts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("context[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
