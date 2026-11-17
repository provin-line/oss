package wireauth_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/wireauth"
)

// The audience of the node that serves a did:dplaax DID is the DID's
// registry, whatever the DID names under it.
func TestAudienceForDID(t *testing.T) {
	for _, d := range []string{
		"did:dplaax:home.example:org:o1",
		"did:dplaax:home.example:org:o1:pipeline:p1",
		"did:dplaax:home.example:org:o1:pipeline:p1:process:s1",
	} {
		if got, err := wireauth.AudienceForDID(d); err != nil || got != "home.example" {
			t.Errorf("AudienceForDID(%s) = %q, %v, want home.example", d, got, err)
		}
	}
}

// A DID that does not parse as did:dplaax has no node to name; the error
// names the DID within a bound however long it is, and the reason the parser
// gives.
func TestAudienceForDID_RefusesWhatDoesNotParse(t *testing.T) {
	if _, err := wireauth.AudienceForDID("not a did"); err == nil || !strings.Contains(err.Error(), `"not a did"`) {
		t.Errorf("not a DID: %v, want an error naming it", err)
	}
	if _, err := wireauth.AudienceForDID("did:dplaax:home.example:org:o/1:pipeline:p1"); err == nil || !strings.Contains(err.Error(), "violates the safe-segment rule") {
		t.Errorf("an unsafe segment: %v, want the parser's reason", err)
	}
	long := "did:dplaax:" + strings.Repeat("x", 5000)
	if _, err := wireauth.AudienceForDID(long); err == nil || len(err.Error()) > 400 || !strings.Contains(err.Error(), fmt.Sprintf("(%d bytes)", len(long))) {
		t.Errorf("a long DID: %.200v, want an error naming its head and length", err)
	}
}
