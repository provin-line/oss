package wireprofile

import "testing"

// Pins the exact wire literal. This is the ONE definition — network/'s
// chainmanager.ByReferenceSubjectPrefix is an alias of this constant (see
// network/pkg/services/chainmanager/subject.go and its
// TestByReferenceSubjectPrefix_MatchesWireprofile), so changing this literal
// changes the wire protocol for both trees at once.
func TestByReferenceSubjectPrefix(t *testing.T) {
	if ByReferenceSubjectPrefix != "byref." {
		t.Fatalf("ByReferenceSubjectPrefix = %q, want %q", ByReferenceSubjectPrefix, "byref.")
	}
}
