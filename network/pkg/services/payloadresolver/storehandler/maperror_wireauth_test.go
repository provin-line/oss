package storehandler

import (
	"fmt"
	"testing"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

// TestMapError_WireauthDelegation proves mapError delegates wireauth
// sentinels to the shared wireautherr.Code classifier: ErrBeforeEpoch is now
// Unavailable (retryable) rather than Unauthenticated, an identity sentinel
// is untouched, and a domain-specific error unrelated to wireauth still maps
// to its own code.
func TestMapError_WireauthDelegation(t *testing.T) {
	if got := connect.CodeOf(mapError(fmt.Errorf("storehandler: verify: %w", wireauth.ErrBeforeEpoch))); got != connect.CodeUnavailable {
		t.Errorf("ErrBeforeEpoch code = %v, want Unavailable", got)
	}
	if got := connect.CodeOf(mapError(wireauth.ErrSignatureInvalid)); got != connect.CodeUnauthenticated {
		t.Errorf("ErrSignatureInvalid code = %v, want Unauthenticated (unchanged)", got)
	}
	if got := connect.CodeOf(mapError(errOwnerMismatch)); got != connect.CodePermissionDenied {
		t.Errorf("domain error code = %v, want PermissionDenied (unchanged)", got)
	}
}
