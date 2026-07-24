package handler

import (
	"fmt"
	"testing"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

// TestMapError_WireauthDelegation and TestPeerMapError_WireauthDelegation
// prove both chainmanager handlers (operator's mapError and peer's
// peerMapError) delegate wireauth sentinels to the shared wireautherr.Code
// classifier: ErrBeforeEpoch is now Unavailable (retryable) rather than
// Unauthenticated, an identity sentinel is untouched, and a domain-specific
// error unrelated to wireauth still maps to its own code.
func TestMapError_WireauthDelegation(t *testing.T) {
	if got := connect.CodeOf(mapError(fmt.Errorf("chainmanager: verify: %w", wireauth.ErrBeforeEpoch))); got != connect.CodeUnavailable {
		t.Errorf("ErrBeforeEpoch code = %v, want Unavailable", got)
	}
	if got := connect.CodeOf(mapError(wireauth.ErrSignatureInvalid)); got != connect.CodeUnauthenticated {
		t.Errorf("ErrSignatureInvalid code = %v, want Unauthenticated (unchanged)", got)
	}
	if got := connect.CodeOf(mapError(chainmanager.ErrNoChainManagerEndpoint)); got != connect.CodeFailedPrecondition {
		t.Errorf("domain error code = %v, want FailedPrecondition (unchanged)", got)
	}
}

func TestPeerMapError_WireauthDelegation(t *testing.T) {
	if got := connect.CodeOf(peerMapError(fmt.Errorf("chainmanager: verify: %w", wireauth.ErrBeforeEpoch))); got != connect.CodeUnavailable {
		t.Errorf("ErrBeforeEpoch code = %v, want Unavailable", got)
	}
	if got := connect.CodeOf(peerMapError(wireauth.ErrSignatureInvalid)); got != connect.CodeUnauthenticated {
		t.Errorf("ErrSignatureInvalid code = %v, want Unauthenticated (unchanged)", got)
	}
	if got := connect.CodeOf(peerMapError(chainmanager.ErrNotOwner)); got != connect.CodePermissionDenied {
		t.Errorf("domain error code = %v, want PermissionDenied (unchanged)", got)
	}
}
