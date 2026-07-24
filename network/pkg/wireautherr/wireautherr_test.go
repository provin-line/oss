package wireautherr_test

import (
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/wireautherr"
)

// TestCode covers every wireauth sentinel this package classifies, plus the
// two boundary cases: a non-wireauth error (ok == false) and a wrapped
// sentinel (errors.Is must see through %w).
func TestCode(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode connect.Code
		wantOK   bool
	}{
		// Structural: the proof shape itself is broken.
		{"missing proof", wireauth.ErrMissingProof, connect.CodeInvalidArgument, true},
		{"malformed proof", wireauth.ErrMalformedProof, connect.CodeInvalidArgument, true},
		{"invalid view", wireauth.ErrInvalidView, connect.CodeInvalidArgument, true},
		// Transient: retryable, not an identity verdict.
		{"resolver unavailable", wireauth.ErrResolverUnavailable, connect.CodeUnavailable, true},
		{"before epoch", wireauth.ErrBeforeEpoch, connect.CodeUnavailable, true},
		// Identity: a definitive rejection.
		{"expired", wireauth.ErrExpired, connect.CodeUnauthenticated, true},
		{"from future", wireauth.ErrFromFuture, connect.CodeUnauthenticated, true},
		{"key resolution", wireauth.ErrKeyResolution, connect.CodeUnauthenticated, true},
		{"signature invalid", wireauth.ErrSignatureInvalid, connect.CodeUnauthenticated, true},
		{"replay", wireauth.ErrReplay, connect.CodeUnauthenticated, true},
		// Wrapped sentinel: errors.Is must still classify it.
		{"wrapped before epoch", fmt.Errorf("chainmanager: verify: %w", wireauth.ErrBeforeEpoch), connect.CodeUnavailable, true},
		// Not a wireauth sentinel at all.
		{"non-wireauth error", errors.New("boom"), 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, ok := wireautherr.Code(tc.err)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && code != tc.wantCode {
				t.Fatalf("code = %v, want %v", code, tc.wantCode)
			}
		})
	}
}
