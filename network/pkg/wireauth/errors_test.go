package wireauth_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/provin-line/oss/network/pkg/wireauth"
)

// The sentinels are constants of type Error with the messages they have
// always had; each matches itself, wrapped, and no other.
func TestSentinels(t *testing.T) {
	sentinels := []struct {
		err  wireauth.Error
		text string
	}{
		{wireauth.ErrMissingProof, "wireauth: missing proof"},
		{wireauth.ErrMalformedProof, "wireauth: malformed proof"},
		{wireauth.ErrInvalidView, "wireauth: invalid view"},
		{wireauth.ErrBeforeEpoch, "wireauth: proof issued before epoch"},
		{wireauth.ErrExpired, "wireauth: proof expired"},
		{wireauth.ErrFromFuture, "wireauth: proof from the future"},
		{wireauth.ErrKeyResolution, "wireauth: cannot resolve signer auth key"},
		{wireauth.ErrResolverUnavailable, "wireauth: signer-key resolver unavailable"},
		{wireauth.ErrSignatureInvalid, "wireauth: signature does not verify"},
		{wireauth.ErrReplay, "wireauth: nonce replay"},
		{wireauth.ErrWrongAudience, "wireauth: proof is for another audience"},
		{wireauth.ErrViewVersion, "wireauth: proof of a view version this verifier does not accept"},
	}
	for i, s := range sentinels {
		if got := s.err.Error(); got != s.text {
			t.Errorf("sentinel %d: Error() = %q, want %q", i, got, s.text)
		}
		wrapped := fmt.Errorf("context: %w", s.err)
		for j, o := range sentinels {
			if got, want := errors.Is(wrapped, o.err), i == j; got != want {
				t.Errorf("errors.Is(wrapped %q, %q) = %v, want %v", s.text, o.text, got, want)
			}
		}
	}
}
