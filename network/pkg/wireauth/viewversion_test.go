package wireauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/network/pkg/wireauth"
)

// A proof carries the version of the view it was signed over.
func TestSign_CarriesTheViewVersion(t *testing.T) {
	signer, _ := signerFor(t, subDID)
	proof, err := wireauth.Sign(signer, "Op", okFields(), wireauth.Claims{SignerDID: subDID, Audience: testAudience, Nonce: "n1", IssuedAt: at()})
	if err != nil {
		t.Fatal(err)
	}
	if proof.ViewVersion != wireauth.ViewVersion {
		t.Errorf("ViewVersion = %d, want %d", proof.ViewVersion, wireauth.ViewVersion)
	}
}

// A verifier refuses a proof of a view version it does not accept with
// ErrViewVersion, before it resolves the signer or spends the nonce: version
// 1, a version it does not know, and none.
func TestVerify_RefusesAViewVersionItDoesNotAccept(t *testing.T) {
	signer, pub := signerFor(t, subDID)
	for _, version := range []int{0, 1, wireauth.ViewVersion + 1} {
		resolver := &countingResolver{mapResolver: mapResolver{subDID: authDoc(subDID, pub)}}
		nonces := &countingNonces{inner: testNonces()}
		v := audienceVerifier(t, resolver, testAudience, nonces)
		proof, err := wireauth.Sign(signer, "Op", okFields(), wireauth.Claims{SignerDID: subDID, Audience: testAudience, Nonce: "n1", IssuedAt: at()})
		if err != nil {
			t.Fatal(err)
		}
		proof.ViewVersion = version
		err = v.Verify(context.Background(), "Op", okFields(), proof, nil)
		if !errors.Is(err, wireauth.ErrViewVersion) {
			t.Errorf("version %d: %v, want ErrViewVersion", version, err)
		}
		if resolver.calls != 0 || nonces.uses != 0 {
			t.Errorf("version %d: %d resolutions and %d nonces spent, want none", version, resolver.calls, nonces.uses)
		}
	}
}

// A verifier accepts the view versions it is configured to, by default the
// current one; it refuses to be configured for a version this package does
// not compose, version 1 among them.
func TestNewVerifier_AcceptsOnlyViewVersionsItComposes(t *testing.T) {
	cfg := func(versions []int) wireauth.VerifierConfig {
		return wireauth.VerifierConfig{
			Resolver: mapResolver{}, Crypto: ed25519.Verifier{},
			Nonces: testNonces(), Audience: testAudience,
			AcceptedViewVersions: versions,
			Clock:                func() time.Time { return at().Add(time.Second) },
			Epoch:                at().Add(-time.Hour),
		}
	}
	for _, versions := range [][]int{{1}, {0}, {wireauth.ViewVersion + 1}, {wireauth.ViewVersion, 1}} {
		if _, err := wireauth.NewVerifier(cfg(versions)); err == nil {
			t.Errorf("AcceptedViewVersions %v: no error", versions)
		}
	}
	for _, versions := range [][]int{nil, {}, {wireauth.ViewVersion}} {
		if _, err := wireauth.NewVerifier(cfg(versions)); err != nil {
			t.Errorf("AcceptedViewVersions %v: %v", versions, err)
		}
	}
}
