package chainmanager

import (
	"context"
	"errors"
	"fmt"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/network/pkg/core"
)

// chainManagerFragment is the DID-document service id (fragment) under which a
// publisher advertises its ChainPeerService endpoint.
const chainManagerFragment = "#chain-manager"

var (
	// ErrNoChainManagerEndpoint is returned when a publisher's DID document does
	// not expose exactly one #chain-manager service endpoint — zero (the
	// publisher offers no peer surface) or more than one (ambiguous; we refuse to
	// silently pick).
	ErrNoChainManagerEndpoint = errors.New("chainmanager: no unique #chain-manager service endpoint")
	// ErrEndpointNotAllowed is returned when a resolved endpoint fails the SSRF
	// guard (an attacker-influenced URL pointing at a private/loopback target).
	ErrEndpointNotAllowed = errors.New("chainmanager: endpoint not allowed")
)

// resolveChainManagerEndpoint extracts the publisher's #chain-manager service
// endpoint URL from its DID document. A registry re-anchors configured service
// ids to absolute form on issue, so the entry may appear either as the bare
// fragment "#chain-manager" or as the absolute "<publisherDID>#chain-manager";
// both are matched. Zero or multiple matches yield ErrNoChainManagerEndpoint —
// the caller must not have to disambiguate.
func resolveChainManagerEndpoint(doc *did.DIDDocument, publisherDID string) (string, error) {
	absolute := publisherDID + chainManagerFragment
	var found string
	n := 0
	for _, s := range doc.Service() {
		if s.ID == chainManagerFragment || s.ID == absolute {
			found = s.ServiceEndpoint
			n++
		}
	}
	if n != 1 {
		return "", fmt.Errorf("%w: %q has %d matches", ErrNoChainManagerEndpoint, publisherDID, n)
	}
	return found, nil
}

// checkEndpointAllowed runs the SSRF guard over a resolved endpoint, mapping a
// guard rejection to the domain sentinel ErrEndpointNotAllowed. The guard is the
// shared core.URLGuard (default-deny; DNS-resolving), so dialing through its
// HTTPClient additionally re-guards at connect time — this preflight is the early
// typed rejection, not the only line of defense.
func checkEndpointAllowed(ctx context.Context, g *core.URLGuard, raw string) error {
	if err := g.CheckURL(ctx, raw); err != nil {
		return fmt.Errorf("%w: %v", ErrEndpointNotAllowed, err)
	}
	return nil
}
