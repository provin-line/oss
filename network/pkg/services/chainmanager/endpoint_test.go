package chainmanager

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/network/pkg/core"
)

const epPub = "did:dplaax:reg:org:acme:pipeline:p1"

func docWithServices(svcs ...did.ServiceEndpoint) *did.DIDDocument {
	return did.New(did.DocumentFields{ID: epPub, Service: svcs})
}

func TestResolveChainManagerEndpoint_BareFragment(t *testing.T) {
	doc := docWithServices(did.ServiceEndpoint{
		ID: "#chain-manager", Type: "ChainManager", ServiceEndpoint: "https://cm.example/chain",
	})
	got, err := resolveChainManagerEndpoint(doc, epPub)
	if err != nil {
		t.Fatalf("resolveChainManagerEndpoint: %v", err)
	}
	if got != "https://cm.example/chain" {
		t.Errorf("endpoint = %q", got)
	}
}

func TestResolveChainManagerEndpoint_AbsoluteID(t *testing.T) {
	// A registry re-anchors configured service ids to absolute form on issue.
	doc := docWithServices(did.ServiceEndpoint{
		ID: epPub + "#chain-manager", Type: "ChainManager", ServiceEndpoint: "https://cm.example/chain",
	})
	got, err := resolveChainManagerEndpoint(doc, epPub)
	if err != nil {
		t.Fatalf("resolveChainManagerEndpoint: %v", err)
	}
	if got != "https://cm.example/chain" {
		t.Errorf("endpoint = %q", got)
	}
}

func TestResolveChainManagerEndpoint_Missing(t *testing.T) {
	doc := docWithServices(did.ServiceEndpoint{
		ID: "#vc-resolver", Type: "VCResolver", ServiceEndpoint: "https://vc.example",
	})
	_, err := resolveChainManagerEndpoint(doc, epPub)
	if !errors.Is(err, ErrNoChainManagerEndpoint) {
		t.Errorf("err = %v, want ErrNoChainManagerEndpoint", err)
	}
}

func TestResolveChainManagerEndpoint_Duplicate(t *testing.T) {
	// Bare + absolute both present → ambiguous, reject (don't silently pick one).
	doc := docWithServices(
		did.ServiceEndpoint{ID: "#chain-manager", Type: "ChainManager", ServiceEndpoint: "https://a.example"},
		did.ServiceEndpoint{ID: epPub + "#chain-manager", Type: "ChainManager", ServiceEndpoint: "https://b.example"},
	)
	_, err := resolveChainManagerEndpoint(doc, epPub)
	if !errors.Is(err, ErrNoChainManagerEndpoint) {
		t.Errorf("err = %v, want ErrNoChainManagerEndpoint (ambiguous)", err)
	}
}

// checkEndpointAllowed wraps a core.URLGuard rejection into the domain sentinel.
// We test the wrapping boundary (our code), not the guard's SSRF table (core's
// own tests cover that): a blocked URL → ErrEndpointNotAllowed, a safe URL → nil.
func TestCheckEndpointAllowed_WrapsGuardRejection(t *testing.T) {
	// Resolver that maps any host to a private address → guard must block.
	priv := core.NewURLGuard(core.WithResolver(func(_ context.Context, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
	}))
	if err := checkEndpointAllowed(context.Background(), priv, "https://evil.example/cm"); !errors.Is(err, ErrEndpointNotAllowed) {
		t.Errorf("blocked endpoint err = %v, want ErrEndpointNotAllowed", err)
	}

	pub := core.NewURLGuard(core.WithResolver(func(_ context.Context, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil // public
	}))
	if err := checkEndpointAllowed(context.Background(), pub, "https://cm.example/cm"); err != nil {
		t.Errorf("safe endpoint err = %v, want nil", err)
	}
}
