package main

import (
	"net/url"
	"strings"
	"testing"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/registry"
)

// P0-6 closure #7: the endpoint migration matrix. A node that terminates TLS
// itself is only actually reachable if every URL a peer follows says https —
// and those URLs come from config and from advertised DID service endpoints,
// not from the listener. A node can serve a perfect TLS listener while still
// advertising http:// to everyone: the listener does not rewrite what it
// advertises.
//
// So this is a CONFIGURATION contract, not a runtime one. The matrix pins the
// full set of URL surfaces an operator must move, and the guard below is what
// makes a missed one loud instead of silent.

// tlsEndpointSurfaces enumerates every URL a native-TLS deployment must move to
// https. Each entry names where the value lives, so a reviewer can check a real
// deployment against this list rather than against memory.
var tlsEndpointSurfaces = []struct {
	surface string
	where   string
}{
	{"advertised #vc-resolver", "provin.network.registry.service-endpoints.vc-resolver.url"},
	{"advertised #audit", "provin.network.registry.service-endpoints.audit.url"},
	{"DID resolution override", "provin.network.chain.nats.resolver-base-url (or registry-base-urls)"},
	{"VC-store / upstream URL", "the peer's advertised #vc-resolver, followed by the sink loop"},
	{"auth-provider registry URL", "the auth provider's DPLAAX_REGISTRY_BASE_URL"},
	{"health / readiness probes", "the orchestrator's probe scheme (compose/k8s)"},
	{"metrics scraper", "the scrape target's scheme"},
}

func TestTLSEndpointMatrix_IsComplete(t *testing.T) {
	// The matrix is evidence, so it must not silently shrink: the ledger's
	// closure condition names these seven surfaces.
	if len(tlsEndpointSurfaces) != 7 {
		t.Errorf("matrix has %d surfaces, want the 7 the P0-6 closure names", len(tlsEndpointSurfaces))
	}
	for _, s := range tlsEndpointSurfaces {
		if s.surface == "" || s.where == "" {
			t.Errorf("matrix entry %+v is not actionable — it must name the surface and where it lives", s)
		}
	}
}

// RequireHTTPSEndpoints is the guard the matrix hangs on: on a TLS posture, a
// config-supplied http:// URL is a misconfiguration that would otherwise
// surface as a peer failing to reach a node that looks perfectly healthy.
func TestRequireHTTPSEndpoints_FlagsCleartextURLsOnATLSPosture(t *testing.T) {
	tlsPosture := core.TLSConfig{CertFile: "c.pem", KeyFile: "k.pem"}
	regCfg := &registry.RegistryConfig{
		ID: "poc.dplaax.dev",
		Endpoints: []did.ServiceEndpoint{
			{ID: "#vc-resolver", Type: "VCResolver", ServiceEndpoint: "http://node:8443"},
			{ID: "#audit", Type: "AuditAPI", ServiceEndpoint: "https://node:8443"},
		},
	}
	chainCfg := &chainconfig.Config{
		NATS: chainconfig.NATSConfig{ResolverBaseURL: "http://registry:8443"},
	}

	warnings := core.RequireHTTPSEndpoints(tlsPosture, endpointURLs(regCfg, chainCfg))
	if len(warnings) != 2 {
		t.Fatalf("warnings = %v, want the two cleartext URLs flagged", warnings)
	}
	joined := strings.Join(warnings, " ")
	for _, want := range []string{"#vc-resolver", "resolver-base-url"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings do not name %s: %v", want, warnings)
		}
	}
}

func TestRequireHTTPSEndpoints_SilentOnACleartextPosture(t *testing.T) {
	// A cleartext-acknowledged node advertising http:// is consistent, not
	// broken. Warning there would train operators to ignore the warning.
	warnings := core.RequireHTTPSEndpoints(core.TLSConfig{AllowCleartext: true}, []core.NamedURL{
		{Name: "#vc-resolver", URL: "http://node:8443"},
	})
	if len(warnings) != 0 {
		t.Errorf("warned on a cleartext posture: %v", warnings)
	}
}

func TestRequireHTTPSEndpoints_SilentWhenEveryURLIsHTTPS(t *testing.T) {
	warnings := core.RequireHTTPSEndpoints(
		core.TLSConfig{CertFile: "c.pem", KeyFile: "k.pem"},
		[]core.NamedURL{
			{Name: "#vc-resolver", URL: "https://node:8443"},
			{Name: "resolver-base-url", URL: "https://registry:8443"},
		})
	if len(warnings) != 0 {
		t.Errorf("warned on a fully-migrated deployment: %v", warnings)
	}
}

func TestEndpointURLs_ParseAsURLs(t *testing.T) {
	// A malformed advertised endpoint would make the guard's scheme check
	// vacuous, so the collector's output must be parseable.
	regCfg := &registry.RegistryConfig{
		Endpoints: []did.ServiceEndpoint{{ID: "#vc-resolver", ServiceEndpoint: "https://node:8443"}},
	}
	for _, nu := range endpointURLs(regCfg, &chainconfig.Config{}) {
		if _, err := url.Parse(nu.URL); err != nil {
			t.Errorf("%s: %v", nu.Name, err)
		}
	}
}
