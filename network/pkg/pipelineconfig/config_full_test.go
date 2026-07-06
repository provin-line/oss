package pipelineconfig_test

import (
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/pipelineconfig"
)

// pipelineConf wraps loop bodies under provin.network.pipeline alongside a node-level
// vc-store-endpoint + vc-store-bearer (empty values => the keys are omitted).
func pipelineConf(endpoint, bearer, body string) string {
	var b strings.Builder
	b.WriteString("provin.network.pipeline {\n")
	if endpoint != "" {
		b.WriteString("  vc-store-endpoint = \"" + endpoint + "\"\n")
	}
	if bearer != "" {
		b.WriteString("  vc-store-bearer = \"" + bearer + "\"\n")
	}
	b.WriteString("  loops {\n")
	b.WriteString(body)
	b.WriteString("\n  }\n}\n")
	return b.String()
}

// adjacentSinkLoop is a valid consuming (sink) loop. The node-level vc-store-endpoint /
// vc-store-bearer validation below is independent of the loop's verification strategy
// (it gates publication, not the per-loop check), so these tests drive it through an
// adjacent loop — slice-17j retired "full", which is now rejected (see below).
const adjacentSinkLoop = `
  archive {
    role = "sink"
    ingress-subject = "did:dplaax:reg:org:acme:pipeline:pipe"
    sink {
      kind = "observation-only"
      verification-strategy = "adjacent"
      upstream-endpoint = "https://acme.example/pipelines/pipe"
    }
  }
`

// fullSinkLoop declares the retired "full" strategy — used only to assert it is rejected.
const fullSinkLoop = `
  archive {
    role = "sink"
    ingress-subject = "did:dplaax:reg:org:acme:pipeline:pipe"
    sink {
      kind = "observation-only"
      verification-strategy = "full"
      upstream-endpoint = "https://acme.example/pipelines/pipe"
    }
  }
`

// slice-17j: "full" is retired. A loop declaring it is rejected as an unknown
// verification-strategy at config load — and rejected for THAT reason (not for a missing
// endpoint/bearer, which load later), so endpoint + bearer are supplied to isolate the cause.
func TestLoad_FullStrategy_Rejected(t *testing.T) {
	cfg := loadWith(t, pipelineConf("https://node.example/", "tok-abc", fullSinkLoop))
	_, err := pipelineconfig.LoadPipelineConfig(cfg)
	if err == nil {
		t.Fatal("verification-strategy \"full\": want error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown verification-strategy") || !strings.Contains(err.Error(), "full") {
		t.Fatalf("error = %q, want an unknown-verification-strategy rejection naming %q", err, "full")
	}
}

// A vc-store-endpoint WITHOUT a vc-store-bearer is a boot error — the VC store is
// L1-protected, so a tokenless client's publish/resolve would be rejected at runtime.
// This isolates the ENDPOINT→bearer rule from the consuming-loop→bearer rule: a
// source-only loop keeps the consuming rule out of reach, and the assertion pins the
// error to the endpoint key so only the endpoint rule can satisfy it.
func TestLoad_VCStoreEndpoint_RequiresBearer(t *testing.T) {
	cfg := loadWith(t, pipelineConf("https://node.example/", "", validSourceLoop))
	_, err := pipelineconfig.LoadPipelineConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "vc-store-endpoint") {
		t.Fatalf("vc-store-endpoint without vc-store-bearer: want error naming vc-store-endpoint, got %v", err)
	}
}

// A malformed vc-store-endpoint (not an http/https URL) is a boot error.
func TestLoad_MalformedVCStoreEndpoint(t *testing.T) {
	cfg := loadWith(t, pipelineConf("not-a-url", "tok", adjacentSinkLoop))
	if _, err := pipelineconfig.LoadPipelineConfig(cfg); err == nil {
		t.Fatal("malformed vc-store-endpoint: want error, got nil")
	}
}

// A vc-store-endpoint with a query or fragment is a boot error: the Connect client
// appends the RPC procedure to the raw base, so a query/fragment would corrupt every
// request path. Reject it at boot rather than fail every RPC at runtime.
func TestLoad_VCStoreEndpoint_RejectsQueryFragment(t *testing.T) {
	for _, ep := range []string{"https://node.example/?x=1", "https://node.example/#frag"} {
		cfg := loadWith(t, pipelineConf(ep, "tok", adjacentSinkLoop))
		if _, err := pipelineconfig.LoadPipelineConfig(cfg); err == nil {
			t.Fatalf("endpoint %q with query/fragment: want error, got nil", ep)
		}
	}
}

// An adjacent-only config still loads with no vc-store-endpoint (17d unaffected) —
// the bearer alone satisfies the consuming-loop requirement (endpoint stays optional).
func TestLoad_AdjacentNeedsNoEndpoint(t *testing.T) {
	cfg := loadWith(t, withBearer(loopsConf(validSinkLoop)))
	pc, err := pipelineconfig.LoadPipelineConfig(cfg)
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	if pc.VCStoreEndpoint != "" {
		t.Fatalf("VCStoreEndpoint = %q, want empty", pc.VCStoreEndpoint)
	}
}
