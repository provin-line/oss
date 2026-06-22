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

// 17e: a "full" sink loads when a vc-store-endpoint + vc-store-bearer are configured,
// and both are captured on the Config.
func TestLoad_ValidFullSink_WithEndpoint(t *testing.T) {
	const endpoint, bearer = "https://node.example/", "tok-abc"
	cfg := loadWith(t, pipelineConf(endpoint, bearer, fullSinkLoop))
	pc, err := pipelineconfig.LoadPipelineConfig(cfg)
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	if pc.VCStoreEndpoint != endpoint {
		t.Fatalf("VCStoreEndpoint = %q, want %q", pc.VCStoreEndpoint, endpoint)
	}
	if pc.VCStoreBearer != bearer {
		t.Fatalf("VCStoreBearer = %q, want %q", pc.VCStoreBearer, bearer)
	}
	if len(pc.Loops) != 1 {
		t.Fatalf("loops: got %d want 1", len(pc.Loops))
	}
	if got := pc.Loops[0].Sink.VerificationStrategy; got != pipelineconfig.StrategyFull {
		t.Fatalf("sink strategy = %q, want %q", got, pipelineconfig.StrategyFull)
	}
}

// 17e: a "full" loop WITHOUT a vc-store-endpoint is a boot error — full needs a
// network credential resolver, which the endpoint configures (fail closed).
func TestLoad_FullStrategy_RequiresEndpoint(t *testing.T) {
	cfg := loadWith(t, pipelineConf("", "", fullSinkLoop))
	if _, err := pipelineconfig.LoadPipelineConfig(cfg); err == nil {
		t.Fatal("full strategy without vc-store-endpoint: want error, got nil")
	}
}

// 17e: a vc-store-endpoint WITHOUT a vc-store-bearer is a boot error — the VC store is
// L1-protected, so a tokenless client's publish/resolve would be rejected at runtime.
// Fail closed at boot rather than ship a node whose publication silently fails.
func TestLoad_VCStoreEndpoint_RequiresBearer(t *testing.T) {
	cfg := loadWith(t, pipelineConf("https://node.example/", "", fullSinkLoop))
	if _, err := pipelineconfig.LoadPipelineConfig(cfg); err == nil {
		t.Fatal("vc-store-endpoint without vc-store-bearer: want error, got nil")
	}
}

// A malformed vc-store-endpoint (not an http/https URL) is a boot error.
func TestLoad_MalformedVCStoreEndpoint(t *testing.T) {
	cfg := loadWith(t, pipelineConf("not-a-url", "tok", fullSinkLoop))
	if _, err := pipelineconfig.LoadPipelineConfig(cfg); err == nil {
		t.Fatal("malformed vc-store-endpoint: want error, got nil")
	}
}

// A vc-store-endpoint with a query or fragment is a boot error: the Connect client
// appends the RPC procedure to the raw base, so a query/fragment would corrupt every
// request path. Reject it at boot rather than fail every RPC at runtime.
func TestLoad_VCStoreEndpoint_RejectsQueryFragment(t *testing.T) {
	for _, ep := range []string{"https://node.example/?x=1", "https://node.example/#frag"} {
		cfg := loadWith(t, pipelineConf(ep, "tok", fullSinkLoop))
		if _, err := pipelineconfig.LoadPipelineConfig(cfg); err == nil {
			t.Fatalf("endpoint %q with query/fragment: want error, got nil", ep)
		}
	}
}

// An adjacent-only config still loads with no vc-store-endpoint (17d unaffected).
func TestLoad_AdjacentNeedsNoEndpoint(t *testing.T) {
	cfg := loadWith(t, loopsConf(validSinkLoop))
	pc, err := pipelineconfig.LoadPipelineConfig(cfg)
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	if pc.VCStoreEndpoint != "" {
		t.Fatalf("VCStoreEndpoint = %q, want empty", pc.VCStoreEndpoint)
	}
}
