package pipelineconfig_test

import (
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/pipelineconfig"
)

const validAggregateLoop = `
  agg {
    role = "aggregate"
    aggregate {
      output-subject = "did:dplaax:reg:org:acme:pipeline:agg"
      issuer {
        did = "did:dplaax:reg:org:acme:pipeline:agg:process:a1"
        key-id = "signing"
        verification-method = "did:dplaax:reg:org:acme:pipeline:agg:process:a1#signing"
      }
      pipeline-id = "agg"
      process-id = "a1"
      verification-strategy = "adjacent"
      window = 5s
      ingresses {
        beta  { subject = "did:dplaax:reg:org:acme:pipeline:srcB", upstream-endpoint = "https://b.example" }
        alpha { subject = "did:dplaax:reg:org:acme:pipeline:srcA", upstream-endpoint = "https://a.example" }
      }
    }
  }
`

func TestLoad_ValidAggregate(t *testing.T) {
	pc, err := pipelineconfig.LoadPipelineConfig(loadWith(t, loopsConf(validAggregateLoop)))
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	if len(pc.Loops) != 1 {
		t.Fatalf("loops: got %d want 1", len(pc.Loops))
	}
	l := pc.Loops[0]
	if l.Role != pipelineconfig.RoleAggregate {
		t.Fatalf("role: got %q", l.Role)
	}
	ac := l.Aggregate
	if ac.OutputSubject != "did:dplaax:reg:org:acme:pipeline:agg" {
		t.Errorf("output-subject: %q", ac.OutputSubject)
	}
	if ac.Issuer.DID != "did:dplaax:reg:org:acme:pipeline:agg:process:a1" || ac.PipelineID != "agg" || ac.ProcessID != "a1" {
		t.Errorf("producing identity: %+v", ac)
	}
	if ac.Window != 5*time.Second {
		t.Errorf("window: got %s want 5s", ac.Window)
	}
	if ac.VerificationStrategy != pipelineconfig.StrategyAdjacent {
		t.Errorf("strategy: %q", ac.VerificationStrategy)
	}
	// Ingresses are loaded by SORTED key: alpha (srcA) before beta (srcB).
	if len(ac.Ingresses) != 2 {
		t.Fatalf("ingresses: got %d want 2", len(ac.Ingresses))
	}
	if ac.Ingresses[0].Subject != "did:dplaax:reg:org:acme:pipeline:srcA" || ac.Ingresses[0].UpstreamEndpoint != "https://a.example" {
		t.Errorf("ingress[0] (alpha): %+v", ac.Ingresses[0])
	}
	if ac.Ingresses[1].Subject != "did:dplaax:reg:org:acme:pipeline:srcB" || ac.Ingresses[1].UpstreamEndpoint != "https://b.example" {
		t.Errorf("ingress[1] (beta): %+v", ac.Ingresses[1])
	}
}

func TestLoad_Aggregate_FailClosed(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"unknown strategy", strings.Replace(validAggregateLoop, `verification-strategy = "adjacent"`, `verification-strategy = "full"`, 1)},
		{"missing window", strings.Replace(validAggregateLoop, `window = 5s`, "", 1)},
		{"non-positive window", strings.Replace(validAggregateLoop, `window = 5s`, `window = 0s`, 1)},
		{"empty ingresses", strings.Replace(validAggregateLoop,
			`ingresses {
        beta  { subject = "did:dplaax:reg:org:acme:pipeline:srcB", upstream-endpoint = "https://b.example" }
        alpha { subject = "did:dplaax:reg:org:acme:pipeline:srcA", upstream-endpoint = "https://a.example" }
      }`, `ingresses {}`, 1)},
		{"output equals an ingress subject", strings.Replace(validAggregateLoop,
			`subject = "did:dplaax:reg:org:acme:pipeline:srcA"`, `subject = "did:dplaax:reg:org:acme:pipeline:agg"`, 1)},
		{"duplicate ingress subject", strings.Replace(validAggregateLoop,
			`subject = "did:dplaax:reg:org:acme:pipeline:srcB"`, `subject = "did:dplaax:reg:org:acme:pipeline:srcA"`, 1)},
		{"missing upstream-endpoint", strings.Replace(validAggregateLoop,
			`, upstream-endpoint = "https://a.example"`, "", 1)},
		{"non-pipeline ingress subject", strings.Replace(validAggregateLoop,
			`subject = "did:dplaax:reg:org:acme:pipeline:srcA"`, `subject = "not-a-did"`, 1)},
		// A source-role key nested under an aggregate loop is rejected.
		{"cross-role source key", strings.Replace(validAggregateLoop,
			`role = "aggregate"`, "role = \"aggregate\"\n    output-subject = \"did:dplaax:reg:org:acme:pipeline:x\"", 1)},
		// A stray shared ingress-subject on an aggregate loop is rejected (fail-closed).
		{"stray ingress-subject", strings.Replace(validAggregateLoop,
			`role = "aggregate"`, "role = \"aggregate\"\n    ingress-subject = \"did:dplaax:reg:org:acme:pipeline:x\"", 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pipelineconfig.LoadPipelineConfig(loadWith(t, loopsConf(tc.body))); err == nil {
				t.Errorf("%s: want boot error, got nil", tc.name)
			}
		})
	}
}

// An aggregate block nested under a source loop is rejected (cross-role, other direction).
func TestLoad_Source_RejectsAggregateKey(t *testing.T) {
	body := strings.Replace(validSourceLoop, `schema-ref = ""`, "aggregate { window = \"5s\" }", 1)
	if _, err := pipelineconfig.LoadPipelineConfig(loadWith(t, loopsConf(body))); err == nil {
		t.Error("aggregate key under a source loop: want boot error")
	}
}

// ingress-subject remains required for source/sink/chained (role-conditional move).
func TestLoad_Source_StillRequiresIngressSubject(t *testing.T) {
	body := strings.Replace(validSourceLoop, `ingress-subject = "ingest.src"`, "", 1)
	if _, err := pipelineconfig.LoadPipelineConfig(loadWith(t, loopsConf(body))); err == nil {
		t.Error("source without ingress-subject: want boot error")
	}
}
