package pipelineconfig_test

import (
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/pipelineconfig"
)

const sinkUpstream = `upstream-endpoint = "https://acme.example/pipelines/pipe"`

// The registry keys are optional: a config without them loads as before, with
// the registries empty (the composition root then derives them).
func TestRegistryOverridesAreOptional(t *testing.T) {
	for name, body := range map[string]string{"sink": validSinkLoop, "chained": validChainedLoop, "aggregate": validAggregateLoop} {
		t.Run(name, func(t *testing.T) {
			pc, err := pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(loopsConf(body))))
			if err != nil {
				t.Fatalf("LoadPipelineConfig: %v", err)
			}
			if pc.VCStoreRegistry != "" || pc.Loops[0].Sink.UpstreamRegistry != "" || pc.Loops[0].Chained.UpstreamRegistry != "" {
				t.Errorf("registries without the keys: %q %q %q, want empty", pc.VCStoreRegistry, pc.Loops[0].Sink.UpstreamRegistry, pc.Loops[0].Chained.UpstreamRegistry)
			}
			for _, ing := range pc.Loops[0].Aggregate.Ingresses {
				if ing.UpstreamRegistry != "" {
					t.Errorf("aggregate ingress registry without the key: %q", ing.UpstreamRegistry)
				}
			}
		})
	}
}

func TestRegistryOverridesAreRead(t *testing.T) {
	conf := "provin.network.pipeline.vc-store-registry = \"node.example\"\n" +
		loopsConf(strings.Replace(validSinkLoop, sinkUpstream, sinkUpstream+"\n      upstream-registry = \"up.example\"", 1))
	pc, err := pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(conf)))
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	if pc.VCStoreRegistry != "node.example" || pc.Loops[0].Sink.UpstreamRegistry != "up.example" {
		t.Errorf("registries = %q, %q; want node.example, up.example", pc.VCStoreRegistry, pc.Loops[0].Sink.UpstreamRegistry)
	}

	chained := strings.Replace(validChainedLoop, sinkUpstream, sinkUpstream+"\n      upstream-registry = \"up.example\"", 1)
	pc, err = pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(loopsConf(chained))))
	if err != nil {
		t.Fatalf("LoadPipelineConfig chained: %v", err)
	}
	if got := pc.Loops[0].Chained.UpstreamRegistry; got != "up.example" {
		t.Errorf("chained upstream-registry = %q, want up.example", got)
	}

	agg := strings.Replace(validAggregateLoop, `upstream-endpoint = "https://b.example" }`, `upstream-endpoint = "https://b.example", upstream-registry = "b.example" }`, 1)
	pc, err = pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(loopsConf(agg))))
	if err != nil {
		t.Fatalf("LoadPipelineConfig aggregate: %v", err)
	}
	found := false
	for _, ing := range pc.Loops[0].Aggregate.Ingresses {
		if ing.UpstreamEndpoint == "https://b.example" {
			found = ing.UpstreamRegistry == "b.example"
		}
	}
	if !found {
		t.Errorf("aggregate ingress upstream-registry not read: %+v", pc.Loops[0].Aggregate.Ingresses)
	}
}

func TestRegistryOverrideGrammar(t *testing.T) {
	for _, bad := range []string{"a b", "*", ".."} {
		t.Run(bad, func(t *testing.T) {
			node := "provin.network.pipeline.vc-store-registry = \"" + bad + "\"\n" + loopsConf(validSinkLoop)
			if _, err := pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(node))); err == nil {
				t.Errorf("vc-store-registry %q: want a boot error", bad)
			}
			sink := strings.Replace(validSinkLoop, sinkUpstream, sinkUpstream+"\n      upstream-registry = \""+bad+"\"", 1)
			if _, err := pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(loopsConf(sink)))); err == nil {
				t.Errorf("sink upstream-registry %q: want a boot error", bad)
			}
			chained := strings.Replace(validChainedLoop, sinkUpstream, sinkUpstream+"\n      upstream-registry = \""+bad+"\"", 1)
			if _, err := pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(loopsConf(chained)))); err == nil {
				t.Errorf("chained upstream-registry %q: want a boot error", bad)
			}
			agg := strings.Replace(validAggregateLoop, `upstream-endpoint = "https://b.example" }`, `upstream-endpoint = "https://b.example", upstream-registry = "`+bad+`" }`, 1)
			if _, err := pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(loopsConf(agg)))); err == nil {
				t.Errorf("aggregate upstream-registry %q: want a boot error", bad)
			}
		})
	}
}
