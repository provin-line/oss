package main

import (
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/registry"
)

// endpointURLs collects the config-supplied URL surfaces of the matrix that
// this binary can see. The orchestrator-side surfaces (probes, scrape target)
// are outside the process and are covered by the matrix documentation, not by
// this guard — a node cannot inspect its own probe configuration.
func endpointURLs(regCfg *registry.RegistryConfig, chainCfg *chainconfig.Config) []core.NamedURL {
	var out []core.NamedURL
	for _, ep := range regCfg.Endpoints {
		out = append(out, core.NamedURL{Name: ep.ID, URL: ep.ServiceEndpoint})
	}
	if chainCfg.NATS.ResolverBaseURL != "" {
		out = append(out, core.NamedURL{Name: "resolver-base-url", URL: chainCfg.NATS.ResolverBaseURL})
	}
	for reg, base := range chainCfg.NATS.RegistryBaseURLs {
		out = append(out, core.NamedURL{Name: "registry-base-urls." + reg, URL: base})
	}
	return out
}
