package pipelineconfig_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/pipelineconfig"
)

const credentialOriginsKey = "provin.network.pipeline.credential-origins"

// By default the bearer goes to no origin but the VC store's.
func TestLoad_CredentialOriginsDefaultToNone(t *testing.T) {
	cfg, err := pipelineconfig.LoadPipelineConfig(loadWith(t, ""))
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	if got := cfg.CredentialOrigins; len(got) != 0 {
		t.Errorf("credential-origins = %q, want none", got)
	}
	if cfg.PresentsCredentialTo("https://peer.example") {
		t.Error("PresentsCredentialTo an unlisted origin = true")
	}
}

// Each origin is held in one spelling: scheme and host lower case, the
// scheme's default port and a bare "/" dropped.
func TestLoad_CredentialOriginsAreNormalized(t *testing.T) {
	conf := credentialOriginsKey + ` = ["HTTPS://Peer.Example:443", "http://10.0.0.7:8080", "https://b.example/", "http://c.example:80"]` + "\n"
	cfg, err := pipelineconfig.LoadPipelineConfig(loadWith(t, conf))
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	want := []string{"https://peer.example", "http://10.0.0.7:8080", "https://b.example", "http://c.example"}
	if got := cfg.CredentialOrigins; !slices.Equal(got, want) {
		t.Errorf("credential-origins = %q, want %q", got, want)
	}
}

// What is not an http(s) origin fails startup.
func TestLoad_CredentialOriginsRefuseWhatIsNotAnOrigin(t *testing.T) {
	for _, v := range []string{
		"", "peer.example", "ftp://peer.example", "https://", "https:///path",
		"https://peer.example/path", "https://user@peer.example",
		"https://peer.example?q=1", "https://peer.example#f", "https://peer.example:x",
	} {
		conf := credentialOriginsKey + ` = ["` + v + `"]` + "\n"
		_, err := pipelineconfig.LoadPipelineConfig(loadWith(t, conf))
		if err == nil || !strings.Contains(err.Error(), "credential-origins") {
			t.Errorf("credential-origins %q: want a credential-origins error, got %v", v, err)
		}
	}
}

// The bearer goes to an endpoint whose origin is the VC store's or a listed
// one, and to no other.
func TestPresentsCredentialTo(t *testing.T) {
	conf := withBearer(`provin.network.pipeline.vc-store-endpoint = "https://store.example:8443/base"
` + credentialOriginsKey + ` = ["https://peer.example"]
`)
	cfg, err := pipelineconfig.LoadPipelineConfig(loadWith(t, conf))
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	for _, endpoint := range []string{
		"https://peer.example", "https://peer.example/", "https://PEER.example:443/a/b",
		"https://store.example:8443", "https://store.example:8443/other",
	} {
		if !cfg.PresentsCredentialTo(endpoint) {
			t.Errorf("PresentsCredentialTo(%q) = false, want true", endpoint)
		}
	}
	for _, endpoint := range []string{
		"http://peer.example", "https://peer.example:8443", "https://peer.example.evil.example",
		"https://evil.example", "https://peer.example@evil.example", "https://u@peer.example",
		"https://store.example", "https://evil.example/https://peer.example", "", "peer.example",
	} {
		if cfg.PresentsCredentialTo(endpoint) {
			t.Errorf("PresentsCredentialTo(%q) = true, want false", endpoint)
		}
	}
}

// A destination the operator configured is always shown the credential: a
// loop's upstream endpoint as well as the VC store.
func TestPresentsCredentialTo_AConfiguredUpstreamEndpoint(t *testing.T) {
	cfg := &pipelineconfig.Config{Loops: []pipelineconfig.LoopConfig{
		{Sink: pipelineconfig.SinkConfig{UpstreamEndpoint: "https://upstream.example:8443/base"}},
		{Aggregate: pipelineconfig.AggregateConfig{Ingresses: []pipelineconfig.AggregateIngress{{UpstreamEndpoint: "https://ingress.example/"}}}},
	}}
	for endpoint, want := range map[string]bool{
		"https://upstream.example:8443/x": true,
		"https://ingress.example/y":       true,
		"https://upstream.example/x":      false,
		"https://other.example/":          false,
	} {
		if got := cfg.PresentsCredentialTo(endpoint); got != want {
			t.Errorf("PresentsCredentialTo(%q) = %v, want %v", endpoint, got, want)
		}
	}
}

// A list written by hand in Go, in another spelling of an origin, matches it.
func TestPresentsCredentialTo_AHandWrittenOrigin(t *testing.T) {
	cfg := &pipelineconfig.Config{CredentialOrigins: []string{"HTTPS://Peer.Example:443"}}
	if !cfg.PresentsCredentialTo("https://peer.example/x") {
		t.Error("a hand-written origin in another spelling did not match")
	}
}
