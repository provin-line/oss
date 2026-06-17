//go:build dev

package main

import (
	"testing"

	"github.com/o3co/protobuf.interceptors/endpoint"

	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/registry"
)

// In a dev build the noop transport is available, but only when explicitly
// enabled via chain.dev.allow-noop-transport (slice-15 D-m2). This exercises the
// dev-tagged chainOperator branch.
func TestBuildHandler_DevNoop(t *testing.T) {
	coreCfg := &core.CoreConfig{DataDir: t.TempDir(), ListenAddr: ":0", AllowLoopback: true}
	regCfg := &registry.RegistryConfig{ID: registryID}
	verifier := endpoint.NewStaticEndpoint(nil)

	// enabled -> boots.
	if _, err := BuildHandler(coreCfg, regCfg,
		&chainconfig.Config{Transport: chainconfig.TransportNoop, AllowNoopTransport: true}, verifier); err != nil {
		t.Fatalf("dev build rejected enabled noop: %v", err)
	}
	// disabled -> refused even in a dev build.
	if _, err := BuildHandler(coreCfg, regCfg,
		&chainconfig.Config{Transport: chainconfig.TransportNoop, AllowNoopTransport: false}, verifier); err == nil {
		t.Fatal("dev build accepted noop without allow-noop-transport")
	}
}
