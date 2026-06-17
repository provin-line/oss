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
	enabled := &chainconfig.Config{Transport: chainconfig.TransportNoop, AllowNoopTransport: true}
	gEn, rEn := newDIDResolution(coreCfg, enabled)
	if _, err := BuildHandler(coreCfg, regCfg, enabled, verifier, gEn, rEn); err != nil {
		t.Fatalf("dev build rejected enabled noop: %v", err)
	}
	// disabled -> refused even in a dev build.
	disabled := &chainconfig.Config{Transport: chainconfig.TransportNoop, AllowNoopTransport: false}
	gDis, rDis := newDIDResolution(coreCfg, disabled)
	if _, err := BuildHandler(coreCfg, regCfg, disabled, verifier, gDis, rDis); err == nil {
		t.Fatal("dev build accepted noop without allow-noop-transport")
	}
}
