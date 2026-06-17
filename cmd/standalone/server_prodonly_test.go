//go:build !dev

package main

import (
	"testing"

	"github.com/o3co/protobuf.interceptors/endpoint"

	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/registry"
)

// In the default (production) build, BuildHandler refuses the noop transport: the
// noop operator is not compiled in, so chainOperator returns an error and the
// boot fails closed (slice-15 D-m2 / slice-11 D-p2). Tagged !dev because a dev
// build legitimately accepts noop (with the flag).
func TestBuildHandler_NoopRequiresDevBuild(t *testing.T) {
	coreCfg := &core.CoreConfig{DataDir: t.TempDir(), ListenAddr: ":0", AllowLoopback: true}
	regCfg := &registry.RegistryConfig{ID: registryID}
	verifier := endpoint.NewStaticEndpoint(nil)
	noop := &chainconfig.Config{Transport: chainconfig.TransportNoop, AllowNoopTransport: true}
	guard, resolver := newDIDResolution(coreCfg, noop)
	_, err := BuildHandler(coreCfg, regCfg, noop, verifier, guard, resolver)
	if err == nil {
		t.Fatal("BuildHandler accepted noop transport in a production build")
	}
}
