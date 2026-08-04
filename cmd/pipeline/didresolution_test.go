package main

import (
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/didresolver"
	"github.com/provin-line/oss/resolver/cache"
)

// newDIDResolution is a textual mirror of netcompose.NewDIDResolution (this
// binary cannot import netcompose), so its did-cache posture can drift
// silently from the netcompose original. This test pins the wrap-when-enabled
// contract by concrete type on THIS root, exactly as
// internal/netcompose/didresolution_test.go pins it on the other, so a
// posture regression fails on whichever mirror carries it.
func TestNewDIDResolution_DIDCachePosture(t *testing.T) {
	coreCfg := &core.CoreConfig{}

	uncachedCfg := &chainconfig.Config{Transport: chainconfig.TransportNoop}
	_, r, err := newDIDResolution(coreCfg, uncachedCfg)
	if err != nil {
		t.Fatalf("newDIDResolution (cache disabled): %v", err)
	}
	if _, ok := r.(*didresolver.Resolver); !ok {
		t.Errorf("cache disabled: resolver is %T, want *didresolver.Resolver (the bare cross-registry resolver)", r)
	}

	cachedCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNoop,
		DIDCache: chainconfig.DIDCacheConfig{
			Enabled:    true,
			TTL:        time.Minute,
			MaxEntries: 8,
			MaxBytes:   1 << 20,
		},
	}
	_, r, err = newDIDResolution(coreCfg, cachedCfg)
	if err != nil {
		t.Fatalf("newDIDResolution (cache enabled): %v", err)
	}
	if _, ok := r.(*cache.Resolver); !ok {
		t.Errorf("cache enabled: resolver is %T, want *cache.Resolver wrapping the cross-registry resolver", r)
	}
}
