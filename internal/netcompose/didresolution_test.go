package netcompose

import (
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/didresolver"
	"github.com/provin-line/oss/resolver/cache"
)

// NewDIDResolution owns the node's cache posture: the did-cache block decides
// whether every verification consumer (chain subscriber, wireauth, mirror,
// pipeline appraisal via cmd/pipeline's mirror of this function) resolves
// through resolver/cache or directly. This test pins the wrap-when-enabled
// contract by concrete type, so a config regression cannot silently leave a
// node uncached (or cached) against its config.
func TestNewDIDResolution_DIDCachePosture(t *testing.T) {
	coreCfg := &core.CoreConfig{}

	uncachedCfg := &chainconfig.Config{Transport: chainconfig.TransportNoop}
	_, r, err := NewDIDResolution(coreCfg, uncachedCfg)
	if err != nil {
		t.Fatalf("NewDIDResolution (cache disabled): %v", err)
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
	_, r, err = NewDIDResolution(coreCfg, cachedCfg)
	if err != nil {
		t.Fatalf("NewDIDResolution (cache enabled): %v", err)
	}
	if _, ok := r.(*cache.Resolver); !ok {
		t.Errorf("cache enabled: resolver is %T, want *cache.Resolver wrapping the cross-registry resolver", r)
	}
}
