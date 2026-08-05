package chainconfig_test

import (
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/chainconfig"
)

// The did-cache block configures the node-wide DID resolution cache
// (resolver/cache). Its loading contract: disabled by default (the uncached
// path is the default composition), reference.conf supplies the bounds, and a
// non-positive bound is a boot error naming the key — the "zero means default"
// convenience lives in resolver/cache for programmatic construction, not here,
// where reference.conf always supplies concrete values.

func TestLoadChainConfig_DIDCacheDefaultsDisabled(t *testing.T) {
	cfg := loadWith(t, `provin.network.chain { transport = "noop" }`)
	c, err := chainconfig.LoadChainConfig(cfg)
	if err != nil {
		t.Fatalf("LoadChainConfig: %v", err)
	}
	if c.DIDCache.Enabled {
		t.Error("DIDCache.Enabled = true by default, want false (uncached is the default composition)")
	}
	if got, want := c.DIDCache.TTL, 60*time.Second; got != want {
		t.Errorf("DIDCache.TTL = %v, want reference default %v", got, want)
	}
	if got, want := c.DIDCache.MaxEntries, 1024; got != want {
		t.Errorf("DIDCache.MaxEntries = %d, want reference default %d", got, want)
	}
	if got, want := c.DIDCache.MaxBytes, 16<<20; got != want {
		t.Errorf("DIDCache.MaxBytes = %d, want reference default %d", got, want)
	}
}

func TestLoadChainConfig_DIDCacheEnabledParses(t *testing.T) {
	cfg := loadWith(t, `provin.network.chain {
  transport = "noop"
  did-cache {
    enabled     = true
    ttl         = 5m
    max-entries = 32
    max-bytes   = 1048576
  }
}`)
	c, err := chainconfig.LoadChainConfig(cfg)
	if err != nil {
		t.Fatalf("LoadChainConfig: %v", err)
	}
	if !c.DIDCache.Enabled {
		t.Error("DIDCache.Enabled = false, want true")
	}
	if got, want := c.DIDCache.TTL, 5*time.Minute; got != want {
		t.Errorf("DIDCache.TTL = %v, want %v", got, want)
	}
	if got, want := c.DIDCache.MaxEntries, 32; got != want {
		t.Errorf("DIDCache.MaxEntries = %d, want %d", got, want)
	}
	if got, want := c.DIDCache.MaxBytes, 1048576; got != want {
		t.Errorf("DIDCache.MaxBytes = %d, want %d", got, want)
	}
}

func TestLoadChainConfig_DIDCacheRejectsNonPositiveBounds(t *testing.T) {
	for name, block := range map[string]struct{ overlay, wantKey string }{
		"zero ttl":         {`did-cache { ttl = 0s }`, "did-cache.ttl"},
		"negative ttl":     {`did-cache { ttl = -1s }`, "did-cache.ttl"},
		"zero entries":     {`did-cache { max-entries = 0 }`, "did-cache.max-entries"},
		"negative entries": {`did-cache { max-entries = -1 }`, "did-cache.max-entries"},
		"zero bytes":       {`did-cache { max-bytes = 0 }`, "did-cache.max-bytes"},
		"negative bytes":   {`did-cache { max-bytes = -1 }`, "did-cache.max-bytes"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := loadWith(t, "provin.network.chain {\n  transport = \"noop\"\n  "+block.overlay+"\n}")
			_, err := chainconfig.LoadChainConfig(cfg)
			if err == nil {
				t.Fatalf("LoadChainConfig accepted %s", name)
			}
			if !strings.Contains(err.Error(), block.wantKey) {
				t.Errorf("error %q does not name the offending key %q", err, block.wantKey)
			}
		})
	}
}
