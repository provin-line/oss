//go:build dev

package netcompose

import (
	"testing"

	"github.com/provin-line/oss/network/pkg/chainconfig"
)

// In a dev build the noop transport is available, but only when explicitly
// enabled via chain.dev.allow-noop-transport (slice-15 D-m2). This exercises the
// dev-tagged ChainOperator branch (main calls ChainOperator before BuildHandler).
func TestChainOperator_DevNoop(t *testing.T) {
	// enabled -> boots.
	enabled := &chainconfig.Config{Transport: chainconfig.TransportNoop, AllowNoopTransport: true}
	if _, err := ChainOperator(enabled); err != nil {
		t.Fatalf("dev build rejected enabled noop: %v", err)
	}
	// disabled -> refused even in a dev build.
	disabled := &chainconfig.Config{Transport: chainconfig.TransportNoop, AllowNoopTransport: false}
	if _, err := ChainOperator(disabled); err == nil {
		t.Fatal("dev build accepted noop without allow-noop-transport")
	}
}
