//go:build !dev

package netcompose

import (
	"testing"

	"github.com/provin-line/oss/network/pkg/chainconfig"
)

// In the default (production) build, the noop transport is refused: the noop
// operator is not compiled in, so ChainOperator returns an error and the boot
// fails closed (slice-15 D-m2 / slice-11 D-p2) — main calls ChainOperator before
// BuildHandler and fatals on the error. Tagged !dev because a dev build
// legitimately accepts noop (with the flag).
func TestChainOperator_NoopRequiresDevBuild(t *testing.T) {
	noop := &chainconfig.Config{Transport: chainconfig.TransportNoop, AllowNoopTransport: true}
	if _, err := ChainOperator(noop); err == nil {
		t.Fatal("ChainOperator accepted noop transport in a production build")
	}
}
