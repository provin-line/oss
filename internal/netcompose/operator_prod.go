//go:build !dev

package netcompose

import (
	"fmt"

	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/infra"
)

// ChainOperator builds the chain transport operator (production build). Only nats
// is available; noop is refused AND is not compiled into this binary at all
// (infra/noop is imported only by the `dev`-tagged variant) — the structural
// "nats-only in prod" guarantee (slice-11 D-p2 / slice-15 D-m2).
func ChainOperator(c *chainconfig.Config) (infra.Operator, error) {
	switch c.Transport {
	case chainconfig.TransportNATS:
		return natsOperator(c)
	default:
		return nil, fmt.Errorf("standalone: transport %q requires a `dev` build (noop is excluded from production builds)", c.Transport)
	}
}
