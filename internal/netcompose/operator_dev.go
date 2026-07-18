//go:build dev

package netcompose

import (
	"fmt"

	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/infra"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/infra/noop"
)

// ChainOperator builds the chain transport operator (dev build). nats as in
// production; noop is additionally available but only when explicitly enabled via
// chain.dev.allow-noop-transport — a second gate inside the dev build.
func ChainOperator(c *chainconfig.Config) (infra.Operator, error) {
	switch c.Transport {
	case chainconfig.TransportNATS:
		return natsOperator(c)
	case chainconfig.TransportNoop:
		if !c.AllowNoopTransport {
			return nil, fmt.Errorf("standalone: noop transport requires chain.dev.allow-noop-transport=true")
		}
		return noop.New(), nil
	default:
		return nil, fmt.Errorf("standalone: unknown transport %q", c.Transport)
	}
}
