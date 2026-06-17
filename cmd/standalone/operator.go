package main

import (
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/infra"
	chainnats "github.com/provin-line/oss/network/pkg/services/chainmanager/infra/nats"
)

// natsOperator builds the production nats infra.Operator from chain config: a
// directory JWT publisher (writes account claims where the nats-server directory
// resolver reads them) signed by the configured trust-root for the node's account.
func natsOperator(c *chainconfig.Config) (infra.Operator, error) {
	return chainnats.New(chainnats.Config{
		AccountSeed:   c.NATS.AccountSeed,
		TrustRootSeed: c.NATS.TrustRootSeed,
		URL:           c.NATS.URL,
		Publisher:     chainnats.NewDirPublisher(c.NATS.ResolverDir),
	})
}
