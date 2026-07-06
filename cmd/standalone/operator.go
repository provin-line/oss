package main

import (
	"fmt"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/infra"
	chainnats "github.com/provin-line/oss/network/pkg/services/chainmanager/infra/nats"
)

// natsOperator builds the production nats infra.Operator from chain config: a
// directory JWT publisher (writes account claims where the nats-server directory
// resolver reads them) signed by the configured trust-root for the node's account.
func natsOperator(c *chainconfig.Config) (infra.Operator, error) {
	op, err := chainnats.New(chainnats.Config{
		AccountSeed:   c.NATS.AccountSeed,
		TrustRootSeed: c.NATS.TrustRootSeed,
		URL:           c.NATS.URL,
		Publisher:     chainnats.NewDirPublisher(c.NATS.ResolverDir),
	})
	if err != nil {
		return nil, err
	}
	// Publish the account's current claims at boot so a freshly-provisioned
	// account is resolvable before its first grant (findings #14). Idempotent;
	// hydrate has already absorbed any previously published grant set, so this
	// never clobbers live grants.
	if err := op.PublishClaims(); err != nil {
		return nil, fmt.Errorf("standalone: publish account claims: %w", err)
	}
	return op, nil
}
