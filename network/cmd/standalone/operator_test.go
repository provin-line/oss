package main

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/network/pkg/chainconfig"
)

// In the default (production) build, the noop transport is refused — it is not
// even compiled in (slice-15 D-m2).
func TestChainOperator_ProdRefusesNoop(t *testing.T) {
	_, err := chainOperator(&chainconfig.Config{
		Transport: chainconfig.TransportNoop, AllowNoopTransport: true,
	})
	if err == nil {
		t.Fatal("production build accepted noop transport")
	}
}

func TestChainOperator_NATS(t *testing.T) {
	acc, _ := nkeys.CreateAccount()
	accSeed, _ := acc.Seed()
	op, _ := nkeys.CreateOperator()
	opSeed, _ := op.Seed()
	o, err := chainOperator(&chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS: chainconfig.NATSConfig{
			URL: "nats://h:4222", AccountSeed: string(accSeed), TrustRootSeed: string(opSeed),
			ResolverDir: t.TempDir(), NodeDID: "did:dplaax:poc.dplaax.dev:org:node",
		},
	})
	if err != nil {
		t.Fatalf("chainOperator(nats): %v", err)
	}
	if o.PublishType() != "nats" {
		t.Errorf("PublishType = %q, want nats", o.PublishType())
	}
}

// The default standalone build must NOT pull in infra/noop — it is dev-build only
// (slice-11 D-p2). Mirrors the slice-14 infra/nats dependency guard.
func TestProdBuild_ExcludesNoop(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps",
		"github.com/provin-line/oss/network/cmd/standalone").CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "chainmanager/infra/noop") {
		t.Error("default standalone build includes infra/noop — must be dev-build only (slice-11 D-p2)")
	}
}
