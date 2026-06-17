// Command standalone is the dplaax network registry server: a single binary that
// loads its HOCON config, constructs the DID / Schema / Signer services over
// file-backed stores, and serves them via ConnectRPC (h2c) behind the L1
// authorization interceptors, plus the public W3C DID resolution route and
// /healthz. Every config value is validated at boot — a misconfigured binary
// dies at startup, never on first request.
package main

import (
	"log"
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/provin-line/oss/hoconconfig"
	"github.com/provin-line/oss/network/pkg/auth"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/registry"
)

func main() {
	// Layer the embedded references with ./config/application.conf and the
	// operator overlay named by CONFIG_OVERLAY (the network-binary convention).
	cfg, err := hoconconfig.Load(".", "CONFIG_OVERLAY")
	if err != nil {
		log.Fatalf("standalone: load config: %v", err)
	}

	coreCfg, err := core.LoadCoreConfig(cfg)
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}
	authCfg, err := auth.LoadAuthConfig(cfg)
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}
	regCfg, err := registry.LoadRegistryConfig(cfg)
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}
	chainCfg, err := chainconfig.LoadChainConfig(cfg)
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}

	verifier, err := auth.NewVerifier(authCfg.PolicyVerifierURL)
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}

	handler, err := BuildHandler(coreCfg, regCfg, chainCfg, verifier)
	if err != nil {
		log.Fatalf("standalone: build server: %v", err)
	}

	srv := &http.Server{
		Addr:    coreCfg.ListenAddr,
		Handler: h2c.NewHandler(handler, &http2.Server{}),
	}
	log.Printf("standalone: listening on %s (registry %q)", coreCfg.ListenAddr, regCfg.ID)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("standalone: serve: %v", err)
	}
}
