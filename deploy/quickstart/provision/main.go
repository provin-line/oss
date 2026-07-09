/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

// Command provision lays down the operator-mode NATS trust material the
// quickstart's broker and standalone node consume — an operator trust root, one
// account, the account's claims JWT in a resolver directory, and a broker config
// that preloads it. It mirrors a production deployment's out-of-band NATS
// provisioning (the same shape the provin.e2e compose harness generates per
// run), so the quickstart commits no cryptographic seeds: every artifact is
// generated fresh into a git-ignored directory before `docker compose up`.
//
// This is NATS decentralized-auth material only (nkey seeds, account JWTs). The
// separate HS256 shared secret used by the auth.provider / policy-verifier /
// bootstrap-token path is an environment variable, not produced here.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	natsop "github.com/provin-line/oss/network/pkg/services/chainmanager/infra/nats"
)

// config parameterizes provision. account is the single NATS account the
// quickstart node runs under; natsURL is the broker URL baked into the account
// operator (used only for its identity here — provision never dials the broker).
// jwtSecret/jwtIssuer/serviceSubject, when a secret is set, mint the node's
// service token (see writeServiceOverlay).
type config struct {
	outDir         string
	account        string
	natsURL        string
	jwtSecret      string
	jwtIssuer      string
	serviceSubject string
	serviceTTL     time.Duration
}

func main() {
	var cfg config
	flag.StringVar(&cfg.outDir, "out", "generated", "output directory for generated NATS trust material (git-ignored)")
	flag.StringVar(&cfg.account, "account", "acme", "NATS account name the node runs under")
	flag.StringVar(&cfg.natsURL, "nats-url", "nats://nats:4222", "broker URL baked into the account operator")
	flag.StringVar(&cfg.jwtSecret, "jwt-secret", os.Getenv("OAUTH_JWT_SECRET"), "HS256 shared secret for the node's service token (empty = skip the service overlay)")
	flag.StringVar(&cfg.jwtIssuer, "jwt-issuer", os.Getenv("OAUTH_JWT_ISSUER"), "iss claim for the node's service token")
	flag.StringVar(&cfg.serviceSubject, "service-subject", "did:dplaax:poc.dplaax.dev:org:acme", "sub claim for the node's service token")
	flag.DurationVar(&cfg.serviceTTL, "service-ttl", 87600*time.Hour, "lifetime of the node's service token (default ~10y — dev)")
	flag.Parse()

	if err := provision(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "provision: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("provisioned NATS trust material for account %q under %s\n", cfg.account, cfg.outDir)
}

// provision generates the operator + account material and writes the broker
// config. Layout (paths the compose file mounts):
//
//	<out>/operator.seed              operator (trust-root) nkey seed
//	<out>/<account>-account.seed     account nkey seed
//	<out>/nats/operator.jwt          self-signed operator JWT (broker trust anchor)
//	<out>/nats/nats-server.conf      operator-mode config preloading the account
//	<out>/jwts/<accountPub>.jwt      account-claims JWT (resolver dir)
func provision(cfg config) error {
	jwtsDir := filepath.Join(cfg.outDir, "jwts")
	natsDir := filepath.Join(cfg.outDir, "nats")
	for _, d := range []string{jwtsDir, natsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	// The node process (a different, non-root uid than this provisioner) uses
	// jwtsDir as its live resolver directory — its DirPublisher creates a temp
	// file and renames it over <accountPub>.jwt at boot, which needs write on
	// the directory itself. Make it group/other-writable so the container node
	// can republish. Umask-proof (MkdirAll is masked). Dev-only permissiveness.
	if err := os.Chmod(jwtsDir, 0o777); err != nil {
		return fmt.Errorf("chmod jwts dir: %w", err)
	}

	// Operator trust root: seed on disk for auditing, self-signed JWT as the
	// broker's trust anchor.
	op, err := nkeys.CreateOperator()
	if err != nil {
		return fmt.Errorf("create operator: %w", err)
	}
	opSeed, err := op.Seed()
	if err != nil {
		return fmt.Errorf("operator seed: %w", err)
	}
	opPub, err := op.PublicKey()
	if err != nil {
		return fmt.Errorf("operator public key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(cfg.outDir, "operator.seed"), opSeed, 0o644); err != nil {
		return fmt.Errorf("write operator seed: %w", err)
	}
	opClaims := jwt.NewOperatorClaims(opPub)
	opClaims.Name = "provin-quickstart"
	opJWT, err := opClaims.Encode(op)
	if err != nil {
		return fmt.Errorf("encode operator jwt: %w", err)
	}
	if err := os.WriteFile(filepath.Join(natsDir, "operator.jwt"), []byte(opJWT), 0o644); err != nil {
		return fmt.Errorf("write operator jwt: %w", err)
	}

	// Account: seed on disk, claims JWT published to the resolver dir via the
	// same operator provin.oss uses at runtime (so the published claims match
	// exactly what the node re-publishes on its first grant).
	acc, err := nkeys.CreateAccount()
	if err != nil {
		return fmt.Errorf("create account: %w", err)
	}
	accSeed, err := acc.Seed()
	if err != nil {
		return fmt.Errorf("account seed: %w", err)
	}
	accPub, err := acc.PublicKey()
	if err != nil {
		return fmt.Errorf("account public key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(cfg.outDir, cfg.account+"-account.seed"), accSeed, 0o644); err != nil {
		return fmt.Errorf("write account seed: %w", err)
	}
	aop, err := natsop.New(natsop.Config{
		AccountSeed:   string(accSeed),
		TrustRootSeed: string(opSeed),
		URL:           cfg.natsURL,
		Publisher:     natsop.NewDirPublisher(jwtsDir),
	})
	if err != nil {
		return fmt.Errorf("account operator: %w", err)
	}
	if err := aop.PublishClaims(); err != nil {
		return fmt.Errorf("publish account claims: %w", err)
	}
	// DirPublisher writes the account JWT 0600-owned by this (root) provisioner;
	// the node runs as a different uid and must READ it at boot (hydrate) before
	// it republishes its own copy. Widen to world-readable. Dev-only.
	if err := os.Chmod(filepath.Join(jwtsDir, accPub+".jwt"), 0o644); err != nil {
		return fmt.Errorf("chmod account jwt: %w", err)
	}

	if err := writeBrokerConfig(natsDir, jwtsDir, accPub); err != nil {
		return err
	}

	if err := writeServiceOverlay(cfg); err != nil {
		return err
	}
	return nil
}

// writeServiceOverlay mints the node's own service token and writes a HOCON
// overlay (<out>/overlay.conf, loaded by the node via CONFIG_OVERLAY) that sets
// pipeline.vc-store-bearer to it. The node uses this token to call its OWN
// L1-gated endpoints — publishing issued VCs to the store, batch-resolving
// references, fetching adjacent evidence — which the real policy-verifier
// authorizes just like any external caller. It is an HS256 JWT signed with the
// same shared secret the provider/verifier use; carrying no scope claim, the
// verifier's scope collector abstains and the declared surface admits it. Dev
// simplification (a production node would hold a properly issued service
// credential, not a shared-secret token). Skipped when no secret is configured.
func writeServiceOverlay(cfg config) error {
	if cfg.jwtSecret == "" {
		return nil
	}
	now := time.Now()
	token, err := mintHS256(cfg.jwtSecret, map[string]any{
		"sub": cfg.serviceSubject,
		"iss": cfg.jwtIssuer,
		"iat": now.Unix(),
		"exp": now.Add(cfg.serviceTTL).Unix(),
	})
	if err != nil {
		return fmt.Errorf("mint service token: %w", err)
	}
	overlay := fmt.Sprintf("provin.network.pipeline.vc-store-bearer = %q\n", token)
	if err := os.WriteFile(filepath.Join(cfg.outDir, "overlay.conf"), []byte(overlay), 0o644); err != nil {
		return fmt.Errorf("write service overlay: %w", err)
	}
	return nil
}

// mintHS256 signs a compact JWS (HS256) over the given claims. Minimal by
// design — the quickstart's only non-provider token minting.
func mintHS256(secret string, claims map[string]any) (string, error) {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	headerJSON, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(headerJSON) + "." + b64(claimsJSON)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64(mac.Sum(nil)), nil
}

// writeBrokerConfig renders nats-server.conf: operator-mode with a memory
// resolver that preloads the account's claims JWT (static claims; a single-node
// quickstart needs no cross-account grants). The operator-JWT path it references
// is <natsDir>/operator.jwt — the same path this tool wrote it to, which is
// valid inside the broker container because the compose file mounts the output
// directory at the identical path there.
func writeBrokerConfig(natsDir, jwtsDir, accPub string) error {
	accJWT, err := os.ReadFile(filepath.Join(jwtsDir, accPub+".jwt"))
	if err != nil {
		return fmt.Errorf("read account jwt: %w", err)
	}
	var b strings.Builder
	b.WriteString("port: 4222\nhttp: 8222\n")
	fmt.Fprintf(&b, "operator: %s\n", filepath.Join(natsDir, "operator.jwt"))
	b.WriteString("resolver: MEMORY\nresolver_preload: {\n")
	fmt.Fprintf(&b, "  %s: %q\n", accPub, strings.TrimSpace(string(accJWT)))
	b.WriteString("}\n")
	if err := os.WriteFile(filepath.Join(natsDir, "nats-server.conf"), []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write nats-server.conf: %w", err)
	}
	return nil
}
