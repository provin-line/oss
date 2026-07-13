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
// quickstart's broker and standalone node consume — an operator trust root, the
// node's account, a system account with a narrowed claims-push user, the
// account-claims JWTs in a resolver directory, and a broker config running the
// directory resolver over that same directory. One directory is the single
// source of truth: the node's DirPublisher writes it, the broker's first
// lookups read it, and the live claims push saves into it — so grants survive
// broker restarts with no baked snapshot to go stale. It mirrors a production
// deployment's out-of-band NATS provisioning (the same shape the provin.e2e
// compose harness generates per run), so the quickstart commits no
// cryptographic seeds: every artifact is generated fresh into a git-ignored
// directory before `docker compose up`.
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
	flag.DurationVar(&cfg.serviceTTL, "service-ttl", 720*time.Hour, "lifetime of the node's service token (default 30d — dev; bound the blast radius of a no-scope shared-secret token)")
	flag.Parse()

	if err := provision(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "provision: %v\n", err)
		os.Exit(1)
	}
}

// provision generates the operator + account material and writes the broker
// config. Layout (paths the compose file mounts):
//
//	<out>/operator.seed              operator (trust-root) nkey seed
//	<out>/<account>-account.seed     account nkey seed
//	<out>/sys-account.seed           system-account nkey seed
//	<out>/sys-user.jwt               narrowed claims-push user JWT (node cred)
//	<out>/sys-user.seed              its USER nkey seed
//	<out>/nats/operator.jwt          self-signed operator JWT (broker trust anchor)
//	<out>/nats/nats-server.conf      operator-mode config, directory resolver
//	<out>/jwts/<accountPub>.jwt      account-claims JWT (resolver dir)
//	<out>/jwts/<sysPub>.jwt          system-account claims JWT (resolver dir)
func provision(cfg config) error {
	jwtsDir := filepath.Join(cfg.outDir, "jwts")
	natsDir := filepath.Join(cfg.outDir, "nats")

	// Idempotency: `docker compose up` re-runs this one-shot container on every
	// up. Complete existing material is REUSED (regenerating seeds under a live
	// stack desynchronizes any container still holding the old trust root);
	// partial material (an interrupted run) fails closed — the artifacts
	// cross-reference each other, so mixing generations yields a broker that
	// silently rejects the node. Only the service overlay is re-minted on reuse:
	// it derives from the shared secret, not the seeds, and carries an expiry.
	accPub, reuse, err := hasCompleteMaterial(cfg, jwtsDir, natsDir)
	if err != nil {
		return err
	}
	if reuse {
		// Re-apply the shared-volume permissions: the node's DirPublisher
		// republishes the account JWT as 0600 owned by the node's uid (see
		// dirpublisher.go), and this provisioner (root) is the only party that
		// can widen it back for every other reader on the next cycle. The
		// broker's directory resolver ALSO rewrites JWTs on claims-update
		// saves, so the same widening applies each cycle.
		if err := os.Chmod(jwtsDir, 0o777); err != nil {
			return fmt.Errorf("chmod jwts dir: %w", err)
		}
		if err := os.Chmod(filepath.Join(jwtsDir, accPub+".jwt"), 0o644); err != nil {
			return fmt.Errorf("chmod account jwt: %w", err)
		}
		chownAllTo(jwtsDir, nodeUID)
		fmt.Println("reusing existing NATS trust material (delete the volume — docker compose down -v — to regenerate)")
		return writeServiceOverlay(cfg)
	}

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
	accPub, err = acc.PublicKey()
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

	// System account + the node's narrowed claims-push user: what lets a grant
	// issued to the LIVE stack take effect without a broker restart.
	sysPub, err := provisionSystemAccount(cfg, op, jwtsDir, accPub)
	if err != nil {
		return err
	}

	// The broker's directory resolver both READS these JWTs on lookup and
	// WRITES them on a live claims-update save (os.WriteFile in place, no
	// rename) — while the node's DirPublisher re-publishes them 0600
	// node-owned. Cross-uid access would EACCES either party, so the compose
	// file runs the broker under the node's uid and this provisioner (root in
	// the container) hands the resolver dir's contents to that uid.
	// Best-effort: chown needs root, so running the tool outside the container
	// (tests, a manual invocation) skips it.
	chownAllTo(jwtsDir, nodeUID)

	if err := writeBrokerConfig(natsDir, jwtsDir, sysPub); err != nil {
		return err
	}

	if err := writeServiceOverlay(cfg); err != nil {
		return err
	}
	fmt.Printf("provisioned NATS trust material for account %q under %s\n", cfg.account, cfg.outDir)
	return nil
}

// nodeUID is the uid the standalone image runs as (cmd/standalone/Dockerfile)
// and, via the compose file's `user:`, the broker too — shared ownership of
// the resolver dir is what lets both re-write account JWTs in place.
const nodeUID = 10001

// chownAllTo hands dir and every entry in it to uid (same gid). Best-effort:
// outside the root provisioning container (e.g. under `go test`) chown is not
// permitted and the dev machine's single-uid situation needs none.
func chownAllTo(dir string, uid int) {
	_ = os.Chown(dir, uid, uid)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		_ = os.Chown(filepath.Join(dir, e.Name()), uid, uid)
	}
}

// hasCompleteMaterial reports whether cfg.outDir already holds a complete,
// internally consistent set of trust artifacts from an earlier run, returning
// the existing account public key when it does. Complete = all core files
// exist AND the resolver dir holds the claims JWTs for the account and system
// account AND the broker config runs the directory resolver with that system
// account (the cross-references broker and node both depend on). Zero core
// files = a fresh volume (generate). Anything in between = an interrupted run
// OR material from a pre-directory-resolver quickstart; fail closed with
// reset guidance rather than mixing artifact generations.
func hasCompleteMaterial(cfg config, jwtsDir, natsDir string) (string, bool, error) {
	core := []string{
		filepath.Join(cfg.outDir, "operator.seed"),
		filepath.Join(cfg.outDir, cfg.account+"-account.seed"),
		filepath.Join(cfg.outDir, "sys-account.seed"),
		filepath.Join(cfg.outDir, "sys-user.jwt"),
		filepath.Join(cfg.outDir, "sys-user.seed"),
		filepath.Join(natsDir, "operator.jwt"),
		filepath.Join(natsDir, "nats-server.conf"),
	}
	present := 0
	for _, p := range core {
		if _, err := os.Stat(p); err == nil {
			present++
		} else if !os.IsNotExist(err) {
			return "", false, fmt.Errorf("stat %s: %w", p, err)
		}
	}
	if present == 0 {
		return "", false, nil
	}
	partial := func(detail string) error {
		return fmt.Errorf("partial NATS trust material under %s (%s); reset the quickstart volume with `docker compose down -v` and re-run", cfg.outDir, detail)
	}
	if present < len(core) {
		return "", false, partial(fmt.Sprintf("%d/%d core artifacts", present, len(core)))
	}
	accSeed, err := os.ReadFile(filepath.Join(cfg.outDir, cfg.account+"-account.seed"))
	if err != nil {
		return "", false, fmt.Errorf("read existing account seed: %w", err)
	}
	accKP, err := nkeys.FromSeed(accSeed)
	if err != nil {
		return "", false, partial("account seed is not a valid nkey seed")
	}
	accPub, err := accKP.PublicKey()
	if err != nil {
		return "", false, fmt.Errorf("existing account public key: %w", err)
	}
	if _, err := os.Stat(filepath.Join(jwtsDir, accPub+".jwt")); err != nil {
		if os.IsNotExist(err) {
			return "", false, partial("resolver dir is missing the account claims JWT")
		}
		return "", false, fmt.Errorf("stat account claims jwt: %w", err)
	}
	sysSeed, err := os.ReadFile(filepath.Join(cfg.outDir, "sys-account.seed"))
	if err != nil {
		return "", false, fmt.Errorf("read existing sys account seed: %w", err)
	}
	sysKP, err := nkeys.FromSeed(sysSeed)
	if err != nil {
		return "", false, partial("sys account seed is not a valid nkey seed")
	}
	sysPub, err := sysKP.PublicKey()
	if err != nil {
		return "", false, fmt.Errorf("existing sys account public key: %w", err)
	}
	if _, err := os.Stat(filepath.Join(jwtsDir, sysPub+".jwt")); err != nil {
		if os.IsNotExist(err) {
			return "", false, partial("resolver dir is missing the system-account claims JWT")
		}
		return "", false, fmt.Errorf("stat sys account claims jwt: %w", err)
	}
	// The sys-user credentials must pair with each other and with THIS
	// account generation: a mixed or tampered volume would otherwise reuse-
	// boot a node whose every grant burns the push budget on a permission
	// violation the error does not name.
	userJWT, err := os.ReadFile(filepath.Join(cfg.outDir, "sys-user.jwt"))
	if err != nil {
		return "", false, fmt.Errorf("read existing sys-user jwt: %w", err)
	}
	userClaims, err := jwt.DecodeUserClaims(strings.TrimSpace(string(userJWT)))
	if err != nil {
		return "", false, partial("sys-user.jwt does not decode as user claims")
	}
	userSeed, err := os.ReadFile(filepath.Join(cfg.outDir, "sys-user.seed"))
	if err != nil {
		return "", false, fmt.Errorf("read existing sys-user seed: %w", err)
	}
	userKP, err := nkeys.FromSeed(userSeed)
	if err != nil {
		return "", false, partial("sys-user seed is not a valid nkey seed")
	}
	userPub, err := userKP.PublicKey()
	if err != nil {
		return "", false, fmt.Errorf("existing sys-user public key: %w", err)
	}
	if userClaims.Subject != userPub {
		return "", false, partial("sys-user.jwt subject does not match sys-user.seed (mixed generations)")
	}
	if userClaims.Issuer != sysPub {
		return "", false, partial("sys-user.jwt is not issued by the existing system account")
	}
	if want := "$SYS.REQ.ACCOUNT." + accPub + ".CLAIMS.UPDATE"; !userClaims.Permissions.Pub.Allow.Contains(want) {
		return "", false, partial("sys-user.jwt is not scoped to the existing account's claims-update subject")
	}
	// The broker config must run the directory resolver over THIS resolver dir
	// with THIS system account: a truncated, foreign, or pre-migration
	// (memory-resolver) nats-server.conf would otherwise reuse-boot a broker
	// that goes stale on the first live grant — the one silent failure in the
	// set (everything else fails loudly).
	conf, err := os.ReadFile(filepath.Join(natsDir, "nats-server.conf"))
	if err != nil {
		return "", false, fmt.Errorf("read existing nats-server.conf: %w", err)
	}
	if !strings.Contains(string(conf), "system_account: "+sysPub) {
		return "", false, partial("nats-server.conf does not configure the existing system account")
	}
	if !strings.Contains(string(conf), "type: full") {
		return "", false, partial("nats-server.conf does not run the directory resolver (pre-migration material)")
	}
	if !strings.Contains(string(conf), "dir: '"+jwtsDir+"'") {
		return "", false, partial("nats-server.conf resolver dir does not point at the resolver directory")
	}
	return accPub, true, nil
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

// provisionSystemAccount creates the system account (operator-signed, claims
// JWT into the resolver dir) and the node's claims-push user. The user is
// NARROWED to publishing exactly the node account's claims-update subject and
// subscribing to request-reply inboxes: a leaked quickstart credential is a
// "re-push this one account's claims" capability, not a broker admin key.
// (Nuance: the broker's dir handler saves any structurally valid JWT whose
// subject matches, without checking its issuer against the trusted operator —
// so a leaked cred can clobber the resolver file with a foreign-signed JWT,
// making the account unresolvable: a DoS, not a privilege escalation.)
// Files are world-readable like the rest of the dev material (the node runs
// as a non-root uid).
func provisionSystemAccount(cfg config, op nkeys.KeyPair, jwtsDir, accPub string) (string, error) {
	sys, err := nkeys.CreateAccount()
	if err != nil {
		return "", fmt.Errorf("create system account: %w", err)
	}
	sysSeed, err := sys.Seed()
	if err != nil {
		return "", fmt.Errorf("system account seed: %w", err)
	}
	sysPub, err := sys.PublicKey()
	if err != nil {
		return "", fmt.Errorf("system account public key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(cfg.outDir, "sys-account.seed"), sysSeed, 0o644); err != nil {
		return "", fmt.Errorf("write system account seed: %w", err)
	}
	sysClaims := jwt.NewAccountClaims(sysPub)
	sysClaims.Name = "SYS"
	sysJWT, err := sysClaims.Encode(op)
	if err != nil {
		return "", fmt.Errorf("encode system account jwt: %w", err)
	}
	if err := os.WriteFile(filepath.Join(jwtsDir, sysPub+".jwt"), []byte(sysJWT), 0o644); err != nil {
		return "", fmt.Errorf("write system account jwt: %w", err)
	}

	user, err := nkeys.CreateUser()
	if err != nil {
		return "", fmt.Errorf("create sys user: %w", err)
	}
	userSeed, err := user.Seed()
	if err != nil {
		return "", fmt.Errorf("sys user seed: %w", err)
	}
	userPub, err := user.PublicKey()
	if err != nil {
		return "", fmt.Errorf("sys user public key: %w", err)
	}
	userClaims := jwt.NewUserClaims(userPub)
	userClaims.Name = "claims-push"
	userClaims.Permissions.Pub.Allow.Add("$SYS.REQ.ACCOUNT." + accPub + ".CLAIMS.UPDATE")
	userClaims.Permissions.Sub.Allow.Add("_INBOX.>")
	userJWT, err := userClaims.Encode(sys)
	if err != nil {
		return "", fmt.Errorf("encode sys user jwt: %w", err)
	}
	if err := os.WriteFile(filepath.Join(cfg.outDir, "sys-user.jwt"), []byte(userJWT), 0o644); err != nil {
		return "", fmt.Errorf("write sys user jwt: %w", err)
	}
	if err := os.WriteFile(filepath.Join(cfg.outDir, "sys-user.seed"), userSeed, 0o644); err != nil {
		return "", fmt.Errorf("write sys user seed: %w", err)
	}
	return sysPub, nil
}

// writeBrokerConfig renders nats-server.conf: operator-mode with the DIRECTORY
// account resolver over the same jwts dir the node's DirPublisher writes and
// the claims push saves into — one source of truth, so a broker restart serves
// current claims (a memory-resolver preload would be a snapshot that goes
// stale the moment a grant lands). The operator-JWT path it references is
// <natsDir>/operator.jwt — the same path this tool wrote it to, which is valid
// inside the broker container because the compose file mounts the output
// directory at the identical path there.
func writeBrokerConfig(natsDir, jwtsDir, sysPub string) error {
	var b strings.Builder
	b.WriteString("port: 4222\nhttp: 8222\n")
	fmt.Fprintf(&b, "operator: %s\n", filepath.Join(natsDir, "operator.jwt"))
	fmt.Fprintf(&b, "system_account: %s\n", sysPub)
	fmt.Fprintf(&b, "resolver {\n  type: full\n  dir: '%s'\n  allow_delete: false\n  interval: \"2m\"\n}\n", jwtsDir)
	if err := os.WriteFile(filepath.Join(natsDir, "nats-server.conf"), []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write nats-server.conf: %w", err)
	}
	return nil
}
