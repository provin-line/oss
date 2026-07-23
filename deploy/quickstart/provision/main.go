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
// quickstart's broker and its two nodes (`network`, the control plane;
// `pipeline`, the data plane — the separated topology, PR3c) consume — an
// operator trust root, the deployment's account, a system account with a
// narrowed claims-push user, the account-claims JWTs in a resolver
// directory, and a broker config running the directory resolver over that
// same directory. One directory is the single source of truth: each node's
// DirPublisher writes it, the broker's first lookups read it, and the live
// claims push saves into it — so grants survive broker restarts with no
// baked snapshot to go stale. It mirrors a production deployment's
// out-of-band NATS provisioning (the same shape the provin.e2e compose
// harness generates per run), so the quickstart commits no cryptographic
// seeds: every artifact is generated fresh into a git-ignored directory
// before `docker compose up`.
//
// It ALSO provisions the separated topology's local pipeline identity keys
// (provisionPipelineIdentity, below) — the external-key story `pipeline`'s
// own boot preflights need, since the registry (`network`) can no longer
// mint a key and have it land where the data plane can read it (two
// processes, two data volumes, unlike the retired all-in-one
// cmd/standalone).
//
// This is NATS decentralized-auth material only (nkey seeds, account JWTs)
// plus the pipeline identity keys just described. The separate HS256 shared
// secret used by the auth.provider / policy-verifier / bootstrap-token path
// is an environment variable, not produced here.
package main

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
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

	// pipelineDataDir/pipelineDID/processDID parameterize
	// provisionPipelineIdentity (below): the separated topology's local-key
	// provisioning for cmd/pipeline, distinct from the NATS/service-token
	// material above.
	pipelineDataDir string
	pipelineDID     string
	processDID      string
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
	flag.StringVar(&cfg.pipelineDataDir, "pipeline-data", "/pipeline-data", "cmd/pipeline's own data directory (the pipeline-data compose volume) — its keys/ subdirectory is where this tool mints the pipeline's local #auth/#signing keypairs")
	flag.StringVar(&cfg.pipelineDID, "pipeline-did", "did:dplaax:poc.dplaax.dev:org:acme:pipeline:readings", "the readings pipeline's own DID (the src loop's output subject) — gets a local #auth/#signing keypair")
	flag.StringVar(&cfg.processDID, "process-did", "did:dplaax:poc.dplaax.dev:org:acme:pipeline:readings:process:s1", "the src loop's process DID (also this deployment's chain.nats node-did) — gets a local #auth/#signing keypair")
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
		return provisionExtras(cfg)
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

	if err := provisionExtras(cfg); err != nil {
		return err
	}
	fmt.Printf("provisioned NATS trust material for account %q under %s\n", cfg.account, cfg.outDir)
	return nil
}

// provisionExtras runs the two provisioning steps that are ORTHOGONAL to
// the NATS trust material's own reuse-vs-fresh split above (both are
// independently idempotent, so both run on every invocation regardless of
// which NATS branch ran): the node's HS256 service-token overlay, and the
// separated topology's local pipeline/process identity keys.
func provisionExtras(cfg config) error {
	if err := writeServiceOverlay(cfg); err != nil {
		return err
	}
	return provisionPipelineIdentity(cfg)
}

// nodeUID is the uid the network and pipeline images run as (their
// Dockerfiles: `adduser -D -u 10001`, the same uid the retired
// cmd/standalone/Dockerfile used) and, via the compose file's `user:`, the
// broker too — shared ownership of the resolver dir (and, since the
// separated-topology provisioning below, the pipeline's own keys dir) is
// what lets each re-write/read its own material in place.
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

// chownRecursive hands every directory and file under (and including) root
// to uid (same gid) — the recursive counterpart to chownAllTo, above (that
// one is deliberately shallow, matching the FLAT jwts dir it targets;
// filestore's per-DID keystore, below, nests one directory per DID path
// segment, so the shallow form would miss everything past the top level).
// Best-effort, same rationale as chownAllTo: outside the root provisioning
// container this is a silent no-op.
func chownRecursive(root string, uid int) error {
	return filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return nil // best-effort; keep walking what IS reachable
		}
		_ = os.Chown(path, uid, uid)
		return nil
	})
}

// externalKeysExport is one subject DID's exported public halves — the JSON
// value shape written to <outDir>/pipeline-external-keys.json (keyed by
// subject DID) and read back by `provin pipeline create --external-key` /
// `provin process create --external-key` (cmd/provin/internal/commands/
// issue.go's externalKeysFileEntry — the two shapes are independent copies
// by design: this tool and that CLI package have no reason to share a Go
// dependency over a two-field JSON object exchanged only through a file on
// disk).
type externalKeysExport struct {
	AuthPublicKey    string `json:"auth_public_key"`
	SigningPublicKey string `json:"signing_public_key"`
}

// provisionPipelineIdentity mints the LOCAL #auth/#signing Ed25519 keypairs
// the separated-topology cmd/pipeline binary needs to already hold before it
// ever boots: main.go's boot preflights (preflightPayloadRetainKeys,
// preflightWireOnlySignerKeys — wiring.go) fail closed at STARTUP when a
// needed key is absent, unlike the retired cmd/standalone's in-process "loop
// idles until issued" model, where the registry's own mint landed directly in
// the same process/data-dir the data plane read from. In the separated
// topology that locality is gone — the registry (cmd/network) and the data
// plane (cmd/pipeline) are different processes with different data dirs — so
// the keys this deployment's loop needs must be minted directly into
// cmd/pipeline's OWN volume, ahead of its first boot, by this tool.
//
// Two subject DIDs need keys: cfg.pipelineDID (the src loop's OutputSubject —
// the identity emit-health reports and by-reference payload retain sign as)
// and cfg.processDID (the src loop's issuer identity AND this deployment's
// chain.nats node-did — the identity RegisterAuditHead and every durable
// custody log's checkpoint signer sign as). Both subjects get BOTH keys
// unconditionally, mirroring provin.e2e's own
// harness.ProvisionExternalIdentity (its doc: "cheaper and less error-prone
// than [...] tracking, per subject, which of the two roles [...] actually
// uses which key").
//
// Private halves are written to cfg.pipelineDataDir/keys via filestore — the
// SAME layout cmd/pipeline's own filestore.New(filepath.Join(coreCfg.DataDir,
// "keys")) reads at boot — and never leave that directory. Public halves are
// exported to <cfg.outDir>/pipeline-external-keys.json (world-readable, like
// every other artifact this tool writes into the shared `provisioned`
// volume): the operator's later `provin pipeline create --external-key
// .../pipeline-external-keys.json` (and the same flag on `process create`)
// submits ONLY these public halves to the registry over
// IssuePipelineRequest/IssueProcessRequest's external_public_keys — the
// registry never generates or holds a private key for either DID, matching
// the tlog-custody trust model (the registry has no loop key).
//
// Idempotent like the NATS material in provision, above: ensureSubjectKeys
// (below) reuses an already-provisioned subject's keys rather than minting
// fresh ones out from under a running pipeline on a `docker compose up`
// re-run.
func provisionPipelineIdentity(cfg config) error {
	keysDir := filepath.Join(cfg.pipelineDataDir, "keys")
	ks := filestore.New(keysDir)

	// The export lives in cfg.outDir (the `provisioned` volume); the private
	// keys live in cfg.pipelineDataDir (the separate `pipeline-data` volume).
	// A `docker compose down -v` that drops only ONE of the two — or any
	// other hand-edit — can leave a still self-consistent private keyset that
	// no longer matches the public halves already handed to the registry via
	// `provin pipeline/process create --external-key`. ensureSubjectKeys
	// cross-checks each subject's freshly-derived export against this prior
	// record (below) and fails closed on a mismatch, rather than silently
	// re-publishing a export that has quietly drifted from what a running
	// pipeline actually signs with.
	priorExported, err := readPriorExport(filepath.Join(cfg.outDir, "pipeline-external-keys.json"))
	if err != nil {
		return fmt.Errorf("provision pipeline identity: %w", err)
	}

	subjects := []string{cfg.pipelineDID, cfg.processDID}
	exported := make(map[string]externalKeysExport, len(subjects))
	for _, subject := range subjects {
		prior, hasPrior := priorExported[subject]
		pub, err := ensureSubjectKeys(ks, subject, prior, hasPrior)
		if err != nil {
			return fmt.Errorf("provision pipeline identity %s: %w", subject, err)
		}
		exported[subject] = pub
	}

	// cmd/pipeline runs as nodeUID; filestore writes 0600 files in 0700 dirs
	// owned by THIS (root) provisioner — without this, the pipeline container
	// could never read its own keys back. Best-effort outside the root
	// container (tests, a manual invocation), same as chownAllTo above.
	if err := chownRecursive(cfg.pipelineDataDir, nodeUID); err != nil {
		return fmt.Errorf("provision pipeline identity: chown %s: %w", cfg.pipelineDataDir, err)
	}

	out, err := json.MarshalIndent(exported, "", "  ")
	if err != nil {
		return fmt.Errorf("provision pipeline identity: marshal export: %w", err)
	}
	if err := os.WriteFile(filepath.Join(cfg.outDir, "pipeline-external-keys.json"), out, 0o644); err != nil {
		return fmt.Errorf("provision pipeline identity: write export: %w", err)
	}
	return nil
}

// ensureSubjectKeys returns subject's exported public halves, minting a
// fresh #auth/#signing keypair pair into ks on first provisioning and
// reusing (deriving the public halves back from the stored private keys,
// validated below) on every later re-run — filestore.SaveKeyPair is
// create-only (it errors on an existing keyset), so a re-run must detect
// completeness itself rather than call it unconditionally. A HALF-present
// keyset (one of the two keys written, the other missing — impossible via
// this function's own atomic SaveKeyPair call, but possible if the volume
// were hand-edited or a process was killed mid-chown) fails closed rather
// than silently minting a mismatched second key.
//
// prior/hasPrior is that same subject's entry from an earlier run's
// pipeline-external-keys.json, when one exists (see provisionPipelineIdentity):
// on the reuse path, the freshly re-derived export must match it exactly, or
// the two volumes backing this deployment (`pipeline-data` for the private
// keys, `provisioned` for the export) have drifted out of sync.
func ensureSubjectKeys(ks *filestore.Store, subject string, prior externalKeysExport, hasPrior bool) (externalKeysExport, error) {
	authPriv, authErr := ks.GetPrivateKey(subject, keystore.KeyIDAuth)
	signPriv, signErr := ks.GetPrivateKey(subject, keystore.KeyIDSigning)
	switch {
	case authErr == nil && signErr == nil:
		authPub, err := validatedPublicKey(authPriv)
		if err != nil {
			return externalKeysExport{}, resetPipelineIdentity(fmt.Sprintf("%s#%s key material is invalid: %v", subject, keystore.KeyIDAuth, err))
		}
		signPub, err := validatedPublicKey(signPriv)
		if err != nil {
			return externalKeysExport{}, resetPipelineIdentity(fmt.Sprintf("%s#%s key material is invalid: %v", subject, keystore.KeyIDSigning, err))
		}
		out := externalKeysExport{
			AuthPublicKey:    base64.StdEncoding.EncodeToString(authPub),
			SigningPublicKey: base64.StdEncoding.EncodeToString(signPub),
		}
		if hasPrior && (prior.AuthPublicKey != out.AuthPublicKey || prior.SigningPublicKey != out.SigningPublicKey) {
			return externalKeysExport{}, resetPipelineIdentity(fmt.Sprintf("%s's previously exported public keys no longer match its locally-held private keys (mixed generations)", subject))
		}
		return out, nil
	case errors.Is(authErr, keystore.ErrNotFound) && errors.Is(signErr, keystore.ErrNotFound):
		authKP, err := (ed25519.Generator{}).Generate()
		if err != nil {
			return externalKeysExport{}, fmt.Errorf("auth keygen: %w", err)
		}
		signKP, err := (ed25519.Generator{}).Generate()
		if err != nil {
			return externalKeysExport{}, fmt.Errorf("signing keygen: %w", err)
		}
		if err := ks.SaveKeyPair(subject, map[keystore.KeyID]*crypto.KeyPair{
			keystore.KeyIDAuth:    authKP,
			keystore.KeyIDSigning: signKP,
		}); err != nil {
			return externalKeysExport{}, fmt.Errorf("save keyset: %w", err)
		}
		return externalKeysExport{
			AuthPublicKey:    base64.StdEncoding.EncodeToString(authKP.PublicKey),
			SigningPublicKey: base64.StdEncoding.EncodeToString(signKP.PublicKey),
		}, nil
	default:
		return externalKeysExport{}, resetPipelineIdentity(fmt.Sprintf("partial keyset (auth: %v, signing: %v)", authErr, signErr))
	}
}

// validatedPublicKey validates priv as a well-formed 64-byte Ed25519 private
// key (seed ‖ embedded public half, the stded25519.PrivateKey layout) and
// returns the embedded public half — after confirming it actually DERIVES
// from the embedded seed. A wrong-size file is rejected before any indexing
// into it (stded25519.PrivateKey.Public() slices priv[32:] unconditionally
// and panics on a too-short key); a right-size-but-corrupted file (e.g. a
// hand-edited or truncated-then-padded public suffix) slices cleanly but
// would not derive from its own seed, so re-deriving and comparing catches
// what a bare length check cannot.
func validatedPublicKey(priv []byte) (stded25519.PublicKey, error) {
	if len(priv) != stded25519.PrivateKeySize {
		return nil, fmt.Errorf("private key is %d bytes, want %d", len(priv), stded25519.PrivateKeySize)
	}
	stored := stded25519.PrivateKey(priv)
	embedded := append(stded25519.PublicKey(nil), stored.Public().(stded25519.PublicKey)...)
	derived := stded25519.NewKeyFromSeed(stored.Seed()).Public().(stded25519.PublicKey)
	if !bytes.Equal(embedded, derived) {
		return nil, errors.New("embedded public half does not derive from the private key's own seed (corrupted key material)")
	}
	return embedded, nil
}

// resetPipelineIdentity formats the reset guidance shared by every
// ensureSubjectKeys failure mode (partial keyset, malformed key material, a
// mismatched export) — the fix is always the same: the local pipeline-data
// keys and the exported public halves (two independent volumes) have
// diverged and must be regenerated together.
func resetPipelineIdentity(detail string) error {
	return fmt.Errorf("%s — reset the quickstart volume (docker compose down -v) and re-run", detail)
}

// readPriorExport best-effort reads an earlier run's pipeline-external-keys.json.
// A fresh volume (no file yet) returns a nil map, not an error — there is
// nothing to cross-check the first time a subject is provisioned. A PRESENT
// but undecodable file, however, fails closed like every other malformed
// artifact in this tool: a corrupt export is exactly the kind of drift
// ensureSubjectKeys' cross-check exists to catch, so silently ignoring it
// here would defeat that check for every subject in the same run.
func readPriorExport(path string) (map[string]externalKeysExport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read existing export %s: %w", path, err)
	}
	var prior map[string]externalKeysExport
	// This is a local dev-provisioning artifact this same tool wrote
	// (cfg.outDir/pipeline-external-keys.json), read back only to cross-check
	// against freshly-derived key material below — never a wire/protocol
	// payload or a signing scope, so canon.StrictDecoder's duplicate-key/
	// precision guarantees have no bearing here. decoder-hygiene-exempt
	if err := json.Unmarshal(raw, &prior); err != nil {
		return nil, resetPipelineIdentity(fmt.Sprintf("existing export %s does not decode as JSON: %v", path, err))
	}
	return prior, nil
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
