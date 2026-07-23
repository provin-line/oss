/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package main

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
)

// testConfig returns a config with every field provision() requires filled
// in with fixed dev values: outDir under dir (the NATS material), a sibling
// pipeline-data directory, and the quickstart's own fixed pipeline/process
// DIDs. provisionPipelineIdentity (main.go) requires a non-empty
// pipelineDataDir/pipelineDID/processDID — a bare config{outDir: ...} literal
// (this file's shape before that function existed) leaves those zero, which
// fails closed as an "empty did". Every provision() call in this file goes
// through this constructor (or one built from it) rather than a bare
// literal, so the tests exercise the same complete shape main() itself
// assembles from flag defaults.
func testConfig(dir string) config {
	return config{
		outDir: dir, account: "acme", natsURL: "nats://nats:4222",
		pipelineDataDir: filepath.Join(dir, "pipeline-data"),
		pipelineDID:     "did:dplaax:poc.dplaax.dev:org:acme:pipeline:readings",
		processDID:      "did:dplaax:poc.dplaax.dev:org:acme:pipeline:readings:process:s1",
	}
}

// provision must lay down exactly the operator-mode NATS artifacts the
// quickstart's broker and node consume, mirroring a production deployment's
// out-of-band provisioning: an operator trust root, one account, the account's
// claims JWT in a resolver dir, and a broker config that preloads it. This test
// pins that contract — the crypto itself is provin.oss's (natsop) and nats-io's;
// what we verify here is that this glue writes coherent, cross-consistent files.
func TestProvision(t *testing.T) {
	dir := t.TempDir()
	if err := provision(testConfig(dir)); err != nil {
		t.Fatalf("provision: %v", err)
	}

	// Every artifact the compose mounts must exist.
	for _, rel := range []string{
		"operator.seed",
		"acme-account.seed",
		"sys-account.seed",
		"sys-user.jwt",
		"sys-user.seed",
		filepath.Join("nats", "operator.jwt"),
		filepath.Join("nats", "nats-server.conf"),
	} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Errorf("missing artifact %s: %v", rel, err)
		}
	}

	// operator.jwt must be a self-signed operator JWT whose subject is the
	// operator public key derived from operator.seed (the broker's trust anchor).
	opSeed := mustRead(t, filepath.Join(dir, "operator.seed"))
	opKP, err := nkeys.FromSeed(opSeed)
	if err != nil {
		t.Fatalf("operator seed not an nkey seed: %v", err)
	}
	opPub, _ := opKP.PublicKey()
	opClaims, err := jwt.DecodeOperatorClaims(strings.TrimSpace(string(mustRead(t, filepath.Join(dir, "nats", "operator.jwt")))))
	if err != nil {
		t.Fatalf("operator.jwt does not decode as operator claims: %v", err)
	}
	if opClaims.Subject != opPub {
		t.Errorf("operator.jwt subject = %q, want operator pubkey %q", opClaims.Subject, opPub)
	}

	// The account seed's public key must be the one whose claims JWT sits in the
	// resolver dir AND the one the broker config preloads — a mismatch means the
	// broker would not resolve the node's account and every publish fails.
	accSeed := mustRead(t, filepath.Join(dir, "acme-account.seed"))
	accKP, err := nkeys.FromSeed(accSeed)
	if err != nil {
		t.Fatalf("account seed not an nkey seed: %v", err)
	}
	accPub, _ := accKP.PublicKey()

	accJWT := mustRead(t, filepath.Join(dir, "jwts", accPub+".jwt"))
	accClaims, err := jwt.DecodeAccountClaims(strings.TrimSpace(string(accJWT)))
	if err != nil {
		t.Fatalf("resolver account jwt does not decode: %v", err)
	}
	if accClaims.Subject != accPub {
		t.Errorf("account jwt subject = %q, want account pubkey %q", accClaims.Subject, accPub)
	}

	conf := string(mustRead(t, filepath.Join(dir, "nats", "nats-server.conf")))
	wantOpRef := "operator: " + filepath.Join(dir, "nats", "operator.jwt")
	if !strings.Contains(conf, wantOpRef) {
		t.Errorf("nats-server.conf does not reference the operator jwt at its written path (%q):\n%s", wantOpRef, conf)
	}
	// The broker resolves accounts from the SAME directory the node's
	// DirPublisher writes and the live claims push saves into — one source of
	// truth across broker restarts (no baked preload snapshot to go stale).
	if !strings.Contains(conf, "type: full") || !strings.Contains(conf, filepath.Join(dir, "jwts")) {
		t.Errorf("nats-server.conf must run the directory resolver over the jwts dir:\n%s", conf)
	}
	if strings.Contains(conf, "resolver_preload") || strings.Contains(conf, "MEMORY") {
		t.Errorf("nats-server.conf still bakes a preload snapshot (stale-claims class):\n%s", conf)
	}

	// System account: configured in the broker, resolvable from the jwts dir,
	// its JWT signed by the operator.
	sysSeed := mustRead(t, filepath.Join(dir, "sys-account.seed"))
	sysKP, err := nkeys.FromSeed(sysSeed)
	if err != nil {
		t.Fatalf("sys account seed not an nkey seed: %v", err)
	}
	sysPub, _ := sysKP.PublicKey()
	if !strings.Contains(conf, "system_account: "+sysPub) {
		t.Errorf("nats-server.conf missing system_account %q:\n%s", sysPub, conf)
	}
	sysJWT := mustRead(t, filepath.Join(dir, "jwts", sysPub+".jwt"))
	sysClaims, err := jwt.DecodeAccountClaims(strings.TrimSpace(string(sysJWT)))
	if err != nil {
		t.Fatalf("sys account jwt does not decode: %v", err)
	}
	if sysClaims.Subject != sysPub || sysClaims.Issuer != opPub {
		t.Errorf("sys account jwt subject/issuer = %q/%q, want %q/%q", sysClaims.Subject, sysClaims.Issuer, sysPub, opPub)
	}

	// Sys user: signed by the sys account, NARROWED to exactly this node's
	// claims-update subject plus the request-reply inbox — a leaked quickstart
	// credential must not be a broker admin credential.
	userClaims, err := jwt.DecodeUserClaims(strings.TrimSpace(string(mustRead(t, filepath.Join(dir, "sys-user.jwt")))))
	if err != nil {
		t.Fatalf("sys-user.jwt does not decode: %v", err)
	}
	if userClaims.Issuer != sysPub {
		t.Errorf("sys user issuer = %q, want sys account %q", userClaims.Issuer, sysPub)
	}
	wantUpdate := "$SYS.REQ.ACCOUNT." + accPub + ".CLAIMS.UPDATE"
	if got := userClaims.Permissions.Pub.Allow; len(got) != 1 || got[0] != wantUpdate {
		t.Errorf("sys user pub allow = %v, want exactly [%s]", got, wantUpdate)
	}
	if got := userClaims.Permissions.Sub.Allow; len(got) != 1 || got[0] != "_INBOX.>" {
		t.Errorf("sys user sub allow = %v, want exactly [_INBOX.>]", got)
	}
	userSeed := mustRead(t, filepath.Join(dir, "sys-user.seed"))
	userKP, err := nkeys.FromSeed(userSeed)
	if err != nil {
		t.Fatalf("sys user seed not an nkey seed: %v", err)
	}
	userPub, _ := userKP.PublicKey()
	if userClaims.Subject != userPub {
		t.Errorf("sys-user.jwt subject = %q, want the sys-user seed's key %q (jwt/seed pairing)", userClaims.Subject, userPub)
	}

	// The node (a non-root uid) must be able to READ the sys-user credentials
	// the root provisioner wrote — same dev posture as the account seed.
	for _, rel := range []string{"sys-user.jwt", "sys-user.seed", "sys-account.seed"} {
		info, err := os.Stat(filepath.Join(dir, rel))
		if err != nil {
			t.Fatalf("stat %s: %v", rel, err)
		}
		if info.Mode().Perm()&0o044 == 0 {
			t.Errorf("%s mode %v is not world-readable — the node uid cannot load it", rel, info.Mode().Perm())
		}
	}
}

// With a shared secret configured, provision must write a service-token overlay
// the node loads via CONFIG_OVERLAY: an HS256 JWT (signed with that secret) bound
// to pipeline.vc-store-bearer, so the node authenticates its own L1-gated calls.
func TestProvision_ServiceOverlay(t *testing.T) {
	dir := t.TempDir()
	const secret = "shared-secret"
	cfg := testConfig(dir)
	cfg.jwtSecret, cfg.jwtIssuer = secret, "http://auth-provider:3000"
	cfg.serviceSubject, cfg.serviceTTL = "did:dplaax:poc.dplaax.dev:org:acme", time.Hour
	if err := provision(cfg); err != nil {
		t.Fatalf("provision: %v", err)
	}

	overlay := string(mustRead(t, filepath.Join(dir, "overlay.conf")))
	const key = "provin.network.pipeline.vc-store-bearer = "
	idx := strings.Index(overlay, key)
	if idx < 0 {
		t.Fatalf("overlay does not set vc-store-bearer:\n%s", overlay)
	}
	token := strings.Trim(strings.TrimSpace(overlay[idx+len(key):]), `"`)

	// The token must be a well-formed HS256 JWS whose signature verifies under
	// the shared secret — i.e. the real policy-verifier (same secret) accepts it.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("service token is not a 3-part JWS: %q", token)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	wantSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if parts[2] != wantSig {
		t.Errorf("service token signature does not verify under the shared secret")
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("claims not JSON: %v", err)
	}
	if claims["sub"] != "did:dplaax:poc.dplaax.dev:org:acme" {
		t.Errorf("service token sub = %v", claims["sub"])
	}
}

// Without a secret, provision must NOT write an overlay (the node then keeps its
// base config — no service token forced on a deployment that didn't ask for one).
func TestProvision_NoSecretNoOverlay(t *testing.T) {
	dir := t.TempDir()
	if err := provision(testConfig(dir)); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "overlay.conf")); err == nil {
		t.Error("overlay.conf written despite no jwt-secret")
	}
}

// Re-running provision over complete existing material must REUSE it, not
// regenerate: `docker compose up` re-runs the one-shot provisioner on every
// up, and regenerating seeds under a live stack desynchronizes any container
// that keeps the old trust root (new seed vs old operator). Idempotency is the
// fix the quickstart promises over `down` → `up` cycles (a full reset stays
// `down -v`).
func TestProvision_Idempotent_ReusesExistingMaterial(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	if err := provision(cfg); err != nil {
		t.Fatalf("first provision: %v", err)
	}

	accSeed := mustRead(t, filepath.Join(dir, "acme-account.seed"))
	accKP, err := nkeys.FromSeed(accSeed)
	if err != nil {
		t.Fatalf("account seed not an nkey seed: %v", err)
	}
	accPub, _ := accKP.PublicKey()

	sysSeed := mustRead(t, filepath.Join(dir, "sys-account.seed"))
	sysKP, err := nkeys.FromSeed(sysSeed)
	if err != nil {
		t.Fatalf("sys account seed not an nkey seed: %v", err)
	}
	sysPub, _ := sysKP.PublicKey()

	artifacts := []string{
		"operator.seed",
		"acme-account.seed",
		"sys-account.seed",
		"sys-user.jwt",
		"sys-user.seed",
		filepath.Join("nats", "operator.jwt"),
		filepath.Join("nats", "nats-server.conf"),
		filepath.Join("jwts", accPub+".jwt"),
		filepath.Join("jwts", sysPub+".jwt"),
	}
	before := map[string][]byte{}
	for _, rel := range artifacts {
		before[rel] = mustRead(t, filepath.Join(dir, rel))
	}

	if err := provision(cfg); err != nil {
		t.Fatalf("second provision: %v", err)
	}
	for _, rel := range artifacts {
		if got := mustRead(t, filepath.Join(dir, rel)); !bytes.Equal(got, before[rel]) {
			t.Errorf("%s changed across an idempotent re-run", rel)
		}
	}
}

// The service overlay is derived from the shared secret (not from the trust
// material) and carries an expiry, so the reuse path must still (re-)mint it:
// a stack first provisioned without a secret, then re-upped with one, gets a
// working vc-store-bearer without a volume reset.
func TestProvision_Idempotent_StillMintsServiceOverlay(t *testing.T) {
	dir := t.TempDir()
	if err := provision(testConfig(dir)); err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "overlay.conf")); err == nil {
		t.Fatal("overlay.conf written despite no jwt-secret")
	}
	cfg := testConfig(dir)
	cfg.jwtSecret, cfg.jwtIssuer = "shared-secret", "http://auth-provider:3000"
	cfg.serviceSubject, cfg.serviceTTL = "did:dplaax:poc.dplaax.dev:org:acme", time.Hour
	if err := provision(cfg); err != nil {
		t.Fatalf("second provision: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "overlay.conf")); err != nil {
		t.Errorf("reuse path did not mint the service overlay: %v", err)
	}
}

// The node's DirPublisher republishes the account claims JWT as 0600 (owned by
// the node's uid) at its first grant; the reuse path must widen the shared
// resolver dir and JWT back so every other reader survives the next up cycle
// (Codex review P1).
func TestProvision_Idempotent_RestoresSharedPermissions(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	if err := provision(cfg); err != nil {
		t.Fatalf("first provision: %v", err)
	}
	accKP, err := nkeys.FromSeed(mustRead(t, filepath.Join(dir, "acme-account.seed")))
	if err != nil {
		t.Fatalf("account seed: %v", err)
	}
	accPub, _ := accKP.PublicKey()
	jwtPath := filepath.Join(dir, "jwts", accPub+".jwt")
	// Simulate the node's republish tightening the file, and a volume driver
	// tightening the dir.
	if err := os.Chmod(jwtPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "jwts"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := provision(cfg); err != nil {
		t.Fatalf("second provision: %v", err)
	}
	if info, _ := os.Stat(jwtPath); info.Mode().Perm() != 0o644 {
		t.Errorf("account jwt mode = %v after reuse, want 0644", info.Mode().Perm())
	}
	if info, _ := os.Stat(filepath.Join(dir, "jwts")); info.Mode().Perm() != 0o777 {
		t.Errorf("jwts dir mode = %v after reuse, want 0777", info.Mode().Perm())
	}
}

// Partial material (an interrupted earlier run) is neither reusable nor safe
// to silently regenerate over — the artifacts cross-reference each other, so
// mixing generations produces a broker that rejects the node with no obvious
// error. Provision must fail closed with reset guidance instead.
func TestProvision_PartialMaterial_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "operator.seed"), []byte("SOOPERATORSEED"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := provision(testConfig(dir))
	if err == nil {
		t.Fatal("provision succeeded over partial trust material")
	}
	if !strings.Contains(err.Error(), "down -v") {
		t.Errorf("error carries no reset guidance: %v", err)
	}
}

// The completeness check must verify the cross-references the stack depends
// on, not just count files: all four core artifacts present but (a) the
// resolver dir missing the claims JWT for the seed's own public key, or
// (b) a nats-server.conf that does not preload that account, are interrupted/
// corrupt states — reuse would boot a broker that rejects the node (a) or a
// broker silently without operator mode (b). Both must fail closed.
func TestProvision_BrokenCrossReference_FailsClosed(t *testing.T) {
	cfg := func(dir string) config {
		return testConfig(dir)
	}
	accPubOf := func(t *testing.T, dir string) string {
		t.Helper()
		accKP, err := nkeys.FromSeed(mustRead(t, filepath.Join(dir, "acme-account.seed")))
		if err != nil {
			t.Fatalf("account seed: %v", err)
		}
		pub, _ := accKP.PublicKey()
		return pub
	}

	t.Run("resolver jwt missing", func(t *testing.T) {
		dir := t.TempDir()
		if err := provision(cfg(dir)); err != nil {
			t.Fatalf("first provision: %v", err)
		}
		if err := os.Remove(filepath.Join(dir, "jwts", accPubOf(t, dir)+".jwt")); err != nil {
			t.Fatal(err)
		}
		err := provision(cfg(dir))
		if err == nil || !strings.Contains(err.Error(), "down -v") {
			t.Fatalf("want fail-closed with reset guidance, got: %v", err)
		}
	})

	t.Run("broker config does not preload the account", func(t *testing.T) {
		dir := t.TempDir()
		if err := provision(cfg(dir)); err != nil {
			t.Fatalf("first provision: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "nats", "nats-server.conf"), []byte("port: 4222\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		err := provision(cfg(dir))
		if err == nil || !strings.Contains(err.Error(), "down -v") {
			t.Fatalf("want fail-closed with reset guidance, got: %v", err)
		}
	})
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// provision must mint LOCAL #auth/#signing keypairs for both the pipeline
// DID and the process DID directly into cfg.pipelineDataDir/keys — the
// separated-topology provisioning cmd/pipeline's own boot preflights need
// (main.go's package doc; wiring.go's preflightPayloadRetainKeys/
// preflightWireOnlySignerKeys) — and export ONLY the public halves to
// <outDir>/pipeline-external-keys.json, world-readable, for
// `provin pipeline/process create --external-key` to submit over the wire.
func TestProvision_PipelineIdentity_WritesLocalKeysAndExport(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	if err := provision(cfg); err != nil {
		t.Fatalf("provision: %v", err)
	}

	ks := filestore.New(filepath.Join(cfg.pipelineDataDir, "keys"))
	exportPath := filepath.Join(cfg.outDir, "pipeline-external-keys.json")
	raw, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	info, err := os.Stat(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o044 == 0 {
		t.Errorf("export mode %v is not world-readable", info.Mode().Perm())
	}

	var export map[string]struct {
		AuthPublicKey    string `json:"auth_public_key"`
		SigningPublicKey string `json:"signing_public_key"`
	}
	if err := json.Unmarshal(raw, &export); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}

	for _, subject := range []string{cfg.pipelineDID, cfg.processDID} {
		entry, ok := export[subject]
		if !ok {
			t.Fatalf("export has no entry for %s", subject)
		}
		for keyID, wantB64 := range map[keystore.KeyID]string{
			keystore.KeyIDAuth:    entry.AuthPublicKey,
			keystore.KeyIDSigning: entry.SigningPublicKey,
		} {
			priv, err := ks.GetPrivateKey(subject, keyID)
			if err != nil {
				t.Fatalf("%s#%s: local private key not found: %v", subject, keyID, err)
			}
			wantPub, err := base64.StdEncoding.DecodeString(wantB64)
			if err != nil {
				t.Fatalf("%s#%s: export value not base64: %v", subject, keyID, err)
			}
			gotPub := stded25519.PrivateKey(priv).Public().(stded25519.PublicKey)
			if !bytes.Equal(gotPub, wantPub) {
				t.Errorf("%s#%s: exported public key does not match the locally-held private key", subject, keyID)
			}
		}
	}
}

// Idempotency (same rationale as the NATS material above): a `docker compose
// up` re-run must REUSE the pipeline's already-provisioned keys — a running
// pipeline container would otherwise have its local keystore silently
// diverge from what the registry was told about, or provision would just
// error on filestore's create-only SaveKeyPair.
func TestProvision_PipelineIdentity_Idempotent_ReusesKeys(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	if err := provision(cfg); err != nil {
		t.Fatalf("first provision: %v", err)
	}
	first := mustRead(t, filepath.Join(cfg.outDir, "pipeline-external-keys.json"))

	if err := provision(cfg); err != nil {
		t.Fatalf("second provision: %v", err)
	}
	second := mustRead(t, filepath.Join(cfg.outDir, "pipeline-external-keys.json"))

	if !bytes.Equal(first, second) {
		t.Errorf("pipeline-external-keys.json changed across an idempotent re-run:\nfirst:  %s\nsecond: %s", first, second)
	}
}

// A half-present keyset (one of #auth/#signing written, the other missing —
// unreachable via provision's own atomic SaveKeyPair call, but possible from
// a hand-edited volume or a process killed mid-chown) must fail closed with
// reset guidance, matching the NATS material's own broken-cross-reference
// posture, rather than silently minting a mismatched second key.
func TestProvision_PipelineIdentity_PartialKeyset_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	if err := provision(cfg); err != nil {
		t.Fatalf("first provision: %v", err)
	}
	keysDir := filepath.Join(cfg.pipelineDataDir, "keys")
	// Remove only the #signing half for one subject, simulating an
	// interrupted or tampered volume.
	subjectDir, err := filestoreDIDDir(keysDir, cfg.pipelineDID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(subjectDir, "signing.key")); err != nil {
		t.Fatal(err)
	}

	err = provision(cfg)
	if err == nil || !strings.Contains(err.Error(), "partial keyset") {
		t.Fatalf("want fail-closed with a partial-keyset error, got: %v", err)
	}
}

// filestoreDIDDir mirrors filestore's own (unexported) Store.didDir mapping
// exactly (filestore.go: `filepath.Join(append([]string{root}, colon-split
// segments...)...)`) — only used to locate a key file to delete for
// TestProvision_PipelineIdentity_PartialKeyset_FailsClosed.
func filestoreDIDDir(keysRoot, subjectDID string) (string, error) {
	parts := append([]string{keysRoot}, strings.Split(subjectDID, ":")...)
	return filepath.Join(parts...), nil
}

// A both-files-present keyset that is nonetheless MALFORMED must fail closed
// with reset guidance rather than export a public key that either panics to
// derive (too short) or does not actually correspond to the private key
// (a corrupted public suffix) — the two shapes validatedPublicKey (main.go)
// rejects before ensureSubjectKeys ever hands a value to base64-encode.
func TestProvision_PipelineIdentity_MalformedKey_FailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, keyPath string)
	}{
		{
			name: "short private key file",
			mutate: func(t *testing.T, keyPath string) {
				t.Helper()
				if err := os.WriteFile(keyPath, []byte{1, 2, 3}, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "corrupted public suffix",
			mutate: func(t *testing.T, keyPath string) {
				t.Helper()
				raw, err := os.ReadFile(keyPath)
				if err != nil {
					t.Fatal(err)
				}
				if len(raw) != stded25519.PrivateKeySize {
					t.Fatalf("fixture key is %d bytes, want %d", len(raw), stded25519.PrivateKeySize)
				}
				corrupted := append([]byte(nil), raw...)
				corrupted[32] ^= 0xFF // flip a bit in the embedded public half (bytes 32:64), not the seed
				if err := os.WriteFile(keyPath, corrupted, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := testConfig(dir)
			if err := provision(cfg); err != nil {
				t.Fatalf("first provision: %v", err)
			}
			keysDir := filepath.Join(cfg.pipelineDataDir, "keys")
			subjectDir, err := filestoreDIDDir(keysDir, cfg.pipelineDID)
			if err != nil {
				t.Fatal(err)
			}
			tt.mutate(t, filepath.Join(subjectDir, "auth.key"))

			err = provision(cfg)
			if err == nil || !strings.Contains(err.Error(), "key material is invalid") {
				t.Fatalf("want fail-closed with an invalid-key-material error, got: %v", err)
			}
			if !strings.Contains(err.Error(), "reset the quickstart volume") {
				t.Errorf("want reset guidance in the error, got: %v", err)
			}
		})
	}
}

// A private keyset that is itself well-formed but no longer matches the
// public halves already exported (pipeline-external-keys.json, a DIFFERENT
// volume than the private keys) must fail closed rather than silently
// re-publish an export a running pipeline's local keystore no longer backs —
// the "mixed generations" case a `docker compose down -v` on just one of the
// two volumes could produce.
func TestProvision_PipelineIdentity_MismatchedExport_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	if err := provision(cfg); err != nil {
		t.Fatalf("first provision: %v", err)
	}

	exportPath := filepath.Join(cfg.outDir, "pipeline-external-keys.json")
	raw, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	var export map[string]externalKeysExport
	if err := json.Unmarshal(raw, &export); err != nil {
		t.Fatal(err)
	}
	entry := export[cfg.pipelineDID]
	entry.AuthPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, stded25519.PublicKeySize))
	export[cfg.pipelineDID] = entry
	out, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exportPath, out, 0o644); err != nil {
		t.Fatal(err)
	}

	err = provision(cfg)
	if err == nil || !strings.Contains(err.Error(), "mixed generations") {
		t.Fatalf("want fail-closed with a mismatched-export error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "reset the quickstart volume") {
		t.Errorf("want reset guidance in the error, got: %v", err)
	}
}

// An existing pipeline-external-keys.json that does not even decode as JSON
// (a hand-edited or truncated `provisioned` volume) must fail closed too —
// silently ignoring it would skip the mismatched-export cross-check above
// for every subject in the same run.
func TestProvision_PipelineIdentity_UndecodablePriorExport_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	if err := provision(cfg); err != nil {
		t.Fatalf("first provision: %v", err)
	}

	exportPath := filepath.Join(cfg.outDir, "pipeline-external-keys.json")
	if err := os.WriteFile(exportPath, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := provision(cfg)
	if err == nil || !strings.Contains(err.Error(), "does not decode as JSON") {
		t.Fatalf("want fail-closed with an undecodable-export error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "reset the quickstart volume") {
		t.Errorf("want reset guidance in the error, got: %v", err)
	}
}
