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
)

// provision must lay down exactly the operator-mode NATS artifacts the
// quickstart's broker and node consume, mirroring a production deployment's
// out-of-band provisioning: an operator trust root, one account, the account's
// claims JWT in a resolver dir, and a broker config that preloads it. This test
// pins that contract — the crypto itself is provin.oss's (natsop) and nats-io's;
// what we verify here is that this glue writes coherent, cross-consistent files.
func TestProvision(t *testing.T) {
	dir := t.TempDir()
	if err := provision(config{outDir: dir, account: "acme", natsURL: "nats://nats:4222"}); err != nil {
		t.Fatalf("provision: %v", err)
	}

	// Every artifact the compose mounts must exist.
	for _, rel := range []string{
		"operator.seed",
		"acme-account.seed",
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
	if !strings.Contains(conf, accPub) {
		t.Errorf("nats-server.conf resolver_preload is missing the account %q:\n%s", accPub, conf)
	}
}

// With a shared secret configured, provision must write a service-token overlay
// the node loads via CONFIG_OVERLAY: an HS256 JWT (signed with that secret) bound
// to pipeline.vc-store-bearer, so the node authenticates its own L1-gated calls.
func TestProvision_ServiceOverlay(t *testing.T) {
	dir := t.TempDir()
	const secret = "shared-secret"
	if err := provision(config{
		outDir: dir, account: "acme", natsURL: "nats://nats:4222",
		jwtSecret: secret, jwtIssuer: "http://auth-provider:3000",
		serviceSubject: "did:dplaax:poc.dplaax.dev:org:acme", serviceTTL: time.Hour,
	}); err != nil {
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
	if err := provision(config{outDir: dir, account: "acme", natsURL: "nats://nats:4222"}); err != nil {
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
	cfg := config{outDir: dir, account: "acme", natsURL: "nats://nats:4222"}
	if err := provision(cfg); err != nil {
		t.Fatalf("first provision: %v", err)
	}

	accSeed := mustRead(t, filepath.Join(dir, "acme-account.seed"))
	accKP, err := nkeys.FromSeed(accSeed)
	if err != nil {
		t.Fatalf("account seed not an nkey seed: %v", err)
	}
	accPub, _ := accKP.PublicKey()

	artifacts := []string{
		"operator.seed",
		"acme-account.seed",
		filepath.Join("nats", "operator.jwt"),
		filepath.Join("nats", "nats-server.conf"),
		filepath.Join("jwts", accPub+".jwt"),
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
	if err := provision(config{outDir: dir, account: "acme", natsURL: "nats://nats:4222"}); err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "overlay.conf")); err == nil {
		t.Fatal("overlay.conf written despite no jwt-secret")
	}
	if err := provision(config{
		outDir: dir, account: "acme", natsURL: "nats://nats:4222",
		jwtSecret: "shared-secret", jwtIssuer: "http://auth-provider:3000",
		serviceSubject: "did:dplaax:poc.dplaax.dev:org:acme", serviceTTL: time.Hour,
	}); err != nil {
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
	cfg := config{outDir: dir, account: "acme", natsURL: "nats://nats:4222"}
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
	err := provision(config{outDir: dir, account: "acme", natsURL: "nats://nats:4222"})
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
		return config{outDir: dir, account: "acme", natsURL: "nats://nats:4222"}
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
