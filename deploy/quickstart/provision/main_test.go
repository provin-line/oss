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

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}
