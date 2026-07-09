#!/usr/bin/env node
/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

// Exchange a DID-signed assertion for a real JWT from the quickstart's
// auth.provider (the `urn:dplaax:oauth:grant-type:did` grant), then print the
// access_token. This is the "real provider" leg of the walkthrough: once
// `provin owner init` has registered the owner DID, the provider can resolve it
// and verify a challenge signed by the owner's key — so we never mint the
// authorization token by hand past bootstrap.
//
// Pure Node stdlib (node:crypto Ed25519 + global fetch) — no npm install. Reads
// the owner's RFC 8037 OKP Ed25519 JWK written by `provin owner init`.
//
// Usage:
//   node did-token.mjs --key <owner.jwk> --did <owner-did> \
//       --provider http://localhost:3000 [--client quickstart]

import { readFileSync } from "node:fs";
import { createPrivateKey, randomBytes, sign as edSign } from "node:crypto";

function parseArgs(argv) {
	const out = { client: "quickstart" };
	for (let i = 0; i < argv.length; i += 2) {
		const flag = argv[i];
		const val = argv[i + 1];
		if (!flag?.startsWith("--") || val === undefined) {
			throw new Error(`bad argument near ${flag}`);
		}
		out[flag.slice(2)] = val;
	}
	for (const req of ["key", "did", "provider"]) {
		if (!out[req]) throw new Error(`--${req} is required`);
	}
	return out;
}

async function main() {
	const args = parseArgs(process.argv.slice(2));

	const jwk = JSON.parse(readFileSync(args.key, "utf8"));
	if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
		throw new Error(`owner key ${args.key} is not an OKP/Ed25519 JWK`);
	}
	const privateKey = createPrivateKey({ key: jwk, format: "jwk" });

	// The provider verifies this challenge against the owner DID's registered
	// verification key. Shape mirrors the auth.provider DID-grant contract:
	// a JSON message {did, timestamp, nonce} signed raw with Ed25519, the
	// signature base64 (standard, not url).
	const message = JSON.stringify({
		did: args.did,
		timestamp: new Date().toISOString(),
		nonce: randomBytes(16).toString("hex"),
	});
	const signature = edSign(null, Buffer.from(message), privateKey).toString("base64");

	const res = await fetch(new URL("/oauth/token", args.provider), {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: "urn:dplaax:oauth:grant-type:did",
			client_id: args.client,
			did: args.did,
			message,
			signature,
		}),
	});

	const text = await res.text();
	if (!res.ok) {
		throw new Error(`token endpoint ${res.status}: ${text}`);
	}
	let body;
	try {
		body = JSON.parse(text);
	} catch {
		throw new Error(`token endpoint returned non-JSON: ${text}`);
	}
	if (!body.access_token) {
		throw new Error(`token response has no access_token: ${text}`);
	}
	process.stdout.write(body.access_token);
}

main().catch((err) => {
	process.stderr.write(`did-token: ${err.message}\n`);
	process.exit(1);
});
