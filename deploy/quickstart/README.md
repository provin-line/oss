# dPLaaX self-host quickstart

Bring up a **fully authenticated** dPLaaX stack on one host and drive a record
end-to-end — from HTTP push ingest to a `VERIFIED` audit verdict — through the
**real** three-layer authorization stack, not a stub.

```text
┌── auth.provider ──┐   issues JWTs from a DID-signed assertion (token issuance)
│  policy-verifier  │   verifies the JWT + evaluates policy         (the PDP)
│      node         │   enforces policy per RPC (the PEP) + runs the pipeline
│      nats         │   chain transport
└───────────────────┘
```

> **Not a production reference.** This stack takes deliberate dev shortcuts: one
> HS256 secret shared across the auth layer, freshly-generated NATS seeds, a
> loopback-friendly node, a long-lived node service token. It exists to *evaluate*
> dPLaaX with real authentication in the loop — see [Going to production](#going-to-production).

## Prerequisites

- **Docker** with Compose v2 (`docker compose`), BuildKit enabled (default).
- The auth-layer services (`policy-verifier`, `auth-provider`) are **published
  images** (`ghcr.io/provin-line/auth-*`, built by provin.auth's
  publish-images workflow and pinned by immutable `sha-` tag in the compose
  file). While `provin.auth` is **private**, pulling them needs a one-time
  registry login with a token that can read the org's packages:

  ```sh
  gh auth token | docker login ghcr.io -u "$(gh api user --jq .login)" --password-stdin
  ```

  Once the repos are public this is unnecessary. Building those two services
  **from source** instead (the commented `build:` blocks in the compose file)
  needs `export GITHUB_TOKEN=$(gh auth token)` for the in-build clone — see
  the Dockerfile headers.
- For the walkthrough (host-side operator tooling): **Go** (to build the `provin`
  CLI), **Node ≥ 20** (the DID-grant helper — Node stdlib only, no `npm install`),
  and `bash` + `openssl` + `curl`.

## 1. Start the stack

```sh
cd deploy/quickstart
docker compose up --build      # provisions NATS trust material, then boots all four services
```

Wait until `policy-verifier` and `auth-provider` are healthy and the node logs
`listening on :8443`. Published ports: node `8443`, policy-verifier `3001`,
auth-provider `3000`.

## 2. Walk a record to VERIFIED

Run these from the repository root in another shell. `provin` is the operator
CLI; build it once:

```sh
go build -o /tmp/provin ./cmd/provin
PROVIN=/tmp/provin
REGISTRY=http://localhost:8443
OWNER=did:dplaax:poc.dplaax.dev:org:acme
PIPELINE=$OWNER:pipeline:readings
PROCESS=$PIPELINE:process:s1
SECRET=quickstart-dev-secret-change-me      # matches the compose default
```

### 2a. Mint a bootstrap token and register the first owner

`RegisterOwner` is L1-gated (`dids:register`), but the auth.provider's DID grant
can only issue a token for an *already-registered* owner — so the very first
registration has no token to present. Bridge it with a short-lived HS256 token
signed with the shared secret (see [First-owner bootstrap](#first-owner-bootstrap)):

```sh
BOOTSTRAP=$(deploy/quickstart/bin/mint-bootstrap-token.sh \
  --owner "$OWNER" --secret "$SECRET" --issuer http://auth-provider:3000)

$PROVIN owner init --did "$OWNER" --key /tmp/acme-owner.jwk \
  --registry "$REGISTRY" --token "$BOOTSTRAP"
# → registered owner did:dplaax:poc.dplaax.dev:org:acme
```

### 2b. Exchange a DID-signed assertion for a real JWT

Now that the owner is registered and resolvable, get a real JWT from the
auth.provider via the `https://dplaax.dev/oauth/grant-type/did` grant (the helper signs
the challenge with the owner key — Node stdlib only):

```sh
TOKEN=$(node deploy/quickstart/bin/did-token.mjs \
  --key /tmp/acme-owner.jwk --did "$OWNER" \
  --provider http://localhost:3000 --client quickstart)
```

### 2c. Create the pipeline + process, then push a record

```sh
$PROVIN pipeline create --did "$PIPELINE" --owner-key /tmp/acme-owner.jwk \
  --registry "$REGISTRY" --token "$TOKEN"
$PROVIN process  create --did "$PROCESS"  --owner-key /tmp/acme-owner.jwk \
  --registry "$REGISTRY" --token "$TOKEN"

curl -X POST "$REGISTRY/ingest/src/push" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"sensor":"temp-01","celsius":21.5}'
# → 202 {"payload_hash":"sha256:..."}
```

### 2d. Read the audit verdict

The source loop signs the record as the process DID and emits it; the sink
observes and verifies it. Within a second or two:

```sh
curl -s -X POST "$REGISTRY/dplaax.audit.v1.AuditService/ListAuditStatuses" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"pageSize":10}'
```

```json
{"entries":[{"headHash":"sha256:…","status":{"linearChain":{
  "confidence":"CONFIDENCE_VERIFIED",
  "axes":{"dataIntegrity":"CONFIDENCE_VERIFIED",
          "signerAuthenticity":"CONFIDENCE_VERIFIED",
          "chainConsistency":"CONFIDENCE_VERIFIED"}}}}]}
```

`CONFIDENCE_VERIFIED` on all three axes — the record was authenticated, signed,
chained, and audited entirely through the real provider + real verifier path.

## How it fits together

- **`provision`** (one-shot init container) generates the NATS operator-mode
  trust material (operator + account seeds, the account claims JWTs in the
  resolver directory, a system account with a **claims-push user narrowed to
  this node's account**, and `nats-server.conf` running the directory
  resolver over that same directory) and mints the node's **service token** —
  an HS256 JWT the node uses to authenticate its *own* L1-gated calls
  (publishing issued VCs, resolving references, fetching adjacent evidence).
  Everything is written to a shared volume; nothing cryptographic is
  committed to the repo. The sys-user files are trust material — in anything
  beyond this dev stack, guard them like signing keys. Re-running
  `docker compose up` **reuses** existing trust material (only the service
  token is re-minted — it carries an expiry); partial material from an
  interrupted run — or material from a pre-directory-resolver quickstart —
  fails closed with a pointer to the reset below.
- **`policy-verifier`** and **`auth-provider`** are *generated* by
  `provin.auth`'s `create-*` CLIs at build time (there is no committed instance
  to build) — see `policy-verifier.Dockerfile` / `auth-provider.Dockerfile`. Both
  are pinned to a `provin.auth` ref via `AUTH_REF`.
- **`node`** is the `standalone` binary (built from this repo). Its authorization
  backend is the default `o3co` — it calls the real policy-verifier. Its NATS
  seeds and its service-token overlay come from the `provision` volume.

### First-owner bootstrap

The bootstrap token is a dev convenience that works *because* this stack shares
one HS256 secret between the provider and the verifier. A production provider
signs with a private key (RS256/EdDSA via JWKS) that no client holds, so there is
nothing to mint against. Production options for seeding the first owner:

- register the first owner during an operator-run provisioning step that holds a
  privileged issued credential, or
- a one-time, audited policy exception scoped to `dids:register` for a known
  bootstrap principal.

### Authorization backends

The node's PDP backend is configurable (`provin.network.auth.backend`):
`o3co` (this quickstart), `opa`, `cedar`, or `static`. `static` is an in-process
allow-list and is **not authentication** — see the network `reference.conf` and
the deployment note in the repo README. This quickstart uses `o3co` precisely to
exercise real JWT verification end-to-end.

## Going to production

Replace, at minimum: the shared HS256 secret with an asymmetric provider key
(JWKS); the generated dev NATS seeds with operator-managed trust material; the
long-lived node service token with a properly issued service credential; and the
loopback-friendly node networking with real network policy. The bootstrap-token
step does not apply to a JWKS/RS256 provider (see above).

## Reset

```sh
docker compose down -v      # also drops the provisioned volume
```
