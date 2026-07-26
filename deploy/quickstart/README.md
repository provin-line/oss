# dPLaaX self-host quickstart

Bring up a **fully authenticated** dPLaaX stack on one host and drive a record
end-to-end — from HTTP push ingest to a `VERIFIED` audit verdict — through the
**real** three-layer authorization stack, not a stub.

```text
┌── auth.provider ──┐   issues JWTs from a DID-signed assertion (token issuance)
│  policy-verifier  │   verifies the JWT + evaluates policy         (the PDP)
│      network      │   registry (control plane): DID/VC/Audit RPCs + the PEP
│      pipeline     │   data plane: the transport loops, wired to `network` over the wire
│      nats         │   chain transport
└───────────────────┘
```

The stack is the separated dplaax topology: `network` (control plane,
`cmd/network`) and `pipeline` (data plane, `cmd/pipeline`) are two independent
processes, each with its own port, talking only over the wire — the shape
production deployments use. The retired all-in-one `cmd/standalone` binary
used to run both halves in one process; this quickstart mirrors the same
separated topology provin.e2e's own compose-runtime scenarios (e.g.
`scenarios/httpingest`) already exercise.

> **Not a production reference.** This stack takes deliberate dev shortcuts: one
> HS256 secret shared across the auth layer, freshly-generated NATS seeds, a
> long-lived pipeline service token, and **cleartext h2c** (`tls.allow-cleartext =
> true`) on the compose bridge with both node ports published loopback-only. In
> production every node must serve TLS (`tls.cert-file`/`key-file`) or sit
> behind a TLS terminator with an isolated backend — see
> [deployment.md → TLS termination](../../docs/architecture/deployment.md#tls-termination)
> and [Going to production](#going-to-production).

## Prerequisites

- **Docker** with Compose v2 (`docker compose`), BuildKit enabled (default).
- The auth-layer services (`policy-verifier`, `auth-provider`) are **published
  images** (`ghcr.io/provin-line/auth-*`, built by provin.auth's
  publish-images workflow and pinned to the moving `v0.2` minor tag in the
  compose file — swap in a `sha-<sha>` tag to pin an exact, reproducible
  build). If the pull is denied (a 401 — the GHCR packages not being public
  in your environment), do a one-time registry login with a token that can
  read the org's packages:

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
docker compose up --build      # provisions NATS trust material + pipeline keys, then boots every service
```

Wait until `policy-verifier`, `auth-provider`, `network`, and `pipeline` are
healthy. Published ports (all bound to `127.0.0.1` only — this stack shares a
dev secret and serves unauthenticated monitoring, so nothing is exposed to the
host's network): `network` (the registry) `8443`, `pipeline` (the data plane)
`8444`, policy-verifier `3001`, auth-provider `3000`.

## 2. Walk a record to VERIFIED

Run these from the repository root in another shell. `provin` is the operator
CLI; build it once:

```sh
go build -o /tmp/provin ./cmd/provin
PROVIN=/tmp/provin
REGISTRY=http://localhost:8443        # network — DID/VC/Audit RPCs
PIPELINE_URL=http://localhost:8444    # pipeline — /ingest/<loop>/push, /metrics
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

### 2c. Create the pipeline + process (external-key mode), then push a record

The separated topology's `pipeline` service carries its OWN local keystore
(`cmd/pipeline`'s boot preflights fail closed if a needed signing key is
missing) — unlike the retired `cmd/standalone`, the registry can no longer
mint the pipeline's loop keys itself and have them land somewhere the data
plane can read (`network` and `pipeline` are different processes with
different data volumes). So `provision` (the init container from step 1)
already minted the pipeline's and process's `#auth`/`#signing` keys directly
into the `pipeline-data` volume, and exported ONLY the public halves to
`pipeline-external-keys.json` inside the shared `provisioned` volume. Pull
that file out and pass it to `--external-key`: the registry then registers
those public keys and never generates or holds a private key for either DID.

```sh
docker compose cp network:/provisioned/pipeline-external-keys.json /tmp/pipeline-external-keys.json

$PROVIN pipeline create --did "$PIPELINE" --owner-key /tmp/acme-owner.jwk \
  --registry "$REGISTRY" --token "$TOKEN" \
  --external-key /tmp/pipeline-external-keys.json
$PROVIN process  create --did "$PROCESS"  --owner-key /tmp/acme-owner.jwk \
  --registry "$REGISTRY" --token "$TOKEN" \
  --external-key /tmp/pipeline-external-keys.json

curl -X POST "$PIPELINE_URL/ingest/src/push" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"sensor":"temp-01","celsius":21.5}'
# → 202 {"payload_hash":"sha256:..."}
```

Push ingest is served by `pipeline` (`$PIPELINE_URL`), never `network`
(`$REGISTRY`) — `network` carries no data plane at all (`cmd/network`'s own
package doc: it refuses to boot with any loop configured).

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

### 2e. Watch the counters (optional)

Both nodes enable `/metrics` (OpenTelemetry counters, Prometheus exposition;
**default-off** in the reference config — enabled here because the compose
publishes both node ports loopback-only). `network` reports audit verdicts
(its own background audit-runner); `pipeline` reports the data-plane loop
families (emit/verify — it runs no audit runner of its own):

```sh
curl -s http://localhost:8444/metrics | grep '^provin_'
# provin_pipeline_emit_attempts_total{loop="src",outcome="success",...} 1
# provin_pipeline_verify_results_total{loop="archive",outcome="verified",...} 1

curl -s http://localhost:8443/metrics | grep '^provin_'
# provin_audit_verdicts_total{verdict="verified",...} 1
```

See `docs/architecture/deployment.md` "Metrics" for the family reference.

### 2f. Export an offline evidence bundle (from the host)

`provin bundle export` archives a head's chain + authority documents into a
self-contained bundle a relying party can verify offline. It wants a **chain
head content address** — take the `headHash` step 2d already printed:

```sh
HEAD=sha256:…      # entries[].headHash from step 2d's ListAuditStatuses

$PROVIN --registry "$REGISTRY" --token "$TOKEN" \
  bundle export --head "$HEAD" --out /tmp/bundle \
  --did-base         "poc.dplaax.dev=$REGISTRY" \
  --vc-resolver-base "poc.dplaax.dev=$REGISTRY" \
  --audit-base       "poc.dplaax.dev=$REGISTRY"
```

Not the `payload_hash` from step 2c: that is the hash of the payload you sent,
equal to the issued credential's input/output hash, and it is a **correlation
handle** rather than a content address. There is no direct call today that maps
one to the other, so enumerating heads is the way to get one — unambiguous here
because this deployment has issued exactly one, and something to keep in mind on
a node that has issued many.

The `--*-base` overrides are required from the host: `network`'s DID
documents advertise the compose-internal `http://network:8443` (reachable
only inside the compose network), while the host reaches the same services
at `$REGISTRY` (`http://localhost:8443`). `--audit-base` is a separate
override from `--did-base` because export defaults to `--aggregate-complete`,
which fetches each issuer's `#audit` receipts to re-verify the
source-commitment axis offline.

## How it fits together

- **`provision`** (one-shot init container) generates the NATS operator-mode
  trust material (operator + account seeds, the account claims JWTs in the
  resolver directory, a system account with a **claims-push user narrowed to
  this deployment's account**, and `nats-server.conf` running the directory
  resolver over that same directory), mints the deployment's **service
  token** — an HS256 JWT both `network` and `pipeline` load (via
  `CONFIG_OVERLAY` and the config file's `include`, respectively) to
  authenticate their *own* L1-gated calls (`network`'s batch-resolver
  fetching peer credentials; `pipeline` publishing issued VCs, resolving
  references, fetching adjacent evidence) — and mints
  `pipeline`'s own local `#auth`/`#signing` keys (the external-key
  provisioning story, step 2c above; see `provision/main.go`'s
  `provisionPipelineIdentity`). Everything is written to shared volumes;
  nothing cryptographic is committed to the repo. The sys-user files and the
  pipeline keys are trust material — in anything beyond this dev stack, guard
  them like signing keys. Re-running `docker compose up` **reuses** existing
  trust material and keys (only the service token is re-minted — it carries
  an expiry); partial material from an interrupted run — or material from a
  pre-directory-resolver or pre-separated-topology quickstart — fails closed
  with a pointer to the reset below.
- **`policy-verifier`** and **`auth-provider`** are *generated* by
  `provin.auth`'s `create-*` CLIs at build time (there is no committed instance
  to build) — see `policy-verifier.Dockerfile` / `auth-provider.Dockerfile`. Both
  are pinned to a `provin.auth` ref via `AUTH_REF`.
- **`network`** (`cmd/network`) is the control plane: DID/Schema/Signer/VC/Audit
  registry RPCs, the background batch-resolver + audit-runner, and public DID
  resolution. It carries no data plane — see `network/config/application.conf`.
  Its authorization backend is the default `o3co` — it calls the real
  policy-verifier. Its own batch-resolver presents the service-token overlay
  (above) against peer `ResolveVC` calls — `CONFIG_OVERLAY` in
  docker-compose.yml points it at the same `/provisioned/overlay.conf`
  `pipeline` loads.
- **`pipeline`** (`cmd/pipeline`) is the data plane: the configured transport
  loops (`src` push-ingress, `archive` an observation-only sink), wired to
  `network` over the wire — it carries NO in-process registry of its own. Its
  NATS seeds and service-token overlay come from the shared `provisioned`
  volume (same as `network`'s); its own signing keys come from the
  `pipeline-data` volume `provision` wrote them into.

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

Each node's PDP backend is configurable (`provin.network.auth.backend`):
`o3co` (this quickstart), `opa`, `cedar`, or `static`. `static` is an in-process
allow-list and is **not authentication** — see the network `reference.conf` and
the deployment note in the repo README. This quickstart uses `o3co` precisely to
exercise real JWT verification end-to-end.

## Going to production

Replace, at minimum: the shared HS256 secret with an asymmetric provider key
(JWKS); the generated dev NATS seeds with operator-managed trust material; the
long-lived pipeline service token with a properly issued service credential; and
the loopback-friendly node networking with real network policy. The
bootstrap-token step does not apply to a JWKS/RS256 provider (see above).

## Reset

```sh
docker compose down -v      # also drops the provisioned and pipeline-data volumes
```
