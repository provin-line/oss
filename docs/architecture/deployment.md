# Deployment

How a provin node is deployed, and the handful of configuration choices that
are **load-bearing** — get them wrong and the node boots fine but cannot do
its job. Config keys live in each package's `reference.conf` (the canonical
key documentation); this page covers the cross-cutting decisions those files
can only describe locally.

## Deployment shapes

| Shape | What runs | Reference |
| --- | --- | --- |
| Single-host evaluation | everything on one host via Docker Compose: node + real auth stack (auth.provider, policy-verifier) + NATS, provisioned trust material | [`deploy/quickstart/`](../../deploy/quickstart/README.md) |
| Single-org production | one `standalone` node per registry, external PDP, operator-managed NATS trust material | this page |
| Cross-org federation | one node per organization; NATS account boundaries carry the export/import seam; peers talk over ChainPeerService (L2 wireauth) | [`network/README.md`](../../network/README.md) |

The node is one binary (`cmd/standalone`): HTTP control plane (ConnectRPC
services + public DID resolution + health endpoints) and the data plane
(pipeline loops) run in one process under one signal-cancelled context.

## Load-bearing configuration

### 1. `resolver-base-url` + `dev.allow-loopback` (single-host deployments)

A node that verifies credentials resolves their issuers' DID documents. The
default resolution URL is derived from the DID's registry segment as
`https://{registry}` — which, on a single-host deployment where the node IS
that registry, points back at itself over a name that typically resolves to
a loopback or private address. The SSRF guard (`network/pkg/core`, fail-closed
"public-internet-only" posture) then **blocks the node's own resolution**:
the node can register issuers but cannot verify what they sign.

Both keys must therefore be set together on single-host deployments:

- `provin.network.chain.nats.resolver-base-url` — where DID resolution
  actually reaches this node (e.g. `http://node:8443` inside a compose
  network).
- `provin.network.core.dev.allow-loopback = true` — permits the guard to
  follow it. **Dev-only by design**: a production multi-host deployment uses
  real public DNS names and keeps `allow-loopback` at its `false` default.

The quickstart wires this combination; if you assemble your own compose
file, this is the first thing to copy.

### 2. Broker account-claims caching (grants after connect)

NATS operator mode resolves account JWTs when an account connects (or when a
JWT expires). Cross-account grants (the export/import seam behind
`chain subscribe`) are carried IN those account JWTs — so a grant issued
**after** either party's account has connected is invisible to the broker
until its claims are re-read. With the non-expiring JWTs the provisioning
tooling generates, "re-read on expiry" never happens.

Operational consequences:

- **The node pushes updated claims automatically** when its sys-user
  credentials are configured (`sys-user-jwt-file` / `sys-user-seed-file`):
  every grant is pushed to the running broker
  (`$SYS.REQ.ACCOUNT.<account>.CLAIMS.UPDATE`) as part of issuing it, and
  the grant RPC fails loudly if the push cannot be confirmed. The quickstart
  provisions this out of the box, with the sys user narrowed to exactly the
  node account's claims-update subject. Treat the sys-user files as trust
  material regardless — in production guard them like signing keys.
- **Fallback runbook** (sys user not configured, or recovering from an
  outage): push the updated claims manually (`nsc push`, or a request to
  `$SYS.REQ.ACCOUNT.<account>.CLAIMS.UPDATE` — the per-account subject is
  served by every resolver type) or restart the broker so the resolver
  re-reads them.
- The broker should resolve accounts from the SAME directory the node
  publishes JWTs into (the quickstart runs the nats directory resolver over
  it). A memory resolver with a baked `resolver_preload` goes stale the
  moment a grant lands and resurrects old claims on broker restart — do not
  deploy that shape beyond static single-account setups.
- Both parties rewrite JWT files in that directory in place (the node's
  publisher on grants, the broker's resolver on claims-update saves), so
  **the broker and the node must run under the same uid** (the quickstart
  does) — the publishers re-tighten file modes on every write, so split-uid
  arrangements cannot keep the files mutually writable today.

Symptom when the push is missing: `chain subscribe` succeeds (the
control-plane record is written) but no events flow — the broker silently
drops the ungranted subject. Nothing errors; the negative capstone tests pin
exactly this behavior as the *security* posture, which is why the
operational side needs this note.

## Health endpoints

- `GET /healthz` — **liveness**, static. Failing means "restart me".
- `GET /readyz` — **readiness**, dependency-aware: evidence store, the
  broker connection (when a data plane runs), external-PDP reachability
  (when one is configured). Failing means "route no new work here". Check
  errors are logged server-side only; the public body carries pass/fail per
  check.

Wire supervisors accordingly (e.g. Kubernetes `livenessProbe` → `/healthz`,
`readinessProbe` → `/readyz`).

## Metrics

`GET /metrics` serves OpenTelemetry counters in Prometheus exposition format,
gated by `provin.network.core.metrics.enabled` (**default `false`**: the
endpoint is unauthenticated on the serving listener and exposes loop names
and traffic/failure/verdict rates — more than `/healthz`. Enable it only
where the listener's network is trusted; the quickstart compose does).

Stable metric families (operational contract — not part of the credential
wire freeze, but renames are CHANGELOG-worthy):

| Prometheus name | Attributes | Meaning |
| --- | --- | --- |
| `provin_pipeline_emit_attempts_total` | `loop`, `outcome=success\|failure` | Emit outcomes per producing loop, keyed on the Emit call's return (success = primary form delivered; a stripped-publish failure is still a success here) |
| `provin_pipeline_emit_stripped_failures_total` | `loop` | Stripped-publish (dual-emit) failures per dual-emitting loop |
| `provin_pipeline_verify_results_total` | `loop`, `outcome=verified\|failed\|indeterminate\|error` | Per-credential **verifier API** outcomes per consuming loop — the seam below the loop's accept/reject policy (`error` = the verifier returned a non-context error, or an anomalous nil result) |
| `provin_audit_verdicts_total` | `verdict=verified\|failed\|indeterminate` | Durably recorded audit verdict **writes** by linear-chain overall verdict (writes, not audited heads: re-audits, per-tick hole re-records, and abandon finalizations each count) |

Family presence follows capability: a family (and its fixed, zero-initialized
label set) appears exactly when the node is configured with the capability —
emit series only for producing loops, stripped series only when the node
dual-emits (a payload store is wired), verify series only for consuming
loops, audit verdicts only when the audit runner runs.

## Durable state

All durable state lives under the configured data dir (see
`network/README.md` "State model"): YAML control-plane records plus the
file-backed evidence dir (credentials, resolution pool, audit queue,
verdicts). Two operational obligations:

- **Back up the data dir.** Audit-reachable deployments promise
  retrospective resolution of source credentials long after issuance —
  evidence retention is a deployment obligation, not an optimization.
- **Evidence grows without bound by default**; monitor disk. To bound live
  disk without deleting records, rotate the relationship-evidence log to a
  cold archive (see below).

In-memory by design (PoC posture): the wireauth nonce store (replay defense
re-arms via the restart epoch barrier) and infra-operator state.

### Evidence log rotation

The relationship-evidence log is append-only and tamper-evident (a hash
chain, replay-verified at open): records are **never** deleted or mutated —
retention IS the audit horizon. To bound live disk, rotate old records to a
cold archive instead of deleting them:

```console
# Stop the daemon first — the log takes a single-opener lock, so an
# online rotate fails loudly (it will NOT corrupt a running log).
$ provin evidence rotate --dir <data-dir>/relationship-evidence
```

Rotation copies the current log into `archive/seg-NNNNNN/` (with a
`manifest.json` recording size, chain head, and — if the log is armed with a
checkpoint signer — a signed final checkpoint), then truncates the live log
to a fresh empty genesis. The archived segment stays independently
replay-verifiable; move `archive/` to cheaper cold storage as needed, keeping
it for the audit horizon. Rotation is crash-safe: an interrupted rotate is
completed or rolled back at the next daemon start.

**Segment stitching (audit across a rotation).** After a rotation the live
log's record indices restart at 0, so the full history is ordered by *segment
number then index*: `seg-000001` records `0..N₁-1`, then `seg-000002`, …, then
the live log. Each segment verifies independently from its own genesis. An
auditor reconstructing the complete relationship history reads the archive
segments in ascending `seg-NNNNNN` order, then the live log. A consumer that
references evidence by a persistent global index across a rotation must switch
to `(segment, index)`; the current relationship-evidence path does not (it
appends and audits the live log), so rotation is transparent to it.

Unsigned caveat: unless the evidence log is armed with a checkpoint signer,
the archived segment's integrity rests on chain replay plus filesystem access
control — the same trust model as the live unsigned log. The `manifest.json`
head is a storage summary, not a cryptographic seal.

## Trust material

NATS operator-mode material (operator/account seeds, account claims JWTs,
broker config) is generated **out of band** and never committed. The
quickstart's one-shot `provision` container shows the shape (and is
idempotent across re-ups); a production deployment provisions the same
artifacts through its own secret management. The auth stack's token-signing
material is separate — see the quickstart README's "Going to production"
for what must change beyond dev (asymmetric provider keys via JWKS,
operator-managed seeds, real service credentials).
