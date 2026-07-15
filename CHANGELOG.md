# Changelog

All notable changes to this repository are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the version is `0.x`, exported Go API and configuration keys may still
change between minor releases. The **v0 credential wire is frozen** as of the
Unreleased line below (see its freeze declaration): changing any byte of the
credential Data Integrity signing scope is a next-MAJOR break, not a minor
change. The first frozen *API* surface is declared at the `1.0` line.

## [Unreleased]

The P0 (public-release hardening) line. Releases as the next minor at the
public/production cut; no intermediate tag is minted.

### v0 credential wire freeze declaration

As of this line the **v0 credential Data Integrity wire — every byte that
participates in a credential signature — is frozen**. Concretely:

- The credential `@context` set: `https://www.w3.org/ns/credentials/v2`
  (embedded verbatim, pinned to the W3C-published normative sha256
  `59955ced6697d61e03f2b2556febe5308ab16842846f5b586d7f1f7adec92734`),
  `https://dplaax.dev/vc/v1`, and `https://provin.dev/vc/v1` (embedded,
  sha256-pinned), and the credential/subject wire members they define.
- The Data Integrity proof algorithm:
  `hashData = SHA-256(canon(proofConfig)) ‖ SHA-256(canon(document))`, the
  W3C proof configuration — the six typed members plus the proof-local
  `@context` copied from the document when it has one (vc-di-eddsa §3.3.1
  step 2; amended within this unreleased line by the Fork W entry below, which
  post-dates and supersedes the original six-member wording) — and the
  base58btc (`z` multibase) `proofValue` encoding.
- Both cryptosuites and their canonicalizations: `eddsa-jcs-2022`
  (actual RFC 8785 via the `jcs-rfc8785` canonicalizer, Phase-1 MUST, issuance
  default, Multikey verification methods) and `eddsa-rdfc-2022` (URDNA2015,
  Phase-2, opt-in), each anchored to the official W3C vc-di-eddsa test vectors
  with every intermediate pinned — for `eddsa-jcs-2022`, end to end: the
  official Example 39 `proofValue` verifies through the production classifier
  path. Artifacts signed under the historical int64-verbatim deviation verify
  only as the `LEGACY_PROVIN_EDDSA_JCS_INT64@1` claim contract. The URDNA2015
  behavior is additionally pinned by a provin-shape KAT against json-gold
  v0.8.0.
- The source-commitment form riding inside the signed credential: the RFC
  6962 Merkle tree hash over JCS-canonicalized source credentials (leaf
  prefix `0x00`, interior `0x01`, odd leaves promoted; empty set = hash of
  the empty string), the `f1220` multihash `source_root` encoding, and the
  `jcs-rfc8785` canonical identifier — a verifier recomputing the root must
  reproduce these bytes exactly.
- The DID verification-method read contracts: OKP/Ed25519 JWK
  (`JsonWebKey2020`) and Multikey (`publicKeyMultibase`, multicodec
  `0xed01`), with method type and key encoding mutually exclusive.

Changing any of the above breaks proof compatibility with already-issued
credentials and is a **next-MAJOR** change. The freeze is enforced by tests
in this repository (W3C vectors, KATs, context digests), not by process.
Exported Go API and configuration keys remain `0.x`-mutable; the wire freeze
is deliberately stricter than the API surface.

Out of scope of this declaration: the repository's OTHER signed views — the
tlog checkpoint `SignedView`, the chain-manager/payload-resolver wire-auth
views, and the DID-document JCS hash recorded into lifecycle logs — are
separate protocol contracts, each pinned by its own golden tests. Changes
there are compatibility-relevant and are called out in this changelog (see
the checkpoint entry under Changed below), but they are versioned by their
own contracts, not by this credential-wire declaration.

### Fork W — full W3C `eddsa-jcs-2022` conformance (BREAKING within Unreleased)

Ratified architecture decision (debate P0-4 = Fork W, 2026-07-15): external
W3C-DI verifier interop is a product goal. `eddsa-jcs-2022` now means what W3C
says it means. All changes below land before any public tag, so they revise the
unreleased freeze declaration above rather than breaking a shipped wire.

- **Canonicalization**: new `jcs-rfc8785` canonicalizer (byte-for-byte RFC 8785;
  unsafe integers round through binary64 like any strict-ES6 implementation).
  Every stored-address path — credential body hash / wire form, DID-document
  hash, source-root leaves, tlog checkpoint views, lifecycle-event maps,
  wire-auth views — now canonicalizes with it, making the long-advertised
  `source_root_canonical: "jcs-rfc8785"` name true. The historical
  int64-verbatim canonicalizer remains for legacy verification only and is
  unreachable from any issuance path.
- **Safe-number admission**: `canon.AdmitSafeNumbers` rejects integer-valued
  JSON numbers outside ±(2^53−1) — in every spelling — before signing. A value
  above the range belongs in the string domain under a versioned schema.
- **Proof wire shape**: proofs carry a proof-local `@context` copied from the
  document (present exactly when the document has one). Verification requires
  the wire member to equal the document's on canonical bytes — without that
  check it would be the one proof member a swap could not break.
- **Verification methods**: issued DID documents (owner, pipeline, process) use
  `Multikey` and carry the frozen contexts
  `["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"]`.
  Legacy JWK documents remain resolvable; proofs signed under them verify as
  the legacy contract.
- **Exact suite dispatch**: one classifier resolves (suite id, proof shape, key
  encoding) to exactly one claim contract — `W3C_EDDSA_JCS_2022_REC_20250515@1`,
  `W3C_EDDSA_RDFC_2022_REC_20250515@1`, or `LEGACY_PROVIN_EDDSA_JCS_INT64@1` —
  with no canonicalizer fallback. `VerifyResult.SuiteContract` reports which
  contract produced every verdict; a chain result carries the head
  credential's.

**Migration notes** (pre-release deployments only; there is no public tag):

- Re-generate owner/pipeline/process DID documents (`provin owner init` against
  a fresh registry, or re-issue). A JWK-era owner document can still be READ,
  but a new binary signs W3C-shaped proofs, which no contract accepts over a
  JWK key — issuance from an old document fails closed until it is re-issued.
- Before upgrading a deployment that has persisted stores, run
  `go run ./internal/numberinventory/cmd/numberinventory <DataDir>` and hold
  the upgrade if it reports BLOCK (an artifact carrying an unsafe integer
  would become unreadable at its stored address under the canonicalizer
  switch). Evidence record for this checkout:
  `docs/evidence/forkw-1-number-inventory-2026-07-15.md` (zero stored
  artifacts here; the tool exists for deployments that have them).
- Old verifiers reject the new seven-member proofs as carrying an unknown
  member (fail-closed). Roll out readers before writers.
- **Legacy sunset schedule** (`confidence.legacy.sunset`): the legacy
  int64-verbatim contract is **Deprecated as of 2026-07-14**; **new legacy
  issuance stops 2026-10-01** (Sunset); the **issuer-side legacy path is
  removed 2027-04-01**. Until Sunset, externally-signed legacy-shaped
  registrations are still admitted (the "read-only" contract governs what this
  repository issues, not yet what it admits); after it, admission requires the
  W3C shape.

### Transport security — P0-6 closure

The TLS posture (F6) shipped earlier in this line; these are the conditions its
closure required, now met with executed evidence rather than review.

- **TLS 1.2 floor, pinned explicitly.** `core.TLSConfig.LoadServerTLS` sets
  `MinVersion` rather than inheriting Go's default — the floor is this project's
  contract, and a contract held by a library default can change under an
  upgrade. Cipher suites still follow the stdlib's secure defaults, deliberately
  (TLS 1.3 suites are not selectable through Go's API, and a frozen allowlist
  would block future stdlib improvements). A wire test drives the floor:
  TLS 1.0/1.1 handshakes fail, 1.2/1.3 negotiate.
- **Certificate preflight.** The pair is loaded and validated before any
  side-effectful boot work, so an unreadable, invalid, or mismatched pair is a
  clean boot failure with no half-initialized stores behind it. The preflighted
  pair is what serves — the files are not re-read at listen time, closing the
  gap between validation and use. Rotation still requires a restart.
- **Endpoint migration matrix.** A TLS listener does not rewrite what a node
  *advertises*: an `http://` service endpoint or resolver override on a TLS
  posture means peers never reach it, while the node looks healthy from the
  inside. Boot now logs a warning naming each such URL (advisory — a migration
  may legitimately be partway through).
- **Actual boot smokes.** The standalone binary is booted from a real config
  with an ephemeral certificate: readiness over HTTPS, a served request,
  graceful shutdown on SIGTERM — plus the negative, that a mismatched pair kills
  boot before the data directory exists. The quickstart is booted on its
  intended cleartext dev profile and its walkthrough run end to end.

### Fixed

- **Config comments were silently deleting the line below them** — a bug in the
  HOCON parser we depend on, worked around here. The spec is unambiguous
  ("anything between `//` or `#` and the next newline is considered a comment and
  ignored"), but gurkankaymak/hocon v1.2.23 lets a `#` comment containing a `//`
  sequence swallow the FOLLOWING line: two documents differing only in comment
  text parse to different results. A `//`-marked comment containing `//` is
  handled correctly, so it is specifically the `#` marker that mis-tokenizes, and
  a URL in an explanatory comment is the natural way to trip it.

  Three shipped defaults had silently vanished this way, parsing cleanly with
  nobody the wiser: `provin.network.auth.opa.base-url`,
  `provin.network.auth.cedar.base-url`, and
  `provin.network.registry.service-endpoints` all resolved to nil. Every
  affected comment is fixed — prose drops the scheme's slashes; comments that
  must show a literal URL switch to the `//` marker — and
  `TestNoHashCommentContainsDoubleSlash` forbids the shape repository-wide,
  because today's harmless swallow (the eaten line happens to be another
  comment) becomes tomorrow's lost setting the moment someone inserts a key
  after it.

- **The quickstart never booted.** `deploy/quickstart/node/config/application.conf`
  failed to parse — for its whole history, on every machine. Same root cause,
  loud instead of quiet: there the swallowed line carried an opening brace
  (`service-endpoints {`), so the braces stopped balancing and the parser
  rejected the file's final `}` as a stray. Nothing caught it — `docker compose
  config` validates the compose file, not the node config inside the container —
  and `TestShippedConfigsParse` now parses every `.conf` the repository ships.
- **The quickstart reported a crash-looping node as healthy.** The node service
  had no healthcheck, so `docker compose up --wait` saw a container that
  `restart: on-failure` kept "running" and declared the stack ready. It now
  waits on the node's own `/readyz`.

### Added

- `eddsa-rdfc-2022` cryptosuite: `canon/urdna2015` (RDF Dataset
  Canonicalization wrapping `piprate/json-gold` v0.8.0) behind an offline
  context allowlist — context resolution never touches the network. The RDFC
  path fails closed on every input shape JSON-LD processing would silently
  drop or mutate from the signing scope: numerics (2^53 truncation), nulls,
  scalar node-array entries, undefined terms, relative `@id`/`@type`,
  blank-node or invalid predicates, `@index`, `@direction`, and malformed
  `@language`. Registered at init behind a full-shape expansion probe.
- Multikey read support: `did.VerificationMethod.PublicKeyMultibase`, with
  fail-closed type↔encoding exclusivity in `did.ExtractPublicKey`.
- `multibase` package: the one base58btc codec shared by `vc` (proofValue)
  and `did` (Multikey), anchored to the W3C proofValue test vector.
- `GetAllowList` chain-manager RPC, `provin chain get-allow`, and the
  `chain:read-allowlist` policy action.
- `pipeline/observer/logobserver`: the reference `ProcessObserver` (one
  structured slog record per event; fire-and-forget by construction).
- `tlog`: RFC 6962 Merkle log with standalone inclusion/consistency proof
  verification.
- Defensive payload re-verification in the provenance signer: a non-nil
  payload must hash to the credential's `outputHash` or signing refuses.
- Live claims push: a chain grant now takes effect without a broker restart —
  the node pushes the updated account claims to the NATS system account
  (`$SYS.REQ.CLAIMS.UPDATE`) at grant issuance
  (`provin.network.chain.nats.sys-user-jwt-file` / `sys-user-seed-file`); the
  manual runbook remains a documented fallback.
- `/metrics` endpoint (OpenTelemetry → Prometheus exposition): per-loop
  emit-attempt/success/failure, stripped-publish failure, verify-outcome, and
  audit-verdict counters. Gated by `provin.network.core.metrics.enabled`
  (default **off** — the listener is not loopback-bound and the series expose
  loop names and traffic/verdict rates).
- `#audit` service advertisement: an issuer's DID document advertises its
  AuditService endpoint, giving `provin bundle export --aggregate-complete` a
  stable receipt-routing derivation (overridable per registry with
  `--audit-base`).
- Node-native TLS: `provin.network.core.tls.cert-file` / `key-file` serve h2
  over TLS (ALPN). A fail-closed boot guard rejects a non-loopback cleartext
  listener unless the operator sets `tls.allow-cleartext` to acknowledge a
  fronting TLS terminator.
- Documentation tree under `docs/`: `architecture/` (overview, process
  catalog, deployment), `protocol/` (service API, L1/L2 auth), and the
  `did:dplaax` method spec.
- `SECURITY.md`: the vulnerability-reporting channel and supported-versions
  policy.

### Changed

- **BREAKING** `keystore.KeyStore` is a custody seam: `Sign` replaces
  `GetPrivateKey` in the interface (KMS-shaped — raw keys no longer egress
  through the contract); `crypto/ed25519.Signer` is removed in favor of raw
  `ed25519.Sign` (file-backend private-key access remains on the concrete
  `filestore.Store` only).
- **BREAKING** `vc`/auth seam: `AttributeOwner` is exported and the
  `auth.Verifier` seam is package-owned.
- **BREAKING** the credential `@context` URIs are frozen as the v0 wire
  vocabulary (repointing either protocol/profile URI is a hash partition).
- **BREAKING** tlog checkpoint `SignedView` now binds a Checkpoint Origin
  (`logId`) into the signed bytes and REJECTS legacy checkpoints without it:
  checkpoints signed before this change no longer verify.
- **BREAKING (default)** the default `listen-addr` is now `127.0.0.1:8443`
  (was `:8443`): a fresh node binds loopback only (secure by default).
  Exposing a non-loopback interface now requires a transport-security posture
  — node TLS (`tls.cert-file`/`key-file`) or an explicit `tls.allow-cleartext`
  acknowledgement — otherwise boot fails closed.
- **BREAKING (config semantics)** `allow-private-networks = true` now CLOSES
  cross-registry DID resolution to the configured registry set: an unmapped
  registry no longer falls back to `https://{registry}`, and private mode with
  no `registry-base-urls` / `resolver-base-url` scoping fails boot. This
  removes a pre-signature internal-scan vector; a deployment that relied on
  blanket-private with open resolution must now enumerate its registries.
- **BREAKING (wire)** `PayloadService.ResolvePayload` now returns `NotFound`
  (was `PermissionDenied`) for a caller not admitted by any owner, collapsing
  the "present but forbidden" and "absent" cases so the serving boundary is no
  longer an existence oracle.
- **BREAKING (default)** `provin bundle export` now defaults to
  `--aggregate-complete`: the offline source-commitment axis is complete by
  default (pass `--aggregate-complete=false` for a linear-only bundle).
- Pre-authentication resource-exhaustion hardening: per-RPC read caps plus an
  outer request-size cap on every mount; a bounded, timed DID-resolution path
  (per-resolve deadline + concurrency cap → `ErrResolverBusy`); nonce-store
  eviction past the acceptance window; server-wide HTTP read/write/idle
  timeouts and a cached `/readyz`; and PDP credentials redacted from logs.
- The payload-fetch client now imposes per-fetch total and idle-read deadlines
  independent of the caller context, so an untrusted serving boundary cannot
  stall a consumer loop.
- Cross-registry and receipt-routing derivations (batch resolver, bundle
  export) now match on exact content address / registry id — no suffix or
  substring matching.

### Removed

- `pipeline/chained/cmd/` placeholder (the standalone runtime is the one
  chained-loop binary).

## [0.1.0] - 2026-07-12

Initial internal release — pinned for internal (private) deployment and soak.

### Added

- The dPLaaX provenance data plane and control plane: pipeline loops
  (source / chained / aggregate / sink), the chain manager, the DID registry,
  schema registry, the durable relationship-evidence log, and the `provin` CLI.
- Cross-organization by-reference payload delivery (structural export-seam
  mode → subject mapping + dual-emit), served from a payload-resolver boundary.
- `provin evidence rotate`: archive+rotate a relationship-evidence log to a
  cold-archive segment without deleting records (the tlog append-only contract
  holds).
- `provin org verify/inspect/diagnose/generate-txt`: DNS-based organization
  endorsement.

### Changed

- wireauth: the default restart epoch is lifted to `boot + MaxFuture`, fully
  closing the cross-restart replay window over the in-memory nonce store.
- by-reference advertisement now degrades when a producer's stripped-publish
  emission is failing (recovery tied to a proven successful stripped publish).

### Notes

- The quickstart pins the `provin.auth` policy-verifier / auth-provider images
  and `AUTH_REF` to `v0.1.0` (built from provin.auth's matching tag).

[Unreleased]: https://github.com/provin-line/oss/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/provin-line/oss/releases/tag/v0.1.0
