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
  six-member proof configuration, and the base58btc (`z` multibase)
  `proofValue` encoding.
- Both cryptosuites and their canonicalizations: `eddsa-jcs-2022` (RFC 8785,
  Phase-1 MUST, issuance default) and `eddsa-rdfc-2022` (URDNA2015, Phase-2,
  opt-in), each anchored to the official W3C vc-di-eddsa test vectors with
  every intermediate pinned. The URDNA2015 behavior is additionally pinned by
  a provin-shape KAT against json-gold v0.8.0.
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
