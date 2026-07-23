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

### P0-1A — immutable wire-variant set (BREAKING within Unreleased)

Ratified architecture decision (debate P0-1 = B2.1, 2026-07-16), slice A of
three: identity. One body can hold several signed forms, because re-issuing a
proof leaves the body — and therefore every successor link — untouched. The VC
store kept **one** credential per body address and let a later write overwrite
it, so a valid proof could be evicted by a later invalid one, and an invalid
proof arriving first could keep the valid one out. Neither is possible now: the
variant set is write-once and append-only.

- **`WireVariantID`** (`wire:v1:jcs-rfc8785:sha256:<hex>`) names one signed form:
  `sha256("provin-wire-variant-v1\0" ‖ RFC8785(full wire document))`. The prefix
  pins the id version, the canonicalization profile and the hash algorithm, so
  none is inferred and a future profile cannot reuse this id space. The digest
  covers the canonical PROJECTION, so two peers spelling one document
  differently admit it under one id and neither can mint a second identity for
  one signed form by re-serializing.
- **Storage is now a trusted façade over a dumb backend.** `vcresolver.Store`
  and its keyed `Put(hash, cred)` are **removed**: a caller can no longer choose
  where its bytes land (both addresses are recomputed), so misfiling is not
  expressible, and the overwrite semantics are gone rather than deprecated.
  `VariantStore` enforces identity, canonical validation, write-once admission,
  winner resolution and defensive copying once, for every backend;
  `VariantBackend` (implemented by `memstore.NewBackend` / `filestore.NewBackend`)
  places named bytes and has no identity semantics at all. A Go interface is a
  method set, not a capability boundary — so the properties live above the seam,
  not in a suite the implementations promise to run.
- **`ResolveVC` changes behaviour**: it now serves the deterministic winner over
  the held variant set (the lexicographically smallest variant id), where it
  previously served whatever was written last. The projection is **provisional,
  not evidence**: it is a function of the set held right now, so it can name a
  different variant once the set grows. It answers "some signed form of this
  body" — enough for a chain hole and for the content-hash check every verifier
  runs, and not enough to audit. `ResolveVCResponse` now says which variant it
  served, so a consumer can pin it.
- **`ResolveVariant` / `ListVariants`** (additive RPCs) are the exact-fetch
  surface: byte-for-byte what was admitted, which is what evidence means.
  `StoreVCResponse` gained `wire_variant_id`; `Service.StoreVC` returns
  `StoreVCResult{BodyAddress, WireVariantID}` and `client.StoreCredential`
  returns `StoredCredential`.
- **Publish round-trip check strengthened**: it compared content addresses,
  which cover the body only — so a store holding a *different signed form of the
  same claims* passed the check that exists to catch exactly that. It now
  compares the variant, which covers the whole document, signature included.
- **Safe-integer gate widened to the full wire document**: it ran on the body,
  so an unsafe integer in a proof member was silently rounded by the RFC 8785
  re-serialization and admitted under an id naming bytes nobody sent, with the
  signature over the original literal.
- **Damage is never absence.** A body whose only copy is a damaged legacy entry
  reports corruption; answering `NotFound` would launder a tampered credential
  into "this node never held it".

Migration and rollback, on-disk (`filestore`):

- Layout: the legacy `<bodyhex>.json` slot stays exactly where it was, and
  variants live under `variants/<bodyhex>/<varianthex>.json`. The pre-slice
  reader opened that exact filename and skipped directories when listing, so the
  subtree is invisible to it: **rolling back to an older binary still resolves
  every body**, because the flat slot is maintained as the projection.
- No migration pass. A body written before this slice is read as a one-element
  variant set on demand — its bytes are exact-fetchable under their own derived
  id — and the first write to that body adopts them into the set before adding
  anything. Flat bytes are retained.
- Rollback is safe in both directions: an older binary writing the flat slot
  while a variant set exists does not lose those bytes — they are held evidence,
  and re-upgrading enumerates and adopts them rather than overwriting.
- Not claimed: two writers on one root. `PutIfAbsent` uses `os.Link` (fails
  EEXIST) rather than a replacing rename, which is cheap insurance against a
  misconfigured shared root — but cross-process fencing is P1-D's, and the
  projection refresh is not safe under two writers.

Scope: this is the identity layer (invariants 1-3, 13, 22). The audit queue and
receipt store remain keyed on the body address, which invariants 6 and 12 rule
out — a verdict must name the variant it evaluated. That is slice B, along with
the evidence views that let bundle/export/audit consumers stop using the
body-only read; until then full invariant-13 conformance is not claimed.
Quarantine, quota and backpressure (invariants 15-18) land with the P0-5 effect
gate. Evidence: `docs/evidence/p0-1a-variant-store-e2e-2026-07-16.md`.

### provin claim registry — issuance closed (profile.spec)

The provin wire profile's spec now exists (provin-line/profile.spec) and its
registry is enforced where it binds: **`vc.New` refuses to emit an unregistered
`provin:` label** (`claim.registry.closed`). Previously any grammatical,
grounded token could be issued, so the registry existed only as constants and a
typo like `provin:summarize` would sign and ship.

The receive path is deliberately untouched: a verifier meeting an unknown label
stays open-world (`credential.claim.open-world-accept`), so a newer node's
label reaches an older node safely — by default, not by coordinated upgrade.
Other namespaces pass the gate untouched; their registries are not this
profile's to enforce.

Alongside it: the profile context (`vc/contexts/provin-v1.jsonld`) is now
VENDORED from provin-line/profile.spec rather than owned here (Model A finally
has a profile repository to live in), pinned by sha256 like the protocol
context; and the profile's conformance vectors run under
`TestProvinProfileAllVectors` (grammar/grounding/registry/topology driven; the
closure norms ledgered as issuer/consumer obligations, which no library check
can drive). `Service.ListVariants` also gained the `pagination.MaxPageSize`
cap, closing a theoretical `limit+1` overflow for direct callers.

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

### Security

- Dependency: `golang.org/x/net` v0.51.0 → v0.55.0 — clears GO-2026-5026
  (`idna.Lookup.ToASCII` accepting ASCII-only Punycode labels; reachable via
  `orgverify.NormalizeFQDN`) and the x/net side of GO-2026-4918 (HTTP/2
  `SETTINGS_MAX_FRAME_SIZE` infinite loop). `x/crypto` v0.51.0 and `x/text`
  v0.37.0 ride along as transitive requirement bumps.

### Fixed

- **Replaced the HOCON parser; three silently-deleted defaults are back.** The
  config layer now uses `o3co/go.hocon`, a full Lightbend-spec implementation, in
  place of `gurkankaymak/hocon`.

  The old parser violated the spec in a way that quietly cost us settings. HOCON
  says "anything between `//` or `#` and the next newline is considered a comment
  and ignored"; that parser let a `#` comment containing a `//` sequence swallow
  the FOLLOWING line, so two documents differing only in comment text parsed to
  different results — and a URL in an explanatory comment is the natural way to
  trip it. It fails loudly only when the swallowed line carries a brace. When it
  carries a key, the file parses and the setting is simply gone:

      provin.network.auth.opa.base-url          => nil
      provin.network.auth.cedar.base-url        => nil
      provin.network.registry.service-endpoints => nil

  all now resolving to their intended `""` / `{}`, with their URL-bearing
  comments left exactly as written. Upgrading was not an option: v1.2.23 is that
  library's latest, every recent version reproduces it, and the upstream report
  (gurkankaymak/hocon#27) has been open since 2022. It had a second defect this
  layer was also working around — `Get` panicked when a path traversed a scalar
  as an object — and that recovery is gone too.

  `hoconconfig`'s facade contract is unchanged (`String`/`Int`/`Bool`/`Duration`/
  `StringList`/`StringMap`/`Keys`/`Has`, with `ErrMissingKey` vs
  `ErrTypeMismatch`), and its test suite passes as written. Strictness is now
  enforced in the facade rather than inherited: the new library coerces
  (`GetString` on an int yields `"3"`), and this layer does not — a type mismatch
  is an error, not a conversion. `ErrTypeMismatch` still distinguishes a path
  that runs through a scalar (`tls = "yes"` where `tls { cert-file = … }` was
  meant) from a key nobody set, so a caller's "absent, use the default" branch
  cannot swallow a misconfiguration.

- **The quickstart never booted.** `deploy/quickstart/node/config/application.conf`
  failed to parse — for its whole history, on every machine. Same root cause,
  loud instead of quiet: there the swallowed line carried an opening brace
  (`service-endpoints {`), so the braces stopped balancing and the parser
  rejected the file's final `}` as a stray. Nothing caught it — `docker compose
  config` validates the compose file, not the node config inside the container —
  and `TestShippedConfigsParse` now parses every `.conf` the repository ships
  with the parser the binaries actually use. Its comments keep their URLs: the
  fix was a spec-compliant parser, not a rule about what may be written in a
  comment.
- **The quickstart reported a crash-looping node as healthy.** The node service
  had no healthcheck, so `docker compose up --wait` saw a container that
  `restart: on-failure` kept "running" and declared the stack ready. It now
  waits on the node's own `/readyz`.

### Added

- `RegisterAuditHead` audit RPC: registers an ADMITTED head for linear async
  audit without a consumed-set receipt — the wire form of the data plane's
  in-process audit-head registration (ordinary sink/chained ingress and
  sink-receipt heads). `RegisterEvidence` cannot serve it: that RPC requires
  a non-empty consumed set and pins an irreversible first-write-wins receipt
  (it remains the aggregate's consumed-set path). Same admission gate, same
  queue, same L1 policy pair (`audit:register` — registering into the audit
  substrate is one grant class) plus an in-band wireauth proof over
  `head_variant_address`.
- `cmd/network`: the control-plane-only node binary (the control-plane half
  of `cmd/standalone`, extracted) — the same ConnectRPC services, DID
  resolution, and health endpoints, with no pipeline loops; it refuses to
  boot if its config declares any. `cmd/standalone` is now **deprecated**,
  remaining as the all-in-one composition until `cmd/network` and a
  pipeline-loop runtime replace it.
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
- The evidence write surface (D7): `AuditService.RegisterEvidence`,
  `PayloadStoreService.RetainPayload` (new service, client-streaming), and
  `ChainService.ReportEmitHealth`. Each is **L1 + in-band wireauth**: the PDP
  gate (the L1 policy option) decides whether the caller may write at all,
  and the request additionally carries a wireauth `AuthProof` the handler
  verifies in-band — the proven DID is authoritative over the registering
  party / payload owner / reporting publisher. New config keys:
  `provin.network.pipeline.max-retain-chunk-size` /
  `max-retain-payload-size` (RetainPayload's per-frame and cumulative-size
  quotas) and `provin.network.chain.emit-health.ttl` /
  `advertise-without-reports` (ReportEmitHealth's report freshness window and
  fail-degraded policy).
- Auditor receipts are first-write-wins: `RegisterEvidence`'s consumed-set
  receipt is pinned on the first successful write, and a later write carrying
  a canonically different set returns `auditor.ErrReceiptConflict` instead of
  silently overwriting it. Consumed-set members are enforced against the full
  content-address grammar (`sha256:<64 lowercase hex>`), closing a path where
  a malformed member could be recorded into an otherwise-immutable receipt.
- `CONFIDENCE_UNRESOLVABLE`: a new audit verdict recorded when chain assembly
  cannot resolve a head after max retries — a resolution outcome (the runner
  never obtained the evidence needed to verify at all), distinct from
  `CONFIDENCE_INDETERMINATE` (a verification outcome: the evidence was
  obtained and evaluated, but the verdict itself could not be concluded).
- Tlog mirror custody: two new TlogService RPCs, `MirrorLogSegment` and
  `GetMirrorState`, let a background shipper on each pipeline process
  replicate checkpoint-aligned segments of its local signed emission log to
  the registry, which custodies and serves the verified prefix — it never
  re-signs. Sync-append stays rejected, so mirroring never rides the
  per-emission hot path; an unmirrored terminal tail is lost from the
  registry's view within the flush interval, and a process that loses its
  local volume rolls to a fresh log identity rather than resuming the old
  one. `MirrorLogSegment` is L1 + in-band wireauth: the PDP gate decides who
  may mirror, and the wireauth proof binds `log_id`, `from_index`,
  `checkpoint.head`, and a digest over the ordered record payload hashes.
  A segment's records travel as one length-prefix-framed blob
  (`record_payloads_framed`), which the registry decodes as a single
  wire-sized allocation and unframes under the batch caps at the decode
  boundary — so a hostile request cannot amplify into an unbounded
  per-element allocation before the caps or the wireauth proof are checked.
  `GetMirrorState` is a plain L1 read (`tlog:read`), the same posture as
  `GetLogCheckpoint`/`ListLogRecords` — no wireauth proof involved. A single
  fail-closed log-identity predicate (`tlogservice/logident`) classifies a
  log id as emission / sink-receipt / sink-reject; the mirror service
  (`tlogservice.Service.MirrorSegment`) uses that classification to pin the
  exact process signer on a log's first accepted segment, so a sibling
  process under the same pipeline can never take over an existing log. The
  registry's mirror store (`tlogservice/mirrorstore`, under
  `DataDir/tlog-mirrors/`) persists the remote loop-signed checkpoint
  verbatim — it has no loop key and never synthesizes one — and serves only
  its verified prefix. It is crash-durable: journals fsync before their
  checkpoint, each log directory is fsynced, and the mirror root's parent is
  fsynced on open, so an acked segment survives power loss.
- Archival sink reject logs now sign their checkpoints with the same
  receipt-issuer identity their config already requires
  (`sink-reject:<receipt-issuer process DID>`), giving them a stable,
  mirrorable identity. They remain custody-only: still never served over
  TlogService reads.
- `tlog/filelog.Log` gains **`CheckpointAt`** (new, additive public method): a
  signed checkpoint over an arbitrary earlier prefix, not just the log's
  current head — the capability the mirror shipper needs to produce a
  checkpoint covering exactly one cap-bounded batch's end. It is deliberately
  outside the `tlog.Log` contract (`memlog` cannot sign at all, and the
  tlog-custody spec's v0 scope excludes `merklelog`), so callers detect it
  structurally instead of every implementation being forced to stub it.
- New config keys `tlog-mirror.max-batch-records` (default 256) and
  `tlog-mirror.max-batch-bytes` (default 4 MiB) bound the shipper's batch
  sizes (the shipper's ticking cadence itself defaults to 5s via
  `tlogship.DefaultFlushInterval`, a Go constant — not a config key). A
  boot-time coherence check now requires `max-batch-bytes >=
  max-credential-size`: a sink-receipt record can carry a full credential, so
  a batch cap below the credential cap could never ship one, even alone.
- `pipeline/runtime`: the network-agnostic data-plane assembly (source/sink/
  chained loop wiring, keystore-backed signing, ingress storage) both
  deployment roots compose. AGENTS.md layer rule 2 (`network/` and
  `pipeline/` never import each other) is now compiler-enforced across the
  whole `pipeline/` tree and pinned by a depsguard test
  (`pipeline/runtime/depsguard_test.go`, mirroring `cmd/network`'s).
  `cmd/standalone` composes it today, through in-process seams;
  `cmd/pipeline` — the data-plane-only binary — arrives next.
- `wireprofile`: the shared wire-convention leaf (`ByReferenceSubjectPrefix`)
  that lets `network/` and `pipeline/` agree on wire constants without
  importing each other.
- `hoconconfig.LoadFile(fileEnv string)`: the `CONFIG_FILE` convention for
  STL (short-lived, per-execution) binaries — a REQUIRED root config file
  named by an environment variable, whose relative `include` directives
  resolve against the FILE's own directory rather than the process's
  working directory (unlike `cmd/network`/`cmd/standalone`'s
  `./config/application.conf` + `CONFIG_OVERLAY` layering, which assumes a
  long-lived working directory). `cmd/pipeline` (below) is its first caller.
- Wire-contract leaf extraction: `auditor`/`tlogservice`/`payloadresolver`
  op-names and signed-view builders now live in per-service `wirecontract`
  leaf packages (stdlib + `vc` only, never `gen/`, never a service root), so
  a wire client can depend on the contract without pulling in server-side
  store/runner logic transitively; each service root keeps back-compat
  aliases, so no existing call site changes.
- `network/pkg/services/schemaregistry/client`: a bounded,
  bearer-authenticated `GetSchema` wire client, mapping a remote NotFound to
  a local `ErrNotFound` sentinel (`errors.Is`) so callers whose semantics
  depend on it (e.g. a full-chain verifier's indeterminate-vs-failed split)
  can distinguish a definitive miss from a transient transport failure.
- `cmd/pipeline`: the data-plane deployment root — an STL (short-lived,
  per-execution) binary that composes `pipeline/runtime` entirely against
  WIRE clients to a `cmd/network` registry (`VCResolverService.StoreVC`,
  `AuditService.RegisterAuditHead` / `RegisterEvidence`,
  `PayloadStoreService.RetainPayload`, `ChainService.ReportEmitHealth`,
  `SchemaService.GetSchema`), never through an in-process registry of its
  own and never importing `cmd/network`'s control-plane packages (AGENTS.md
  layer rule 2). Four named fail-closed boot guards: a zero-loop config is a
  misconfiguration for this binary (run `cmd/network` instead); loops
  require the NATS transport; any loop requires BOTH
  `provin.network.pipeline.vc-store-endpoint` and its bearer, since the
  endpoint doubles as the ONE registry base URL for every wire dependency
  this binary composes; and the DID resolver must be constructible
  (including the F8 private-network posture). Every wire call signs as a
  specific local identity held in this binary's OWN pipeline-local keystore
  (`DataDir/keys` — the registry never holds a loop key): the node's own
  subscriber identity for audit-head registration, each loop's configured
  issuer for evidence/receipts, and — per OWNING producing loop, since a
  node can run more than one — its own output-subject identity for
  by-reference payload retain, because `PayloadStoreService.RetainPayload`
  enforces `owner_did == the wireauth-proven signer` and a shared
  node-identity client could satisfy at most one loop's retains before
  every other loop's emission aborted. A fifth boot guard preflights that
  every producing loop's retain key is provisioned, turning that gap into a
  clean boot failure instead of a first-emit surprise. Its HTTP surface is
  minimal: `/healthz` (liveness), `/readyz` (NATS + registry reachability),
  and the configured `/ingest/<loop>/...` push routes — no ConnectRPC
  services of its own, and (unlike `cmd/network`/`cmd/standalone`) no
  `/metrics` yet (deferred). Shutdown runs in a FIXED order (tlog-custody
  spec D8): the HTTP server drains in-flight requests, then the data-plane
  loops drain, then the mirror shippers and emit-health reporters stop,
  then each shipper gets one final flush attempt on a fresh context, then
  the shared NATS connection and every durable log's file handle close.
- The mirror shipper (Tlog mirror custody, above) is now LIVE: `cmd/pipeline`
  wires one `tlogship.Shipper` per durable custody log
  (`pipeline/runtime.Runtime.CustodyLogs()` — every local durable log the
  binary opened, sink-reject logs included), each shipping through a
  `network/pkg/services/tlogservice/client.Client` signed as that SPECIFIC
  log's own checkpoint-signer identity, and torn down as part of
  `cmd/pipeline`'s ordered shutdown above (each shipper's final flush runs
  on a fresh, never-already-canceled context; a drain that cannot finish
  within its budget is not a shutdown failure — the tail stays durable
  locally and the next boot's shipper resumes it from the registry's own
  acked cursor). `cmd/standalone` still does not ship: it continues to
  serve TlogService reads from its in-process map and mirrors nothing.

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
- **BREAKING (import path)** `chainwalk` moves from
  `pipeline/provenance/chainwalk` to `vc/chainwalk`: it is vc-domain
  verification, not a pipeline concern. No behavior change — update the
  import path.
- `cmd/network`'s registry now always drains its wire-fed pool: the batch
  resolver and audit runner no longer gate on `HasConsumingLoop()` (a
  predicate that is meaningless for a binary that runs zero pipeline loops by
  construction) — they boot-validate a non-empty VC-store bearer before
  constructing themselves, rather than silently starving every peer fetch at
  runtime. `cmd/standalone` reproduces the old gate at its own call site, so
  its zero-loop/source-only behavior is unchanged.
- `cmd/network` by-reference advertisement is now publisher-scoped and
  fail-degraded: a publisher self-reports its stripped-publish health via
  `ReportEmitHealth`, and `NeverReported` / `Expired` / unhealthy reports
  degrade advertisement for that publisher unless
  `chain.emit-health.advertise-without-reports` is set (default `false`).
  `cmd/standalone`'s existing node-global `WithByReferenceHealth` gate is
  unchanged.
- `dplaax.did.v1` external-key issuance: `IssuePipelineRequest` /
  `IssueProcessRequest` gain an optional field 3, `ExternalPublicKeys` (raw
  32-byte Ed25519 `auth_public_key` / `signing_public_key`), letting the
  caller mint its own Pipeline/Process `#auth`/`#signing` keypair LOCALLY and
  hand the registry only the public halves. Present, `didregistry` assembles
  and registers the document over exactly those public keys (the same
  Multikey encoding a server-generated key gets) and never mints or stores a
  private key for the DID; absent, today's server-side mint is unchanged —
  the back-compat default every existing caller keeps using. This closes the
  hole the all-in-one `cmd/standalone` masked once the topology separated:
  the tlog-custody trust model's premise is "the registry has no loop key,"
  but `IssuePipeline`/`IssueProcess` minted BOTH keypairs server-side
  regardless of deployment shape, so a `cmd/pipeline` data-plane node had no
  way to keep its own signing key off the `cmd/network` registry that mints
  it. Delegation verification and every other authorization check are
  identical in both modes; no PDP/policy change — the RPC-level `dids:issue`
  grant already covers both, since it gates the method, not the request
  shape. No dedicated didregistry client wrapper package exists to extend:
  `cmd/provin` and every other consumer drive the generated
  `didpbconnect.DIDServiceClient` directly, so the regenerated surface is
  immediately usable with no further client-side change.

### Removed

- `pipeline/chained/cmd/` placeholder (the standalone runtime is the one
  chained-loop binary).
- `cmd/standalone` — the all-in-one node binary (control plane + data plane
  in one process), deprecated since `cmd/network`'s addition earlier in this
  line. Production is now `cmd/network` (control plane) + `cmd/pipeline`
  (data plane) as two separately deployed, wire-composed binaries; no
  all-in-one binary survives. The separated topology has its own end-to-end
  proof: this repository's `cmd/pipeline/separated_e2e_test.go` and the
  `provin.e2e` harness's 11 scenarios, both green against real
  `cmd/network` + `cmd/pipeline` processes over a real broker. Coverage
  cmd/standalone's own test suite carried that had no successor was
  relocated to its honest home rather than dropped: `internal/httpserve` and
  `internal/netcompose` gained their first direct unit tests for
  `BuildServer`/`HTTP2Server`/`OuterRequestCapBytes`/`BuildMetricsHandler`/
  `MaybeMountMetrics`/`WithMetrics` (previously exercised only incidentally,
  through cmd/standalone), and `cmd/pipeline` gained a direct unit test for
  its `pushRoutes`' PDP-denial (403) mapping (`push.go` there is cmd/standalone's
  former copy, now the only one).

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
