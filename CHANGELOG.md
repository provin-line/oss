# Changelog

All notable changes to this repository are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the version is `0.x`, exported Go API and configuration keys may still
change between minor releases. The **v0 credential wire is frozen** as of the
`0.2.0` line below (see its freeze declaration): changing any byte of the
credential Data Integrity signing scope is a next-MAJOR break, not a minor
change. The first frozen *API* surface is declared at the `1.0` line.

## [Unreleased]

### Added

- `keybinding`: the key binding — a `KeyBindingCredential` in which an issuer
  binds a key (`keyId` and an RFC 7517 public JWK in its one RFC 7638 spelling:
  Ed25519, P-256 or RSA, each a key the `crypto` validators accept) to a
  subject, of a kind, with roles (always a list), of a key class, for one
  relying party (`audience`), from `validFrom` until `validUntil` (both
  required, UTC to the second), with a `BitstringStatusListEntry` in the
  issuer's revocation list — and the revocation list itself (a W3C
  `BitstringStatusListCredential`, at least 131 072 entries, at most 16 MiB
  expanded). `Issue` and `IssueStatusList` sign with eddsa-jcs-2022;
  `Verifier.VerifyBinding` checks a binding against the trust `Anchor` (the
  issuer, its issuance keys, the longest validity, the oldest list) and the
  held list, and `Verifier.VerifyStatusList` checks a list and refuses one
  older than the one held, a later one that clears a mark of the one held
  (`ErrStatusListRevocationCleared`: a revocation is not reversible, so an
  issuer restored to an older state cannot undo one in the list held; a mark
  past the end of a shorter list counts as cleared), one not yet valid, and
  one whose id is not a DID URL of its issuer. Two lists of the same
  `validFrom` are the same list when their content hashes are equal: the
  SHA-256 of the RFC 8785 form of the credential without its proof, with
  `encodedList` replaced by `sha256:` and the lowercase hex SHA-256 of the
  expanded bits. So the same list compressed otherwise (gzip's bytes differ
  between Go versions and between issuers) is the same list, and every other
  member is covered as it is. `Verifier.RestoreStatusList` rebuilds the held
  list after a restart from the last raw list held, checked
  the same way but however old (not dated after the given time), as the floor
  of the marks a later list must keep; `VerifyBinding` takes it only while it
  is current. A list whose signing key has left the anchor is not held,
  restored or in a running process, and its marks are not compared. An index
  marked stays marked in every later list of that id. A `StatusList` is
  read-only (accessors) and is current only while its signing key is in the
  anchor. The wire holds no JSON numbers (the list index is a decimal string).
  Each refusal is a constant `keybinding.Error`; `ErrSignatureUnestablished`
  (the issuer's document unavailable now) is not `ErrSignature`. What an
  issuer may bind (its scope) is not evaluated here.

- `decisionrecord`: the record a deciding party writes for each decision
  (`Record`: id, deciding party, time, outcome — `Accepted`, `Refused`, or
  `Unenforced` when only checks the deciding party records without enforcing
  refused: the deciding party did not enforce the refusal, and a reader takes
  what was decided on as one that may have gone ahead — the refusing check
  and reason, the parties it is attributed to, what was decided on as an
  ordered list of content addresses, the party's own fields — never a
  payload; a decision has the strongest outcome of its records, refused over
  unenforced over accepted), and `Filter`, which writes it at a level chosen
  explicitly: `all`, `refusals` (refused and unenforced records), `summary`
  (`Summary`, each decision counted once per window by its outcome, through
  `SummaryRecorder`, keeping the ids of accepted decisions only, so a flood
  of refusals or unenforced decisions does not grow its memory; a writer
  records a decision accepted any number of times, then unenforced or
  refused at most once, see `Record`) or `none`;
  the zero level and a `Filter` not made by `NewFilter` are refused. At `all` a
  record the sink does not accept is an error, so the deciding party refuses
  the decision; at other levels it is a warning, so an unenforced decision
  may go ahead without its record. A malformed record (`Record.Validate` states
  the rules: what a reader keys on is present and valid UTF-8, a time within
  the years 0000–9999, a check exactly on a refused or unenforced record,
  each evidence a role and an address) is an error at every level, `none`
  included. A `Summary` follows the same kind of rules (`Summary.Validate`),
  with each count from 0 to 2^53−1 (`Count.N` is an `int64`) and the counts
  ordered by outcome, then check, each compared as text (`accepted`,
  `refused`, `unenforced`). Every sink in this package checks records and
  summaries as well. Evidence addresses are
  `contentaddress.Address`. Sinks: JSON lines (`NewJSONLines`) and
  structured log (`NewLog`). The purpose-first sink writes its delivery
  decisions through it (see Changed).

- `contentaddress`: the content address of dPLaaX (`sha256:` and 64
  lowercase hex digits) as a type, `Address`, that only `Of` (the address of
  bytes) and `Parse` (that one spelling and nothing else) make. It is
  comparable and a map key, the zero `Address` is no address (`IsZero`), and
  it is written and read as JSON text in its one spelling (`MarshalText`,
  `UnmarshalText`; the zero `Address` is not written, so a field that may
  hold none is a pointer or carries `omitzero`).

- `vc.IssuerVerifier`, `vc.WithIssuerVerifier`, `vc.NewDIDDocumentIssuers`,
  `vc.IssuerKey`, and the constant `vc.ErrIssuerNotFound` (of the new type
  `vc.Error`): how a `vc.Verifier` establishes an issuer — the key its proof
  verifies under, and the Owner responsible for it — can be replaced, so a
  deployment that registers its stages elsewhere needs no DID document per
  stage. The default, `NewDIDDocumentIssuers`, reads both from DID documents as
  before. The Verifier keeps the proof policy (run before the key is asked for),
  the rule that the key is the one the proof names (`IssuerKey.ID` must be its
  `verificationMethod`), the proof verification, and the rule that the Owner is
  the one the issuer's Process DID names (`credential.field.issuer`); `Verify`, `VerifyChain`,
  `VerifySignerAuthenticity`, `AttributeOwner` and `ClassifyChain` all go
  through it. An error wrapping `ErrIssuerNotFound` reads as failed, any other
  as indeterminate.

- `vc.ValidateChainLinks(chain)` and `vc.ValidateChainFrom(chain, originInput)`:
  the links of a chain (origin first) without its signatures — the origin
  claims no predecessor; each later credential names its predecessor's content
  address, takes its non-empty `outputHash` as `inputHash`, and includes its
  issuer in a source commitment it carries — through the same implementation as
  `VerifyChain`. `ValidateChainFrom` also requires the origin's `inputHash` to
  be `originInput`. A broken link is a `*vc.ChainLinkError` with the
  credential's index; an empty chain, a nil credential or an empty
  `originInput` is another error. A prefix of a linked chain is linked.

- `vc.Credential` and `(*vc.Verifier).VerifySignerAuthenticity`: the
  signer-authenticity axis alone, for a Data Integrity–secured credential of any
  type, returned as `vc.SignerAuthenticityResult` (state; suite contract,
  issuer and verification method, set only when the proof verified;
  notations). It is the same evaluation, through the same implementation, as
  `Verify`'s axis (proof policy, issuer DID resolution, the assertionMethod key,
  the proof, the cryptosuite lifecycle) and checks nothing of the credential's
  type or content. A caller accepts only the suite contract and the key its
  credential type requires; under the RDFC contract, JSON shapes that expand to
  the same statements verify alike. `Credential` is read only through
  `UnmarshalJSON` (the strict decoder); `Credential.Issuer` reads a string
  issuer or an issuer object's `id`, and `Credential.Types` is nil for a
  malformed `type`.

- `crypto/es256` and `crypto/rs256`: `crypto.Verifier` implementations for
  ES256 (ECDSA P-256 with SHA-256; the key is the SEC1 uncompressed point, the
  signature `r || s`) and RS256 (RSASSA-PKCS1-v1_5 with SHA-256; the key is the
  DER of a PKCS #1 RSAPublicKey with an odd modulus of 2048 to 4096 bits).
  Malformed keys and signatures are typed errors (`Error` constants), as with
  `crypto/ed25519`. ES256 signature bytes are not unique (`(r, n-s)` verifies
  as `(r, s)` does), so nothing may count or deduplicate signatures by them.

- `provin.network.auth.plain-internal` (list of `host:port`, default empty):
  the PDP endpoints that may be called over plaintext `http://`. A listed
  endpoint is reached only at a private address (checked on every connection).
  Applies to the `o3co`, `opa` and `cedar` backends; a malformed entry fails
  startup naming the key. The quickstart configs set it for
  `policy-verifier:3001`.
- `(*vc.DataIntegrityProof).ProofValueBytes` returns the bytes a proof's
  `proofValue` encodes, decoded by the encoding its cryptosuite sets:
  multibase base58btc, carrying the signature, for eddsa-jcs-2022 and
  eddsa-rdfc-2022. It verifies nothing: not the signature, and not whether
  `vc` supports the cryptosuite. Its decoding is bounded as
  `multibase.DecodeBase58Btc` bounds it. `vc.VerifyProof` and
  `vc.VerifyProofUnderContract` decode through it.
- `canon.DuplicateKeyError.Other`: for a key refused because it differs from
  another key, or from a struct field, only in case (see Changed), that other
  key or field name. Empty for an exact duplicate, as before.
- `(*delegation.DelegationCredential).UnmarshalJSON`: a delegation credential
  is read under `canon.StrictDecoder`'s rules by encoding/json too.
- `(*bundle.Manifest).UnmarshalJSON` and `bundle.Manifest.MarshalJSON`: a
  bundle manifest decoded with encoding/json is read as `bundle.Verify` reads
  it, strictly and in the exact shape of its version, and is written in that
  shape, as `bundle.Export` writes it.
- `appraisal.SpineEntry.Extensions` (`map[string]any`, as
  `appraisal.Manifest.Extensions`): the members of a spine entry other than
  `bodyAddress` and `wireVariantId`, which the dPLaaX schema admits. They are
  kept when a manifest is read and are in its identity (`ID`). An extension
  that is one of the two fields, exactly or in another case, gets no identity
  (`Validate`). `SpineEntry` has its own `MarshalJSON` and `UnmarshalJSON`,
  which read and write an entry as a manifest does.
- `provin.network.pipeline.credential-origins` (default `[]`): origins
  (`scheme://host[:port]`) `vc-store-bearer` may be shown to besides the
  destinations the operator configured (`vc-store-endpoint` and each loop's
  `upstream-endpoint`, which are always included): peers the pipeline learns
  of at runtime. In Go, `pipelineconfig.Config.CredentialOrigins` holds them
  (the loader writes scheme and host lower case, without the default port),
  and `(*pipelineconfig.Config).PresentsCredentialTo` reports whether any fetch
  of the pipeline may present the bearer to an endpoint, reading any spelling
  of a listed origin. A value that is not an http(s) origin fails startup.
- `provin bundle export --credential-origin <origin>` (repeatable): an origin
  (`scheme://host[:port]`) the `--token` may be shown to, besides
  `--registry`'s, read in the same spelling as `credential-origins`.
- `canon.Float64(n json.Number) (float64, error)`: the IEEE 754 double
  nearest the value of a JSON number (ties to even), read from the RFC 8259
  grammar only, whatever its exponent; its value does not depend on how the
  number is spelled, and its work is linear in the length of the literal. A
  number that rounds to zero is ±0. Every error it returns wraps exactly one
  of `canon.ErrNotJSONNumber`, for anything that is not an RFC 8259 number,
  and `canon.ErrBeyondDoubleRange`, for a number that rounds to infinity
  (constants of the new type `canon.Error`, the errors canon reports by value;
  match them with `errors.Is`). Every `json.Number` this module reads as a
  double is read through it.

### Changed

- **BREAKING (Go API)** `eddsa-rdfc-2022` is registered only when a process
  calls the new `vc.RegisterEdDSARDFC2022`; `vc`'s init registers
  `eddsa-jcs-2022` alone. Until then nothing in `vc` issues or verifies an
  `eddsa-rdfc-2022` proof or runs JSON-LD processing: `vc.CreateProof`,
  `vc.VerifyProof`, `vc.VerifyProofUnderContract` and
  `vc.VerifyProofWithContract` refuse it before reading anything else of
  the proof, and the `vc.Builder` where it creates the proof, with an error
  that wraps the new `vc.ErrCryptosuiteNotRegistered` and names
  `vc.RegisterEdDSARDFC2022`. `vc.CreateProof`, the `vc.Builder` and
  `vc.VerifyProof` wrap it for any suite nothing registers too, in place of
  their former "unknown cryptosuite" error. A `vc.Verifier` finds its signer
  authenticity
  failed before looking up the issuer. Verifying such a proof canonicalizes
  the untrusted document before its signature is checked, so a verifier
  takes that on only when it chooses to. A process that issues or verifies
  the suite calls the function once, from its `main` or an `init` function
  of its main package; a second call does nothing. The function's doc
  states the bounds and the forms refused. `vc.RegisterCryptosuite` refuses
  the suite's name, and `scripts/check-rdfc-registration.sh` (`make lint`)
  keeps every package of this module from calling the function. This amends
  the v0.2.0 credential wire freeze, for security (below, under 0.2.0).
- **BREAKING (Go API and wire)** `eddsa-rdfc-2022` accepts as `@context`
  only the IRIs of the three contexts `vc` embeds (the W3C VC v2 context,
  dplaax's and provin's): `vc.CreateProof`, the `vc.Builder` and every verify
  function refuse a document, or a proof, holding a context written in it,
  at any depth (a term's scoped context and an `@import` included), `null`,
  or another IRI, before it is canonicalized (Security, below). Credentials,
  presentations and provin's documents of the embedded contexts alone are
  unchanged. `canon/urdna2015`'s `Canonicalize`, called by a program itself,
  still reads a document's own contexts.
- **BREAKING (wire)** provin's own binaries do not call
  `vc.RegisterEdDSARDFC2022`, so they refuse an `eddsa-rdfc-2022` credential
  they verified before; this release has no setting that turns the suite on
  in them. `eddsa-jcs-2022`, the issuance default, is unchanged.
- **Delivery decisions are now recorded by default** (at `all`, no payload is
  delivered without its accepted record; refusal records are best effort; the
  other levels keep less). Every delivery decision of the purpose-first sink (a sink loop with an `agent-access` block;
  `sink.Config.Appraiser`) writes a `decisionrecord.Record` through the new
  `sink.Config.DecisionRecorder`: an envelope that does not decode is refused
  (check `decode`); the appraisal's decision is accepted on `ACCEPT` and refused
  (check `appraisal`) otherwise, with the attributes `appraisalDecision` and
  `decisionProfile`. A decision recorded as accepted that a later stage refuses
  is recorded again under the same `DecisionID` as refused, the check being that
  stage's reject reason (`verdict`, `allow-list`, `ingress-store-failure`,
  `malformed-credential`, `payload-fetch`, `payload-delivery-violation`,
  `binding-gate`, `appraisal`); a context cancellation before the write is
  refused with check `cancelled`. An error from the writer is never recorded as
  a refusal (the writer may have delivered): the decision gets a further
  accepted record whose reason says the write outcome is unknown. Records hold
  content addresses (the EvidenceView ID, and the payload address on the
  write-outcome record), never payload bytes. The legacy verifier path is
  unchanged. **It is on for every user of the purpose-first sink**, at level
  `all`: if the accepted record cannot be written the delivery is refused (new
  reject reason `decision-record`), and the default `log` output writes one
  `info` entry per record (a decision that is accepted and then refused or
  write-errored writes two). Turn it off with
  `provin.decision-record.level = "none"`. Records after the accepted one are
  best effort: if one cannot be written the accepted record stands, so the
  record may show an acceptance that was not delivered, never a delivery without
  its acceptance. HOCON configs are unaffected: the keys below have defaults, so
  existing configs keep booting, and a malformed value fails startup naming the
  key.
  - `provin.decision-record.level`: `all` (default) | `refusals` | `summary` |
    `none`.
  - `provin.decision-record.sink`: `log` (default, the process's structured
    logger) | `jsonl`.
  - `provin.decision-record.path`: the JSON-lines file; required when `sink` is
    `jsonl`, an error otherwise. Opened append-only and unbuffered (mode 0600
    when created; the mode of an existing file is unchanged), closed on
    shutdown. Lines are written to the OS without `fsync` (the same posture as
    the sink file output), the file grows without bound (rotate with
    copytruncate or a restart), and an unterminated last line from a previous
    process is ended with a newline before the first new record.
  - `provin.decision-record.summary-window` (default `1m`): how often counts
    are written at level `summary`, and once at shutdown.

  **BREAKING (Go API)**: `sink.New` with `Appraiser` and no `DecisionRecorder`
  fails with `sink.ErrMissingDecisionRecorder`; `runtime.Build` with a sink loop
  that has `agent-access` fails unless `runtime.Config.DecisionRecord` is set
  (embedders that call `runtime.Build` must set it; the zero value is refused).
  New: `sink.RejectDecisionRecord`, `pipelineconfig.Config.DecisionRecord` and
  `runtime.Config.DecisionRecord` (`Level`, `Output`, `Path`, `SummaryWindow`).

- `vc.Verifier.AttributeOwner` and `ClassifyChain` errors for an Owner that is
  established not to exist (a broken controller chain, an issuer that is not a
  Process DID) now wrap `vc.ErrIssuerNotFound`; a transient failure does not.

- The signer-authenticity axis fails a credential whose issuer is empty before
  resolving anything; with a bare-fragment `verificationMethod` it could
  previously be indeterminate during a resolver outage. `Verify`'s overall
  verdict does not change: the wire form already fails an empty issuer.

- **BREAKING (config)** `backend = "cedar"` verifies the caller's bearer JWT in
  the node and asks the Cedar agent about the token's `sub`; previously the raw
  bearer was the principal. Existing cedar configs must add
  `provin.network.auth.cedar.jwt.{issuer,audience}` and exactly one of
  `jwks-url` (https) / `secret` (with optional `secret-encoding`: `utf8` |
  `hex` | `base64`), or the node does not boot. With `jwks-url` the key set is
  cached 10 minutes, refetched at most every 30 seconds, and kept as a 30 minute
  stale grace for known key ids, so a withdrawn key can be trusted for up to 40
  minutes during a JWKS outage.
- **BREAKING (config)** A PDP at a non-loopback `http://` URL is refused unless
  its `host:port` is listed in `provin.network.auth.plain-internal`
  (`protobuf.interceptors` v0.5.0+). Deployments with a plaintext PDP on a
  private network must add the entry or the node does not boot.
- **BREAKING (wire)** A PDP outage is reported as `Unavailable`. With
  `protobuf.interceptors` v0.6.0 an unreachable or overloaded PDP (HTTP
  429/502/503/504, timeout) fails an L1-guarded RPC with ConnectRPC
  `Unavailable` instead of `Internal`, and the pipeline's push endpoint answers
  503 with `Retry-After` instead of 403. The pipeline's wire retry therefore
  retries L1-guarded RPCs through a PDP outage within its existing budget. HTTP
  500 and malformed PDP answers remain `Internal` / 403. With the `cedar`
  backend a token-check failure, a JWKS outage included, stays
  `Unauthenticated`.
- **BREAKING (wire)** With the `o3co` backend an allow now requires HTTP 200 with
  a complete decision envelope (`resource`, `action`, `decision`, `reason` with
  `reason.groups`); an empty 200 or 204 no longer allows. The PDP also must not
  redirect.
- CLI: `owner init`, `pipeline create`, `process create`, `bundle export`,
  and `bundle verify` now reject unexpected positional arguments after
  flags as a usage error, matching the Stage 2 commands. Previously stray
  arguments were silently ignored and the command proceeded.
- **Binaries build on Go 1.26.8, and the module needs Go 1.26.** The network,
  pipeline and quickstart provision images move from `golang:1.25.5-alpine`
  to `golang:1.26.8-alpine`, `go.mod` pins `toolchain go1.26.8`, and its minimum
  is `go 1.26.0` (required by `protobuf.interceptors` v0.6.0). Go 1.25 no longer
  receives security fixes: `govulncheck` reported 18 standard-library
  vulnerabilities on the old toolchain and reports none now.
- Dependency refresh: `github.com/o3co/protobuf.interceptors` (and its
  `connectrpc` module) v0.2.0 / v0.2.1 → v0.6.0, which authorizes a stream
  before its handler runs, refuses placeholder values that would restructure
  the authorized resource (no policy here uses placeholders), and re-checks a
  stream per message; `connectrpc.com/connect` 1.21.0, `nats.go` 1.53.1,
  `nats-io/jwt` 2.8.2, `nkeys` 0.4.16, `o3co/go.hocon` 1.13.0,
  `golang.org/x/crypto` 0.57.0, `golang.org/x/net` 0.60.0, `golang.org/x/sys`
  0.48.0, plus `github.com/go-jose/go-jose/v4` 4.1.6 (new, for the cedar JWT
  check).
- Dependency refresh to the latest releases: `connectrpc.com/connect` 1.21.1,
  `nats-server` 2.15.1 and `nats.go` 1.55.0, `o3co/go.hocon` 1.14.2,
  `piprate/json-gold` 0.9.1, `prometheus/client_golang` 1.25.0,
  OpenTelemetry 1.47.0 (`exporters/prometheus` 0.69.0), `golang.org/x/net`
  0.61.0, `golang.org/x/sys` 0.49.0, and what `go mod tidy` carries with them
  (`golang.org/x/crypto` 0.58.0, `x/text` 0.43.0, `x/time` 0.16.0). The
  quickstart's broker image moves to `nats:2.15.1`, the server line the
  broker-contract tests now run against.
- Quickstart: the auth layer moves to provin.auth v0.3 (the `:v0.3` images,
  `AUTH_REF=v0.3.0` for the source-build fallback). Its policy-verifier
  accepts only RFC 9068 access tokens, so every token the quickstart uses now
  carries `iss` and `aud`, and the ones it mints itself (the bootstrap token
  and the pipeline's service token) are typed `at+jwt`. The audience is
  `https://quickstart.provin.invalid` (override: `OAUTH_JWT_AUDIENCE`); the
  provider takes its DID-grant `allowedAudiences` from the new
  `auth-provider/quickstart.conf` overlay.
  Two defaults change because v0.3 refuses the old ones at boot: the shared
  HS256 secret is now long enough to carry 32 bytes of key material after
  decoding, and the issuer is `http://localhost:3000` (the provider requires
  https for a non-loopback issuer; the issuer is an identifier, not a URL
  anything dials). An existing `.env` that sets `OAUTH_JWT_SECRET` or
  `OAUTH_JWT_ISSUER` must meet the same rules.
- `vc.VerifyProof` and `vc.VerifyProofUnderContract`, and through them
  `vc.VerifyProofWithContract`, decode `proofValue` before they canonicalize
  the proof configuration and the document. A `proofValue` that does not
  decode (not base58btc, or longer than `multibase.DecodeBase58Btc` allows)
  is refused without canonicalizing anything: an eddsa-rdfc-2022 proof over
  an ordinary credential took about 560 µs and 400 KB to refuse this way,
  and takes about 1 µs. A `proofValue` that decodes still costs a
  canonicalization before its signature is checked, so this does not bound
  the work a forged proof can cause. A proof whose `proofValue` does not
  decode, over a document that does not canonicalize, is now refused with
  the decode error rather than the canonicalization error.
- **BREAKING (Go API)** `vc.VerifyProof` refuses a proof without a
  proof-local `@context` over a document with one. A legacy eddsa-jcs-2022
  proof, which has none, is verified with `vc.VerifyProofWithContract` or
  `vc.VerifyProofUnderContract`. An eddsa-rdfc-2022 proof without one, the
  shape vc-di-eddsa §3.2.1 produces, is now refused by every verify function
  in `vc`: this package's RDFC contract requires the member, and
  `vc.VerifyProof` was the one path that accepted it.
- `vc.Verifier` (signer authenticity) refuses a proof no key can verify, one
  under a cryptosuite no claim contract names or one whose `proofValue` does
  not decode, before it looks up the suite's lifecycle phase or the issuer's
  key; `delegation.Verify` refuses one whose `proofValue` does not decode
  before it resolves the issuer. `vc.Verifier` now gives such a proof a
  failed verdict where a transient issuer-key error made it indeterminate,
  so a caller that retries indeterminate verdicts no longer retries it, and
  it fails a proof under a suite no claim contract names whatever a
  lifecycle registry says about the suite. `keybinding`, which maps those
  verdicts, returns `keybinding.ErrSignature` for such a proof where it
  returned `keybinding.ErrSignatureUnestablished`. `delegation.Verify` now
  returns the decode error, without resolving, where it returned the
  resolver's error (also one wrapping `resolver.ErrNotFound`) or the
  key-extraction error.
- **BREAKING (Go API)** `canon.AdmitSafeNumbers` refuses a number of
  magnitude 2^53 − 0.5 or more, whether or not it is an integer: a
  non-integer such as `9007199254740991.5`, which binary64 rounds to
  9007199254740992, is now refused where it was admitted. Below the bound
  nothing changes, nor do the refusals of a literal that is not an RFC 8259
  number or whose exponent lies beyond the bounds. Every number refused for
  its magnitude, integers included, has one new `UnsafeNumberError.Reason`
  text, whatever its kind; code that matched the old text must change.
  `canon/testdata/number-literals.json` gives the new verdicts, its
  `unsafe-integer` now covering such non-integers. The callers here refuse
  the same numbers: `vc.CreateProof`, `keybinding`, the DID registry, the VC
  resolver's `StoreVC`, and `resolver/cache`, which does not cache them.
- **BREAKING (Go API)** `schema.ValidateJSONSchema`, `(*local.Validator).Add`
  and `(*local.Validator).Validate` refuse a schema or payload holding a number
  longer than 256 bytes, or whose exponent part (after `e` or `E`) lies beyond
  ±400 (`1e401`, `1e-401`, `0e999999`). Every number of at most 256 bytes
  whose exponent part lies within ±400 is read as before; that includes every
  binary64 value as `encoding/json` and RFC 8785 write it. The schema
  registry's `RegisterSchema` refuses such a schema too; a schema stored
  before the upgrade is not checked again.
- **BREAKING (Go API)** `schema.ValidateJSONSchema`, `(*local.Validator).Add`
  and `(*local.Validator).Validate` refuse a regular expression not written
  in the forms ECMA-262 and Go's regexp read alike (Security, below): in a
  schema's `pattern` or `patternProperties`, and in a payload value checked
  as format `regex`. Forms Go compiled before are among them: inline flags
  such as `(?i)`, `\pL` and other one-letter class names, `\z`, `\Q…\E`,
  POSIX classes such as `[[:alpha:]]`, and a `-` that Go reads as a literal
  between a class escape and another member, as in `[\w-.]`. A schema
  holding one no longer registers, and a payload value holding one now fails
  format `regex`.
- **BREAKING (wire)** The schema registry's `RegisterSchema` refuses such a
  schema with `InvalidArgument`, as it refuses one that does not compile. A
  schema stored before the upgrade is not checked again.
- **BREAKING (Go API)** `schema.ValidateJSONSchema` and
  `(*local.Validator).Add` refuse a schema nested deeper than 64 levels (each
  object, array and scalar is a level), holding more than 4,096 objects and
  booleans and one per 8 bytes of the schema (counted wherever they are, in
  a `default` or an example too, since a `$ref` can make any of them a
  subschema), or whose JSON pointers and URLs, summed, pass 2^16 bytes and
  16 per byte of the schema (each value's pointer counted escaped for a URL,
  as the library keeps it, and each URL its ids and references resolve to:
  `$id`, draft-04's `id`, `$ref`, `$dynamicRef`, `$recursiveRef`, escaped);
  and one whose check against its metaschema needs more than a work budget
  of 2^20 steps and 16 per byte of the schema. The error names the bound.
  SchemaStore's schemas nest at most 23 deep, hold at most one object or
  boolean per 40 bytes, their pointers and URLs come to at most 4.03 bytes
  per byte, and their checks need at most 11.5% of the budget.
  `schema/README.md` states the bounds. They also refuse a reference by a
  JSON pointer whose array index is not written as RFC 6901 writes one
  (`#/allOf/00`, `+0`, `-0`, `01`): the pointer is not found. No SchemaStore
  schema writes one.
- **BREAKING (wire)** The schema registry's `RegisterSchema` refuses such a
  schema with `InvalidArgument`. A schema stored before the upgrade is not
  checked again, but `(*local.Validator).Add` refuses it when a validator
  loads it.
- The YAML stores (the chain manager's subscriptions and allow lists, the
  schema registry's versions, the DID registry's status and lifecycle events)
  refuse to write a record whose YAML would not read back as written, and
  write a byte field (a schema body, an outward DID document snapshot) as one
  base64 string instead of a sequence of one integer per byte. A record an
  earlier version wrote with its bytes as such a sequence still reads, at the
  earlier cost; one an earlier version stored that does not read back (a
  key `<<`, for example) still fails as before. A refused record surfaces as
  an error the handlers report as `Internal` and the node logs: the entry
  points below admit only values that read back, so a refusal means a check
  before the store let one through. Times are stored in UTC.
- **BREAKING (wire)** The schema registry admits a schema name or prerelease
  (and looks up a version) only of 1 to 128 characters of `[A-Za-z0-9._-]`,
  the first a letter or digit; anything else is `InvalidArgument`. It admitted
  any string without `/`, `\` or NUL.
- `chainmanager` `Subscribe` refuses a publisher's connection info with a key
  other than `subject`, `account`, `url` and `publishType`, or a value other
  than empty or a letter or digit followed by up to 999 characters a URL, a
  NATS subject or account key, or a DID uses. It is the publisher's fault
  (`ErrRemotePeer`): the remote registration is undone and nothing is
  imported or stored.
- **BREAKING (Go API)** `(*local.Validator).Validate` refuses a payload nested
  deeper than 512 levels, whose validation needs more than its work budget,
  2^20 steps plus 16 per byte of the payload, or that would apply schemas
  within one another more than 10,000 deep; the error names the bound.
  `schema/README.md` states them.
- The JSON Schema library is a copy inside this module, `internal/jsonschema`:
  `santhosh-tekuri/jsonschema/v6` v6.0.3 (Apache-2.0, its LICENSE copied
  unchanged) with a work budget added, `ValidateWithBudget`, and with a
  number `big.Rat` cannot read (such as `1e1000001`) reported as an error,
  where v6.0.3 panics or takes it as unequal to every number: in the number
  keywords, `enum`, `const` and `uniqueItems`, at any depth of a value, so
  also when a schema is compiled against the metaschema. Under its own import path, every module that imports this one
  builds with it. go.mod no longer requires `santhosh-tekuri/jsonschema/v6`,
  and `golang.org/x/text` becomes a direct requirement. When upstream bounds
  its own work and releases the error for such numbers, the schema package
  goes back to the upstream module and the copy goes
  (`internal/jsonschema/README.md`).
- **BREAKING (Go API)** `canon.StrictDecoder` refuses, as a
  `*canon.DuplicateKeyError` naming both, two keys of one object that differ
  only in case as encoding/json folds names (also the Kelvin and long-s
  signs), whatever the target; and, where the target holds a struct, a key
  that matches one of its fields only that way (`"V"` for a field `v`).
  Fields are resolved by encoding/json's rules, through pointers and through
  an interface already holding a pointer; a type that decodes itself
  (`json.Unmarshaler`, `encoding.TextUnmarshaler`) is outside the check.
  Keys that match exactly, and keys no field has, are read as before. An
  unkeyed composite literal of `canon.DuplicateKeyError` no longer compiles
  (it gained `Other`). `bundle.Verify` decodes the manifest's wire struct
  through the strict decoder too, and reports a manifest whose keys collide,
  exactly or by case, as `ErrBundleIntegrity`.
- **BREAKING (wire)** Since the strict decoder refuses keys that differ only in
  case whatever the target, so do the paths that decode others' JSON with it
  into maps: the push ingress (`apipush`, now HTTP 400) and the ingest loop,
  the jsonata filter and converter, the DID registry, the VC resolver, and
  JSON Schema documents and payloads. No fixture here has such keys.
- **BREAKING (Go API)** `vc.DataIntegrityProof` and
  `delegation.DelegationCredential` are read under `canon.StrictDecoder`'s
  rules on every path: decoding one with encoding/json (also inside another
  value) refuses a duplicate key or invalid Unicode (invalid UTF-8 or an
  unpaired surrogate) where it took the last value or replaced the bytes with
  U+FFFD, and a key that differs from another key, or from a field, only in
  case, where it read it as the field. A number inside a proof's `@context` is now a `json.Number`, as in a
  document decoded strictly, where it was a `float64`: the bytes the
  `@context` mirror check compares are the same, and a number a `float64`
  cannot hold is refused when the proof is verified rather than when it is
  decoded. A struct that embeds `delegation.DelegationCredential` now gets its
  `UnmarshalJSON`, so encoding/json no longer decodes that struct's own
  fields; such a struct needs its own `UnmarshalJSON`.
- **BREAKING (Go API)** Decoding a `bundle.Manifest` with encoding/json reads
  it as `bundle.Verify` does. It refuses what `Verify` refuses: a document the
  strict rules refuse (keys that collide, exactly or by case, are
  `ErrBundleIntegrity`), an unknown member or a member of another version (a
  v1 manifest with `receipts`), a scope its version does not name, and an
  unknown version. The manifest is read afresh: a member the document omits
  is zero, where encoding/json kept the receiver's value. A struct that embeds
  `bundle.Manifest` needs its own `UnmarshalJSON`, as above. Encoding one
  writes the shape of its version: a v2 manifest always has `receipts`
  (`null` when it has none), and a v1 manifest with receipts, or one of a
  version no shape names, is an error where it was written as given.
- **BREAKING (wire)** An evaluation view manifest is read member by member,
  exactly as named (`appraisal.Manifest`'s `UnmarshalJSON`), and refused
  (`ErrInvalidManifest`) where it was read before: a member that is a known
  field in another case (`"HEAD"`, or `"BodyAddress"` in a spine entry), and
  `null` for the manifest, a spine entry, or a known field (it was read as
  empty). Every other member, at the top or in a spine entry, is kept as an
  extension, in the identity, so a manifest whose spine entries carry other
  members has a different `EvidenceViewID` than before, and one stored for it
  no longer passes `ValidateID`. A number in an extension that
  `canon.AdmitSafeNumbers` refuses gets no identity, as on the other identity
  paths: `ID`, `CanonicalBytes`, `NewView` and `View.ValidateShape` refuse it.
- **BREAKING (Go API)** `appraisal.SpineEntry` holds a map (`Extensions`), so
  it is no longer comparable: `==` on it and its use as a map key no longer
  compile, and neither does an unkeyed composite literal with its two values.
  A decoded entry's `Extensions` is an empty map, not nil, so a deep
  comparison with an entry built without one differs. A `SpineEntry` decoded
  on its own is read as a manifest reads it (duplicate keys, a field in
  another case, and `null` are refused; other members are kept). A manifest
  built in Go gets no identity, and is not encoded, with an extension that is
  a field in another case; it gets no identity with an extension value that
  is not a JSON value as decoding gives it, or a Go integer (a `float32` is
  canonicalized widened but encoded short, so its identity would not be that
  of its encoding).
- **BREAKING (Go API)** A tlog checkpoint has one spelling of what it signs:
  `(*tlog.Checkpoint).SignedView` (and so `tlog.SignCheckpoint` and every
  checkpoint verification) refuses a head with an upper-case letter, and a
  timestamp not in UTC, with a fraction of a second, or outside the years
  RFC 3339 writes (0000–9999). `tlog.SignCheckpoint` called with a time not
  in UTC is refused, where the view used to carry its offset (the wire
  carried UTC only, so such a signature did not verify after transport).
  `tlog.VerifyConsistency` and `tlog.VerifyInclusion` refuse a head not in
  lower case. The logs here stamp UTC whole seconds and write lower-case
  heads, so nothing they write is refused.
- **BREAKING (Go API)** `canon.StrictDecoder` refuses a decode target it
  reaches through more than 64 pointers and interfaces, as one that holds
  itself is (an interface holding a pointer to itself, interfaces holding
  pointers to each other, a pointer type to itself), wherever the document
  gives it a value, before anything is decoded. encoding/json follows such a
  target without end: with Go 1.26 a pointer type to itself allocates without
  end and interfaces holding pointers to each other loop without end
  (encoding/json guards only an interface holding a pointer to itself); with
  Go 1.27 every such target overflows the stack, a fatal error. A `null`
  there, and a chain of more than 64 without a cycle, decoded before and are
  refused too. The target is the caller's Go value, not input.
- `vc` judges `credential.claim.charset` (the White_Space, Cc and Cf
  characters a transformation claim may not contain) with tables generated
  from the Unicode Character Database 15.0.0, the version the specification
  pins, instead of the Go `unicode` tables: a toolchain whose tables are of
  another Unicode version (Go 1.27 carries 17.0) judges a claim the same.
  Today the three classes are the same in 15.0 and 17.0, so no claim is
  judged differently; the tables guard against a later version.
  `go generate ./vc` rebuilds them, refusing UCD files whose SHA-256 is not
  the pinned one.
- **BREAKING (config)** The batch resolver presents `vc-store-bearer` only to
  the configured destinations' origins and to `credential-origins`, and fetches
  from any other peer without it. A deployment whose batch resolver fetches
  from L1-protected peers other than its configured destinations must list
  them in `credential-origins` before upgrading: until then those fetches are
  refused by the peer, and the resolver gives those holes up after its
  retries (`batch-resolver.max-retries`). Every call of the node and the
  pipeline that presents the bearer follows no redirect, so a destination
  that redirects must be configured at its final URL. The quickstart, whose
  only peer is its own VC store, needs no change.
- **BREAKING (CLI)** `provin bundle export` shows `--token` only to
  `--registry`'s origin and to `--credential-origin` origins, and calls an
  issuer's advertised `#audit` or `#vc-resolver` endpoint (or a base mapped to
  one) at any other origin without it. An export whose issuers' endpoints are
  L1-protected at another origin must name it with `--credential-origin`.
  Every CLI call that shows the token, to the registry included and in every
  command, follows no redirect. The quickstart, whose endpoints are all the
  registry's, needs no change.
- `canon/jcs` and the jsonata filter and converter read a JSON number as a
  double through `canon.Float64`. `jcs` refuses a `json.Number` that is not an
  RFC 8259 number (`+1`, `.5`, `01`), in its RFC 8785 and legacy forms alike,
  where it read Go's wider syntax; a number from a decoded document is always
  one. The jsonata filter and converter refuse a document holding a number
  beyond the double range, as an Apply or Convert error. When `jcs`, the
  filter or the converter cannot read a number, its error matches
  `canon.ErrNotJSONNumber` or `canon.ErrBeyondDoubleRange` with `errors.Is`.
  Where the earlier
  reading took a number's double from its spelling rather than its value,
  the canonical form and the value an expression sees are now those of the
  double nearest its value. `scripts/check-number-hygiene.sh` (in
  `make lint`), a line-based textual check, flags any other `Float64` method
  or `ParseFloat` outside `canon.Float64`.

### Security

- `eddsa-rdfc-2022` reads a document only through the contexts `vc` embeds
  (Changed, BREAKING): a document can no longer define a term of its own, so
  every term an `eddsa-rdfc-2022` proof is checked through is defined in
  contexts this module holds, and a document that writes a context is
  refused before JSON-LD processing runs on it.
- `eddsa-rdfc-2022` is off until a program calls `vc.RegisterEdDSARDFC2022`
  (Changed, BREAKING): a verifier runs JSON-LD processing on an untrusted
  document, before its signature is checked, only when it chooses to.
- `vc.VerifyProofUnderContract` verifies a proof only under the contract of
  the suite it names: a proof of `eddsa-rdfc-2022` under an `eddsa-jcs-2022`
  contract, or the reverse, is refused, so a proof's suite says how it was
  signed whichever contract a caller names. `vc.VerifyProofWithContract` and
  `vc.Verifier`, which take the contract from the proof, are unchanged.
- `canon/urdna2015` refuses a document some value of which its canonical
  form would not hold, so every value of a document it accepts is signed by
  an `eddsa-rdfc-2022` proof. JSON-LD processing leaves values out of the
  dataset at several steps of its algorithms; rather than list those forms,
  `Canonicalize` counts the document's values in the document, in its
  expanded form and in the dataset, and refuses a document whose counts
  disagree. So that each value stays one value at every stage, a document on
  the RDFC path:
  - may not use `@index`, `@direction`, JSON literals (`@json`, or the
    `rdf:JSON` datatype) or blank node labels (`_:`; RDFC-1.0 gives every
    blank node a label of its own, so a label would not be signed);
  - may use `@language` only in a value object, and must write a value
    object's keys as `@value`, `@type` and `@language` (not as aliases);
  - must write a language tag, in a value object or a context, in ASCII
    letters, digits and hyphens: json-gold lowercases a tag with Unicode case
    mapping, so `İt` would be signed as `it`;
  - may not write the RDF collection vocabulary out (`rdf:first` or
    `rdf:rest` as a property, `rdf:nil` as an IRI): it would be signed as the
    list `@list` makes. A list is written with `@list`;
  - may give a value object at most one datatype, and a boolean none but
    `xsd:boolean`;
  - may not give one node's property the same RDF term twice, as when a node
    is written out in full in two places or a type is repeated: write a node
    once and refer to it elsewhere by its `@id`;
  - may not hold a node object that adds no statement to the dataset;
  - may not use a context (its own, or one the canonicalizer serves) that
    sets `@base` or defines a term with an `@id`, `@type`, `@index` or
    `@language` container, an alias of `@value`, one term as an alias of two
    keywords, or a `@vocab` beginning with `@`. The RDFC path resolves no
    relative IRI against a base, so two spellings of one IRI are not signed
    as one.

  What is signed is the document's meaning: spellings JSON-LD gives one RDF
  term (an IRI through the contexts, a language tag in any ASCII case, a
  string with `xsd:string` written or not, a boolean or the string of its name
  typed `xsd:boolean`) are signed as that term, and the values of a property
  outside a list are signed as a set, in no order. A context's own text is not
  signed: a term the document does not use adds nothing. A document accepted
  before that meets these keeps its canonical bytes; one that writes a value
  twice is now refused, such as a self-issued credential whose issuer and
  subject, one id, both carry the same `name`, or a `type` that lists
  `VerifiableCredential` twice. `eddsa-jcs-2022`, the default, signs the
  document's JSON bytes and is not affected.
- `canon.AdmitSafeNumbers` works in time linear in its input: it reads each
  `json.Number` in time linear in its length, without `math/big`, and spells
  the path to a number only into an error. A 9-byte literal such as
  `1e-999999` cost about 10 ms, and a literal that is not an integer does not
  stop the check, so a few kilobytes of numbers cost seconds before any
  signature was checked; a 20 KB array nested 10 000 deep cost 158 MB of
  path strings. Every RFC 8259 number keeps its verdict (except where the
  range changes, under Changed), including the
  refusal as not a valid literal of an exponent beyond int64 and, for a
  nonzero value, of an exponent net of the digits after the point beyond
  ±10^6 (now documented), and every refusal keeps its `Path`. A `json.Number`
  that is not an RFC 8259 number (`+1`, `.5`, `01`, `1_000`, `0x10`, `1/2`),
  which only a caller building one by hand can pass, is now refused as not a
  valid literal; some were admitted. `canon/testdata/number-literals.json`
  holds the gate's verdict on each boundary.
- `canon.StrictDecoder` refuses a document nested deeper than 10000 arrays
  and objects before walking it, and walks the rest in time linear in its
  length. Built with Go 1.26 or earlier, about a megabyte of `[` made the
  walk recurse until the goroutine stack overflowed, a fatal error that
  stops the whole process, before any signature was checked
  (`json.Decoder.Token` limits depth only from Go 1.27, where jsonv2 is the
  default). The walk also copied the path to a value once for each of its
  siblings, so siblings deep in a document each cost their depth: 823 KB
  nested 8 704 deep took 8.5 s. `encoding/json` refused the same depth when
  decoding, so no document that decoded is refused now. The refusal of a
  too-deep document is a plain error naming the limit (`*json.SyntaxError`
  before, and still from Go 1.27), also when a duplicate key follows the
  too-deep part.
- `multibase.DecodeBase58Btc` refuses a value of more than 8192 characters
  after the "z" prefix before decoding any of it. Decoding base58 costs the
  square of the length, and `proofValue` is decoded before its signature is
  checked: 700 KB took 7.8 s. 8192 characters hold every byte string of up to
  5998 bytes — every Ed25519, ECDSA and BLS key and signature, and ML-DSA's
  (up to 4627 bytes), but not SLH-DSA's (7856 bytes and more); a longer
  value, which decoded before, is now refused. A value without the prefix is
  refused quoting at most its first 32 characters (it was quoted whole).
- `canon/urdna2015` canonicalizes a document within a work bound in each of
  its stages: building the dataset, writing the canonical form, and
  labelling its blank nodes. An eddsa-rdfc-2022 proof
  (`vc.VerifyProofWithContract`, `vc.VerifyProof`) canonicalizes its
  document before the signature is checked. A document past any of these
  bounds is refused with the new `urdna2015.ErrTooComplex` ("urdna2015:
  dataset too complex to canonicalize"), of the new constant error type
  `urdna2015.Error`; `errors.Is` finds it through `vc.CreateProof`,
  `vc.VerifyProof`, `vc.VerifyProofWithContract` and
  `vc.VerifyProofUnderContract`. The error wrapping it names the stage
  ("node map:", "canonical form:" or "labelling:") and the bound, for a
  person reading it; that text is not part of the contract.

  Building the dataset: json-gold's node map compares each value one node's
  property gathers with those the property already holds. Before it runs,
  those comparisons are counted by the node map's own rules (one node per
  `@id`, aliases as one property, `@type` and `@reverse`), as the most any
  order of the values takes, and a document that would need more than 2^20
  plus 16 per value is refused. One property of one node holds at most about
  1,460 distinct values: a document with more is refused with
  `ErrTooComplex` both when a proof is created and when one is verified.
  Ordinary credentials use at most 2% of the bound.

  Writing the canonical form: it writes each quad's IRIs whole, so it can be
  many times the document's size. Once the dataset is built, and before its
  blank nodes are labelled, a document whose canonical form, each blank
  node's label counted at its longest, would be longer than 1 MiB plus 32
  bytes per byte of the document (written as JSON) is refused. Ordinary credentials use at most 3% of the bound, and large
  documents of the shapes measured have canonical forms of at most about 12
  times their size.

  Labelling, as RDFC-1.0 §4.4.3 requires: a dataset whose blank nodes are so
  alike that labelling them would take more than 262 144 steps and 64 per
  quad (a step being of about the same time whatever the dataset) is
  refused. json-gold, which did the labelling, has no bound, and its time
  grows exponentially with blank nodes no quad of their own tells apart (7
  in a 1 KB dataset took 240 ms, each one more about 9 times as long). A
  refusal costs about 10–20 ms and 3.5 µs per quad. Refused: 6 or more blank
  nodes all linked to each other, a ring of 56 or more, a list of
  62 or more equal values, and two alike nodes each with 7 or more alike
  leaves (json-gold took 24, 11, 13 and 61 ms on the smallest of these).
  Every other dataset keeps its canonical bytes: the labelling is
  json-gold's, done in `canon/urdna2015` until json-gold can bound it. Where
  json-gold's own answer depends on map order (two blank nodes told apart
  only by the blank graph a quad sits in), the labelling gives one of its
  answers, always the same one.
- Ed25519 public keys are validated by the new `crypto/ed25519.ValidatePublicKey`
  (with the new constant error type `ed25519.Error`): a key must be 32 bytes,
  must not be of small order (the eight low-order points, in every encoding
  including non-canonical ones and either sign bit), and must be the canonical
  encoding of a point on the curve. The errors are `ed25519.ErrPublicKeySize`,
  `ed25519.ErrSmallOrder` and `ed25519.ErrInvalidPoint`.
- `crypto/ed25519.Verifier.Verify` applies that check to the public key and
  returns `ed25519.ErrSmallOrder` for a signature whose R (its first 32 bytes)
  is of small order, with `ed25519.ErrSignatureSize` for a wrong signature
  size, instead of a verdict. `crypto.Verifier` documents that an implementation
  may refuse a key or signature with an error.
- The DID registry refuses a small-order or invalid key in the external public
  keys of `IssuePipeline` / `IssueProcess` (replacing the all-zero check), and an
  owner document in `RegisterOwner` that carries one in any verification method
  listed under `authentication` or `assertionMethod`; both are `ErrInvalidArgument`.
- `did.ExtractPublicKey` and `did.ExtractPublicKeyAndEncoding` refuse an Ed25519
  key, in either encoding (Multikey or JWK), that `ed25519.ValidatePublicKey`
  refuses, with an error wrapping the new constant `did.ErrInvalidPublicKey`
  (of the new type `did.Error`) and the `ed25519` sentinel. Every reader of keys
  from DID documents in this repository (credential, delegation,
  wire-authentication, transparency-log and organization-fingerprint
  verification, and the DID registry's check of an owner document's own proof)
  therefore refuses such a key when it extracts it. `did.EncodeEd25519Multikey`
  and `did.NewMultikeyVerificationMethod` refuse the same keys.
- `did.ExtractPublicKey` (and every reader of keys in this repository) reads a
  key reference, and every method id in the document, only as `#fragment` or
  `<the document's DID>#fragment`, with a single `#` and a fragment of
  `[A-Za-z0-9._-]` (a deliberate profile restriction, narrower than DID Core),
  through the new `did.AbsoluteKeyID`; anything else, and a document whose id
  is not a DID, is the new `did.ErrInvalidKeyReference`. `#x#signing` and a
  bare `signing` were read as `#signing`; a method whose id names another DID
  was extracted as this document's key; a method with such an id beside the
  real one was skipped. A document that holds such a method is now refused as
  a whole, whatever key is asked for. A method carries exactly one key member,
  its type's: any other `publicKey*` or `secretKey*` member, `blockchainAccountId`
  or `ethereumAddress`, which some readers read first, is refused. The DID
  registry's owner-document check uses the same rule and wraps
  `did.ErrInvalidKeyReference`.
- A JWK verification method's `x` must be the canonical unpadded base64url
  spelling of the key (zero trailing bits, no line breaks); another spelling of
  the same bytes is refused.
- `RegisterOwner` checks the keys of an owner document before its proof, so an
  unusable key that a reader could extract through `authentication` or
  `assertionMethod` — the proof's own `#signing` included, which was
  `ErrUnauthorized` — is `ErrInvalidArgument` wrapping `did.ErrInvalidPublicKey`.
  Such a key of the wrong size is now refused the same way (it was skipped).
- `RegisterOwner` stores an owner document only when every key in it is one
  `did.ExtractPublicKey` extracts through `authentication` or
  `assertionMethod`; anything else is `ErrInvalidArgument`. It refuses a
  verification method listed under neither relationship, sharing its id with
  another method, controlled by another DID, or of a type or encoding not read
  here (anything but an Ed25519 Multikey or JWK); an entry of those
  relationships that is an embedded method or a reference to a missing or
  foreign key; an embedded method under `keyAgreement`,
  `capabilityInvocation` or `capabilityDelegation`; a legacy top-level
  `publicKey` list; and a `verificationMethod` entry that is not an object.
  Such documents were stored and served to outside resolvers, whose readers may
  pick among those keys differently. A duplicated `#signing`, or one controlled
  by another DID, was `ErrUnauthorized` and is now `ErrInvalidArgument`.
  Documents stored before this change are not checked again. Every method id
  and every relationship reference must name a key of the document, spelled
  `#fragment` or `<the document's DID>#fragment` with a single `#` and a
  fragment of `[A-Za-z0-9._-]`: an id under another DID, `#x#signing` (read
  here as `#signing`), a bare `signing`, and a fragment that URL parsers read
  differently (`#sign%69ng`, whitespace, other characters) are refused. A member that carries keys
  (`authentication`, `assertionMethod`, `keyAgreement`, `capabilityInvocation`,
  `capabilityDelegation`, `publicKey`) must be a list when present.
- `vc.VerifyProofUnderContract` pins the proof's `@context` under every
  contract, as `vc.VerifyProofWithContract` already did before calling it:
  under the two W3C contracts (`vc.ContractW3CEdDSAJCS2022` and
  `vc.ContractW3CEdDSARDFC2022`) it must mirror the document's, and under
  `vc.ContractLegacyProvinEdDSAJCSInt64` the proof must carry none. The
  proof configuration is rebuilt from the document's `@context`, so on this
  path the wire `proof.@context` is outside the signature: a proof whose
  `@context` was swapped, removed or added after signing verified when
  `vc.VerifyProofUnderContract` was called directly. Nothing the issuer
  signed could be changed, but one signed artifact verified in more than one
  wire form, including eddsa-jcs-2022 forms a W3C verifier refuses. Called
  directly under a W3C contract, a document without `@context` is now
  refused too, as the classifier refuses that shape.
  `vc.VerifyProofWithContract` now leaves the check to
  `vc.VerifyProofUnderContract`, and its answers are unchanged.
- `vc.VerifyProof` requires the proof's `@context` to mirror the document's
  whenever the document has one, so a proof whose `@context` was removed
  after signing no longer verifies through it. It checked the member only
  when the proof carried one: an eddsa-jcs-2022 proof with its `@context`
  stripped verified here, though `vc.VerifyProofWithContract` and a W3C
  verifier refuse it. Nothing the issuer signed could be changed. A document
  without `@context` still needs a proof without one. The proofs this now
  refuses are listed under Changed.
- The `cedar` PDP backend authenticates the caller. In 0.3.0 and earlier it
  gave the Cedar agent the raw bearer token as the principal without
  verifying it, so the principal was whatever string the caller sent. It now
  verifies the bearer as a JWT: a signature by a key from the configured key
  set or by the configured HS256 secret, an `exp` that has not passed and,
  if the token has one, an `nbf` that has (both with 30 s of leeway), an
  `iss` equal to the configured issuer, an `aud` that contains the
  configured audience, and a non-empty `sub`, which it gives the agent as
  the principal. The token must be a compact JWS in its one spelling (three
  base64url segments without padding, the unused bits of each segment's last
  character zero: a line break, which base64 decoding skips, or nonzero
  unused bits, which it ignores, are refused), and its claims are read under
  `canon.StrictDecoder`'s rules (no duplicate keys at any depth, valid
  Unicode, no two keys of one object that differ only in case), so a `sub`
  whose bytes are not valid Unicode is refused rather than read with U+FFFD,
  and two different `sub` values are not read as one. A token that fails any
  check is refused. The configuration this needs
  (`provin.network.auth.cedar.jwt.*`) is under Changed.
- What `canon.AdmitSafeNumbers` admits, RFC 8785 writes within ±(2^53−1), so
  a check of the canonical bytes RFC 8785 defines agrees with the check of
  the value. A
  non-integer of magnitude 2^53 − 0.5 or more (`9007199254740991.5`) passed
  the check, and its canonical form, an integer beyond ±(2^53−1)
  (`9007199254740992`), did not. So `vcresolver.StoreVC`, which every caller
  here hands canonical bytes, could store such a credential on one node and
  refuse it on the next (the batch resolver re-submits the canonical form of
  what it fetches), or refuse to store a credential the node had verified;
  `keybinding` refused a binding or status list that `vc.CreateProof` had
  signed, when it came in canonical form; and `resolver/cache`, for a
  document a registry served as written, could return on a hit another
  spelling of the number than the miss had. The harm was to availability
  and to the cache's fidelity: no signed byte could change.
- `canon.AdmitSafeNumbers` spells the path to a refused number once. It
  copied the path once per level, so refusing a number 10 000 levels deep,
  which `canon.StrictDecoder` lets through, allocated 160 MB before any
  signature was checked; it now allocates about 1 MB.
- `canon/urdna2015` keeps the canonical N-Quads one-to-one. It refuses a
  document whose dataset holds an IRI, wherever it sits in a quad (subject,
  predicate, object, graph name, datatype), that is not valid UTF-8 or holds
  a character N-Quads' IRIREF excludes unescaped and an RFC 3987 IRI cannot
  hold: a space, `<`, `>`, `"`, `{`, `}`, `|`, `^`, `` ` `` or `\` (control
  characters were already refused). Such an IRI was written as it was, which
  broke the N-Quads line; with a space or `>`, two documents of different
  meaning could have the same canonical bytes, and an eddsa-rdfc-2022 proof
  over one verified over the other. It also refuses a literal that is not
  valid UTF-8 or holds a character RDFC-1.0 (Appendix A) writes escaped and
  URDNA2015 writes as it is (BS, FF, U+0000–U+0007, VT, U+000E–U+001F, DEL,
  U+FFFE and U+FFFF), and a literal typed `rdf:langString` without a
  language tag, which was written as no N-Quads parser reads it. So the bytes
  signed are RDFC-1.0's canonical form of the dataset, and no byte the frozen
  v0 wire signs changes. `vc.CreateProof` and every verify function in `vc`
  refuse such a document under eddsa-rdfc-2022; eddsa-jcs-2022 is not
  affected.
- The node's clients for other organizations' servers bound what they take
  from one, so such a server cannot exhaust the node's memory or hold its
  work indefinitely. None of them accepts compression any more, so what a
  response takes in memory is what it takes on the wire.
  - `chainmanager/peerclient`, which a subscriber uses to call a publisher,
    reads a response of at most 256 KiB and ends every call within 30
    seconds, whatever the caller's context. It read a response of any size
    (connect's default) and waited as long as the publisher did, also for the
    compensating `Disconnect`, which runs under a context that is never
    cancelled while the chain manager holds its lock.
  - `payloadresolver/client` refuses a streamed frame larger than its
    `MaxBytes` (and the frame's protobuf framing) with
    `connect.CodeResourceExhausted`, without holding it in memory. It read a
    whole frame, of any size, before checking the total.
  - The batch resolver's fetch from a peer, and a sink's fetch from its
    declared upstream registry, end within 30 seconds; they waited as long
    as the server did.
  - `provin bundle export --aggregate-complete` reads at most 1 MiB a
    response from an issuer's `#audit` and `#vc-resolver` endpoints, and each
    call ends within 30 seconds; it read any size and waited as long as the
    endpoint did.
  - The SSRF-guarded HTTP client (`core.URLGuard.HTTPClient`) takes at most
    64 KiB of response headers (net/http's default is 10 MiB).
- The JSON Schema checks read numbers in bounded time.
  `santhosh-tekuri/jsonschema` reads every number as an exact rational, at a
  cost that grows steeply with its exponent: `1e999999` alone took about
  10 ms, so a megabyte of such numbers, in a schema sent to `RegisterSchema`
  (compiled before it is stored) or in a payload checked by `schema/local`,
  could cost minutes. A number whose exponent is beyond ±10^6 the library
  cannot read at all: a schema bound holding one was silently dropped, and a
  payload holding one made validation panic. Numbers beyond the bounds above
  are now refused before the library reads them; within them, a 1 MiB
  payload of numbers at the bounds takes about 0.2 s.
- The node's HTTP server bounds what a request makes it read before any
  handler decides on it, so a client cannot hold the server's handlers with
  a stalled request or its memory with an oversized one. It takes at most
  64 KiB of request headers (net/http's default is 1 MiB). It drops a request
  whose body stalls while it is read, on HTTP/1 and HTTP/2 alike: one that
  delivers nothing for 30 seconds or, chunked on HTTP/1, fewer than 16 KiB;
  and a body the handler leaves unread gets the same 30 seconds while
  net/http discards it. As for writes, the bound is on progress, not rate: a
  body trickled a byte at a time is not dropped. A large body sent at a
  steady pace, and a response streamed after the body, are not cut. The
  outer request-size bound (derived from the configured size limits) now
  also covers HTTP/2 streams on the cleartext (h2c) listener, besides HTTP/1
  requests (also one asking to upgrade to h2c); it covered only HTTP/1
  requests there, and each handler's own limit (connect's read limit per
  RPC, the push handler's) was the only bound on an HTTP/2 stream.
- The YAML stores hold only records that read back as written, so a stored
  value, also one another organization sent, cannot change when it is read or
  make reading the store fail: the schema registry and the chain manager hold
  what they store to forms that read back, and the stores refuse anything
  else. Reading a schema body or an outward snapshot
  written as a byte sequence allocated about 1.3 KB per byte (about 1.4 GB
  for a 1 MiB schema) on every read; written as base64 it allocates about
  76 bytes per byte, 17 times less.
- `canon/urdna2015` spells the path to a refused value only into the error.
  It built the path string at every value, which cost the number of values
  times their depth before any signature was checked: an eddsa-rdfc-2022
  document nested 8000 deep allocated 546 MB, and now 53 MB (json-gold's
  expansion is the rest). The walk now costs the same per value at any depth
  or width. The error text is unchanged.
- `tlog/filelog` and `tlog/merklelog` read their file in time and memory
  linear in its size when they open it. Finding each line copied the rest of
  the file, so the cost was the size times the number of lines: an
  80 000-record, 10 MB log took about 10 s to open, now about 0.2 s, and a
  1.4 MB one allocated 184 MB, now about 11 MB.
- The node's HTTP server drops a request whose body is not read to its end
  within 60 seconds of the request's start, whatever its pace, so it spends a
  bounded time reading one request's body. `RetainPayload`
  (`PayloadStoreService`), the one client-streaming RPC, lifts that limit
  once its caller, past L1 authorization, has proven its DID in the first
  frame, and keeps only the stall bound for the payload frames after it. The
  deployment guide gives the limits and says to set a rate or time limit for
  `RetainPayload` at the proxy in front where one is wanted.
- The JSON Schema payload check bounds the library's work on a payload by a
  budget that grows with the payload's size. Reading a number is charged by
  its length and its exponent, and comparing it with a bound by the size of
  both; two objects are compared by their names in order, so a validation
  takes the same steps each time. What the budget does not count, the work
  per step that grows with nesting, the depth bound keeps small. A regular
  expression, in a schema
  (`pattern`, `patternProperties`) or in a payload checked as format
  `regex`, is refused before it is parsed unless it is written in the forms
  ECMA-262 (which JSON Schema's regular expressions follow) and Go's regexp
  read alike: no inline flags such as `(?i)`, no lookarounds or
  backreferences, Unicode classes by general category only, of at most
  8,192 ranges together, repeat counts without a leading zero, and groups
  nested at most 32 deep. Two forms keep Go's meaning, as before: `.` also
  matches `\r`, U+2028 and U+2029, and `\s` holds only the ASCII spaces
  (`\t \n \f \r` and space). It is refused before it is compiled when its
  size (an upper bound of its instructions) passes 8,192. A schema is
  refused at registration when its regular expressions, together, pass 2^14
  plus one per 4 bytes of the schema. Matching and compiling one is charged
  to the budget by its size, and a payload value checked as format `regex`
  by its length before it is compiled, so the budget bounds the time of that
  work as it does every other step's. A conformance error states only the
  first failure, in at most 1 KiB, written within that bound: where it is in
  the payload and the keyword it fails, with the library's description only
  where that grows with the payload alone, not where it quotes what the
  schema holds (a `required` list, `enum` or `const` values, a pattern). The
  library's text lists every failure and could run to hundreds of megabytes.
- `(*local.Validator).Add` checks a schema against the metaschema whatever id
  it is added under: every schema is compiled at one fixed location, as
  admission compiles it. One added under an id below `json-schema.org`
  skipped the check.
- Registering a schema (`schema.ValidateJSONSchema`, `(*local.Validator).Add`,
  the schema registry's `RegisterSchema`) takes memory linear in the
  schema's size, and time about linear: within the bounds above (Changed), a
  schema of 1 MiB keeps at most about 170 MB once compiled (the worst shapes
  measured keep 127 MB and compile in at most about 0.5 s; one the
  metaschema's budget refuses is refused in at most about 0.8 s). Sorting the
  names of an object that `uniqueItems` hashes, in the metaschema's check,
  takes up to a factor of log n more where the names share a long prefix, as
  the library's work budget states; a 1 MiB schema of such names compiles in
  about 9 ms. The copy of the JSON Schema library compiles in about linear
  time: it finds a queued subschema, a resource by id and
  a dynamic anchor without a search, adds a subschema read for a reference
  without copying what is compiled, hashes a number with its sign, reads a
  metaschema's vocabularies once, and resolves each URL a reference resolves
  to once in a compile; it reads a JSON pointer's array index only as RFC
  6901 writes one, so an item is compiled under one location, not again for
  each spelling of its index (`00`, `+0`, `-0`); and it checks the schema
  against its metaschema within a work budget, so a shape whose check takes
  more than linear work is refused at that bound. Each is a patch of its own
  (`internal/jsonschema/patches/`). A schema the metaschema refuses is
  refused with its first failure, and every compile error and conformance
  error the schema package states is at most 1 KiB in all, a failure's
  location at most half of it (a caller's prefix, such as
  `(*local.Validator).Add`'s, comes on top); the library's text listing
  every failure, indented per level, is not built.
- `canon.StrictDecoder` no longer lets two keys that differ only in case into
  one object, nor a key that matches a struct field only by case. encoding/json
  reads both into the same struct field, the later one winning, and reads
  `"V"` into a field `v`; a reader that tells case apart sees two keys, or
  none. The strict decoder refused only exact duplicates.
- A bundle manifest decoded with encoding/json goes through the strict and
  per-version checks `bundle.Verify` runs; a caller's decode skipped them.
- A Data Integrity proof and a delegation credential are read as strictly by
  any decoder that honours `json.Unmarshaler` as by the strict paths that
  check them. A caller that decoded one with encoding/json got the last of two
  duplicate keys, a key in another case read as the field, and invalid UTF-8
  or an unpaired surrogate replaced with U+FFFD, where the strict paths refuse
  all three.
- An `appraisal.Manifest`'s identity (`ID`) covers every member it was read
  from. It re-read the members into the struct through encoding/json, which
  matched names case-insensitively and dropped unknown members: a member of a
  spine entry the struct lacks left `ID` unchanged, and `"HEAD"` was read as
  the head while also kept as an extension. A spine entry's other members are
  now in the identity, and a member that is a field in another case is
  refused. A number in an extension is admitted before it is canonicalized,
  as on the other identity paths, so the identity holds the number the
  manifest carries.
- Two tlog checkpoints whose timestamps differ by less than a second could
  share one signature: the signed view writes the timestamp to the second.
  One root in two spellings (a head in upper case) got two verdicts:
  `VerifyConsistency` compared heads as text for equal sizes but as bytes
  otherwise. Each value now has one spelling, and a value in another is
  refused.
- A page token has one spelling: `pagination.DecodeToken` refuses
  (`ErrInvalidToken`, so `InvalidArgument` from every listing RPC) a token
  not spelled as `EncodeToken` writes it. Base64 decoding skipped line breaks
  and ignored the unused bits of the last character, so one cursor had many
  tokens.
- The batch resolver presented the node's L1 bearer (`vc-store-bearer`) to
  every peer it fetched from, including endpoints that others choose. It now
  presents it only to the origins of the destinations the operator configured
  and those listed in `credential-origins`, so the token, which lets its holder
  call this node's L1-protected services as the node, reaches only parties the
  operator named. `provin bundle export` showed the caller's
  `--token` to every endpoint the exported chain's issuers advertise; it now
  shows it only to `--registry`'s origin and to the origins named with
  `--credential-origin`. No call of the node, the pipeline or the CLI that
  carries a credential follows a redirect, so the credential does not reach a
  server a named origin redirects to (net/http forwards an `Authorization`
  header to another port or a subdomain).
- Every reader of a `json.Number` as a double in this module (the RFC 8785
  and legacy canonicalizers, the jsonata filter and converter) reads it
  through one helper, `canon.Float64`, so one number is read as the one
  double nearest its value, whatever its spelling, and only RFC 8259 numbers
  are read; the jsonata filter and converter evaluate no number they cannot
  read as one.
- The text of `canon`'s errors does not grow with the document it was given.
  `canon.UnsafeNumberError` and `canon.DuplicateKeyError` write each literal,
  key and path they name within 128 bytes: whole when it fits, or else its
  head and its length, `… (N bytes)`, cut where a character starts, with
  what is not UTF-8 written as U+FFFD. Their fields still hold the values
  verbatim. `canon.StrictDecoder` names a trailing token and the path to a
  decode target that holds itself the same way, and returns every error
  within 1024 bytes: one whose text would be longer or not UTF-8
  (encoding/json's, or a type's own decoding's, which write a number's
  literal or a time's text) is returned wrapped, its text cut. `errors.Is`
  and `errors.As` find the error it wraps; a type assertion or `==` does
  not. `canon.Float64` names its literal, quoted, within 128 bytes the same
  way; it named the first 80 bytes, which could end inside a character, and
  not the length.

## [0.3.0] - 2026-08-05

The Paper 04 line: the delivery gate appraises the exact evidence it
accepts, and the resolution cost that appraisal pays becomes measured —
and recoverable — instead of implied. The paper's functional-evaluation
revision is `38b87cf`; its scaling and cache-posture revision is
`4174829b`; both are ancestors of this tag.

### Added

- Opt-in, TTL- and byte-bounded DID document cache (`resolver/cache`),
  composed beneath input capture so the EvidenceView keeps committing the
  digests of the documents actually used. Disabled by default.
- Upstream pinning tests for the load-bearing resolution counts, next to
  the verifier that owns them, so a change to the verify path fails in the
  same run as the change.

### Changed

- Agent delivery is gated on an exact local appraisal: the appraised
  spine, profile, and payload binding are fixed in the delivery record.
- Release hardening: artifacts build with the same Go toolchain CI tests;
  digests are identity.

### Fixed

- Owner-init `AlreadyExists` settles over the public route, not an
  authorized one.
- Verify fixtures orphaned by the hardened verifier repaired.

## [0.2.0] - 2026-07-27

The P0 (public-release hardening) line, cut at the public/production cut as
this section always said it would be — no intermediate tag was minted between
`0.1.0` and here, so everything below is one release.

This is the first supported line: `SECURITY.md` names `0.2.x` as the supported
line and `0.1.x` as an internal soak line, unsupported at the public cut, which
until this tag existed left the repository with no supported version at all.

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
  step 2; amended within this same release line by the Fork W entry below,
  which post-dates and supersedes the original six-member wording) — and the
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

**Amended (Unreleased), for security, not compatibility:** `eddsa-rdfc-2022`
stays frozen on the wire: for a document it accepts, the bytes it
canonicalizes and signs do not change. It is now opt-in for verifying as well
as for issuing: a process accepts it only once it calls
`vc.RegisterEdDSARDFC2022`, since verifying it runs JSON-LD processing on the
untrusted document before the signature is checked. `canon/urdna2015` also
refuses a document some value of which the canonical form would not hold,
and a document past its work bounds (Unreleased, Security), so a credential
signed under the suite over such a document no longer verifies here.

Out of scope of this declaration: the repository's OTHER signed views — the
tlog checkpoint `SignedView`, the chain-manager/payload-resolver wire-auth
views, and the DID-document JCS hash recorded into lifecycle logs — are
separate protocol contracts, each pinned by its own golden tests. Changes
there are compatibility-relevant and are called out in this changelog (see
the checkpoint entry under Changed below), but they are versioned by their
own contracts, not by this credential-wire declaration.

### Fork W — full W3C `eddsa-jcs-2022` conformance (BREAKING within this line)

Ratified architecture decision (debate P0-4 = Fork W, 2026-07-15): external
W3C-DI verifier interop is a product goal. `eddsa-jcs-2022` now means what W3C
says it means. All changes below landed before any public tag, so they revise
the freeze declaration above — which ships for the first time in this same
release — rather than breaking a wire anyone had.

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

### P0-1A — immutable wire-variant set (BREAKING within this line)

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
- **The quickstart's offline-bundle instructions had never been executed, and
  did not work.** README §2f accumulated three defects behind the fact that
  nothing ran it — `walkthrough.sh` discarded the ingest response and exited
  before the export step:
  - it passed `payload_hash` to `bundle export --head`. That is a correlation
    handle, not a chain head content address, and **no call maps one to the
    other** — the head comes from enumerating `ListAuditStatuses` (see
    `E2E-F-030` in the harness's findings register for the missing surface);
  - it placed the global flags before the group/operation
    (`provin --registry … bundle export …`), which the CLI does not accept.
    §2a and §2c already had the right order, so this one call site was the
    outlier;
  - it omitted `--allow-loopback` while pointing DID resolution at
    `http://localhost:8443`. The SSRF guard on those fetches is fail-closed, so
    the issuers did not resolve, signer-authenticity and chain-consistency came
    back indeterminate, and export **correctly refused to write an archive that
    could not re-verify offline**. The fix passes the flag; the refusal was
    right.

  `walkthrough.sh` now runs the export and the offline verify as steps ⑥/⑦, and
  verifies **both** anchors — `--head` (what data flowed) and `--digest` (the
  whole archive, authority documents included). Verifying only the head would
  have left the stronger anchor unexercised, which is how §2f got into this
  state. A new README §2g documents `bundle verify`, which appeared nowhere
  before: §2f claimed a relying party could verify offline and never showed the
  command.

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
- CI gate on the `provin.e2e` harness (`.github/workflows/e2e.yml`): every
  commit here runs the harness's black-box scenarios in **both** runtimes —
  process (real `cmd/network` + `cmd/pipeline` subprocesses against a real
  broker) and compose (the same scenarios in containers built from this
  commit). The harness is pinned by SHA and this repository is whatever is
  proposed, so a red run means *this* commit broke something rather than that
  a test moved. The pairing was asymmetric before: the harness gated its own
  changes against a pinned product revision, and nothing ran when the product
  changed — an oss commit could break every scenario with no gate noticing.

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
- **BREAKING (wire)** the L2 wire-auth boot-window rejection (`ErrBeforeEpoch`
  — a wireauth-signed call racing `cmd/network`'s restart-epoch barrier) now
  maps to a retryable `Unavailable` (was a permanent `Unauthenticated`) across
  every wire-auth handler. A conforming peer recovers by re-signing with its
  current clock and re-calling; `cmd/pipeline`'s own loss-sensitive call sites
  now do this automatically via a bounded, re-signing retry
  (`cmd/pipeline/wireretry.go`) instead of dropping on the first rejection
  (see `docs/protocol/auth.md`).
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
- `cmd/pipeline` `/metrics`: the OTel/Prometheus exposition bridge, gated
  behind `provin.network.core.metrics.enabled` (default off, same as
  `cmd/network`'s). A dedicated copy of `internal/netcompose`'s
  `BuildMetricsHandler`/`WithMetrics`/`MaybeMountMetrics` (that package stays
  banned in this binary's production import graph —
  `depsguard_test.go` pins it) built directly over `pipeline/runtime`'s own
  `LoopMetrics` (`dp.Metrics()`): the three data-plane counter families
  (`provin_pipeline_emit_attempts_total`,
  `provin_pipeline_emit_stripped_failures_total`,
  `provin_pipeline_verify_results_total`) per configured loop, with no
  `provin_audit_verdicts_total` family — this binary runs no audit runner
  (that remains `cmd/network`'s own `/metrics` concern).
- `provin` CLI: `pipeline create`/`process create` gain an optional
  `--external-key <path>` flag switching issuance to the external-key path
  (`didpb.ExternalPublicKeys`, `#20` above) — the registry registers the
  caller's own locally-minted public halves instead of minting a keypair
  server-side. The flag reads a small JSON file (keyed by subject DID,
  `auth_public_key`/`signing_public_key` base64) that the separated
  topology's own key holder exports; `deploy/quickstart/provision` is
  today's one producer of that file.
- `deploy/quickstart`: migrated from the retired `cmd/standalone` single-node
  compose service to the separated topology — a `network` service
  (`cmd/network`, `CONFIG_OVERLAY` convention) and a `pipeline` service
  (`cmd/pipeline`, `CONFIG_FILE` convention, `depends_on: network: condition:
  service_healthy`), each with its own `/readyz` healthcheck and published
  host port (`8443`/`8444`). `provision` (the one-shot init container) now
  also mints the pipeline's own local `#auth`/`#signing` keypairs directly
  into a new `pipeline-data` volume — cmd/pipeline's boot preflights need
  them present before its first boot, unlike the retired all-in-one binary's
  in-process "loop idles until issued" model — and exports the public halves
  to `pipeline-external-keys.json` for the external-key CLI flag above to
  consume. `TestShippedConfigsParse` covers both new split `application.conf`
  files under the real HOCON parser.
- `deploy/quickstart`: the auth-layer services are pulled as published images
  rather than built from source. They pin the moving `ghcr.io/provin-line/auth-*`
  **`v0.2`** minor tag with `pull_policy: always`, so a patch release of the auth
  stack reaches the quickstart without a pin bump; swap in a `sha-<sha>` tag for
  an exact, reproducible build. The provider's image is
  `ghcr.io/provin-line/auth-provider` — it was briefly `auth-auth-provider`,
  from prefixing an `auth-` onto a component already named `auth-provider`, and
  the old name is deleted rather than aliased (GHCR has neither rename nor
  alias).

### Removed

- `pipeline/chained/cmd/` placeholder (the standalone runtime was the one
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

[Unreleased]: https://github.com/provin-line/oss/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/provin-line/oss/releases/tag/v0.2.0
[0.1.0]: https://github.com/provin-line/oss/releases/tag/v0.1.0
