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

## [0.4.0] - YYYY-MM-DD

This release fixes twelve security advisories and bounds what a node takes in
before it checks a signature. It has breaking changes: read **Breaking
changes** before upgrading.

### Security

- **`eddsa-rdfc-2022` proofs cover every value of a document**
  ([GHSA-f2pv-v7jx-372m](https://github.com/provin-line/oss/security/advisories/GHSA-f2pv-v7jx-372m);
  affects 0.2.0 to 0.3.0).
  JSON-LD processing drops some values without an error, so a document could
  carry values its proof did not cover. `canon/urdna2015` now counts a
  document's values in the document, in its expanded form and in the dataset,
  and refuses a document whose counts disagree. So that each value stays one
  value at every stage, the RDFC path also refuses forms JSON-LD drops or
  merges, among them blank node labels, `@set` and the framing keywords,
  `@language` outside a value object, a language tag outside ASCII, the RDF
  collection vocabulary written out, the same RDF term twice on one node's
  property, a node object that adds no statement, a value object or an empty
  object or array where JSON-LD keeps none, an array inside an array, a
  member named `""` outside a context, and a context that sets `@base` or
  defines a map container. Where
  a program reads documents' own contexts (`WithLocalContexts`, under
  Breaking changes), more context forms are refused, aliases of `@context`
  and `@json` among them. `canon/urdna2015`'s package doc lists what is
  refused, and by which stage. What is signed is the document's meaning:
  spellings JSON-LD gives one RDF term are signed as that term, and a
  property's values outside a list as a set. A document 0.3.0 accepted that
  meets these keeps its canonical bytes; one that writes a value twice is now
  refused, such as a self-issued credential whose issuer and subject, one id,
  both carry the same `name`.
  `eddsa-jcs-2022` is not affected.
- **The `cedar` PDP backend authenticates the caller**
  ([GHSA-f7pq-gwf9-m29h](https://github.com/provin-line/oss/security/advisories/GHSA-f7pq-gwf9-m29h);
  affects 0.1.0 to 0.3.0).
  0.3.0 gave the Cedar agent the raw bearer token as the principal, without
  verifying it. The node now verifies the bearer as a JWT (a signature by the
  configured key set or HS256 secret, `exp` and `nbf` with 30 s of leeway,
  `iss`, an `aud` containing the configured audience, a non-empty `sub`), in
  its one compact-JWS spelling, with its claims read under
  `canon.StrictDecoder`'s rules, and gives the agent its `sub`. The
  configuration it needs is under Breaking changes.
- **A credential reaches only the parties its operator names**
  ([GHSA-7gqg-xf9h-699j](https://github.com/provin-line/oss/security/advisories/GHSA-7gqg-xf9h-699j);
  affects 0.1.0 to 0.3.0).
  The batch resolver presented the node's L1 bearer (`vc-store-bearer`) to
  every peer it fetched from, including endpoints others choose; it now
  presents it only to the origins of the configured destinations and of the
  new `pipeline.credential-origins`. `provin bundle export` showed `--token`
  to every endpoint the exported chain's issuers advertise; it now shows it
  only to `--registry`'s origin and to the new `--credential-origin` origins.
  No call of the node, the pipeline or the CLI that carries a credential
  follows a redirect. What to configure is under Breaking changes.
- **A request that stops arriving no longer holds the node's HTTP server**
  ([GHSA-94vw-4854-vgp3](https://github.com/provin-line/oss/security/advisories/GHSA-94vw-4854-vgp3);
  affects 0.1.0 to 0.3.0).
  Before any handler decides on a request, the server of both node binaries
  (`internal/httpserve`):
  - takes at most 64 KiB of headers (net/http's default is 1 MiB);
  - drops a request whose body delivers nothing for 30 seconds (or, chunked on
    HTTP/1, fewer than 16 KiB), or is not read to its end within 60 seconds of
    the request's start. `RetainPayload`, the one client-streaming RPC, lifts
    the 60-second bound once its caller has proven its DID in the first frame,
    and keeps the stall bound;
  - on HTTP/1, holds what net/http reads of a body itself, to discard what a
    handler leaves of it, to the same 30 seconds, and after a failed read
    reads the body no further and closes the connection after the answer;
  - applies the outer request-size bound to HTTP/2 streams on the cleartext
    (h2c) listener too;
  - returns the error of a failed read or close of a body within 512 bytes of
    UTF-8, wrapping the original (net/http quotes what it read in some).

  The bound is on progress, not rate: a body sent at a steady pace and a
  response streamed after the body are not cut. The deployment guide gives the
  limits.
- **A deeply nested document no longer crashes the process**
  ([GHSA-rrqg-h838-mfjv](https://github.com/provin-line/oss/security/advisories/GHSA-rrqg-h838-mfjv);
  affects 0.1.0 to 0.3.0).
  `canon.StrictDecoder` refuses a document nested deeper than 10,000 arrays
  and objects before walking it. Built with Go 1.26 or earlier, about a
  megabyte of `[` overflowed the goroutine stack, a fatal error, before any
  signature was checked. `encoding/json` refuses the same depth, so no
  document that decoded is refused now. The refusal is a plain error naming
  the limit, not a `*json.SyntaxError`.
- **Checks made before a signature is checked take time linear in their
  input**
  ([GHSA-r57m-fpfp-vpr7](https://github.com/provin-line/oss/security/advisories/GHSA-r57m-fpfp-vpr7);
  affects 0.1.0 to 0.3.0).
  - `canon.AdmitSafeNumbers` reads each number in time linear in its length,
    without `math/big` (a 9-byte literal such as `1e-999999` cost about
    10 ms). Every RFC 8259 number keeps its verdict, but for the range under
    Breaking changes; a `json.Number` that is not an RFC 8259 number, which
    only a caller building one can pass, is refused.
  - `canon.StrictDecoder` walks a document in time linear in its length (it
    copied a value's path for each of its siblings: 823 KB nested 8,704 deep
    took 8.5 s).
  - `multibase.DecodeBase58Btc` refuses a value of more than 8,192 characters
    after its prefix before decoding it (decoding costs the square of the
    length: 700 KB took 7.8 s). 8,192 characters hold every byte string of up
    to 5,998 bytes: every Ed25519, ECDSA and BLS key and signature, and
    ML-DSA's, but not SLH-DSA's.
  - `canon/urdna2015` canonicalizes within a work bound in each stage:
    building the dataset, writing the canonical form, and labelling its blank
    nodes, as RDFC-1.0 §4.4.3 requires (json-gold's labelling had no bound: 7
    blank nodes no quad tells apart took 240 ms, each one more about 9 times
    as long). A document past a bound is refused with the new
    `urdna2015.ErrTooComplex`, which `errors.Is` finds through `vc`'s create
    and verify functions. One property of one node holds at most about 1,460
    distinct values. Ordinary credentials use at most 2% of the dataset's
    bound, 3% of the canonical form's and less than half of the labelling's,
    and every dataset within them keeps its canonical bytes. The package doc
    states the bounds.
- **Schema admission and payload validation are bounded**
  ([GHSA-893p-p56r-f82x](https://github.com/provin-line/oss/security/advisories/GHSA-893p-p56r-f82x);
  affects 0.1.0 to 0.3.0).
  The JSON Schema library read every number as an exact rational (a megabyte
  of large exponents could cost minutes, and a number it could not read made
  validation panic or a schema bound disappear), compiled some shapes in time
  far above linear, and ran any regular expression Go compiles. Now:
  - a number longer than 256 bytes, or whose exponent part lies beyond ±400,
    is refused before the library reads it;
  - a schema is refused past bounds on its depth, its objects and its pointers
    and URLs, or when its check against its metaschema needs more than a work
    budget. It compiles in time about linear in its size; one of 1 MiB keeps
    at most about 170 MB once compiled;
  - a payload is validated within a work budget of 2^20 steps and 16 per byte
    of the payload, nested at most 512 deep;
  - a regular expression is accepted only in the forms ECMA-262 and Go's
    regexp read alike (Unicode classes by general category only, groups
    nested at most 32 deep), within 8,192 instructions, and a schema's
    regular expressions together within 2^14 plus one per 4 bytes of the
    schema; matching one is charged to the budget;
  - an error states its first failure, within 1 KiB.

  `schema` and `schema/local` do not bound a schema's or a payload's size:
  their callers do, as the network's schema registration does at 1 MiB.
  `schema/README.md` gives the bounds and what a schema and a validation cost
  at worst. What is newly refused is under Breaking changes.
- **A document no longer ends the program that canonicalizes it for
  `eddsa-rdfc-2022`**
  ([GHSA-5g26-3jj5-v85f](https://github.com/provin-line/oss/security/advisories/GHSA-5g26-3jj5-v85f);
  affects 0.2.0 to 0.3.0).
  json-gold, which `canon/urdna2015` uses for JSON-LD expansion and the
  dataset, panics on some documents, before a proof's signature is checked.
  `canon/urdna2015`, and with it `vc`, return such a panic as an error, its
  text within 128 bytes; json-gold keeps no state between calls.
  `eddsa-rdfc-2022` is also off until a program turns it on, and reads only
  the contexts `vc` embeds (Breaking changes).
- **RDFC's canonical N-Quads are one-to-one**
  ([GHSA-445x-fhpg-78wj](https://github.com/provin-line/oss/security/advisories/GHSA-445x-fhpg-78wj);
  affects 0.2.0 to 0.3.0).
  `canon/urdna2015` refuses a document whose dataset holds an IRI that is not
  valid UTF-8 or holds a character N-Quads' IRIREF excludes unescaped (a
  space, `<`, `>`, `"`, `{`, `}`, `|`, `^`, `` ` `` or `\`); a literal that is
  not valid UTF-8 or holds a character RDFC-1.0 (Appendix A) writes escaped
  and URDNA2015 writes as it is (BS, FF, U+0000–U+0007, VT, U+000E–U+001F,
  DEL, U+FFFE, U+FFFF); or an `rdf:langString` literal without a language
  tag. Two documents of different meaning could have the same canonical
  bytes. The bytes signed are now RDFC-1.0's canonical form, and no byte the
  frozen v0 wire signs changes. `eddsa-jcs-2022` is not affected.
- **A JSON number is canonicalized as its value**
  ([GHSA-w66m-v92r-p775](https://github.com/provin-line/oss/security/advisories/GHSA-w66m-v92r-p775);
  affects 0.2.0 to 0.3.0).
  Built with Go 1.26 or earlier, `canon/jcs` and the jsonata filter and
  converter read some long number literals as another value. Every reader of
  a `json.Number` as a double in this module now reads it through the new
  `canon.Float64`: the double nearest its value, whatever its spelling, from
  RFC 8259 numbers only.
- **Rejection records and audit notations do not grow with what others
  sent**
  ([GHSA-6whw-pc5x-jv9v](https://github.com/provin-line/oss/security/advisories/GHSA-6whw-pc5x-jv9v);
  affects 0.1.0 to 0.3.0).
  A sink's reject record (`Detail`, `IssuerDID`), a delivery decision's
  `Reason`, the errored `Result.Error` of a sink, a chained step and an ingest
  step, apipush's 400 answer, and each audit notation the auditor records or
  serves (`GetAuditStatus`, `ListAuditStatuses`) are within 1,024 bytes of
  UTF-8: whole when they fit, or else their head and their length,
  `… (N bytes)`. A value they name is quoted within 128 bytes. A record
  stored before is not rewritten; it is served bounded. A reject record never
  carries the refused payload; its `Detail` may quote an excerpt of it within
  that bound.
- **Small-order Ed25519 keys are refused**
  ([GHSA-h2g5-9vcc-8j6f](https://github.com/provin-line/oss/security/advisories/GHSA-h2g5-9vcc-8j6f);
  affects 0.1.0 to 0.3.0).
  The new `crypto/ed25519.ValidatePublicKey` (errors `ErrPublicKeySize`,
  `ErrSmallOrder`, `ErrInvalidPoint` of the new type `ed25519.Error`)
  refuses a key that is not 32 bytes, is of small order in any encoding, or
  is not the canonical encoding of a point. `crypto/ed25519.Verifier.Verify`
  applies it, and returns `ErrSmallOrder` for a signature whose R is of small
  order (`crypto.Verifier` documents that a verifier may return an error).
  `did.ExtractPublicKey` and `did.ExtractPublicKeyAndEncoding` refuse such a
  key in either encoding, wrapping the new `did.ErrInvalidPublicKey`, so every
  reader of keys from DID documents here refuses it, and so do
  `did.EncodeEd25519Multikey` and `did.NewMultikeyVerificationMethod`. The
  DID registry refuses one in `IssuePipeline` and `IssueProcess` (replacing
  the all-zero check) and in an owner document's `authentication` or
  `assertionMethod` methods (`ErrInvalidArgument`).
- A pipeline loop bounds what it takes in over the transport, whatever the
  messaging backend delivers: an envelope's credential by
  `pipeline.max-credential-size`, its inline payload by the new
  `pipeline.max-inline-payload-size` (1 MiB), the whole message by the two
  and the envelope's framing before it is decoded, and a source loop's raw
  input by `pipeline.max-push-body-size`, as the push route bounds it. With
  the three keys and NATS's `max_payload` at their defaults (1 MiB each)
  nothing changes. A node that lowered `max-credential-size` or
  `max-push-body-size` below 1 MiB now refuses transport messages past them
  too. A refused message is dropped and logged (an archival sink records a
  decode failure), its error naming two sizes only.
- The node's clients for other organizations' servers bound what they take:
  `chainmanager/peerclient` reads at most 256 KiB a response and ends every
  call within 30 seconds; `payloadresolver/client` refuses a streamed frame
  larger than its `MaxBytes` without holding it; the batch resolver's fetch
  and a sink's fetch from its upstream registry end within 30 seconds;
  `provin bundle export --aggregate-complete` reads at most 1 MiB a response
  within 30 seconds; and the SSRF-guarded HTTP client takes at most 64 KiB of
  response headers. None of them accepts compression.
- Error texts do not grow with the input:
  - `canon.UnsafeNumberError` and `canon.DuplicateKeyError` write each
    literal, key and path within 128 bytes (their fields still hold the
    values verbatim), and `canon.StrictDecoder` returns every error within
    1,024 bytes;
  - `canon/urdna2015`'s refusals quote a key or value within 64 bytes, and a
    path and json-gold's error within 256, and name the byte where a literal
    or an IRI stops being UTF-8;
  - every service of the network node answers an error within 1,024 bytes of
    UTF-8, keeping its code and details; the log lines of the batch resolver,
    the auditor, the resolver's pool and the audit stores name an error
    within 1,024 bytes, and the batch resolver's a DID or an endpoint within
    128;
  - every log line of the pipeline names an error within 1,024 bytes.

  A text is cut as its head and its length, `… (N bytes)`, where a character
  starts, and a cut error wraps the original, so `errors.Is` and `errors.As`
  find it. An error whose `Error` method panics, as a nil pointer's may, no
  longer makes `canon.StrictDecoder`, a network answer, a pipeline step or a
  log call panic: its text is what `fmt` writes for it, or a fixed text naming
  its type.
- Walks of a value built in Go refuse one nested past 10,000 objects and
  arrays before their recursion could exhaust the goroutine stack:
  `canon.AdmitSafeNumbers`, `canon/jcs`, `canon/urdna2015` (wrapping
  `urdna2015.ErrTooComplex`), `wireauth.Sign` and `Verify`, `appraisal`'s
  `Manifest` and `SpineEntry`, and `did`'s `Hash` (`did.New` and `Body` copy
  a `publicKeyJwk` without recursing). A value decoded by encoding/json or
  `canon.StrictDecoder` is never deeper.
- A Data Integrity proof verifies in one wire form.
  `vc.VerifyProofUnderContract` verifies a proof only under the contract of
  the suite it names, and pins the proof's `@context` under every contract,
  as `vc.VerifyProofWithContract` did: under the W3C contracts it mirrors the
  document's, under the legacy one there is none. `vc.VerifyProof` requires
  the mirror whenever the document has a `@context`. A proof whose `@context`
  was swapped, removed or added after signing verified on these paths;
  nothing the issuer signed could change. The proofs now refused are under
  Breaking changes.
- Each value has one spelling:
  - `canon.StrictDecoder` refuses two keys of one object that differ only in
    case, and a key that matches a struct field only by case (encoding/json
    read both into one field);
  - a Data Integrity proof, a delegation credential and a bundle manifest
    decoded with encoding/json go through the strict checks their verifiers
    run;
  - an `appraisal.Manifest`'s identity covers every member it was read from;
  - a JWK verification method's `x` must be the canonical unpadded base64url
    spelling of the key;
  - a tlog checkpoint signs a lower-case head and a UTC timestamp to the
    second, so two checkpoints within a second cannot share a signature and
    one root gets one verdict;
  - `pagination.DecodeToken` accepts a page token only as `EncodeToken`
    writes it.
- Keys in DID documents are read one way. `did.ExtractPublicKey`, and every
  reader of keys here, reads a key reference and every method id only as
  `#fragment` or `<the document's DID>#fragment`, a fragment of
  `[A-Za-z0-9._-]` (the new `did.AbsoluteKeyID`); anything else, and a
  document holding it, is the new `did.ErrInvalidKeyReference`. A method
  carries only its type's key member. `RegisterOwner` checks an owner
  document's keys before its proof, and stores it only when every key in it
  is one `did.ExtractPublicKey` extracts through `authentication` or
  `assertionMethod` (`ErrInvalidArgument` otherwise); a member that carries
  keys must be a list. Refusals that were `ErrUnauthorized` (permission
  denied on the wire), such as a duplicated `#signing`, one controlled by
  another DID, or an unusable key of the proof, are now `ErrInvalidArgument`.
  Documents stored before are not checked again.
- What `canon.AdmitSafeNumbers` admits, RFC 8785 writes within ±(2^53−1), so
  a check of a credential's canonical bytes agrees with the check of its
  value (a credential could be stored on one node and refused on the next,
  and `resolver/cache` could answer a hit with another spelling of a number).
  It also spells the path to a refused number once: refusing one 10,000
  levels deep allocated 160 MB. The range is under Breaking changes.
- The YAML stores hold only records that read back as written, so a stored
  value, also one another organization sent, cannot change when it is read
  or make reading the store fail. A byte field is written as base64: reading
  a 1 MiB schema body allocated about 1.4 GB, and now 17 times less. A record
  0.3.0 wrote reads as it did. Times are stored in UTC.
- `(*local.Validator).Add` checks a schema against its metaschema whatever id
  it is added under; one added under an id below `json-schema.org` skipped
  the check.
- `tlog/filelog` and `tlog/merklelog` open their file in time and memory
  linear in its size (a 10 MB log took about 10 s, now 0.2 s), and
  `canon/urdna2015` builds the path to a refused value only for its error (a
  document nested 8,000 deep allocated 546 MB, now 53 MB).

### Breaking changes

- **`eddsa-rdfc-2022` is off by default and reads only the contexts `vc`
  embeds** (Go API, wire).
  - `vc`'s init registers `eddsa-jcs-2022` alone. Until a process calls the
    new `vc.RegisterEdDSARDFC2022`, `vc.CreateProof`, the `vc.Builder` and
    every verify function refuse the suite with an error wrapping the new
    `vc.ErrCryptosuiteNotRegistered`, and a `vc.Verifier` finds signer
    authenticity failed. `vc.CreateProof`, the `vc.Builder` and
    `vc.VerifyProof` wrap it for any suite nothing registers too, where their
    error wrapped nothing. `vc.RegisterCryptosuite` refuses the suite's
    name, and `make lint` keeps this module's packages from calling the
    function. This amends the v0.2.0 credential wire freeze, for security.
  - With the suite on, `vc` accepts as `@context` only the IRIs of the three
    contexts it embeds (the W3C VC v2 context, dplaax's and provin's), and
    refuses a document or a proof holding a context written in it, at any
    depth, `null` or another IRI, before canonicalizing it. 0.3.0 accepted a
    context written in the document.
  - provin's binaries do not call the function, so they refuse an
    `eddsa-rdfc-2022` credential they verified before; this release has no
    setting that turns the suite on in them.
  - `canon/urdna2015`'s `Canonicalize` refuses by default a document holding
    a `@context` other than the IRIs of contexts its `Canonicalizer` serves.
    A program that canonicalizes documents with their own contexts passes the
    new `urdna2015.WithLocalContexts()` to `NewCanonicalizer`, only for
    documents it trusts, and bounds their size: with its own context a
    document can make the work grow as the square of its size. Observed on
    darwin/arm64 with the option, not bounds: about 2.7 GB allocated for
    250 KB and about 37 GB for 1 MiB (a long `urn:` `@vocab`), and about 18 s
    for 250 KB and more than 150 s for 1 MiB (a long default language).
    `NewCanonicalizer` takes options (`...urdna2015.Option`): every call
    compiles as before, but it no longer assigns to a variable of type
    `func(map[string][]byte) *urdna2015.Canonicalizer`.

  Migration: a process that issues or verifies `eddsa-rdfc-2022` calls
  `vc.RegisterEdDSARDFC2022` once, from its `main` or an `init` of its main
  package, its documents use only the embedded contexts, and it bounds the
  size of what it verifies: `vc` does not, and within its bounds the
  costliest 1 MiB shape measured takes about 1 s and 0.9 GB (the function's
  doc).
  `eddsa-jcs-2022`, the issuance default, is unchanged.
- **`vc` refuses proofs it cannot verify earlier** (Go API).
  - `vc.VerifyProof` refuses a proof without a proof-local `@context` over a
    document with one. An `eddsa-rdfc-2022` proof without one, the shape
    vc-di-eddsa §3.2.1 produces, is refused by every verify function.
  - `vc.Verifier` refuses a proof under a cryptosuite no claim contract
    names, or whose `proofValue` does not decode, before looking up the
    suite's lifecycle or the issuer's key: it fails such a proof where a
    transient issuer-key error made it indeterminate, whatever a lifecycle
    registry says. `delegation.Verify` returns the decode error without
    resolving the issuer.
  - `vc.VerifyProofUnderContract` refuses a proof whose suite is not the
    contract's, a proof `@context` that does not mirror the document's under
    a W3C contract or is present under the legacy one, and, under a W3C
    contract, a document without `@context`.

  Migration: verify a legacy `eddsa-jcs-2022` proof, which has no
  `@context`, with `vc.VerifyProofWithContract` or
  `vc.VerifyProofUnderContract`.
- **`canon` reads more strictly** (Go API, wire).
  - `canon.AdmitSafeNumbers` refuses a number of magnitude 2^53 − 0.5 or
    more, integer or not (`9007199254740991.5` was admitted), with one new
    `UnsafeNumberError.Reason` text for every number refused for its
    magnitude. `canon/testdata/number-literals.json` gives the verdicts.
    `vc.CreateProof`, the DID registry, the VC resolver's `StoreVC` and
    `resolver/cache` refuse the same numbers.
  - `canon.StrictDecoder` refuses, as a `*canon.DuplicateKeyError` naming
    both, two keys of one object that differ only in case as encoding/json
    folds names, and a key that matches a struct field only that way. So do
    the paths that decode others' JSON with it: the push ingress (HTTP 400),
    the ingest loop, the jsonata filter and converter, the DID registry, the
    VC resolver, and JSON Schema documents and payloads. `bundle.Verify`
    reports colliding keys as `ErrBundleIntegrity`.
  - `canon.StrictDecoder` refuses a decode target it reaches through more
    than 64 pointers and interfaces, as one that holds itself, which
    encoding/json follows without end.
  - `vc.DataIntegrityProof` and `delegation.DelegationCredential` are read
    under `canon.StrictDecoder`'s rules on every path, encoding/json
    included; a number inside a proof's `@context` is a `json.Number`.

  Migration: code that matched the old `Reason` text, or builds
  `canon.DuplicateKeyError` as an unkeyed literal (it gained `Other`),
  changes; a struct embedding `delegation.DelegationCredential` needs its own
  `UnmarshalJSON`.
- **Schemas and payloads past the new bounds are refused** (Go API, wire).
  `schema.ValidateJSONSchema`, `(*local.Validator).Add` and `Validate` refuse
  a schema or payload holding a number longer than 256 bytes or whose
  exponent part lies beyond ±400; a regular expression not in the forms
  ECMA-262 and Go read alike (among the forms Go compiled: inline flags such
  as `(?i)`, `\pL`, `\z`, `\Q…\E`, POSIX classes, and a `-` Go reads as a
  literal after a class escape, as in `[\w-.]`); a schema past its shape
  bounds or its metaschema budget, or referring by a JSON pointer whose array
  index is not written as RFC 6901 writes one; and a payload nested deeper
  than 512 levels, past its work budget, or applying schemas within one
  another more than 10,000 deep. `schema/README.md` states the bounds. The
  schema registry's `RegisterSchema` refuses such a schema with
  `InvalidArgument`, and admits a schema name or prerelease only of 1 to 128
  characters of `[A-Za-z0-9._-]`, the first a letter or digit (0.3.0 refused
  only an empty name, `.`, `..`, and one with `/`, `\` or NUL). A schema
  stored before is not checked again, but `(*local.Validator).Add` refuses
  it when a validator loads it.

  Migration: write such patterns in the shared forms. SchemaStore's schemas
  are within the shape bounds and need at most 11.5% of the metaschema
  budget.
- **Manifests are read and written in one shape** (Go API, wire).
  - Decoding a `bundle.Manifest` with encoding/json reads it as
    `bundle.Verify` does, afresh and in the exact shape of its version;
    encoding writes that shape (a v2 manifest always has `receipts`), and is
    an error for a v1 manifest with receipts or a version no shape names.
  - An evaluation view manifest (`appraisal.Manifest`) is read member by
    member, exactly as named: a known field in another case, and `null` for
    the manifest, a spine entry or a field, are refused, and every other
    member is kept as an extension in its identity. So a manifest whose spine
    entries carry other members has a different `EvidenceViewID` than in
    0.3.0, and one stored for it no longer passes `ValidateID`.
  - `appraisal.SpineEntry` holds a map (`Extensions`), so it is no longer
    comparable, and an unkeyed literal with its two values no longer
    compiles. A decoded entry's `Extensions` is an empty map, not nil. A
    number in an extension that `canon.AdmitSafeNumbers` refuses gets no
    identity.

  Migration: a struct embedding `bundle.Manifest` needs its own
  `UnmarshalJSON`; an `EvidenceViewID` stored for such a manifest is computed
  again.
- **A tlog checkpoint has one spelling of what it signs** (Go API).
  `(*tlog.Checkpoint).SignedView`, `tlog.SignCheckpoint` and every checkpoint
  verification refuse a head with an upper-case letter and a timestamp not
  in UTC, with a fraction of a second, or outside 0000–9999;
  `tlog.VerifyConsistency` and `tlog.VerifyInclusion` refuse a head not in
  lower case. The logs here write nothing refused. Migration: sign with a UTC
  time in whole seconds.
- **Pipeline parts and the runtime take explicit bounds and a decision
  recorder** (Go API).
  - `envelopecodec.New` takes `envelopecodec.Limits` (`MaxCredentialSize`,
    `MaxInlinePayloadSize`) and returns an error (`ErrInvalidLimits`); a codec
    without bounds can no longer be made, and the zero `Codec` refuses every
    message. `UnmarshalEnvelope` refuses what passes them
    (`ErrMessageTooLarge`, `ErrCredentialTooLarge`,
    `ErrInlinePayloadTooLarge`).
  - `ingest.New` requires `ingest.Config.MaxPayloadSize`
    (`ErrInvalidMaxPayloadSize`); `Process` refuses a longer input.
  - `runtime.Config` gains `MaxCredentialSize` and `MaxInlinePayloadSize`,
    which `runtime.Build` requires, before it dials, when a loop is
    configured, and `MaxIngestPayloadSize`, which it requires when a source
    loop is: it bounds the loop's raw input and, through the new
    `PushBinding.MaxBodySize`, its push route.
  - `sink.New` with an `Appraiser` and no `DecisionRecorder` fails with
    `sink.ErrMissingDecisionRecorder`, and `runtime.Build` with a sink loop
    that has `agent-access` fails unless `runtime.Config.DecisionRecord` is
    set.

  Migration: a program that calls `runtime.Build` sets the new fields;
  `cmd/pipeline` sets them from its configuration.
- **Authorization configuration and answers** (config, wire).
  - `backend = "cedar"` needs `provin.network.auth.cedar.jwt.{issuer,audience}`
    and exactly one of `jwks-url` (https) or `secret` (with an optional
    `secret-encoding`: `utf8`, `hex` or `base64`), or the node does not boot.
    With `jwks-url` the key set is cached 10 minutes, refetched at most every
    30 seconds, and kept for known key ids for 30 minutes during a JWKS
    outage, so a withdrawn key can be trusted for up to 40 minutes.
  - A PDP at a non-loopback `http://` URL is refused unless its `host:port`
    is listed in the new `provin.network.auth.plain-internal`.
  - A PDP outage (HTTP 429, 502, 503, 504, or a timeout) fails an L1-guarded
    RPC with `Unavailable` instead of `Internal`, and the pipeline's push
    endpoint answers 503 with `Retry-After` instead of 403, so the
    pipeline's wire retry retries through it. HTTP 500 and a
    malformed answer stay `Internal` and 403; with `cedar`, a failed token
    check stays `Unauthenticated`.
  - With the `o3co` backend an allow requires HTTP 200 with a complete
    decision envelope; an empty 200 or a 204 no longer allows, and the PDP
    must not redirect.

  Migration: a cedar deployment adds the JWT settings, and a plaintext PDP on
  a private network is listed in `plain-internal`.
- **Credentials are presented only to named origins** (config, CLI). The
  batch resolver fetches from a peer outside its configured destinations and
  `pipeline.credential-origins` without `vc-store-bearer`, and
  `provin bundle export` calls an endpoint outside `--registry`'s origin and
  its `--credential-origin` origins without `--token`. Neither follows a
  redirect with a credential. Migration: list other L1-protected peers in
  `credential-origins` (with the CLI, `--credential-origin`) before
  upgrading, and configure each destination at its final URL. The quickstart
  needs no change.
- **Input newly refused by the security fixes** (Go API, wire). Besides the
  entries above, the Security section lists input this release refuses that
  0.3.0 accepted: RDFC documents in the forms listed there, a base58btc value
  of more than 8,192 characters, a small-order Ed25519 key, a DID key
  reference or owner document read in more than one way (the DID registry
  answers `InvalidArgument` where it answered permission denied), a JWK `x`
  or a page token in another spelling, and a schema added below
  `json-schema.org` that its metaschema refuses.
- **The module needs Go 1.26** (build). `go.mod` sets `go 1.26.0`, which
  `protobuf.interceptors` v0.6.0 requires, and `toolchain go1.26.8`; the
  images build on `golang:1.26.8-alpine`. Go 1.25 no longer receives
  security fixes.

### Added

- `keybinding`: the key binding, a `KeyBindingCredential` in which an issuer
  binds a key (`keyId` and a public JWK: Ed25519, P-256 or RSA) to a subject,
  of a kind, with roles, of a key class, for one relying party, from
  `validFrom` until `validUntil`, with an entry in the issuer's revocation
  list, and that list (a W3C `BitstringStatusListCredential`). `Issue` and
  `IssueStatusList` sign with `eddsa-jcs-2022`. `Verifier.VerifyBinding`
  checks a binding against the trust `Anchor` and the held list;
  `Verifier.VerifyStatusList` refuses a list older than the one held, one
  that clears a mark (a revocation is not reversible), one not yet valid, and
  one whose id is not a DID URL of its issuer; `Verifier.RestoreStatusList`
  rebuilds the held list after a restart. Each refusal is a constant
  `keybinding.Error`. The package doc states the rules.
- `decisionrecord`: the record a deciding party writes for each decision
  (`Record`: id, deciding party, time, outcome `Accepted`, `Refused` or
  `Unenforced`, the refusing check and reason, the parties, and what was
  decided on as content addresses, never a payload), and `Filter`, which
  writes it at a level chosen explicitly: `all`, `refusals`, `summary`
  (counts per window, through `SummaryRecorder`) or `none`. At `all` a record
  the sink does not accept is an error, so the decision is refused; at the
  other levels it is a warning. Sinks: JSON lines (`NewJSONLines`) and
  structured log (`NewLog`). The purpose-first sink writes its delivery
  decisions through it (Changed).
- `contentaddress`: the content address of dPLaaX (`sha256:` and 64
  lowercase hex digits) as a type, `Address`, made only by `Of` and `Parse`,
  comparable, written and read as JSON text in its one spelling.
- `vc.IssuerVerifier`, `vc.WithIssuerVerifier`, `vc.NewDIDDocumentIssuers`,
  `vc.IssuerKey` and `vc.ErrIssuerNotFound` (of the new type `vc.Error`): how
  a `vc.Verifier` establishes an issuer, the key its proof verifies under and
  the Owner responsible, can be replaced, so a deployment that registers its
  stages elsewhere needs no DID document per stage. The default reads both
  from DID documents. An error wrapping `ErrIssuerNotFound` reads as failed,
  any other as indeterminate; `AttributeOwner` and `ClassifyChain` wrap it for
  an Owner established not to exist.
- `vc.ValidateChainLinks(chain)` and `vc.ValidateChainFrom(chain,
  originInput)`: the links of a chain without its signatures, through the
  same implementation as `VerifyChain`; a broken link is a
  `*vc.ChainLinkError` with the credential's index.
- `vc.Credential` and `(*vc.Verifier).VerifySignerAuthenticity`: the
  signer-authenticity axis alone, for a Data Integrity credential of any
  type, as `vc.SignerAuthenticityResult`.
- `(*vc.DataIntegrityProof).ProofValueBytes`: the bytes a proof's
  `proofValue` encodes, decoded by its cryptosuite's encoding and bounded as
  `multibase.DecodeBase58Btc` bounds it. It verifies nothing.
- `crypto/es256` and `crypto/rs256`: `crypto.Verifier` implementations for
  ES256 (ECDSA P-256, SHA-256; SEC1 uncompressed key, `r || s` signature)
  and RS256 (RSASSA-PKCS1-v1_5, SHA-256; PKCS #1 key, 2048 to 4096 bits).
  ES256 signature bytes are not unique, so nothing may count or deduplicate
  signatures by them.
- `canon.Float64(n json.Number) (float64, error)`: the IEEE 754 double
  nearest a JSON number's value (ties to even), from the RFC 8259 grammar
  only, in time linear in its length. Its errors wrap `canon.ErrNotJSONNumber`
  or `canon.ErrBeyondDoubleRange`, of the new type `canon.Error`.
- `canon.DuplicateKeyError.Other`: for a key refused because it differs from
  another key or a struct field only in case, that other name.
- `(*delegation.DelegationCredential).UnmarshalJSON`,
  `(*bundle.Manifest).UnmarshalJSON` and `bundle.Manifest.MarshalJSON`, and
  `appraisal.SpineEntry.Extensions` with its own `MarshalJSON` and
  `UnmarshalJSON`: these are read and written in one shape (Breaking changes).
- Types and errors the entries above name: `urdna2015.Error`, `did.Error`,
  `ed25519.Error` (with `ErrSignatureSize`), `sink.RejectDecisionRecord`, and
  `DecisionRecord` in `pipelineconfig.Config` and `runtime.Config`.
- Configuration keys:
  - `provin.network.auth.plain-internal` (list of `host:port`, default empty):
    the PDP endpoints that may be called over plaintext `http://`, reached
    only at a private address. The quickstart sets it for
    `policy-verifier:3001`.
  - `provin.network.pipeline.credential-origins` (default `[]`): origins the
    pipeline may show `vc-store-bearer` to besides its configured
    destinations (`pipelineconfig.Config.CredentialOrigins`,
    `PresentsCredentialTo`).
  - `provin.network.pipeline.max-inline-payload-size` (default 1 MiB): the
    most bytes of an inline payload in an envelope a loop receives
    (`pipelineconfig.Config.MaxInlinePayloadSize`).
  - `provin.decision-record.level` (`all`, the default, `refusals`,
    `summary` or `none`), `.sink` (`log`, the default, or `jsonl`), `.path`
    (the JSON-lines file, required with `jsonl`) and `.summary-window`
    (default `1m`).

  A malformed value fails startup.
- `provin bundle export --credential-origin <origin>` (repeatable): an origin
  the `--token` may be shown to, besides `--registry`'s.

### Changed

- **Delivery decisions are recorded by default.** Every delivery decision of
  the purpose-first sink (a sink loop with an `agent-access` block) writes a
  `decisionrecord.Record` through the new `sink.Config.DecisionRecorder`: an
  envelope that does not decode is refused (check `decode`); the appraisal's
  decision is accepted on `ACCEPT` and refused (check `appraisal`) otherwise;
  a decision accepted that a later stage refuses is recorded again under the
  same id as refused, the check being that stage's reject reason. A writer's
  error is never recorded as a refusal (the writer may have delivered).
  Records hold content addresses, never payload bytes. At level `all`, if the
  accepted record cannot be written the delivery is refused (new reject
  reason `decision-record`), and the default `log` output writes one `info`
  entry per record; turn it off with `provin.decision-record.level = "none"`.
  Records after the accepted one are best effort. Existing configs keep
  booting. The legacy verifier path is unchanged.
- `vc.VerifyProof` and `vc.VerifyProofUnderContract`, and through them
  `vc.VerifyProofWithContract`, decode `proofValue` before they canonicalize
  anything: a `proofValue` that does not decode is refused in about 1 µs,
  where an `eddsa-rdfc-2022` proof over an ordinary credential took about
  560 µs. A proof whose `proofValue` does not decode, over a document that
  does not canonicalize, is refused with the decode error.
- `canon/jcs` and the jsonata filter and converter read a JSON number as a
  double through `canon.Float64`: `jcs` refuses a `json.Number` that is not
  an RFC 8259 number (`+1`, `.5`, `01`), and the jsonata filter and converter
  refuse a document holding a number beyond the double range; their errors
  match `canon.ErrNotJSONNumber` or `canon.ErrBeyondDoubleRange`.
  `scripts/check-number-hygiene.sh` (in `make lint`) flags any other reading
  of a double.
- `vc` judges `credential.claim.charset` with tables generated from Unicode
  15.0.0, the version the specification pins, instead of Go's `unicode`
  tables, so a toolchain of another Unicode version judges a claim the same.
  `go generate ./vc` rebuilds them from pinned files.
- `chainmanager`'s `Subscribe` refuses a publisher's connection info with a
  key other than `subject`, `account`, `url` and `publishType`, or a value
  other than empty or a letter or digit followed by up to 999 characters
  that a URL, a NATS subject or account key, or a DID uses
  (`ErrRemotePeer`): the remote registration is undone and nothing is
  imported or stored.
- The pipeline's interfaces, configs and constructors through which a part is
  plugged in state, by pointing to one rule in `pipeline/contract`'s doc,
  that the methods of a part's errors that `fmt` and `errors.Is` and
  `errors.As` call return without a panic, also for a nil pointer. A part
  that already does so is unaffected.
- The JSON Schema library is a copy inside this module,
  `internal/jsonschema`: `santhosh-tekuri/jsonschema/v6` v6.0.3 (Apache-2.0,
  its LICENSE copied unchanged) with a work budget and with a number
  `big.Rat` cannot read reported as an error. `go.mod` no longer requires
  `santhosh-tekuri/jsonschema/v6` (0.3.0 required v6.0.2). The schema package
  goes back to the upstream module when upstream bounds its own work
  (`internal/jsonschema/README.md`).
- Quickstart: the auth layer moves to provin.auth v0.3 (the `:v0.3` images,
  `AUTH_REF=v0.3.0`). Its policy-verifier accepts only RFC 9068 access
  tokens, so every token the quickstart uses carries `iss` and `aud`, and the
  ones it mints are typed `at+jwt`; the audience is
  `https://quickstart.provin.invalid` (`OAUTH_JWT_AUDIENCE`). The shared HS256
  secret is now long enough to carry 32 bytes of key material, and the issuer
  is `http://localhost:3000`; an existing `.env` that sets `OAUTH_JWT_SECRET`
  or `OAUTH_JWT_ISSUER` must meet the same rules.
- Dependencies, from 0.3.0: `connectrpc.com/connect` 1.20.0 → 1.21.1,
  `github.com/o3co/protobuf.interceptors` (and its `connectrpc` module)
  0.2.0 / 0.2.1 → 0.6.0 (it authorizes a stream before its handler runs and
  re-checks it per message), `nats-server` 2.12.6 → 2.15.1, `nats.go`
  1.50.0 → 1.55.0, `nats-io/jwt` 2.8.1 → 2.8.2, `nkeys` 0.4.15 → 0.4.16,
  `piprate/json-gold` 0.8.0 → 0.9.1, `o3co/go.hocon` 1.8.0 → 1.14.2,
  `prometheus/client_golang` 1.23.2 → 1.25.0, OpenTelemetry 1.44.0 → 1.47.0
  (`exporters/prometheus` 0.66.0 → 0.69.0), `golang.org/x/net` 0.55.0 →
  0.61.0, `golang.org/x/sys` 0.45.0 → 0.49.0, `golang.org/x/crypto` 0.52.0 →
  0.58.0, `golang.org/x/text` 0.39.0 → 0.43.0, `golang.org/x/time` 0.15.0 →
  0.16.0, `google.golang.org/protobuf` 1.36.11 → 1.36.12, and
  `github.com/go-jose/go-jose/v4` 4.1.6 (new, for the cedar JWT check). The
  quickstart's broker image moves from `nats:2.12.6` to `nats:2.15.1`.
  `govulncheck` reported 18 standard-library vulnerabilities on the old
  toolchain and reports none now.

### Fixed

- The signer-authenticity axis fails a credential whose issuer is empty
  before resolving anything; with a bare-fragment `verificationMethod` it was
  indeterminate during a resolver outage. `Verify`'s overall verdict does not
  change.
- CLI: `owner init`, `pipeline create`, `process create`, `bundle export` and
  `bundle verify` reject unexpected positional arguments after flags as a
  usage error; they were ignored.

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

**Amended (0.4.0), for security, not compatibility:** `eddsa-rdfc-2022`
stays frozen on the wire: for a document it accepts, the bytes it
canonicalizes and signs do not change. It is now opt-in for verifying as well
as for issuing: a process accepts it only once it calls
`vc.RegisterEdDSARDFC2022`, since verifying it runs JSON-LD processing on the
untrusted document before the signature is checked. `canon/urdna2015` also
refuses a document some value of which the canonical form would not hold,
and a document past its work bounds (0.4.0, Security), so a credential
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

[Unreleased]: https://github.com/provin-line/oss/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/provin-line/oss/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/provin-line/oss/releases/tag/v0.3.0
[0.2.0]: https://github.com/provin-line/oss/releases/tag/v0.2.0
[0.1.0]: https://github.com/provin-line/oss/releases/tag/v0.1.0
