# verification — formal models of provin OSS

This directory is a test-only Go module (`github.com/provin-line/oss/verification`)
that checks provin OSS against formal models and against third-party standard
test vectors. It has no production code and is outside the root module: `go
test ./...` at the root does not enter it. It holds Tamarin models of two
security properties of the implementation, and the standard vectors
([below](#standard-vectors)) under [`vectors/`](vectors):

| model | tool | subject |
| --- | --- | --- |
| [`tamarin/wireauth.spthy`](tamarin/wireauth.spthy) | Tamarin 1.12.0 (with Maude 3.5.1) | the L2 peer wire proof ([auth.md § L2](../docs/protocol/auth.md#l2--peer-wire-proof-wireauth)): the signed view and its audience, single-use nonces, the nonce recorded only after the signature verifies |
| [`tamarin/bearerorigins.spthy`](tamarin/bearerorigins.spthy) | Tamarin 1.12.0 (with Maude 3.5.1) | where a node shows its L1 bearer (`vc-store-bearer`) |

The properties of the dPLaaX protocol itself (provenance chains, delegation)
are modelled in the specification repository, `dplaax.spec`, under `formal/`.
These models are of this implementation: they model what the code does, under
the premises each contract below states, and show whether that holds against
an attacker.

## Contract of `wireauth.spthy`

A model is only as good as the assumptions it is read under. The model's
header comment says the same.

- **Attacker.** The network is the attacker's (Dolev-Yao): every message is
  read, replayed, altered and composed at will. The attacker makes DIDs of its
  own, and its DID documents may list any key, an honest signer's included.
- **Trusted.** The verifier, which is never taken over; DID resolution (a
  DID's `#auth` key reaches the verifier directly); signatures, which cannot
  be forged without the key.
- **Open to compromise.** Any signing key, through the rule `Compromise`,
  which records `Compromised(k)`.
- **Nonces.** An honest signer draws a fresh nonce for each proof
  (`wireauth.NewNonce`, which every caller of `wireauth.Sign` uses).
  `no_burn` rests on this.
- **Persistence and time.** None. `issuedAt` is an opaque term of the view.
  The acceptance window, the restart epoch, the eviction of nonces and
  restarts are outside the model; the nonce store here never forgets. That
  forgetting after the window is safe is a property of time, left to a TLA+
  model (`NonceEpoch`) not yet written.
- **Store.** One verifier, with one nonce store, per network process
  (`internal/netcompose/server.go`), shared by every surface that verifies an
  L2 proof. The store's `Use` is an atomic check-and-set (the restriction
  `NonceStore`).
- **Audience.** Each verifier has one audience, its node's registry ID
  (D-w12). The view binds the audience; the verifier refuses a proof that
  names another, and rebuilds the view with its own. Several verifiers may
  have one audience (replicas, each with a store of its own); a deployment
  runs one verifier per audience, which closes `replay_across_replicas`
  ([auth.md § L2](../docs/protocol/auth.md#l2--peer-wire-proof-wireauth)).
- **Requests.** A request is its op and its fields: a handler acts only on the
  fields it passes to `Verifier.Verify`, and the op values are distinct across
  the surfaces that share the verifier. An honest signer signs for whatever
  audience, op, issuedAt and fields it is handed.
- **Events.** `Accepted(V, R, S, op, n, t, f)`: verifier `V`, whose audience
  is `R`, accepted the proof (`Verify` returned nil and recorded the nonce).
  `ReplayRejected(...)`: the signature verified and the nonce was already
  recorded (`ErrReplay`).
- **Not modelled.** The fields' value grammar and the JCS bytes (D-w11; for
  test vectors and fuzzing), authorization (a refusal leaves the store as it
  was, which is what a rule that does not fire does), DID spelling (the view
  and the store key use the same string), key rotation.

## Contract of `bearerorigins.spthy`

- **Attacker.** Dolev-Yao. It chooses every endpoint the node fetches from (a
  `StoreVC` caller's hint, an issuer's DID document) and every redirect's
  target, and runs servers of its own (servers it takes over).
- **Trusted.** The node; the path to a named origin's server, which the
  attacker neither reads nor redirects. The assumption is TLS's: it holds for
  an `https` origin, and an `http` origin is outside it.
- **Open to compromise.** Any server, through `CompromiseServer`; a server
  taken over hands the attacker every bearer it has received, before or after.
- **Named origins.** The destinations the operator configured
  (`vc-store-endpoint`, each loop's upstream endpoint) and
  `credential-origins`; the model does not tell them apart.
- **Events.** `Received(o, tok)`: the server of origin `o` received the
  bearer. `K(tok)`: the attacker knows it.
- **Not modelled.** Parsing a URL and comparing origins (`internal/origin`'s
  tests), transport enforcement, the CLI's `--token`.

## Lemmas and implementation

`wireauth.spthy`:

| lemma | kind | property | implementation |
| --- | --- | --- | --- |
| `executable_accept` | exists-trace | an honest DID's proof is accepted with no key compromised (reachability) | — |
| `executable_alias` | exists-trace | two honest DIDs on one key each have a proof accepted | — |
| `forgery_after_compromise` | exists-trace | with its key taken over, an honest DID has a proof accepted that it never signed: the exception in `view_binding` is live | — |
| `view_binding` | all-traces | a proof accepted for a DID under an honest key not taken over was signed by that DID, for that op, nonce, issuedAt and fields: no reuse for another DID naming the same key, nor for another op | `viewBytes` (D-w1); `Verifier.Verify` steps 4–6 |
| `accepted_only_for_audience` | all-traces | a proof accepted at a verifier under an honest key not taken over was signed for that verifier's audience: a proof made for one node does not go through at another | `viewBytes` and the audience check in `Verifier.Verify` step 1 (D-w12) |
| `executable_replay_rejected` | exists-trace | an accepted proof presented again to the same verifier is turned away | — |
| `once_per_store` | all-traces | a verifier accepts a signer's nonce once; this restates the store's check-and-set | `NonceStore.Use` as an atomic check-and-set (a premise) |
| `nonce_per_signer` | exists-trace | one verifier accepts one nonce for two signers: the store's scope is per signer | `NonceStore` keyed by `(signerDID, nonce)` (D-w10) |
| `no_burn` | all-traces | an honest proof is turned away as a replay only when that proof was accepted before, or its signer's key was taken over: a forgery spends no legitimate signer's nonce | `Verifier.Verify` step 8, last and only on success; `NonceStore` keyed per signer |
| `replay_across_replicas` | exists-trace | what the audience leaves: one proof accepted at two verifiers that have the same audience, each with a store of its own | — (a deployment runs one verifier per audience) |

`bearerorigins.spthy`:

| lemma | kind | property | implementation |
| --- | --- | --- | --- |
| `executable_presentation` | exists-trace | a named origin's server receives the bearer with no server taken over (reachability) | — |
| `redirect_reachable` | exists-trace | a server answers a fetch that carries the bearer with a redirect | — |
| `leak_after_named_compromise` | exists-trace | once a named recipient is taken over, the attacker can have the bearer: past that point it is not kept secret | — |
| `delivered_only_to_named` | all-traces | the bearer reaches the server of a named origin only, a redirect's target included | `pipelineconfig.Config.PresentsCredentialTo`; `origin.Confine` |
| `bearer_secrecy` | all-traces | the attacker learns the bearer only from a named recipient that received it and was taken over before | the same, on every client that carries the bearer |

Most exists-trace lemmas are there so that the all-traces lemmas are not
vacuous: a safety property holds trivially of a model in which nothing is
accepted, and an exception nobody can reach is no exception. Two show a
boundary the model does not close: `replay_across_replicas` and
`leak_after_named_compromise`. For them, proved means the trace they describe
is reachable.

### In the code

Every client that carries `vc-store-bearer` either targets a destination the
operator configured over a client wrapped by `origin.Confine`
(`cmd/pipeline/main.go`, `cmd/pipeline/wiring.go`, the payload store client
in `network/pkg/services/payloadresolver/client`), or is the batch resolver's
peer fetcher, which adds the bearer and `origin.Confine` only when
`PresentsCredentialTo` admits the endpoint
(`internal/netcompose/batchresolver.go`).

## Negative controls

Each control changes one thing in the default build: it removes a check, or
(`RecordBeforeSignature`) adds a path around one. `check.sh MODEL FLAG` runs
it, and the lemmas it is expected to falsify are in
`tamarin/MODEL.expected.tsv`.

| model | build | changes | falsifies |
| --- | --- | --- | --- |
| wireauth | `ViewOmitsSigner` | the view no longer covers the signer DID (D-w1) | `view_binding` (an attacker's DID that names an honest key) |
| wireauth | `ViewOmitsAudience` | the view no longer covers the audience (D-w12) | `accepted_only_for_audience` (a proof made for one verifier accepted at another) |
| wireauth | `ViewOmitsOp` | the view no longer covers the op | `view_binding`, `no_burn` (the proof accepted under another op first) |
| wireauth | `AudienceFromWire` | the verifier rebuilds the view with the audience the proof names, and does not compare it with its own | `accepted_only_for_audience` |
| wireauth | `NoNonceStore` | the store's check-and-set is gone: nothing stops a replay from being accepted | `once_per_store` |
| wireauth | `RecordBeforeSignature` | a path records the nonce before the signature is checked | `no_burn` |
| wireauth | `StoreKeyedByNonce` | the store is keyed by the nonce alone, not per signer (D-w10) | `no_burn`, `nonce_per_signer` |
| bearerorigins | `PresentToAnyEndpoint` | the named-origin check is gone | `delivered_only_to_named`, `bearer_secrecy` |
| bearerorigins | `FollowRedirects` | `origin.Confine` is gone: a redirect is followed | `delivered_only_to_named`, `bearer_secrecy` |

## Standard vectors

`vectors/` runs third-party test vectors through the product's own code, so
that an implementation detail the project's tests share with the code cannot
hide a departure from a standard.

| suite | source (pinned commit) | through | checks |
| --- | --- | --- | --- |
| Wycheproof: Ed25519, ECDSA P-256 with SHA-256 (`r \|\| s`), RSA PKCS #1 v1.5 with SHA-256 at 2048, 3072 and 4096 bits | [C2SP/wycheproof](https://github.com/C2SP/wycheproof) `d17cc89` | `crypto/ed25519`, `crypto/es256`, `crypto/rs256`: each `Verifier` | 1,248 vectors |
| RFC 8785: the reference implementation's input and output pairs, and Appendix B's number samples | [cyberphone/json-canonicalization](https://github.com/cyberphone/json-canonicalization) `32a4819`; the RFC | `canon/jcs` (`CanonicalizeRFC8785`), at the canonicalizer stage | 6 pairs, 26 numbers |
| JSON-Schema-Test-Suite, draft 2020-12, the required tests | [json-schema-org/JSON-Schema-Test-Suite](https://github.com/json-schema-org/JSON-Schema-Test-Suite) `245a45a` | `schema/local`: `Add` compiles the schema under the product's policy, `Validate` checks the data | 46 files, 385 cases, 1,300 tests |

The files are in `vectors/testdata/`, unmodified, each source with its
license and a README; `testdata/SOURCES.tsv` pins every file by SHA-256, and
a test fails when one changes or is added without a row. The tests read the
files and run nothing from them.

**Expectations.** A vector's expected outcome is its own (valid or invalid).
Where the product's contract gives another, the outcome is listed in
`vectors/<suite>.expected.tsv` with its reason; those rows were written from
the contracts before the vectors were run. A result that differs from the
expectation, a row no vector uses and a row that repeats the vector's own
outcome all fail.

- **Wycheproof** (`wycheproof.expected.tsv`): every vector Wycheproof marks
  `acceptable` has a row. Ed25519 public keys of small order are refused
  (`ed25519.ValidatePublicKey`); signatures under a mixed-order key are
  accepted as the standard library's equation accepts them; an RSA signature
  whose DigestInfo lacks its NULL parameter is refused (strict PKCS #1 v1.5).
  Every other vector has its own outcome.
- **RFC 8785**: no exceptions. The canonicalizer gives every reference input
  its output byte for byte, and every finite value of Appendix B its
  serialization; NaN and Infinity are refused. The reference input
  `structures` uses object names that differ only in case, which the
  product's strict decoder refuses (`canon.DuplicateKeyError`), so that pair
  is checked at the canonicalizer stage only; through the strict decoder the
  other five give the same bytes. What admission refuses before
  canonicalization (`canon.AdmitSafeNumbers`, such as RFC 8785's own `1e30`)
  is not part of this stage. The W3C JCS test vectors are checked by `vc`'s
  own tests (`vc/w3c_forkw_internal_test.go`, `vc/rdfc_internal_test.go`).
- **JSON-Schema-Test-Suite** (`jsonschema.expected.tsv`): an outcome is
  classed by what the product does with it (an assertion that holds or
  fails, or which refusal), and an error no class names fails. Two classes
  are the profile's exclusions:
  - `refused-external-ref`: a schema that refers to a document outside
    itself (the suite's remote schemas at `http://localhost:1234`) is
    refused, as the product loads no external `$ref` (22 cases, listed
    before the run);
  - `refused-pattern-dialect`: a pattern that names a Unicode general
    category by its long name (`\p{Letter}`) is refused, as the product's
    pattern dialect takes the short names only (`L`, `Lu`, `Nd` …; 2 cases,
    found in the run and added after review).

  Each row also names the error it expects, so a refusal for another reason
  fails. The classes for bounds and budgets, for a schema its metaschema
  refuses, and for a payload the decoder refuses were declared empty before
  the run, and stay empty.

## Results

A lemma is in one of five states: **proved**; **refuted as expected** (a
negative control); **refuted, a design gap**; **unresolved** (the search did
not finish, timed out, or the model is ill-formed); **not started**. An
unresolved lemma does not count as proved. It is recorded here and the model
is still merged; by the next release it is proved, weakened, or dropped. A
refutation that is not expected fails CI.

| model | build | state |
| --- | --- | --- |
| wireauth | default | all ten proved |
| wireauth | each of the seven controls | the lemmas in the table above refuted as expected; the others proved |
| bearerorigins | default | all five proved |
| bearerorigins | each of the two controls | the lemmas in the table above refuted as expected; the others proved |
| `NonceEpoch` (TLA+: the acceptance window, the restart epoch, eviction) | — | not started |

Unresolved: none.

| standard vectors | state |
| --- | --- |
| Wycheproof (1,248 vectors) | every vector has its expected outcome; 32 rows in the table, all for `acceptable` vectors |
| RFC 8785 (6 pairs, 26 numbers) | every result as expected |
| JSON-Schema-Test-Suite (1,300 tests) | every test has its expected outcome; 24 cases in the table |

## Running the checks

```sh
verification/tamarin/check.sh --all-builds              # every model, every build (what CI runs)
verification/tamarin/check.sh                           # every model, default build
verification/tamarin/check.sh wireauth                  # one model
verification/tamarin/check.sh wireauth ViewOmitsSigner  # one negative control
TIMEOUT=120 verification/tamarin/check.sh --all-builds  # seconds per lemma (600 by default)
(cd verification && go test ./...)                      # the standard vectors (what CI's vectors job runs)
```

`check.sh` runs `tamarin-prover` on each lemma in a process of its own, reads
the prover's summary (its exit code is 0 for a refuted lemma too), classes the
result, and exits 0 only when every lemma has the result `MODEL.expected.tsv`
names. A lemma that runs out of time is unresolved, not refuted.
`--all-builds` reads the builds from each `MODEL.expected.tsv`, so CI lists
none of them.

Before it runs the prover, `check.sh` checks the model and its expectations
against each other, and stops with the reason when they drift apart: a
`FLAG` the expectations do not name as a build (`tamarin-prover` ignores an
unknown `-D` and would check the default model), an `#ifdef` of the model
that is no build, a build that is no `#ifdef`, an expected lemma the model
does not have, a lemma inside an `#ifdef`, an `#ifdef` on more than one flag,
an expected result other than `verified`, `falsified` or `unresolved`.

The script is byte for byte the same as `dplaax.spec`'s
`formal/tamarin/check.sh`, so `cmp` or a SHA-256 shows when the two drift.

Tools: Tamarin 1.12.0 and Maude 3.5.1, the versions CI pins by SHA-256
([`.github/workflows/formal.yml`](../.github/workflows/formal.yml)). On macOS:
`brew install tamarin-prover/tap/tamarin-prover` (Maude comes with it).

## Review

CI runs the models when `verification/tamarin/` or the workflow changes. A
pull request that changes a model, or the code a model's contract describes
(`network/pkg/services/chainmanager/wireauth`, the callers of `wireauth.Sign`
and where their audience comes from (`cmd/pipeline/audience.go`, the chain
manager's subscriber), the node's verifier (`internal/netcompose`), the
handlers that verify an L2 proof,
`pipelineconfig.Config.PresentsCredentialTo`, `internal/origin`, the clients
that carry `vc-store-bearer`), is reviewed for whether the contract above
still holds of the code.

Where a model and the code disagree, neither wins by default: the
disagreement is judged, the one in error is fixed, and the outcome is
recorded.
