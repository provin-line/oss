# P0-1A variant store — e2e evidence (2026-07-16)

The store layer under every credential this node holds was rebuilt in this
slice. Unit and conformance tests cover the semantics; this records that the
whole stack still boots and still verifies, which no test in the repo can claim
on its own.

Same discipline as the P0-6 closure record: the point is that these were RUN,
not read.

## The quickstart, actually booted

```text
docker compose config --quiet          → RC=0
docker compose up --build --wait       → RC=0
  node / nats / auth-provider / policy-verifier: Healthy
  provision: Exited (as designed)
deploy/quickstart/bin/walkthrough.sh   → RC=0
  ① bootstrap token → owner init      registered did:dplaax:poc.dplaax.dev:org:acme
  ② DID grant → real JWT
  ③ pipeline + process create          issued …:pipeline:readings, …:process:s1
  ④ HTTP push ingest                   status 202
  ⑤ audit verdict                      ✅ VERIFIED
     dataIntegrity / signerAuthenticity / chainConsistency = CONFIDENCE_VERIFIED
     head sha256:4ee0da5d12975a8e209e650d6a930103f9314377922e7a8ec325bca94265c96a
docker compose down -v                 → RC=0
```

Every credential in that run was admitted through `VariantStore.PutVariant`,
stored under `variants/<bodyhex>/<varianthex>.json`, and read back through the
projection the audit runner resolves with. The verdict is the whole chain
walking that store.

## What the e2e test adds

`cmd/standalone/variantstore_e2e_test.go` drives the case the quickstart cannot
produce on its own — two signed forms of ONE body — over real HTTP, through the
production client, against the file backend:

- both survive; the first is byte-identical after the second lands (the
  eviction that used to happen silently)
- each fetches exactly through `ResolveVariant`
- both enumerate under the body through `ListVariants`
- the body-only read still answers and names which variant it served; that id
  fetches the bytes it just served
- re-publishing identical bytes is idempotent and does not duplicate (publishers
  retry)

## Suite

```text
go test ./...        → 89 packages, 0 fail
go test -race ./...  → 0 fail
make lint            → RC=0
```

## Scope

This is the identity layer (P0-1 slice A: invariants 1-3, 13, 22). The audit
queue and receipt store are still keyed on the body address, which invariants 6
and 12 rule out — a verdict has to name the variant it evaluated. That is slice
B's, and the call sites say so rather than pretending otherwise.

## Provenance

- Spec: `docs/draft/p0-1a-variant-identity-spec-2026-07-15.md` (ratified 2026-07-16)
- Ledger: `.tmp/provin-p0-1-decision-ledger.md` (B2.1)
- Catalog: dplaax.spec_draft `efa14b5` (identity-001..007)
