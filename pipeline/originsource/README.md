# originsource — FirstDrop-Issuing Component

The Origin Source component type. Its **only definitional property** is emitting a new
FirstDrop VC (empty `previousCredential` — cuts the chain). Internal mechanics —
input cardinality, Pool/cache state, external lookups, aggregation logic — are
protocol-invisible and free for the implementation to choose.

## Linear chain invariant — and the optional origin commitment

The chain is strictly linear: an Origin Source's FirstDrop carries **no upstream
link**. Aggregation severs identity with upstream data; the chain attests to "what
happened to this data from the aggregation point onward". Input manifests, when an
application needs them, live in the data payload as the aggregator's business logic.
Paper 01 §4.8's exclusion is a statement about **chain topology** (no DAG, no parent
links) and the **base credential schema** (no upstream-reference fields) — both hold
unchanged.

What a FirstDrop MAY additionally carry is the **origin commitment**
(`derived_from` / `source_root` / `source_root_canonical` — see
`packages/vc.OriginCommitment`): a namespaced wire-profile audit attribute binding
the issuer to the claimed source set at issuance time. It is a content commitment,
not a parent link — verifiers never traverse it on the per-event path; auditors
resolve the claimed sources asynchronously and recompute the root on demand.

Emitting it is the **audit-reachable conformance class**: config-driven per
deployment, never required by the wire profile itself. Deployment profiles (e.g. a
regulatory domain such as battery passports) may mandate the class; outside it, a
plain FirstDrop is fully conformant. The commitment proves the claim was not altered
after issuance — it does not prove the claim is complete. Omission detection is an
audit-layer reconciliation: claimed commitments vs counterparties' ingress VC stores
(mass-balance over signed records).

## Trigger rule

Whether a boundary preserves the chain or starts one is decided by the **trigger
rule** (normative for the provin wire profile — see
[pipeline/README.md](../README.md)): Origin Source mechanics are exactly the
boundaries whose run is NOT triggered by a single Pipeline-conformant predecessor
event.

## Mechanics (reference-implementation naming)

| Mechanics | Trigger | Internal shape | Status in this repo |
|---|---|---|---|
| `externalsource/` | external push / file / poll / non-conformant credential arrival (boundary translation) | stateless ingestion | `apipush/` reference implementation |
| `aggregate/` | timer / window over pooled Pipeline-conformant inputs | pool + windowing (stateful) | conventions only |

Enrichment is **not** an Origin Source mechanics: it is a chain-preserving
FilterConvert step pattern (see
[../filterconvert/README.md](../filterconvert/README.md)).

Mechanics are conventions, not Type Contract distinctions — at the protocol level
there is exactly one Origin Source type.
