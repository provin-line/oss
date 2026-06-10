# originsource — FirstDrop-Issuing Component

The Origin Source component type. Its **only definitional property** is emitting a new
FirstDrop VC (empty `previousCredential` — cuts the chain). Internal mechanics —
input cardinality, Pool/cache state, external lookups, aggregation logic — are
protocol-invisible and free for the implementation to choose.

## Linear chain invariant — no upstream-reference fields

The chain is strictly linear: an Origin Source's FirstDrop carries **no**
upstream-reference credential fields (`derived_from` / `source_root` were removed
from the design — Paper 01 §4.8 forbids them at the credential schema layer).
Aggregation severs identity with upstream data; the chain attests to "what happened
to this data from the aggregation point onward". When an application needs to record
which inputs were used, that lives in the data payload as the aggregator's business
logic, never in the credential.

> **Note (pending design discussion B1):** the variant taxonomy below predates the
> current spec drafts and is under review — in particular whether enrichment is a
> chain-*continuing* operation (FilterConvert with side-fetch) rather than an Origin
> Source variant. Do not build against this section until that lands.

## Variants (reference-implementation naming, by input cardinality N)

| Variant | N | Internal mechanics | Status in this repo |
|---|---|---|---|
| `externalsource/` | 0 | Ingestion from outside the network (HTTP push / file / poll) | `apipush/` reference implementation |
| `enrichment/` | 1 | One Pipeline-conformant input joined with external lookups | Interface + conventions only |
| `aggregate/` | ≥ 1 | Pool + windowing / aggregation over Pipeline-conformant inputs | Interface + conventions only |

Variants are conventions, not Type Contract distinctions — at the protocol level there
is exactly one Origin Source type.
