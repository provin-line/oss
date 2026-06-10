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
