# filter — FilterFlow Step Contract

Defines the FilterFlow step: stateless conditional pass/drop over a single event
payload. **Statelessness is definitional** — no cross-event state, no cache, no pool.

## Interface

```go
type Filter interface {
    Apply(ctx context.Context, data []byte) (*Result, error)
}

type Result struct {
    Pass bool
}
```

`Apply` is the only call; it must be safe to call concurrently.

## Error vs filtered distinction

These two outcomes are deliberately separate:

| Outcome | Meaning | Processor maps to |
| --- | --- | --- |
| `err != nil` | Step failure (expression evaluation error, invalid JSON) | `StatusErrored` — drop loudly |
| `Pass=false, err=nil` | Falsy verdict — event intentionally dropped | `StatusFiltered` — drop silently |

An error is not a filter result. A filter result is not an error.

## Sub-packages

### `jsonata/`

JSONata implementation of `Filter`. Key properties:

- **Pre-compile at startup**: all expressions are compiled by `New`; any compile
  error or empty list fails construction. Filters never degrade at runtime.
- **All-truthy semantics**: all expressions must yield a truthy result for
  `Pass=true`. Evaluation short-circuits on the first falsy result.
- **Undefined is falsy**: a JSONata no-match (missing field, empty path) yields
  `Pass=false` with `nil` error — it is a filter verdict, not a step failure.
- **Truthiness rule** — delegated to `jlib.Boolean` (jsonata-go's own
  `$boolean()` implementation) by construction:
  - `false` / `null` / undefined → falsy
  - `0` → falsy; any other number → truthy (including `int`-typed results from
    built-ins such as `$count(...)` and `$length(...)`)
  - `""` → falsy; non-empty string → truthy
  - empty array → falsy; empty object → falsy; everything else → truthy
- **Strict input decode**: `Apply` decodes input via `canon.StrictDecoder`.
  Duplicate keys (e.g. `{"value":0,"value":20}`) and trailing data are rejected
  as errors — they never reach expression evaluation.
- **Numeric model**: `StrictDecoder` preserves numbers as `json.Number`; these
  are normalized before JSONata evaluation — integral values fitting `int64`
  become `int64`, others become `float64`. Inside JSONata expressions,
  arithmetic and comparison operate in `float64`. Integer identity is preserved
  through the Go value tree up to `int64`; integers above 2^53 lose precision
  once they enter JSONata arithmetic or comparison. See
  `TestApplyIntegerPrecision` for the pinned golden behavior.
- **Concurrency**: `jsonata-go`'s `Expr.Eval` creates a fresh environment per
  call and reads compiled state without mutation; concurrent `Apply` calls on the
  same `*Filter` are safe without additional locking.
