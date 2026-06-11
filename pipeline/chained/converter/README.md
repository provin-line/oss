# converter — Stateless JSON→JSON Transformation

The ConvertFlow step contract: `Converter` interface and subset output validation.
All implementations are stateless — the same input always produces the same output.

## Converter interface

```go
type Converter interface {
    Convert(ctx context.Context, data []byte) ([]byte, error)
}
```

A non-nil error means the step itself failed (maps to `contract.StatusErrored` at the
processor layer). A Converter never filters; pass/drop decisions belong to the filter
step.

`Convert` must be safe to call concurrently.

## Two JSONata modes (jsonata/ sub-package)

### Whole-document mode — `New(expr string)`

The expression receives the full input document as its evaluation context and its result
becomes the output document. Useful for document reshaping (field rename, projection,
computed fields from scratch).

### Per-field steps mode — `NewSteps(steps []FieldStep)`

Each step evaluates its expression against the document produced by the previous step
(the original input for step 0) and writes the result into the named top-level field.
Steps compose sequentially: step N reads from the output of step N-1, enabling derived
fields. Example: step 1 computes `full = firstName & " " & lastName`; step 2 reads
`$.full` to build a greeting.

**Field validation**: each `FieldStep.Field` must be non-empty; `NewSteps` returns an
error at construction time if any step has an empty field name.

Both modes pre-compile all expressions at construction. Empty expression / empty steps
slice → construction error. Invalid syntax → construction error. Fail at startup, not
at runtime.

## Composition rule (steps mode)

Steps mutate the document in order. Each step sees all fields written by prior steps.
The final document (all original fields plus all step-assigned fields) is marshaled as
the output.

## ValidateSubset

```go
func ValidateSubset(doc []byte, required []string) error
```

Checks that a JSON object contains all top-level fields listed in `required`. Dotted
paths are **not** supported; each element must be a plain top-level key. Returns an
error naming the first missing field. Returns nil if `required` is empty or all fields
are present. Intended for post-transform output validation before forwarding an event.

Decodes via `canon.StrictDecoder`, consistent with the protocol-boundary hard rule.

## Strict input decode

`Convert` decodes its input via `canon.StrictDecoder`, which enforces:

- **Trailing-data rejection**: a document must be exactly one JSON value. `{"a":1} {"b":2}` → error.
- **Duplicate-key rejection** (RFC 8785 §3.2.5): `{"a":1,"a":2}` → error.
- **Numeric precision preservation** via `json.Number`.

This guarantees that the bytes hashed into the signed `outputHash` match the bytes
actually decoded — input is never silently laundered.

## Numeric model

After strict decode the `json.Number` values are normalized before passing to
jsonata-go:

| Value category                          | Go type   | Notes                                                     |
| --------------------------------------- | --------- | --------------------------------------------------------- |
| Integral, fits int64                    | `int64`   | Identity preserved exactly, including integers above 2^53 |
| Fraction, exponent, or integer > int64  | `float64` | Precision may be lost above 2^53                          |

Arithmetic operators (`+`, `-`, `*`, `/`) and comparisons (`>`, `<`, `=`, …) operate on
the native Go types, so expressions like `{"next": $.age + 1}` and `$.age > 18` work
correctly.

**Integer identity caveat**: arithmetic involving integers above 2^53 operates in
float64 internally and loses precision at the float64 boundary. Field-access paths
(`$`, `$.field`) preserve int64 exactly.

**Golden test result**: input `{"n": 9007199254740993}`, expression `$`, output
`{"n":9007199254740993}` (precision preserved via int64 identity). With standard
`json.Unmarshal` (float64) the output would be `{"n":9007199254740992}` (precision
lost).

## Error contracts

| Condition | Error site |
|---|---|
| Empty expression / empty steps | `New` / `NewSteps` (construction) |
| Empty `FieldStep.Field` | `NewSteps` (construction) |
| Invalid JSONata syntax | `New` / `NewSteps` (construction) |
| Invalid JSON input (incl. trailing data, duplicate keys) | `Convert` |
| Whole-document expression returns undefined | `Convert` |
| Per-field step expression returns undefined | `Convert` (names step index and field) |
| JSONata evaluation error | `Convert` |
