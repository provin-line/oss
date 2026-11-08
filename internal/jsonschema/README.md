# internal/jsonschema — a copy of santhosh-tekuri/jsonschema with a work budget

This directory is a copy of the JSON Schema library
[`github.com/santhosh-tekuri/jsonschema/v6`](https://github.com/santhosh-tekuri/jsonschema)
with two patches added: a work budget for validation, and an error in place
of a panic for a number `big.Rat` cannot read. The schema package
(`schema/internal/schemadoc`) is its only user. It lives here, under its own
import path, so that every module that imports `github.com/provin-line/oss`
builds with the patch. A `replace` directive in go.mod would apply only when
this module is the main module.

## Origin

| | |
| --- | --- |
| Module | `github.com/santhosh-tekuri/jsonschema/v6` |
| Version | `v6.0.3` |
| Commit | `b0fc661f4939578bc429f408c18202573dbafcc4` |
| Module zip | `h1:1EYB5IzjZawrrnELUi78f9fPu57HuXjmddZPjrls/28=` (go.sum) |
| License | Apache License 2.0: [LICENSE](LICENSE), copied unchanged from the module. The module has no NOTICE file. |

Copied: the library's non-test Go files, package `kind`, and the embedded
`metaschemas`. Not copied: upstream's tests and test data, `cmd/jv`, its README
and its CI and tool configuration.

## Changes

Every changed file says so at its top, and every changed statement is
marked `work budget` or `large number`, except the import paths.

1. **Import path.** `output.go`, `util.go` and `validator.go` import package
   `kind` as `github.com/provin-line/oss/internal/jsonschema/kind`.
2. **Work budget.** `(*Schema).ValidateWithBudget(v, budget)` validates as
   `Validate` does, within a number of steps, and returns a
   `*BudgetExceededError` when validation would take more. `Validate` is
   unchanged. A RegexpEngine whose Regexp says the size of its program (a
   `Size() int` method) has each position of a string matched against it,
   and each value it compiles as format `regex`, charged by that size
   (`PatternInstructionsPerStep`, `PatternCompileStepsPerInstruction`); a
   value checked as format `regex` is also charged by its length before it is
   compiled (`PatternParseStepsPerByte`). Reading a number is charged by its
   length and its exponent, and comparing it with a bound by the size of
   both; two objects are compared by their names in order, so a validation
   takes the same steps each time. New files: `budget.go`, `budget_test.go`,
   `budget_internal_test.go`.
   Changed lines in `validator.go`, `util.go`, `vocab.go`, `roots.go`,
   `objcompiler.go` and `schema.go`.
   [patches/work-budget.patch](patches/work-budget.patch) is this change as a
   diff against upstream v6.0.3, with upstream's import path.
3. **Large number.** A number `big.Rat` cannot read (such as `1e1000001`) is
   reported as a `kind.LargeNumber` error where upstream v6.0.3 reads a nil
   `big.Rat` and panics, or takes the number as unequal to every number:
   - the number keywords (`minimum`, `maximum`, `exclusiveMinimum`,
     `exclusiveMaximum`, `multipleOf`);
   - the comparison `enum`, `const` and `uniqueItems` use, so `uniqueItems`
     answers the same at any length;
   - the hash `uniqueItems` uses past 20 items.

   A number at any depth of a value counts. Compiling a schema validates it
   against the metaschema, whose `type` and `required` carry `uniqueItems`
   and whose `multipleOf` carries `exclusiveMinimum`, so this also covers
   `Compile`. A number the schema holds counts as well: an `enum` holding one
   refuses a number that reaches that entry before a match. The hash now also
   returns the `InvalidJsonValue` it built for a value of a type that is not
   JSON, which v6.0.3 dropped.

   A `LargeNumber` is an ordinary assertion failure: `not` inverts it and
   `if` steers on it. The compiler's reading of a number keyword is
   unchanged: it takes a keyword whose number it cannot read as absent. The
   schema package refuses such numbers, in a schema or a payload, before the
   library reads them.

   The number keywords follow upstream's fix on its default branch, `boon`
   (commit `9ae86900`), and the kind `LargeNumber` is upstream's; the
   comparison and the hash are not fixed there as of `e1b31f4`. New file:
   `largenumber_test.go`. Changed lines in `kind/kind.go`, `validator.go`
   and `util.go`. [patches/large-number.patch](patches/large-number.patch) is
   this change as a diff against upstream v6.0.3 with
   `patches/work-budget.patch` applied, with upstream's import path.

Check the patches against upstream's own tests: check out upstream at the
commit above with its `testdata/JSON-Schema-Test-Suite` submodule, apply
`patches/work-budget.patch` and then `patches/large-number.patch`, and run
`go test ./...` there. To run the test suite through the budget as well, have
`suite_test.go` call `sch.ValidateWithBudget(test.Data, 1<<62)` in place of
`sch.Validate(test.Data)`.

## How the schema package uses it

The schema package (`schema/internal/schemadoc`) is the only user; the
decoder hygiene check fails if another package imports this directory. It
decodes every schema and payload with `canon.StrictDecoder`, bounds every
number and the payload's depth before the library sees it, denies every
loader and leaves content assertion off. So the library decodes JSON only for
its embedded metaschemas. On that basis the decoder hygiene check skips
`loader.go` and `content.go`, and the number check skips `kind/kind.go`,
which formats error messages with `big.Rat`'s `Float64`. Turning on a loader
or content assertion would bring the library's own decoding of input back.

## Leaving

When upstream bounds its own work, by a budget or a way to stop a validation,
and releases a version that reports every number it cannot read as an error
(the number keywords and the `uniqueItems` hash, in `Validate` and in
`Compile`), switch the schema package to the upstream module and delete this
directory. Until then, apply upstream releases here by copying them again and
re-applying the changes above; drop the large-number patch once a release
carries the fix.
