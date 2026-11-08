# internal/jsonschema — a copy of santhosh-tekuri/jsonschema with a work budget

This directory is a copy of the JSON Schema library
[`github.com/santhosh-tekuri/jsonschema/v6`](https://github.com/santhosh-tekuri/jsonschema)
with patches added: a work budget for validation, an error in place of a
panic for a number `big.Rat` cannot read, compiling a schema in time
about linear in its size (up to a factor of log n where `uniqueItems` sorts
object names that share a long prefix, as `ValidateWithBudget` states), its
check against its metaschema within a work budget,
and a JSON pointer's array index read only as RFC 6901 writes one (Changes,
below). The schema package (`schema/internal/schemadoc`) is its
only user. It lives here, under its own import path, so that every module
that imports `github.com/provin-line/oss` builds with the patches. A
`replace` directive in go.mod would apply only when this module is the main
module.

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
marked with the name of its change (`work budget`, `large number`,
`compile index`, `resource index`, `subschema journal`, `dynamic anchor
set`, `hash sign`, `metaschema budget`, `vocabulary cache`, `pointer
index`, `reference index`), except the import paths. Each change from 4 on is a patch of its own, so it can be
offered upstream on its own.

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
4. **Compile index.** The queue of subschemas one `Compile` compiles keeps
   an index by location, so finding whether a subschema is already queued
   takes constant time; upstream searches the list, so compiling n
   subschemas takes time in n². Changed lines in `compiler.go`.
   [patches/compile-index.patch](patches/compile-index.patch).
5. **Resource index.** A root keeps its resources by id too, so finding a
   resource by id (when an `$id` is added, when a subschema's base is found,
   and when a `$ref` to an id is resolved) takes constant time; upstream
   searches every resource, so n embedded resources take time in n².
   Changed lines in `root.go` and `roots.go`.
   [patches/resource-index.patch](patches/resource-index.patch).
6. **Subschema journal.** A subschema read for a reference outside the
   schema's keywords is added to its root in place, each addition recorded,
   and a failure to add or check it takes the additions back, so the
   subschema is admitted whole or not at all, as upstream's is; upstream
   copies the whole root for each such subschema, so n of them take time and
   memory in n². Changed
   lines in `root.go` and `roots.go` (the copy goes); new test file
   `compile_test.go`. [patches/subschema-journal.patch](patches/subschema-journal.patch).
7. **Dynamic anchor set.** A resource's dynamic anchors are found in its
   anchors rather than each anchor searched for among them, so n dynamic
   anchors take time in n, not n². Changed lines in `compiler.go`.
   [patches/dynamic-anchor-set.patch](patches/dynamic-anchor-set.patch).
8. **Hash sign.** The hash `uniqueItems` uses past 20 items writes a
   number's sign: without it, numbers of one magnitude hash alike, and every
   pair of them is compared. Changed line in `util.go`; new test file
   `hash_internal_test.go`. [patches/hash-sign.patch](patches/hash-sign.patch).
9. **Metaschema budget.** `(*Compiler).CompileWithBudget(loc, budget)`
   compiles as `Compile` does, checking the schema, and each subschema it
   reads for a reference, against its metaschema within a work budget of
   the steps `ValidateWithBudget` counts, and returns a
   `*BudgetExceededError` when the checks would take more. `Compile` is
   unchanged. Changed lines in `compiler.go`, `roots.go` and `budget.go`;
   tests in `compile_test.go`.
   [patches/metaschema-budget.patch](patches/metaschema-budget.patch).
10. **Vocabulary cache.** The vocabularies of a metaschema a resource's
    `$schema` names are read once per compiler, until a vocabulary is
    registered; upstream reads them again for each resource, so n resources
    naming a metaschema with a long `$vocabulary` take time in n times its
    length. Changed lines in `loader.go` and `compiler.go`.
    [patches/vocabulary-cache.patch](patches/vocabulary-cache.patch).
11. **Pointer index.** A JSON pointer reads an array index only as RFC 6901
    §4 writes one: `0`, or digits not beginning with `0`. Upstream reads it
    with `strconv.Atoi`, so `00`, `+0` and `-0` each reach the first item;
    a reference by each spelling compiles the item's subtree again, under a
    location as long as the spelling. Such a pointer is now not found
    (`JSONPointerNotFoundError`). This brings the library to RFC 6901, and
    is a candidate to offer upstream. Changed lines in `util.go`; tests in
    `compile_test.go`.
    [patches/pointer-index.patch](patches/pointer-index.patch).
12. **Reference index.** Within one compile, the target of a reference that
    resolves inside its root is found once for each URL it resolves to, and
    kept by that URL; upstream builds the target's location again for each
    reference, so n references to a resource at a location L bytes long
    take time and memory in n times L. A resource's id stays with one
    resource for the compile, so its target does not change. Changed lines
    in `compiler.go` and `objcompiler.go`; tests in `compile_test.go`.
    [patches/reference-index.patch](patches/reference-index.patch).

Each patch from 4 on is a diff against upstream v6.0.3 with the patches
before it applied, with upstream's import path.

Check the patches against upstream's own tests: check out upstream at the
commit above with its `testdata/JSON-Schema-Test-Suite` submodule, apply the
patches in the order above (`work-budget`, `large-number`, `compile-index`,
`resource-index`, `subschema-journal`, `dynamic-anchor-set`, `hash-sign`,
`metaschema-budget`, `vocabulary-cache`, `pointer-index`,
`reference-index`), and run `go test ./...` there. To run the test suite through the budget as well, have
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

When upstream bounds its own work, by a budget or a way to stop a validation
or a compile, releases a version that reports every number it cannot read
as an error (the number keywords and the `uniqueItems` hash, in `Validate`
and in `Compile`), compiles a schema in time linear in its size (changes
4 to 8, 10 and 12), and reads an array index only as RFC 6901 writes one
(change 11), switch the schema package to the upstream module and delete
this directory. Until then, apply upstream releases here by copying
them again and re-applying the changes above; drop a patch once a release
carries its fix.
