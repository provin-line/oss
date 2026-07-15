# ForkW-1 number inventory — evidence record (2026-07-15)

Gate for the stored-address canonicalization switch (ForkW-1 §2.2b-1, user
decision B). Recorded so the switch rests on a scan rather than on an
assumption.

## What was run

```text
$ go run ./internal/numberinventory/cmd/numberinventory <roots...>
scanned=0 unsafe=0 undecodable=0
RESULT: CLEAR — no artifact changes bytes under RFC 8785
```

Tool: `internal/numberinventory` (unit-tested: detects unsafe integers in every
spelling — plain, exponent, fraction — reports undecodable artifacts as blockers
rather than passes, and treats a never-created store as an empty result).

## Scope — read this before relying on the result

**The scan inspected zero artifacts, because no persisted provin store exists in
this environment.** The stores this gate cares about
(`<DataDir>/{keys,dids,chain,evidence,tlog}`, the vcresolver filestore, the DID
registry store) are created at runtime under a configured `DataDir`; this
checkout has none, and no provin/quickstart Docker volume is present on the
machine. Tests use `t.TempDir()`, which is gone before this runs.

So the honest reading is:

- **CLEAR for this environment.** There is no stored artifact whose content
  address could change under the switch, because there is no stored artifact.
- **NOT a claim about any other deployment.** A running deployment with a
  populated `DataDir` was not reached and was not inspected. Zero-scanned is not
  the same evidence as many-scanned-and-clean.

## Why the switch proceeds anyway

1. **Nothing reachable can break.** The switch cannot invalidate an address that
   does not exist.
2. **New artifacts cannot reintroduce the hazard.** `canon.AdmitSafeNumbers`
   (canon.number.safe-integer / .raw-token-guard) rejects unsafe integers at the
   raw-token stage before signing, so post-switch artifacts stay inside the range
   where legacy and RFC 8785 bytes are identical.
3. **Operators with data get the tool and the instruction.** The CHANGELOG
   migration note directs any deployment holding a populated `DataDir` to run
   this scan before upgrading, and to hold the upgrade if it reports BLOCK.

## What would have blocked

An artifact carrying an integer outside ±(2^53-1) in any spelling, or an
artifact the strict decoder could not read (uninspected ≠ safe). Either result
sends the slice back to decision A: leave stored-address canonicalization on the
legacy path until the P0-1 raw-variant store can rescue legacy addresses.

## Provenance

- Slice spec: `provin.poc/docs/draft/forkw-1-jcs-rfc8785-suite-spec-2026-07-15.md`
- Decision: §2.2b = B (inventory then switch), user, 2026-07-15
- Repo state: worktree at `3d28823` + the ForkW-1 working tree
