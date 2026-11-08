# scripts/ — Lint Hygiene Checks

Repository-specific lint scripts. Every `check-*.sh` is run by `make lint`
(also the single entry point for any future CI), and a failing check fails
the target:

- `check-decoder-hygiene.sh` — every JSON decode on a protocol path goes through the
  strict decoder in `canon`; direct `json.Unmarshal` requires a
  `decoder-hygiene-exempt` comment. Aliased or dot imports of `encoding/json`
  are rejected outright (they would defeat the check).
- `check-canonicalizer-hygiene.sh` — canonicalization happens only via `canon`
  entry points (no ad-hoc `json.Marshal` of signing scopes); `json.Marshal` /
  `json.NewEncoder` in a canon-importing file requires a
  `canonicalizer-hygiene-exempt` comment. Same aliased-import rejection.
- `check-number-hygiene.sh` — every JSON number read as a double goes through
  `canon.Float64` (the RFC 8259 grammar only, correctly rounded, whatever the
  number's spelling). Any other `Float64` method (`json.Number`'s, called, as a
  method value or as a method expression) and any `ParseFloat` (`strconv`'s
  under any import name, or `math/big`'s) needs a `number-hygiene-exempt`
  comment stating why the string is not a JSON number; `rand.Float64()` and a
  mention of `canon.Float64` pass. The check is line-based and textual: it
  does not resolve imports or types.
- `check-gofmt.sh` — all Go files, including generated `gen/`, are gofmt-clean.

Exemption comments go on the flagged line or the line directly above it (for
the decoder and canonicalizer checks, also on the `"encoding/json"` import
line, as a whole-file exemption), and must state *why* the hygiene rule cannot
matter at that site.

Non-check scripts:

- `sync-spec-vectors.sh` — vendor the dplaax conformance vectors byte-exact and
  regenerate `conformance/vectors/dplaax/MANIFEST.sha256` (run when adopting a
  spec change; see `conformance/README.md`).
