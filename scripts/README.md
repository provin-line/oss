# scripts/ — CI Hygiene Checks

Repository-specific lint scripts. Every `check-*.sh` is run by `make lint`
(the CI lint entry point), and a failing check fails the target:

- `check-decoder-hygiene.sh` — every JSON decode on a protocol path goes through the
  strict decoder in `canon`; direct `json.Unmarshal` requires a
  `decoder-hygiene-exempt` comment.
- `check-canonicalizer-hygiene.sh` — canonicalization happens only via `canon`
  entry points (no ad-hoc `json.Marshal` of signing scopes); `json.Marshal` in a
  canon-importing file requires a `canonicalizer-hygiene-exempt` comment.
- `check-gofmt.sh` — all Go files are gofmt-clean.

Exemption comments go on the flagged line, the line directly above it, or the
`"encoding/json"` import line (whole-file exemption), and must state *why* the
hygiene rule cannot matter at that site.

Non-check scripts:

- `sync-spec-vectors.sh` — vendor the dplaax conformance vectors byte-exact and
  regenerate `conformance/vectors/dplaax/MANIFEST.sha256` (run when adopting a
  spec change; see `conformance/README.md`).
