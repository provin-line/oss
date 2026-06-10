# scripts/ — CI Hygiene Checks

Repository-specific lint scripts run by `make lint` and CI:

- `check-decoder-hygiene.sh` — every JSON decode on a protocol path goes through the
  strict decoder in `packages/canon`; direct `json.Unmarshal` requires a
  `decoder-hygiene-exempt` comment.
- `check-canonicalizer-hygiene.sh` — canonicalization happens only via `packages/canon`
  entry points (no ad-hoc `json.Marshal` of signing scopes).
