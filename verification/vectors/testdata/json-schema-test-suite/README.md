# JSON-Schema-Test-Suite (draft 2020-12)

Source: https://github.com/json-schema-org/JSON-Schema-Test-Suite
Commit: 245a45abc90190c0bff04d97e6d2b541b4bb9f12
License: MIT (`LICENSE`, fetched verbatim from the repository at that commit)

Files: every `tests/draft2020-12/*.json` at that commit (the required tests, 46 files), unmodified. The `optional/` tests are not included. The remote schemas some tests refer to (`remotes/`, served at `http://localhost:1234`) are not included either: provin OSS refuses a schema that refers outside itself, and the expectations list those tests.

The files are data only; tests read them and never run anything from them.
