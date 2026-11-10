# JSON Canonicalization Scheme (RFC 8785) test data

Source: https://github.com/cyberphone/json-canonicalization (the reference implementation named by RFC 8785)
Commit: 32a48195b9b20fe67b1795e39e4509f14d860b45
License: Apache License 2.0. `LICENSE` is the repository's own notice, fetched verbatim at that commit; it names the license without its text, which is in this repository's root `LICENSE`. The repository has no NOTICE file at that commit.

Files, from `testdata/` at that commit, unmodified:

- `input/<name>.json`: a JSON text.
- `output/<name>.json`: its canonical form, byte for byte.

Names: `arrays`, `french`, `structures`, `unicode`, `values`, `weird`.

The files are data only; tests read them and never run anything from them.
