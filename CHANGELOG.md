# Changelog

All notable changes to this repository are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the version is `0.x`, exported Go API, wire formats, and configuration
keys may still change between minor releases. The first frozen surface is
declared at the `1.0` line.

## [0.1.0] - 2026-07-12

Initial internal release — pinned for internal (private) deployment and soak.

### Added

- The dPLaaX provenance data plane and control plane: pipeline loops
  (source / chained / aggregate / sink), the chain manager, the DID registry,
  schema registry, the durable relationship-evidence log, and the `provin` CLI.
- Cross-organization by-reference payload delivery (structural export-seam
  mode → subject mapping + dual-emit), served from a payload-resolver boundary.
- `provin evidence rotate`: archive+rotate a relationship-evidence log to a
  cold-archive segment without deleting records (the tlog append-only contract
  holds).
- `provin org verify/inspect/diagnose/generate-txt`: DNS-based organization
  endorsement.

### Changed

- wireauth: the default restart epoch is lifted to `boot + MaxFuture`, fully
  closing the cross-restart replay window over the in-memory nonce store.
- by-reference advertisement now degrades when a producer's stripped-publish
  emission is failing (recovery tied to a proven successful stripped publish).

### Notes

- The quickstart pins the `provin.auth` policy-verifier / auth-provider images
  and `AUTH_REF` to `v0.1.0` (built from provin.auth's matching tag).

[0.1.0]: https://github.com/provin-line/oss/releases/tag/v0.1.0
