# network/pkg/core — Server Foundation

Shared foundation for all network services.

- **Config**: merges the three HOCON layers (see `packages/hoconconfig`) into the
  typed runtime config tree. Each service package contributes its `reference.conf`
  at `init()`. Operator overrides are validated at startup — invalid values fail the
  boot, never silently disable a feature.
- **Secrets**: URI-scheme resolution (`file://` now; `vault://`, `awssm://` as seams).
- **Outbound URL validation**: SSRF-resistant checks (blocks loopback, link-local,
  cloud-metadata ranges; explicit loopback opt-in for local dev). Must be called
  before any outbound request to an endpoint learned from data (DID Documents,
  caller-supplied upstream endpoints).
