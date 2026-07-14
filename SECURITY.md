# Security Policy

## Status

provin is a **proof-of-concept**. The directory structure and per-layer
conventions are in place and the credential wire is frozen (see
[CHANGELOG.md](CHANGELOG.md)), but this is not a hardened production system,
and the [quickstart](deploy/quickstart/README.md) is explicitly **not a
production reference**. We nonetheless take vulnerability reports seriously
and will assess every one.

## Reporting a vulnerability

**Please do not open a public issue for a suspected vulnerability.** Public
disclosure of an unpatched flaw puts every deployment at risk.

Report privately through **GitHub Private Vulnerability Reporting** on this
repository: the **Security** tab → **Report a vulnerability**. This opens a
private advisory visible only to you and the maintainers.

Please include, to the extent you can:

- affected version or commit,
- impact (what an attacker gains),
- reproduction steps or a proof of concept,
- any embargo/disclosure timing you would like us to honor.

We do **not** commit to an acknowledgement or remediation SLA, and we do not
operate a bug-bounty program. We will engage on the private advisory and
coordinate disclosure with you.

## Supported versions

While the project is `0.x`, only the latest published minor line receives
security assessment and fixes.

| Version | Status |
| --- | --- |
| `0.2.x` | Supported once `v0.2.0` is published (the first public line). |
| `0.1.x` | Internal soak line; **unsupported** at the public cut. |
| `< 0.1` | Unsupported; no backports. |

"Supported" means eligible for security assessment and remediation — not an
SLA. A fix may ship as a patch, a minor, or — if it must change the **frozen
credential wire** — a major release; the wire freeze (CHANGELOG) makes some
remediations a next-major break by construction.

## Trust boundaries

provin separates trust into three layers; a report is most useful when it
names which boundary it crosses. None of these substitutes for another.

- **L1 — API access.** Bearer token plus an external policy decision point
  authorize each RPC. The enforcement point verifies no token itself; a
  misconfigured or `static` PDP is an authorization-only posture, not
  authentication. See [docs/protocol/auth.md](docs/protocol/auth.md).
- **L2 — peer wire proof.** Internet-facing peer and payload surfaces carry
  a per-RPC Ed25519 proof over a canonical view, with replay defense; there
  is no auth-off mode. See [docs/protocol/auth.md](docs/protocol/auth.md).
- **Transport confidentiality.** The node serves cleartext h2c; bearer tokens
  and payloads are only as confidential as the transport. A boot guard
  requires **either** node-native TLS **or** an explicit cleartext
  acknowledgement before a non-loopback listener will start — the guard
  enforces that a posture is *chosen*, not that TLS is *present*: the
  acknowledgement path relies on the operator isolating the cleartext backend
  behind a real terminator. See
  [deployment.md → TLS termination](docs/architecture/deployment.md#tls-termination).
- **L3 — provenance.** The credential chain — Data Integrity proofs,
  content-addressed links, transparency logs, audit verdicts — is
  independently verifiable. That independence covers **cryptographic
  provenance verification only**; peer authorization, relationship evidence,
  payload availability, and audit completeness still depend on L2 and on the
  operational duties in
  [docs/concepts/audit-obligations.md](docs/concepts/audit-obligations.md).

Method-specific considerations (registry authority, key rotation,
correlation, resolution-response authenticity) are documented in
[docs/did/method.md](docs/did/method.md#security-and-privacy-considerations)
and are not repeated here. A full repository-wide threat model is planned for
after the initial public release.
