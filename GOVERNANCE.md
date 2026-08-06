# Governance

## Current model

provin is maintained by [1o1 Co. Ltd.](https://1o1.co.jp/) (see
[MAINTAINERS.md](MAINTAINERS.md)). Decision authority over releases, the
credential-wire freeze, and the provin wire profile currently rests with the
1o1 maintainers. This is a deliberate starting point, not the end state — see
"Growing the maintainer group" below.

## Changing the frozen wire (next-MAJOR)

The v0 credential Data Integrity wire is frozen. The freeze is enforced by
tests in this repository — the official W3C vc-di-eddsa vectors, KATs, and
sha256-pinned contexts — not by process; see the CHANGELOG's "v0 credential
wire freeze declaration" for the exact scope. Changing any frozen byte:

1. requires a public proposal issue stating the change, the compatibility
   break, and the migration path;
2. requires explicit maintainer approval recorded on that issue;
3. ships only as the next MAJOR version. Credentials issued under the previous
   wire must remain verifiable — verification support is versioned, not
   withdrawn.

## Growing the maintainer group

We intend provin to outgrow a single steward. The path in:

- **Contributors** — anyone, through issues and pull requests. A sustained
  record of high-quality contributions is the only qualification.
- **Maintainers** — contributors with such a record are invited by the
  existing maintainers, recorded in MAINTAINERS.md, and carry review and
  release authority.
- **Multi-organization maintainership** — once maintainers span more than one
  organization, this document will be revised to a consensus model with
  explicit escalation rules. Single-company authority is not the intended end
  state.

## Security

Vulnerability reporting and support windows are defined in
[SECURITY.md](SECURITY.md).
