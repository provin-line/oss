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

## Issue labels

Two independent axes.

**State — what is blocking this issue.** Exactly one, always present:

| Label | Meaning |
|---|---|
| `needs-decision` | A direction must be chosen before any code can start. |
| `needs-research` | The question is empirical — something must be measured or evaluated before a direction can be chosen. |
| `blocked` | The direction is settled; the work waits on an external dependency, named in the issue. |
| `ready` | The direction is settled and nothing blocks it. Open for work. |

**Type — what the work is:**

| Label | Meaning |
|---|---|
| `bug` | The code contradicts a contract it states. |
| `documentation` | The documentation claims more than the code guarantees; the fix is documentation only. |
| `enhancement` | Neither — something that should exist does not. Includes CI coverage and performance work. |

A type label is applied only once the outcome is committed. An issue that
records a question rather than a plan carries its state label and no type: the
absence says we have not decided what this becomes, which is the honest reading
while `needs-decision` or `needs-research` is on it. Adding a type earlier would
announce a commitment the issue text declines to make.

Labels move as the work does. An issue gains a type and turns `ready` when its
direction is settled — not when someone starts writing code. A wire change under
"Changing the frozen wire" above is `needs-decision` until maintainer approval is
recorded on the proposal issue, and `ready` after.

`good first issue` and `help wanted` are orthogonal to both axes and may be added
to any `ready` issue.

## Security

Vulnerability reporting and support windows are defined in
[SECURITY.md](SECURITY.md).
