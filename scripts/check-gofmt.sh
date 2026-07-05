#!/usr/bin/env bash
# gofmt drift guard: `make lint` fails if any Go file is not gofmt-clean,
# printing the offending files. gen/ is deliberately INCLUDED (unlike the
# hygiene checks, which exclude it because generated code cannot carry
# exemption comments): generated Go must also be gofmt-clean, and drift there
# signals a generator misconfiguration worth failing on.
set -euo pipefail
cd "$(dirname "$0")/.."

drift=$(gofmt -l .)
if [ -n "$drift" ]; then
  echo "check-gofmt: files not gofmt-clean:" >&2
  printf '%s\n' "$drift" >&2
  exit 1
fi
