#!/usr/bin/env bash
# gofmt drift guard: `make lint` fails if any tracked Go file is not
# gofmt-clean, printing the offending files.
set -euo pipefail
cd "$(dirname "$0")/.."

drift=$(gofmt -l .)
if [ -n "$drift" ]; then
  echo "check-gofmt: files not gofmt-clean:" >&2
  printf '%s\n' "$drift" >&2
  exit 1
fi
