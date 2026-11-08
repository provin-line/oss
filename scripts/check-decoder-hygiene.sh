#!/usr/bin/env bash
# Every JSON decode on a protocol path goes through canon.StrictDecoder
# (duplicate-key rejection, trailing-data rejection, UseNumber) — see
# AGENTS.md "Wire-protocol integrity conventions". A direct json.Unmarshal /
# json.NewDecoder call in non-test code must carry a `decoder-hygiene-exempt`
# comment explaining why precision/duplicates cannot matter there.
#
# Exemption positions (checked in this order):
#   1. whole file — the token on the `"encoding/json"` import line
#      (for files that ARE the strict decode path, e.g. canon/strict.go)
#   2. call site  — the token on the call line or the line directly above
#
# Aliased or dot imports of encoding/json (`j "encoding/json"`) are rejected
# outright: the calls would no longer match `json.` and the check would go
# blind. A blank import (`_`) is allowed — it cannot be called.
#
# This is a syntactic check: it matches call syntax (`json.Unmarshal(`), so a
# prose comment mentioning the function name does not trip it, but a comment
# containing literal call syntax would — reword the comment or carry the token.
# gen/ is excluded: generated code cannot carry hand-written exemptions.
# Two files of internal/jsonschema (a copy of an upstream library, kept as
# upstream wrote it apart from its documented patch; its README.md) are
# excluded: loader.go decodes the library's embedded metaschemas (trusted) and
# the files and URLs its loaders read, and content.go decodes a string under
# content assertion. The schema package, the copy's only user, denies every
# loader and leaves content assertion off, and decodes schemas and payloads
# with canon.StrictDecoder itself; this script fails if another package
# imports internal/jsonschema.
set -euo pipefail
cd "$(dirname "$0")/.."

violations=""
while IFS= read -r f; do
  aliased=$(awk '
    {
      line = $0
      sub(/^[[:space:]]*import[[:space:]]+/, "", line)
      sub(/^[[:space:]]+/, "", line)
      if (line ~ /^[A-Za-z.][A-Za-z0-9_]*[[:space:]]+"encoding\/json"/ && line !~ /^_[[:space:]]/)
        printf "%s:%d: aliased or dot import of encoding/json defeats this check\n", FILENAME, FNR
    }
  ' "$f")
  if [ -n "$aliased" ]; then
    violations="${violations}${aliased}
"
    continue
  fi
  if grep -Eq '^[[:space:]]*(import[[:space:]]+)?"encoding/json".*decoder-hygiene-exempt' "$f"; then
    continue
  fi
  out=$(awk '
    /json\.(Unmarshal|NewDecoder)\(/ && $0 !~ /decoder-hygiene-exempt/ && prev !~ /decoder-hygiene-exempt/ {
      printf "%s:%d: %s\n", FILENAME, FNR, $0
    }
    { prev = $0 }
  ' "$f")
  if [ -n "$out" ]; then
    violations="${violations}${out}
"
  fi
done < <(find . -name '*.go' ! -name '*_test.go' ! -path './gen/*' ! -path './internal/jsonschema/loader.go' ! -path './internal/jsonschema/content.go' ! -path './.git/*' | sort)

users=$(grep -rl --include='*.go' '"github.com/provin-line/oss/internal/jsonschema' . | grep -v -e '^./internal/jsonschema/' -e '^./schema/internal/schemadoc/' -e '^./gen/' || true)
if [ -n "$users" ]; then
  violations="${violations}${users}: imports internal/jsonschema; its exclusion above holds only for schema/internal/schemadoc
"
fi

if [ -n "$violations" ]; then
  printf '%s' "$violations" >&2
  echo "check-decoder-hygiene: direct encoding/json decode on a non-test path." >&2
  echo "Route it through canon.StrictDecoder, or add a decoder-hygiene-exempt" >&2
  echo "comment (same line or line above) stating why strictness cannot matter." >&2
  exit 1
fi
