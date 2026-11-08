#!/usr/bin/env bash
# Every JSON number read as a double goes through canon.Float64, so every
# reader in the module takes one number as one double: the RFC 8259 grammar
# only, correctly rounded, whatever the number's spelling. In non-test code,
# any other Float64 method (json.Number's, called, as a method value or as a
# method expression) and any ParseFloat (strconv's under any import name, or
# math/big's) reads with Go's own float syntax and is refused here, unless the
# marker `number-hygiene-exempt` is on the line or the line directly above, in
# a comment explaining why the string read is not a JSON number. math/rand's
# rand.Float64() is not a number read and passes; so does a mention of
# canon.Float64.
#
# canon/float.go is the helper itself. gen/ is excluded: generated code
# cannot carry hand-written exemptions. Like the other check-*.sh scripts,
# this is a line-based textual check: it matches the identifiers on each
# line, comments included, and resolves neither imports nor types.
set -euo pipefail
cd "$(dirname "$0")/.."

violations=""
while IFS= read -r f; do
  out=$(awk '
    {
      line = $0
      gsub(/(^|[^A-Za-z0-9_])rand\.Float64\(\)/, " ", line)
      gsub(/(^|[^A-Za-z0-9_])canon\.Float64([^A-Za-z0-9_]|$)/, " ", line)
      if ((line ~ /\.Float64([^A-Za-z0-9_]|$)/ || line ~ /(^|[^A-Za-z0-9_])ParseFloat([^A-Za-z0-9_]|$)/) && $0 !~ /number-hygiene-exempt/ && prev !~ /number-hygiene-exempt/)
        printf "%s:%d: %s\n", FILENAME, FNR, $0
    }
    { prev = $0 }
  ' "$f")
  if [ -n "$out" ]; then
    violations="${violations}${out}
"
  fi
done < <(find . -name '*.go' ! -name '*_test.go' ! -path './gen/*' ! -path './.git/*' ! -path './canon/float.go' | sort)

if [ -n "$violations" ]; then
  printf '%s' "$violations" >&2
  echo "check-number-hygiene: a JSON number read as a double outside canon.Float64." >&2
  echo "Read it with canon.Float64, or add a number-hygiene-exempt comment stating" >&2
  echo "why the string is not a JSON number." >&2
  exit 1
fi
