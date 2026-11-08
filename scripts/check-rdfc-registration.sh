#!/usr/bin/env bash
# eddsa-rdfc-2022 is off until a process calls vc.RegisterEdDSARDFC2022, and
# the registration holds for the whole process: a library that called it
# would open JSON-LD processing on untrusted documents for every program
# that imports it. So no non-test file of this module refers to the function
# but its definition in vc/cryptosuite.go; a program that wants the suite
# calls it from its own main or an init function of its main package. And no
# non-test package but vc and canon/urdna2015 imports canon/urdna2015 or
# json-gold, so JSON-LD processing is reached only through vc. And no
# non-test file outside it imports internal/rdfccorpus, the documents the
# RDFC tests read, or a package below it, so no program carries them.
#
# The check reads Go's lexical forms: comments (line and block) and string,
# raw string and rune literals are skipped, across lines; a //go:linkname
# directive is read as code. It does not resolve imports or types.
set -euo pipefail
cd "$(dirname "$0")/.."

violations=""
while IFS= read -r f; do
  out=$(awk -v file="$f" '
    BEGIN { state = "code" }   # code, block (/* */), raw (` `)
    {
      line = $0
      code = ""
      i = 1
      n = length(line)
      if (state == "code" && line ~ /^[[:space:]]*\/\/go:linkname[[:space:]]/) {
        code = line
        i = n + 1
      }
      while (i <= n) {
        c = substr(line, i, 1)
        if (state == "block") {
          if (substr(line, i, 2) == "*/") { state = "code"; i += 2 } else { i++ }
          continue
        }
        if (state == "raw") {
          if (c == "`") { state = "code" }
          i++
          continue
        }
        if (substr(line, i, 2) == "//") { break }
        if (substr(line, i, 2) == "/*") { state = "block"; i += 2; code = code " "; continue }
        if (c == "`") { state = "raw"; i++; code = code " "; continue }
        if (c == "\"" || c == "\047") {
          q = c
          i++
          while (i <= n) {
            d = substr(line, i, 1)
            if (d == "\\") { i += 2; continue }
            i++
            if (d == q) { break }
          }
          code = code " "
          continue
        }
        code = code c
        i++
      }
      if (file == "./vc/cryptosuite.go" && code ~ /^func RegisterEdDSARDFC2022\(/)
        next
      if (code ~ /(^|[^A-Za-z0-9_])RegisterEdDSARDFC2022([^A-Za-z0-9_]|$)/)
        printf "%s:%d: %s\n", file, FNR, $0
    }
  ' "$f")
  if [ -n "$out" ]; then
    violations="${violations}${out}
"
  fi
done < <(find . -name '*.go' ! -name '*_test.go' ! -path './.git/*' | sort)

# The JSON-LD processing the function opens is reached only through vc: no
# other non-test package imports canon/urdna2015 or json-gold.
imports=$(find . -name '*.go' ! -name '*_test.go' ! -path './.git/*' ! -path './vc/*' ! -path './canon/urdna2015/*' -print0 |
  xargs -0 grep -lE '"github.com/(provin-line/oss/canon/urdna2015|piprate/json-gold)' 2>/dev/null || true)
if [ -n "$imports" ]; then
  printf '%s\n' "$imports" >&2
  echo "check-rdfc-registration: canon/urdna2015 or json-gold imported outside vc and canon/urdna2015." >&2
  echo "JSON-LD processing runs only through vc, where vc.RegisterEdDSARDFC2022 opens it." >&2
  exit 1
fi

# The RDFC tests' documents are read only by tests: no non-test file but the
# package's own imports it, or a package below it.
corpus=$(find . -name '*.go' ! -name '*_test.go' ! -path './.git/*' \
  ! \( -path './internal/rdfccorpus/*' ! -path './internal/rdfccorpus/*/*' \) -print0 |
  xargs -0 grep -lE '"github\.com/provin-line/oss/internal/rdfccorpus(/[^"]*)?"' 2>/dev/null || true)
if [ -n "$corpus" ]; then
  printf '%s\n' "$corpus" >&2
  echo "check-rdfc-registration: internal/rdfccorpus imported outside a test." >&2
  echo "It holds the documents the RDFC tests read; only tests import it." >&2
  exit 1
fi

if [ -n "$violations" ]; then
  printf '%s' "$violations" >&2
  echo "check-rdfc-registration: vc.RegisterEdDSARDFC2022 referred to outside a test." >&2
  echo "It opens eddsa-rdfc-2022 for the whole process; only a program's own main" >&2
  echo "or an init function of its main package calls it, never a package of this module." >&2
  exit 1
fi
