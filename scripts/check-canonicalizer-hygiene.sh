#!/usr/bin/env bash
# Canonicalization happens only via canon entry points — no ad-hoc
# json.Marshal of signing scopes. The check is self-scoping: a non-test file
# that imports this module's canon packages participates in
# canonicalization/signing-scope construction, so any json.Marshal /
# json.NewEncoder there is suspect and must carry a
# `canonicalizer-hygiene-exempt` comment saying why the bytes are not (or
# provably equal to) a canonical form.
# Files that never touch canon may marshal freely (storage, transport,
# operator output) — encoding/json is not banned, ad-hoc canonical forms are.
#
# Exemption positions (checked in this order):
#   1. whole file — the token on the `"encoding/json"` import line
#   2. call site  — the token on the call line or the line directly above
#
# Aliased or dot imports of encoding/json are rejected outright (they would
# blind the check); a blank import (`_`) is allowed.
# Syntactic check; same caveats as check-decoder-hygiene.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

violations=""
while IFS= read -r f; do
  if ! grep -q '"github.com/provin-line/oss/canon' "$f"; then
    continue
  fi
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
  if grep -Eq '^[[:space:]]*(import[[:space:]]+)?"encoding/json".*canonicalizer-hygiene-exempt' "$f"; then
    continue
  fi
  out=$(awk '
    /json\.(Marshal(Indent)?|NewEncoder)\(/ && $0 !~ /canonicalizer-hygiene-exempt/ && prev !~ /canonicalizer-hygiene-exempt/ {
      printf "%s:%d: %s\n", FILENAME, FNR, $0
    }
    { prev = $0 }
  ' "$f")
  if [ -n "$out" ]; then
    violations="${violations}${out}
"
  fi
done < <(find . -name '*.go' ! -name '*_test.go' ! -path './gen/*' ! -path './.git/*' | sort)

if [ -n "$violations" ]; then
  printf '%s' "$violations" >&2
  echo "check-canonicalizer-hygiene: ad-hoc encoding/json encoding in a canon-importing file." >&2
  echo "Emit canonical bytes via canon/jcs (or a canonical MarshalJSON), or add" >&2
  echo "a canonicalizer-hygiene-exempt comment stating why these bytes are not" >&2
  echo "a signing scope." >&2
  exit 1
fi
